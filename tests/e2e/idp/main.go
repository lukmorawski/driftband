// A stand-in for a single sign-on provider, for the browser tests of the
// throwaway stack (scripts/test-stack.sh). It speaks OpenID Connect the way
// Microsoft Entra ID does for one tenant: discovery, the authorization
// endpoint, the token endpoint and the signing keys. Instead of a real
// sign-in page it asks who is signing in (subject and email), which is what
// a test types in.
//
// It serves HTTPS with a certificate it creates at start and writes to
// IDP_CERT, so that the application can be told to trust it (SSL_CERT_DIR).
// It keeps no secrets worth protecting and must never be reachable from
// outside a test network.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type grant struct {
	nonce, challenge, redirect, clientID string
	sub, email                           string
}

var (
	issuer   = env("IDP_ISSUER", "https://idp:8443/"+env("IDP_TENANT", "00000000-0000-0000-0000-000000000000")+"/v2.0")
	clientID = env("IDP_CLIENT_ID", "driftband-e2e")
	secret   = os.Getenv("IDP_CLIENT_SECRET") // made up per run by the stack
	key      *rsa.PrivateKey
	mu       sync.Mutex
	grants   = map[string]grant{}
)

const kid = "e2e-key"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return b64(b)
}

var page = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Test sign-in</title>
<h1>Test sign-in</h1>
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<p><label>Subject <input name="sub" required></label></p>
<p><label>Email <input name="email"></label></p>
<p><button type="submit" name="decision" value="allow">Continue</button>
<button type="submit" name="decision" value="deny" formnovalidate>Cancel</button></p>
</form></html>`))

func main() {
	if secret == "" {
		log.Fatal("IDP_CLIENT_SECRET is required")
	}
	var err error
	if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		log.Fatal(err)
	}
	u, err := url.Parse(issuer)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := certificate(u.Hostname())
	if err != nil {
		log.Fatal(err)
	}
	base := strings.TrimSuffix(u.Path, "/")
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
			"response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET "+base+"/keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("GET "+base+"/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" ||
			q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("redirect_uri") == "" {
			http.Error(w, "bad authorization request", http.StatusBadRequest)
			return
		}
		hidden := map[string]string{}
		for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "code_challenge"} {
			hidden[k] = q.Get(k)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, map[string]any{"Action": base + "/signin", "Hidden": hidden})
	})
	mux.HandleFunc("POST "+base+"/signin", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		f := r.PostForm
		back, err := url.Parse(f.Get("redirect_uri"))
		if err != nil || f.Get("client_id") != clientID {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q := url.Values{"state": {f.Get("state")}}
		if f.Get("decision") != "allow" || f.Get("sub") == "" {
			q.Set("error", "access_denied")
		} else {
			code := random()
			mu.Lock()
			grants[code] = grant{nonce: f.Get("nonce"), challenge: f.Get("code_challenge"), redirect: f.Get("redirect_uri"),
				clientID: f.Get("client_id"), sub: f.Get("sub"), email: f.Get("email")}
			mu.Unlock()
			q.Set("code", code)
		}
		back.RawQuery = q.Encode()
		http.Redirect(w, r, back.String(), http.StatusSeeOther)
	})
	mux.HandleFunc("POST "+base+"/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		f := r.PostForm
		mu.Lock()
		g, ok := grants[f.Get("code")]
		delete(grants, f.Get("code"))
		mu.Unlock()
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || f.Get("grant_type") != "authorization_code" || f.Get("client_id") != g.clientID || f.Get("client_secret") != secret ||
			f.Get("redirect_uri") != g.redirect || b64(sum[:]) != g.challenge {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		now := time.Now()
		claims := map[string]any{"iss": issuer, "aud": g.clientID, "sub": g.sub, "nonce": g.nonce, "iat": now.Unix(),
			"exp": now.Add(5 * time.Minute).Unix(), "tid": strings.Split(strings.TrimPrefix(base, "/"), "/")[0]}
		if g.email != "" {
			claims["email"], claims["preferred_username"] = g.email, g.email
		}
		tok, err := sign(claims)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id_token": tok, "access_token": random(), "token_type": "Bearer", "expires_in": 300})
	})
	srv := &http.Server{Addr: env("IDP_LISTEN", ":8443"), Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	log.Printf("test identity provider: issuer %s", issuer)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// sign returns claims as an RS256 JSON Web Token.
func sign(claims map[string]any) (string, error) {
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	body, _ := json.Marshal(claims)
	input := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// certificate creates a self-signed certificate for host, valid for a day,
// and writes it to IDP_CERT for whoever has to trust it.
func certificate(host string) (tls.Certificate, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Driftband test identity provider"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{host},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if out := os.Getenv("IDP_CERT"); out != "" {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.WriteFile(out+".tmp", pemBytes, 0o644); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.Rename(out+".tmp", out); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
