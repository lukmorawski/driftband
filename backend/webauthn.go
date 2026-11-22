package main

// Security keys and passkeys (WebAuthn / FIDO2) as second factors, next to
// TOTP. A user enrolls a roaming hardware key ("key", e.g. a YubiKey) or a
// passkey ("passkey": a discoverable credential with user verification, kept
// by this device, a phone or a password manager). Signing in still starts
// with the password; any enrolled factor then completes it.
//
// The protocol itself (challenges, origin and RP ID checks, signature and
// counter verification) is done by github.com/go-webauthn/webauthn.
// Credential records are sealed in the database, and pending ceremonies are
// kept server-side: single use, valid for a few minutes.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	webauthnTTL            = 5 * time.Minute
	maxWebauthnCredentials = 10
	maxPendingChallenges   = 5 // per user and purpose
)

var errNoRelyingParty = errors.New("security keys and passkeys need Driftband to be opened through a host name (not an IP address); set APP_URL to its public address")

// relyingParty builds the WebAuthn relying party for a request: the origin is
// APP_URL when it is set (the address users are meant to use), otherwise the
// address of the request. Browsers only use a credential on the origin it
// was created for, so a request sent with another Host cannot borrow one.
func (a *App) relyingParty(r *http.Request) (*webauthn.WebAuthn, error) {
	origin := a.appURL
	if origin == "" {
		scheme := "http"
		if a.isHTTPS(r) {
			scheme = "https"
		}
		origin = scheme + "://" + r.Host
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil {
		return nil, errNoRelyingParty
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:                  strings.ToLower(u.Hostname()),
		RPDisplayName:         "Driftband",
		RPOrigins:             []string{u.Scheme + "://" + u.Host},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: webauthnTTL, TimeoutUVD: webauthnTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: webauthnTTL, TimeoutUVD: webauthnTTL},
		},
		// Password managers add outputs nobody asked for (credProps); they
		// carry nothing that is trusted here.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		return nil, errNoRelyingParty
	}
	return w, nil
}

// storedCredential is one enrolled key or passkey.
type storedCredential struct {
	ID       int64
	Kind     string // key | passkey
	Name     string
	Created  time.Time
	LastUsed *time.Time
	Cred     webauthn.Credential
}

// waUser is the account as the WebAuthn library sees it. The user handle is
// the numeric id: it identifies the account without revealing the email.
type waUser struct {
	id     int64
	email  string
	creds  []storedCredential
	broken int // enrolled credentials whose record does not open
}

func (u *waUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.id)) // #nosec G115 -- ids are positive
	return b
}
func (u *waUser) WebAuthnName() string        { return u.email }
func (u *waUser) WebAuthnDisplayName() string { return u.email }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.creds))
	for i, c := range u.creds {
		out[i] = c.Cred
	}
	return out
}

func credentialContext(userID int64) string {
	return "webauthn_credential:user:" + strconv.FormatInt(userID, 10)
}

// webauthnUser loads a user's enrolled credentials. A row that does not open
// with this user's context (changed in the database, or SECRET_KEY replaced)
// can no longer sign in; it is counted, so that an account whose keys all
// became unusable is not quietly left with the password alone.
func (a *App) webauthnUser(ctx context.Context, userID int64, email string) (*waUser, error) {
	rows, err := a.db.Query(ctx, `SELECT id, kind, name, data, created_at, last_used_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	u := &waUser{id: userID, email: email}
	for rows.Next() {
		var c storedCredential
		var sealed []byte
		if err := rows.Scan(&c.ID, &c.Kind, &c.Name, &sealed, &c.Created, &c.LastUsed); err != nil {
			return nil, err
		}
		plain, err := a.sealer.openFor(credentialContext(userID), sealed)
		if err != nil || json.Unmarshal(plain, &c.Cred) != nil {
			u.broken++
			continue
		}
		u.creds = append(u.creds, c)
	}
	return u, rows.Err()
}

func (a *App) sealCredential(userID int64, c *webauthn.Credential) ([]byte, error) {
	j, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return a.sealer.sealFor(credentialContext(userID), j)
}

// saveChallenge stores a pending ceremony and returns its token. Expired
// ceremonies are removed, and a user keeps only the newest few.
func (a *App) saveChallenge(ctx context.Context, userID int64, purpose, kind, name string, s *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	_, _ = a.db.Exec(ctx, `DELETE FROM webauthn_challenges WHERE expires_at < now()`)
	_, _ = a.db.Exec(ctx, `
		DELETE FROM webauthn_challenges WHERE user_id = $1 AND purpose = $2 AND token NOT IN (
			SELECT token FROM webauthn_challenges WHERE user_id = $1 AND purpose = $2 ORDER BY expires_at DESC LIMIT $3)`,
		userID, purpose, maxPendingChallenges-1)
	token := randomToken()
	_, err = a.db.Exec(ctx, `INSERT INTO webauthn_challenges (token, user_id, purpose, kind, name, data, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		token, userID, purpose, kind, name, data, time.Now().Add(webauthnTTL))
	return token, err
}

// takeChallenge returns a pending ceremony and removes it: a challenge is
// answered once, by the user it was issued to.
func (a *App) takeChallenge(ctx context.Context, token string, userID int64, purpose string) (s webauthn.SessionData, kind, name string, err error) {
	var data []byte
	err = a.db.QueryRow(ctx, `
		DELETE FROM webauthn_challenges WHERE token = $1 AND user_id = $2 AND purpose = $3 AND expires_at > now()
		RETURNING data, kind, name`, token, userID, purpose).Scan(&data, &kind, &name)
	if err != nil {
		return s, "", "", err
	}
	err = json.Unmarshal(data, &s)
	return s, kind, name, err
}

// twoFactorList turns the stored state into the list shown in the UI:
// "totp", "key", "passkey".
func twoFactorList(totp bool, kinds []string) []string {
	out := []string{}
	if totp {
		out = append(out, "totp")
	}
	for _, k := range []string{"key", "passkey"} {
		for _, have := range kinds {
			if have == k {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

func kindLabel(kind string) string {
	if kind == "passkey" {
		return "passkey"
	}
	return "security key"
}

func credentialView(c storedCredential) map[string]any {
	v := map[string]any{"id": c.ID, "kind": c.Kind, "name": c.Name, "created_at": c.Created.Unix(), "last_used_at": nil}
	if c.LastUsed != nil {
		v["last_used_at"] = c.LastUsed.Unix()
	}
	return v
}

// ----- handlers -----

// handleWebauthnList returns the signed-in user's keys and passkeys, and
// whether this address can enroll or use them.
func (a *App) handleWebauthnList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	wu, err := a.webauthnUser(r.Context(), u.ID, u.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	list := []map[string]any{}
	for _, c := range wu.creds {
		list = append(list, credentialView(c))
	}
	out := map[string]any{"credentials": list, "available": true, "limit": maxWebauthnCredentials}
	if _, err := a.relyingParty(r); err != nil {
		out["available"], out["reason"] = false, err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleWebauthnRegisterBegin starts enrolling a key or passkey (password
// confirmation required) and returns the options for navigator.credentials.
func (a *App) handleWebauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Password string `json:"password"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Kind != "key" && in.Kind != "passkey" {
		writeErr(w, http.StatusBadRequest, "kind must be key or passkey")
		return
	}
	if in.Name == "" {
		in.Name = map[string]string{"key": "Security key", "passkey": "Passkey"}[in.Kind]
	}
	if len(in.Name) > 60 {
		writeErr(w, http.StatusBadRequest, "name too long (max 60 characters)")
		return
	}
	ctx := r.Context()
	if !a.checkPassword(w, r, u, in.Password, "account.webauthn_setup", "password is incorrect") {
		return
	}
	rp, err := a.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := a.webauthnUser(ctx, u.ID, u.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if len(wu.creds) >= maxWebauthnCredentials {
		writeErr(w, http.StatusConflict, "the limit of "+strconv.Itoa(maxWebauthnCredentials)+" keys and passkeys is reached; remove one first")
		return
	}
	// A hardware key is a plain second factor: no stored (discoverable)
	// credential and no PIN. A passkey is discoverable and verifies the user
	// (fingerprint, face or PIN) on every use.
	sel := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.CrossPlatform,
		ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
		UserVerification:        protocol.VerificationDiscouraged,
	}
	if in.Kind == "passkey" {
		sel = protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}
	}
	exclude := make([]protocol.CredentialDescriptor, len(wu.creds))
	for i, c := range wu.creds {
		exclude[i] = c.Cred.Descriptor()
	}
	options, session, err := rp.BeginRegistration(wu,
		webauthn.WithAuthenticatorSelection(sel),
		webauthn.WithExclusions(exclude),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start enrollment")
		return
	}
	token, err := a.saveChallenge(ctx, u.ID, "register", in.Kind, in.Name, session)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start enrollment")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.webauthn_setup", kindLabel(in.Kind)+" enrollment started")
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "options": options})
}

// handleWebauthnRegisterFinish verifies the authenticator's answer and
// stores the new credential.
func (a *App) handleWebauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Token      string          `json:"token"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	session, kind, name, err := a.takeChallenge(ctx, in.Token, u.ID, "register")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "enrollment expired or already used; start again")
		return
	}
	rp, err := a.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := a.webauthnUser(ctx, u.ID, u.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	refuse := func(why string) {
		a.audit(ctx, u, clientIP(r), "denied.account.webauthn_add", kindLabel(kind)+": "+why)
		writeErr(w, http.StatusBadRequest, "the "+kindLabel(kind)+" was not accepted: "+why)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Credential)
	if err != nil {
		refuse("malformed response")
		return
	}
	cred, err := rp.CreateCredential(wu, session, parsed)
	if err != nil {
		refuse(webauthnReason(err))
		return
	}
	sealed, err := a.sealCredential(u.ID, cred)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encrypt failed")
		return
	}
	c := storedCredential{Kind: kind, Name: name, Cred: *cred}
	err = a.db.QueryRow(ctx, `INSERT INTO webauthn_credentials (user_id, kind, name, credential_id, data) VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		u.ID, kind, name, cred.ID, sealed).Scan(&c.ID, &c.Created)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "this key is already enrolled")
			return
		}
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.webauthn_add", kindLabel(kind)+" \""+name+"\"")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "credential": credentialView(c)})
}

// handleWebauthnDelete removes one of the user's keys or passkeys (password
// confirmation required, like turning TOTP off).
func (a *App) handleWebauthnDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	var kind, name string
	if err := a.db.QueryRow(ctx, `SELECT kind, name FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, u.ID).Scan(&kind, &name); err != nil {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	if !a.checkPassword(w, r, u, in.Password, "account.webauthn_remove", "password is incorrect") {
		return
	}
	if _, err := a.db.Exec(ctx, `DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.webauthn_remove", kindLabel(kind)+" \""+name+"\"")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webauthnReason is a short, safe description of a verification error for
// the audit log and the user (never the raw response).
func webauthnReason(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Details != "" {
		return pe.Details
	}
	return "verification failed"
}

// ----- sign-in -----

// webauthnLoginOptions issues a sign-in challenge for the user's keys and
// passkeys. Called only after the password was verified.
func (a *App) webauthnLoginOptions(r *http.Request, wu *waUser) (map[string]any, error) {
	rp, err := a.relyingParty(r)
	if err != nil {
		return nil, err
	}
	options, session, err := rp.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return nil, err
	}
	token, err := a.saveChallenge(r.Context(), wu.id, "login", "", "", session)
	if err != nil {
		return nil, err
	}
	return map[string]any{"token": token, "options": options}, nil
}

// webauthnLogin verifies the answer to a sign-in challenge and returns the
// credential that signed it. The stored record (signature counter, flags,
// last use) is updated; a counter that went backwards means the key may
// have been cloned, and the sign-in is refused.
func (a *App) webauthnLogin(r *http.Request, wu *waUser, token string, response json.RawMessage) (*storedCredential, error) {
	ctx := r.Context()
	session, _, _, err := a.takeChallenge(ctx, token, wu.id, "login")
	if err != nil {
		return nil, errors.New("challenge expired or already used")
	}
	rp, err := a.relyingParty(r)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, errors.New("malformed response")
	}
	cred, err := rp.ValidateLogin(wu, session, parsed)
	if err != nil {
		return nil, errors.New(webauthnReason(err))
	}
	if cred.Authenticator.CloneWarning {
		return nil, errors.New("signature counter went backwards (the key may have been copied)")
	}
	for i := range wu.creds {
		c := &wu.creds[i]
		if string(c.Cred.ID) != string(cred.ID) {
			continue
		}
		c.Cred = *cred
		if sealed, err := a.sealCredential(wu.id, cred); err == nil {
			_, _ = a.db.Exec(ctx, `UPDATE webauthn_credentials SET data = $1, last_used_at = now() WHERE id = $2 AND user_id = $3`, sealed, c.ID, wu.id)
		}
		return c, nil
	}
	return nil, errors.New("unknown credential")
}
