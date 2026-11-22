package main

// A software authenticator for the tests: it answers WebAuthn enrollment and
// sign-in challenges the way a hardware key or passkey does (ES256, "none"
// attestation), so the real verification code runs end to end.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testOrigin is the address the test server claims to be reached at.
const testOrigin = "https://driftband.test"

type softKey struct {
	t      *testing.T
	priv   *ecdsa.PrivateKey
	id     []byte
	count  uint32
	origin string
	uv     bool // verifies the user (PIN, fingerprint): what a passkey does
}

func newSoftKey(t *testing.T, uv bool) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softKey{t: t, priv: priv, id: id, origin: testOrigin, uv: uv}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// publicKeyOptions digs the "publicKey" object out of a begin response
// ({"options": {"publicKey": ...}}) or a sign-in answer
// ({"webauthn": {"options": {"publicKey": ...}}}).
func publicKeyOptions(t *testing.T, r *resp) map[string]any {
	t.Helper()
	holder := r.JSON
	if w, ok := r.JSON["webauthn"].(map[string]any); ok {
		holder = w
	}
	opts, _ := holder["options"].(map[string]any)
	pk, _ := opts["publicKey"].(map[string]any)
	if pk == nil {
		t.Fatalf("no WebAuthn options in %s", r.Body)
	}
	return pk
}

func (k *softKey) rpHash() []byte {
	u, _ := url.Parse(k.origin)
	h := sha256.Sum256([]byte(u.Hostname()))
	return h[:]
}

func (k *softKey) clientData(typ, challenge string) []byte {
	j, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	return j
}

func (k *softKey) flags(attested bool) byte {
	f := byte(0x01) // user present
	if k.uv {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	return f
}

// register answers an enrollment challenge.
func (k *softKey) register(begin *resp) map[string]any {
	k.t.Helper()
	pk := publicKeyOptions(k.t, begin)
	pub, err := k.priv.PublicKey.ECDH()
	if err != nil {
		k.t.Fatal(err)
	}
	point := pub.Bytes() // 0x04 | X | Y
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:65]})
	var ad bytes.Buffer
	ad.Write(k.rpHash())
	ad.WriteByte(k.flags(true))
	_ = binary.Write(&ad, binary.BigEndian, k.count)
	ad.Write(make([]byte, 16)) // AAGUID
	_ = binary.Write(&ad, binary.BigEndian, uint16(len(k.id)))
	ad.Write(k.id)
	ad.Write(cose)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad.Bytes()})
	return map[string]any{
		"id": b64u(k.id), "rawId": b64u(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(k.clientData("webauthn.create", pk["challenge"].(string))),
			"attestationObject": b64u(att),
			"transports":        []string{"usb"},
		},
		"clientExtensionResults": map[string]any{},
	}
}

// assert answers a sign-in challenge; the signature counter goes up by one.
func (k *softKey) assert(challenge *resp) map[string]any {
	k.t.Helper()
	pk := publicKeyOptions(k.t, challenge)
	k.count++
	var ad bytes.Buffer
	ad.Write(k.rpHash())
	ad.WriteByte(k.flags(false))
	_ = binary.Write(&ad, binary.BigEndian, k.count)
	cd := k.clientData("webauthn.get", pk["challenge"].(string))
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(ad.Bytes(), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	return map[string]any{
		"id": b64u(k.id), "rawId": b64u(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(cd),
			"authenticatorData": b64u(ad.Bytes()),
			"signature":         b64u(sig),
		},
		"clientExtensionResults": map[string]any{},
	}
}

// enroll registers a new software key (kind: key | passkey) for a and
// returns it with the id of the stored credential.
func (e *env) enroll(a *actor, kind string, uv bool) (*softKey, int64) {
	e.t.Helper()
	k := newSoftKey(e.t, uv)
	r := e.must(e.req(a, "POST", "/api/account/webauthn/register/begin",
		map[string]any{"password": a.Password, "kind": kind, "name": "test " + kind}), 200, "webauthn begin")
	r = e.must(e.req(a, "POST", "/api/account/webauthn/register/finish",
		map[string]any{"token": r.JSON["token"], "credential": k.register(r)}), 200, "webauthn finish")
	return k, int64(r.JSON["credential"].(map[string]any)["id"].(float64))
}

// loginWith signs in with the password and then the key's answer to the
// challenge the server issued.
func (e *env) loginWith(a *actor, k *softKey) *resp {
	e.t.Helper()
	ch := e.login(a.Email, a.Password, "")
	if ch.Status != 401 || ch.JSON["two_factor_required"] != true {
		e.t.Fatalf("expected a second-factor challenge: %d %s", ch.Status, ch.Body)
	}
	return e.req(anon, "POST", "/api/auth/login", map[string]any{"email": a.Email, "password": a.Password,
		"webauthn_token": ch.JSON["webauthn"].(map[string]any)["token"], "credential": k.assert(ch)})
}

// ----- pictures -----

// testPNG is a w x h picture: the top half red, the bottom half blue,
// optionally with a transparent corner.
func testPNG(t *testing.T, w, h int, transparent bool) []byte {
	t.Helper()
	return encodePNG(t, testImage(w, h, transparent))
}

func testImage(w, h int, transparent bool) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.NRGBA{R: 220, A: 255}
			if y >= h/2 {
				c = color.NRGBA{B: 220, A: 255}
			}
			if transparent && x < w/4 && y < h/4 {
				c.A = 0
			}
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func avatarBody(mime string, file []byte) map[string]any {
	return map[string]any{"type": mime, "data": base64.StdEncoding.EncodeToString(file)}
}
