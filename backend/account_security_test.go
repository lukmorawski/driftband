package main

// Security rules of the account features added with security keys and
// passkeys, profile pictures and sealed notification channels.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/jpeg"
	"math/rand"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Security keys and passkeys.

func TestSecurityKeyAsSecondFactor(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("fido")
	a := o.Member
	ctx := context.Background()

	// Enrollment needs the password, and the answer of a real authenticator.
	if r := e.req(a, "POST", "/api/account/webauthn/register/begin", map[string]any{"password": "Wrong-pass-123", "kind": "key"}); r.Status != 403 {
		t.Fatalf("begin with wrong password: %d", r.Status)
	}
	if r := e.req(a, "POST", "/api/account/webauthn/register/begin", map[string]any{"password": a.Password, "kind": "u2f"}); r.Status != 400 {
		t.Errorf("unknown kind accepted: %d", r.Status)
	}
	key, credID := e.enroll(a, "key", false)

	// Stored sealed: the record cannot be read or forged in the database.
	var data []byte
	_ = testDB.QueryRow(ctx, `SELECT data FROM webauthn_credentials WHERE id = $1`, credID).Scan(&data)
	if len(data) == 0 || data[0] != sealedV2 || bytes.Contains(data, []byte("publicKey")) {
		t.Fatal("credential record is not sealed")
	}

	// The password alone no longer signs in.
	r := e.login(a.Email, a.Password, "")
	if r.Status != 401 || r.JSON["two_factor_required"] != true || r.JSON["totp_required"] != false || r.cookie(sessionCookie) != nil {
		t.Fatalf("password alone must not sign in: %d %s", r.Status, r.Body)
	}
	if m, _ := json.Marshal(r.JSON["methods"]); string(m) != `["webauthn"]` {
		t.Errorf("methods = %s", m)
	}
	// A TOTP code is not a way around a key-only account.
	if r := e.login(a.Email, a.Password, "123456"); r.Status != 401 || r.cookie(sessionCookie) != nil {
		t.Errorf("code accepted for an account without TOTP: %d", r.Status)
	}

	// Password, then the key.
	t0 := dbNow(t)
	ch := e.login(a.Email, a.Password, "")
	answer := map[string]any{"email": a.Email, "password": a.Password,
		"webauthn_token": ch.JSON["webauthn"].(map[string]any)["token"], "credential": key.assert(ch)}
	ok := e.must(e.req(anon, "POST", "/api/auth/login", answer), 200, "login with key")
	if ok.cookie(sessionCookie) == nil {
		t.Fatal("no session after key sign-in")
	}
	var detail string
	_ = testDB.QueryRow(ctx, `SELECT detail FROM audit_log WHERE org_id = $1 AND action = 'auth.login' AND created_at >= $2 ORDER BY id DESC LIMIT 1`, a.OrgID, t0).Scan(&detail)
	if !strings.Contains(detail, "security key") {
		t.Errorf("sign-in audit does not name the factor: %q", detail)
	}
	// The same answer is worthless a second time (challenge is single use).
	t0 = dbNow(t)
	if r := e.req(anon, "POST", "/api/auth/login", answer); r.Status != 401 || r.cookie(sessionCookie) != nil {
		t.Errorf("replayed key answer accepted: %d", r.Status)
	}
	if !auditHas(t, a.OrgID, a.Email, "auth.login_failed", t0) {
		t.Error("refused key answer not audited")
	}

	// A valid answer does not help without the password.
	ch = e.login(a.Email, a.Password, "")
	if r := e.req(anon, "POST", "/api/auth/login", map[string]any{"email": a.Email, "password": "Wrong-pass-123",
		"webauthn_token": ch.JSON["webauthn"].(map[string]any)["token"], "credential": key.assert(ch)}); r.Status != 401 || r.JSON["two_factor_required"] != nil {
		t.Errorf("key answer with wrong password: %d %s", r.Status, r.Body)
	}

	// An answer collected on another site (phishing proxy) is refused.
	phish := *key
	phish.origin = "https://driftband.test.evil.example"
	if r := e.loginWith(a, &phish); r.Status != 401 {
		t.Errorf("answer for another origin accepted: %d", r.Status)
	}
	key.count = phish.count

	// A key that was never enrolled is refused.
	if r := e.loginWith(a, newSoftKey(t, false)); r.Status != 401 {
		t.Errorf("unknown key accepted: %d", r.Status)
	}

	// A challenge issued to one account cannot complete another's sign-in.
	other := o.Admin
	otherKey, _ := e.enroll(other, "key", false)
	chA := e.login(a.Email, a.Password, "")
	if r := e.req(anon, "POST", "/api/auth/login", map[string]any{"email": other.Email, "password": other.Password,
		"webauthn_token": chA.JSON["webauthn"].(map[string]any)["token"], "credential": otherKey.assert(chA)}); r.Status != 401 {
		t.Errorf("another account's challenge accepted: %d", r.Status)
	}

	// A signature counter that goes backwards means a copied key.
	e.must(e.loginWith(a, key), 200, "second key login")
	key.count -= 2
	if r := e.loginWith(a, key); r.Status != 401 {
		t.Errorf("cloned key (counter went backwards) accepted: %d", r.Status)
	}
	key.count += 2

	// TOTP next to the key: either factor completes the sign-in.
	secret := e.must(e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}), 200, "totp setup").JSON["secret"].(string)
	e.must(e.req(a, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "totp enable")
	r = e.login(a.Email, a.Password, "")
	if m, _ := json.Marshal(r.JSON["methods"]); string(m) != `["totp","webauthn"]` || r.JSON["totp_required"] != true {
		t.Errorf("methods with both factors = %s", m)
	}
	e.must(e.login(a.Email, a.Password, currentTotp(t, secret, 1)), 200, "login with code")
	e.must(e.loginWith(a, key), 200, "login with key")
	if me := e.must(e.req(a, "GET", "/api/me", nil), 200, "me"); len(me.JSON["two_factor"].([]any)) != 2 {
		t.Errorf("me.two_factor = %v", me.JSON["two_factor"])
	}
	e.must(e.req(a, "POST", "/api/account/2fa/disable", map[string]any{"password": a.Password}), 200, "totp disable")

	// A record that no longer opens (changed in the database, or the server
	// key was replaced) does not leave the account with the password alone.
	var saved []byte
	_ = testDB.QueryRow(ctx, `SELECT data FROM webauthn_credentials WHERE id = $1`, credID).Scan(&saved)
	broken := append([]byte{}, saved...)
	broken[len(broken)-1] ^= 1
	if _, err := testDB.Exec(ctx, `UPDATE webauthn_credentials SET data = $1 WHERE id = $2`, broken, credID); err != nil {
		t.Fatal(err)
	}
	if r := e.login(a.Email, a.Password, ""); r.Status != 401 || r.cookie(sessionCookie) != nil || !strings.Contains(string(r.Body), "administrator") {
		t.Errorf("an account whose key record is unreadable signed in with the password alone: %d %s", r.Status, r.Body)
	}
	if _, err := testDB.Exec(ctx, `UPDATE webauthn_credentials SET data = $1 WHERE id = $2`, saved, credID); err != nil {
		t.Fatal(err)
	}
	e.must(e.loginWith(a, key), 200, "login after the record was restored")

	// Removing a key needs the password; afterwards the password is enough.
	if r := e.req(a, "POST", pathf("/api/account/webauthn/%d/delete", credID), map[string]any{"password": "Wrong-pass-123"}); r.Status != 403 {
		t.Errorf("remove with wrong password: %d", r.Status)
	}
	if r := e.req(other, "POST", pathf("/api/account/webauthn/%d/delete", credID), map[string]any{"password": other.Password}); r.Status != 404 {
		t.Errorf("a teammate removed someone else's key: %d", r.Status)
	}
	e.must(e.req(a, "POST", pathf("/api/account/webauthn/%d/delete", credID), map[string]any{"password": a.Password}), 200, "remove")
	e.must(e.login(a.Email, a.Password, ""), 200, "login after removing the key")
}

func TestPasskeyEnrollmentRules(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("passkey")
	a := o.Member

	begin := func(kind string) *resp {
		return e.must(e.req(a, "POST", "/api/account/webauthn/register/begin", map[string]any{"password": a.Password, "kind": kind, "name": "Laptop"}), 200, "begin")
	}
	finish := func(b *resp, k *softKey) *resp {
		return e.req(a, "POST", "/api/account/webauthn/register/finish", map[string]any{"token": b.JSON["token"], "credential": k.register(b)})
	}

	// A passkey must verify the user (PIN, fingerprint, face).
	b := begin("passkey")
	sel := publicKeyOptions(t, b)["authenticatorSelection"].(map[string]any)
	if sel["userVerification"] != "required" || sel["residentKey"] != "required" {
		t.Errorf("passkey options: %v", sel)
	}
	t0 := dbNow(t)
	if r := finish(b, newSoftKey(t, false)); r.Status != 400 {
		t.Errorf("passkey without user verification accepted: %d", r.Status)
	}
	if !auditHas(t, a.OrgID, a.Email, "denied.account.webauthn_add", t0) {
		t.Error("refused enrollment not audited")
	}
	// The challenge was used up by the refused attempt.
	if r := finish(b, newSoftKey(t, true)); r.Status != 400 {
		t.Errorf("enrollment challenge reused: %d", r.Status)
	}
	passkey := newSoftKey(t, true)
	e.must(finish(begin("passkey"), passkey), 200, "passkey enrolled")
	e.must(e.loginWith(a, passkey), 200, "login with passkey")

	// A hardware key is asked for as a roaming authenticator without a PIN.
	b = begin("key")
	sel = publicKeyOptions(t, b)["authenticatorSelection"].(map[string]any)
	if sel["authenticatorAttachment"] != "cross-platform" || sel["userVerification"] != "discouraged" {
		t.Errorf("key options: %v", sel)
	}
	if ex, _ := publicKeyOptions(t, b)["excludeCredentials"].([]any); len(ex) != 1 {
		t.Errorf("enrolled credentials are not excluded: %v", ex)
	}
	// The same authenticator twice, another origin, another user's challenge.
	if r := finish(b, passkey); r.Status != 409 {
		t.Errorf("same credential enrolled twice: %d", r.Status)
	}
	evil := newSoftKey(t, false)
	evil.origin = "https://evil.example"
	if r := finish(begin("key"), evil); r.Status != 400 {
		t.Errorf("enrollment from another origin accepted: %d", r.Status)
	}
	b = begin("key")
	if r := e.req(o.Admin, "POST", "/api/account/webauthn/register/finish", map[string]any{"token": b.JSON["token"], "credential": newSoftKey(t, false).register(b)}); r.Status != 400 {
		t.Errorf("another user's enrollment challenge accepted: %d", r.Status)
	}

	// The list shows what is enrolled, never key material.
	l := e.must(e.req(a, "GET", "/api/account/webauthn", nil), 200, "list")
	if n := len(l.JSON["credentials"].([]any)); n != 1 || l.JSON["available"] != true {
		t.Errorf("list: %s", l.Body)
	}
	if strings.Contains(string(l.Body), "publicKey") || strings.Contains(string(l.Body), b64u(passkey.id)) {
		t.Errorf("list exposes credential data: %s", l.Body)
	}

	// At most 10 per account.
	for i := 1; i < maxWebauthnCredentials; i++ {
		e.enroll(a, "key", false)
	}
	if r := e.req(a, "POST", "/api/account/webauthn/register/begin", map[string]any{"password": a.Password, "kind": "key"}); r.Status != 409 {
		t.Errorf("limit not enforced: %d", r.Status)
	}

	// A platform administrator's two-factor reset removes keys and passkeys.
	sa := e.superadmin()
	e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/reset-password", a.ID), map[string]any{"reset_2fa": true}), 200, "reset")
	var n int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM webauthn_credentials WHERE user_id = $1`, a.ID).Scan(&n)
	if n != 0 {
		t.Errorf("%d credentials left after a two-factor reset", n)
	}

	// Reached through an IP address there is no relying party to bind to.
	e.app.appURL = "http://192.0.2.10:8080"
	if r := e.req(o.Owner, "POST", "/api/account/webauthn/register/begin", map[string]any{"password": o.Owner.Password, "kind": "key"}); r.Status != 400 {
		t.Errorf("enrollment on an IP address: %d", r.Status)
	}
	if l := e.must(e.req(o.Owner, "GET", "/api/account/webauthn", nil), 200, "list"); l.JSON["available"] != false {
		t.Errorf("list claims keys are available on an IP address")
	}
}

func TestTeamSignInDetails(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("team")
	e.enroll(o.Member, "passkey", true)
	secret := e.must(e.req(o.Admin, "POST", "/api/account/2fa/setup", map[string]any{"password": o.Admin.Password}), 200, "setup").JSON["secret"].(string)
	e.must(e.req(o.Admin, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "enable")

	row := func(viewer *actor, id int64) map[string]any {
		for _, u := range e.must(e.req(viewer, "GET", "/api/users", nil), 200, "users").List {
			if m := u.(map[string]any); int64(m["id"].(float64)) == id {
				return m
			}
		}
		t.Fatalf("user %d not listed", id)
		return nil
	}
	// Owners and admins see the last sign-in and the second factors of all.
	for _, viewer := range []*actor{o.Owner, o.Admin} {
		if m := row(viewer, o.Member.ID); m["last_login"] == nil || jsonOf(m["two_factor"]) != `["passkey"]` {
			t.Errorf("%s sees member as %v", viewer.Role, m)
		}
		if m := row(viewer, o.Admin.ID); jsonOf(m["two_factor"]) != `["totp"]` {
			t.Errorf("%s sees admin as %v", viewer.Role, m)
		}
		if m := row(viewer, o.Owner.ID); jsonOf(m["two_factor"]) != `[]` {
			t.Errorf("%s sees owner as %v", viewer.Role, m)
		}
	}
	// Members see them only for themselves.
	if m := row(o.Member, o.Admin.ID); m["last_login"] != nil || m["two_factor"] != nil {
		t.Errorf("member sees an admin's sign-in details: %v", m)
	}
	if m := row(o.Member, o.Member.ID); m["last_login"] == nil || jsonOf(m["two_factor"]) != `["passkey"]` {
		t.Errorf("member does not see their own details: %v", m)
	}
	// The platform view lists the factors too.
	sa := e.superadmin()
	l := e.must(e.req(sa, "GET", pathf("/api/admin/orgs/%d/users", o.Owner.OrgID), nil), 200, "admin users")
	if !strings.Contains(string(l.Body), `"two_factor":["passkey"]`) || !strings.Contains(string(l.Body), `"two_factor":["totp"]`) {
		t.Errorf("admin view lacks the factors: %s", l.Body)
	}
}

func jsonOf(v any) string { j, _ := json.Marshal(v); return string(j) }

// ---------------------------------------------------------------------------
// Profile pictures.

// pngHeader is a PNG that only claims its size: signature and IHDR.
func pngHeader(w, h uint32) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8], ihdr[9] = 8, 6 // 8 bit RGBA
	chunk := append([]byte("IHDR"), ihdr...)
	out := []byte("\x89PNG\r\n\x1a\n")
	out = binary.BigEndian.AppendUint32(out, 13)
	out = append(out, chunk...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(chunk))
}

// jpegWithOrientation is the test picture as a JPEG whose EXIF header says
// how the camera was held.
func jpegWithOrientation(t *testing.T, orientation uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, testImage(200, 120, false), &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	tiff := []byte("II*\x00\x08\x00\x00\x00\x01\x00") // little endian, IFD at 8, one entry
	tiff = append(tiff, 0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00)
	tiff = binary.LittleEndian.AppendUint16(tiff, orientation)
	tiff = append(tiff, 0, 0, 0, 0, 0, 0)
	seg := append([]byte("Exif\x00\x00"), tiff...)
	app1 := []byte{0xFF, 0xE1}
	app1 = binary.BigEndian.AppendUint16(app1, uint16(len(seg)+2))
	app1 = append(app1, seg...)
	j := b.Bytes()
	return append(append(append([]byte{}, j[:2]...), app1...), j[2:]...)
}

func TestAvatarUpload(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("avatar")
	a := o.Member
	set := func(mime string, file []byte) *resp {
		return e.req(a, "POST", "/api/account/avatar", avatarBody(mime, file))
	}
	stored := func() (string, image.Image) {
		r := e.must(e.req(a, "GET", pathf("/api/users/%d/avatar", a.ID), nil), 200, "get avatar")
		img, _, err := image.Decode(bytes.NewReader(r.Body))
		if err != nil {
			t.Fatalf("stored picture does not decode: %v", err)
		}
		return r.Header.Get("Content-Type"), img
	}

	// An opaque picture is stored as a 256 x 256 JPEG, whatever was sent.
	big := testPNG(t, 1200, 800, false)
	r := e.must(set("image/png", append(big, []byte("<script>alert(1)</script>")...)), 200, "upload")
	mime, img := stored()
	if mime != "image/jpeg" || img.Bounds().Dx() != avatarSize || img.Bounds().Dy() != avatarSize {
		t.Errorf("stored as %s %v", mime, img.Bounds())
	}
	got := e.must(e.req(a, "GET", pathf("/api/users/%d/avatar?v=%s", a.ID, r.JSON["avatar"]), nil), 200, "get")
	if bytes.Contains(got.Body, []byte("script")) {
		t.Error("data appended to the upload survived")
	}
	if cc := got.Header.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
		t.Errorf("picture is cacheable by shared caches: %q", cc)
	}
	if got.Header.Get("X-Content-Type-Options") != "nosniff" || got.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("picture served without nosniff / CSP: %v", got.Header)
	}
	if me := e.must(e.req(a, "GET", "/api/me", nil), 200, "me"); me.JSON["avatar"] != r.JSON["avatar"] {
		t.Errorf("me.avatar = %v", me.JSON["avatar"])
	}
	// Transparency is kept (PNG).
	e.must(set("image/png", testPNG(t, 300, 300, true)), 200, "transparent")
	if mime, _ := stored(); mime != "image/png" {
		t.Errorf("transparent picture stored as %s", mime)
	}
	// The camera's orientation is applied: turned right, the top (red) of
	// the sensor picture ends up on the right.
	e.must(set("image/jpeg", jpegWithOrientation(t, 6)), 200, "rotated jpeg")
	_, img = stored()
	rr, _, rb, _ := img.At(avatarSize-10, avatarSize/2).RGBA()
	lr, _, lb, _ := img.At(10, avatarSize/2).RGBA()
	if rr < rb || lb < lr {
		t.Errorf("EXIF orientation ignored: right r=%d b=%d, left r=%d b=%d", rr, rb, lr, lb)
	}

	// Refused: wrong kinds of file, whatever they claim to be.
	for name, c := range map[string]struct {
		mime string
		file []byte
		want int
	}{
		"pdf as png":           {"image/png", []byte("%PDF-1.7\n1 0 obj"), 415},
		"html":                 {"text/html", []byte("<html><script>alert(1)</script></html>"), 415},
		"svg":                  {"image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`), 415},
		"png declared as jpeg": {"image/jpeg", testPNG(t, 64, 64, false), 415},
		"png without a type":   {"", testPNG(t, 64, 64, false), 415},
		"zip":                  {"image/png", []byte("PK\x03\x04aaaaaaaaaaaaaaaa"), 415},
		"empty":                {"image/png", nil, 400},
		"too small":            {"image/png", testPNG(t, 8, 8, false), 400},
		"truncated":            {"image/png", testPNG(t, 400, 400, false)[:200], 400},
		// Decompression bombs: a header claiming far more pixels than allowed.
		"bomb 30000 x 30000":  {"image/png", pngHeader(30000, 30000), 400},
		"bomb 4097 x 4097":    {"image/png", pngHeader(4097, 4097), 400},
		"bomb 1 x 2000000000": {"image/png", pngHeader(64, 2000000000), 400},
		"over 5 MB":           {"image/png", append(testPNG(t, 64, 64, false), make([]byte, avatarMaxBytes)...), 413},
	} {
		t0 := dbNow(t)
		if r := set(c.mime, c.file); r.Status != c.want {
			t.Errorf("%s: status %d, want %d (%s)", name, r.Status, c.want, r.Body)
		}
		if c.want != 400 || len(c.file) > 0 {
			if !auditHas(t, a.OrgID, a.Email, "denied.account.avatar_set", t0) {
				t.Errorf("%s: refusal not audited", name)
			}
		}
	}
	if r := e.req(a, "POST", "/api/account/avatar", `{"type":"image/png","data":"not base64 !!"}`); r.Status != 400 {
		t.Errorf("bad base64: %d", r.Status)
	}
	// The earlier picture is still there after the refusals.
	stored()

	// Only the user's own organization can fetch it.
	out := e.newOrg("avatar-other")
	if r := e.req(out.Owner, "GET", pathf("/api/users/%d/avatar", a.ID), nil); r.Status != 404 {
		t.Errorf("another organization fetched the picture: %d", r.Status)
	}
	e.must(e.req(o.Owner, "GET", pathf("/api/users/%d/avatar", a.ID), nil), 200, "teammate")
	e.must(e.req(a, "DELETE", "/api/account/avatar", nil), 200, "remove")
	if r := e.req(a, "GET", pathf("/api/users/%d/avatar", a.ID), nil); r.Status != 404 {
		t.Errorf("removed picture still served: %d", r.Status)
	}

	// Uploads are rate limited per user.
	spammer := o.Admin
	last := 0
	for i := 0; i <= avatarUploadsMax; i++ {
		last = e.req(spammer, "POST", "/api/account/avatar", avatarBody("image/png", []byte("x"))).Status
	}
	if last != 429 {
		t.Errorf("upload %d: status %d, want 429", avatarUploadsMax+1, last)
	}
}

// The header parsers must survive anything: they run on untrusted bytes.
func TestAvatarParsersOnGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := jpegWithOrientation(t, 8)
	if exifOrientation(base) != 8 {
		t.Fatalf("orientation of the reference picture: %d", exifOrientation(base))
	}
	for i := 0; i < 20000; i++ {
		b := append([]byte{}, base[:rng.Intn(len(base))]...)
		for j := 0; j < 4 && len(b) > 0; j++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		if o := exifOrientation(b); o < 1 || o > 8 {
			t.Fatalf("orientation %d", o)
		}
		_ = sniffImage(b)
		if _, _, _, err := makeAvatar(context.Background(), b, "image/jpeg"); err == nil && len(b) < 100 {
			t.Fatalf("a %d-byte fragment was accepted", len(b))
		}
	}
}

// ---------------------------------------------------------------------------
// Notification channels at rest.

func TestChannelsSealedWithSalt(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("sealed")
	ctx := context.Background()
	mail := map[string]any{"name": "mail", "kind": "email",
		"config": map[string]any{"host": "smtp.sealed-example.org", "port": 587, "security": "starttls", "from": "alerts@sealed-example.org",
			"to": []string{"noc@sealed-example.org"}, "auth": "password", "username": "relay-user-4711"},
		"secrets": map[string]any{"password": "smtp-Secret-0815"}}
	id1 := int64(e.must(e.req(o.Owner, "POST", "/api/notify/channels", mail), 200, "mail 1").JSON["id"].(float64))
	id2 := int64(e.must(e.req(o.Owner, "POST", "/api/notify/channels", mail), 200, "mail 2").JSON["id"].(float64))

	row := func(id int64) (cfg string, secret []byte, ver int) {
		_ = testDB.QueryRow(ctx, `SELECT config::text, secret, enc_version FROM notify_channels WHERE id = $1`, id).Scan(&cfg, &secret, &ver)
		return
	}
	cfg, s1, ver := row(id1)
	_, s2, _ := row(id2)
	if cfg != "{}" || ver != 2 {
		t.Errorf("settings stored outside the sealed record: config=%s enc_version=%d", cfg, ver)
	}
	for _, clear := range []string{"smtp.sealed-example.org", "relay-user-4711", "noc@sealed-example.org", "smtp-Secret-0815", "username", "host"} {
		if bytes.Contains(s1, []byte(clear)) {
			t.Errorf("%q readable in the database", clear)
		}
	}
	// Salted: identical channels share neither salt nor ciphertext.
	if s1[0] != sealedV2 || bytes.Equal(s1[1:1+sealSaltLen], s2[1:1+sealSaltLen]) || bytes.Equal(s1, s2) {
		t.Error("identical channels are stored identically (no per-record salt)")
	}
	// The API still shows the settings to the organization, never the secret.
	l := e.must(e.req(o.Member, "GET", "/api/notify/channels", nil), 200, "list")
	if !strings.Contains(string(l.Body), "smtp.sealed-example.org") || strings.Contains(string(l.Body), "smtp-Secret-0815") {
		t.Errorf("list: %s", l.Body)
	}

	// A sealed record copied into another organization's row does not open.
	other := e.newOrg("sealed-other")
	if _, err := testDB.Exec(ctx, `UPDATE notify_channels SET secret = $1 WHERE id = $2`, s1, other.ChannelID); err != nil {
		t.Fatal(err)
	}
	if l := e.must(e.req(other.Owner, "GET", "/api/notify/channels", nil), 200, "list"); strings.Contains(string(l.Body), "sealed-example.org") {
		t.Errorf("a record moved between organizations was opened: %s", l.Body)
	}
	// A modified record does not open either.
	s1[len(s1)-1] ^= 1
	if _, err := e.app.sealer.openFor(channelContext(o.Owner.OrgID), s1); err == nil {
		t.Error("tampered record accepted")
	}

	// Rows written by older versions (settings in clear, unsalted secrets)
	// are re-sealed at startup and keep working.
	legacySecret, _ := e.app.sealer.seal([]byte(`{"bot_token":"` + testBotToken + `"}`))
	var legacy int64
	if err := testDB.QueryRow(ctx, `INSERT INTO notify_channels (org_id, name, kind, config, secret, enc_version)
		VALUES ($1, 'legacy', 'telegram', '{"chat_id":"-100424242"}', $2, 1) RETURNING id`, o.Owner.OrgID, legacySecret).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	e.must(e.req(o.Owner, "POST", pathf("/api/notify/channels/%d/test", legacy), nil), 200, "legacy row works before the upgrade")
	e.app.migrateChannelSecrets(ctx)
	cfg, sealed, ver := row(legacy)
	if cfg != "{}" || ver != 2 || sealed[0] != sealedV2 || bytes.Contains(sealed, []byte("-100424242")) {
		t.Errorf("legacy row not re-sealed: config=%s enc_version=%d", cfg, ver)
	}
	e.must(e.req(o.Owner, "POST", pathf("/api/notify/channels/%d/test", legacy), nil), 200, "legacy row after the upgrade")
	got := e.sink.all()
	if last := got[len(got)-1]; last.Path != "/bot"+testBotToken+"/sendMessage" || !strings.Contains(last.Body, "-100424242") {
		t.Errorf("re-sealed channel lost its settings: %+v", last)
	}
	// Running it again changes nothing.
	e.app.migrateChannelSecrets(ctx)
	if _, again, _ := row(legacy); !bytes.Equal(again, sealed) {
		t.Error("an already sealed row was sealed again")
	}
}

// ---------------------------------------------------------------------------
// The TOTP secret at rest.

func TestTotpSecretSealed(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("totpseal")
	a, b := o.Member, o.Admin
	ctx := context.Background()
	stored := func(u *actor) string {
		var v string
		_ = testDB.QueryRow(ctx, `SELECT totp_secret FROM users WHERE id = $1`, u.ID).Scan(&v)
		return v
	}
	enable := func(u *actor) string {
		secret := e.must(e.req(u, "POST", "/api/account/2fa/setup", map[string]any{"password": u.Password}), 200, "setup").JSON["secret"].(string)
		e.must(e.req(u, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "enable")
		return secret
	}
	secretA := enable(a)
	sealedA := stored(a)
	// Whoever reads the database cannot generate codes.
	if !strings.HasPrefix(sealedA, totpSealedPrefix) || strings.Contains(sealedA, secretA) {
		t.Fatalf("TOTP secret readable in the database: %q", sealedA)
	}
	e.must(e.login(a.Email, a.Password, currentTotp(t, secretA, 1)), 200, "login with a sealed secret")

	// A secret copied to another account does not open there, and neither
	// does a changed one. No code is accepted then: not the right one, and
	// not the one of an empty secret.
	secretB := enable(b)
	sealedB := stored(b)
	for name, bad := range map[string]string{"another account's value": sealedA, "a changed value": sealedB[:len(sealedB)-2] + "AA", "garbage": totpSealedPrefix + "!!"} {
		if _, err := testDB.Exec(ctx, `UPDATE users SET totp_secret = $1, totp_last_step = 0 WHERE id = $2`, bad, b.ID); err != nil {
			t.Fatal(err)
		}
		for _, code := range []string{currentTotp(t, secretB, 0), currentTotp(t, secretA, 0), currentTotp(t, "", 0)} {
			if r := e.login(b.Email, b.Password, code); r.Status != 401 || r.cookie(sessionCookie) != nil {
				t.Errorf("%s: a code was accepted: %d", name, r.Status)
			}
		}
		if r := e.login(b.Email, b.Password, ""); r.Status != 401 {
			t.Errorf("%s: the password alone signed in: %d", name, r.Status)
		}
	}

	// Secrets stored in clear by earlier versions keep working and are
	// sealed at startup.
	legacy := newTotpSecret()
	if _, err := testDB.Exec(ctx, `UPDATE users SET totp_secret = $1, totp_enabled = true, totp_last_step = 0 WHERE id = $2`, legacy, o.Owner.ID); err != nil {
		t.Fatal(err)
	}
	e.app.limiter.clear("login-email:"+o.Owner.Email, "login-email:"+b.Email)
	e.must(e.login(o.Owner.Email, o.Owner.Password, currentTotp(t, legacy, 0)), 200, "login with a legacy secret")
	e.app.migrateTotpSecrets(ctx)
	if v := stored(o.Owner); !strings.HasPrefix(v, totpSealedPrefix) || strings.Contains(v, legacy) {
		t.Errorf("legacy secret not sealed: %q", v)
	}
	e.must(e.login(o.Owner.Email, o.Owner.Password, currentTotp(t, legacy, 1)), 200, "login after the secret was sealed")
	before := stored(o.Owner)
	e.app.migrateTotpSecrets(ctx)
	if stored(o.Owner) != before || stored(a) != sealedA {
		t.Error("an already sealed secret was sealed again")
	}
}

func TestSealedRecords(t *testing.T) {
	s, err := sealerFromKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.sealFor("ctx-a", []byte("payload"))
	b, _ := s.sealFor("ctx-a", []byte("payload"))
	if bytes.Equal(a, b) || bytes.Contains(a, []byte("payload")) {
		t.Fatal("sealing is deterministic or not encrypting")
	}
	if p, err := s.openFor("ctx-a", a); err != nil || string(p) != "payload" {
		t.Fatalf("round trip: %q %v", p, err)
	}
	if _, err := s.openFor("ctx-b", a); err == nil {
		t.Error("opened under another context")
	}
	other, _ := sealerFromKey(bytes.Repeat([]byte{8}, 32))
	if _, err := other.openFor("ctx-a", a); err == nil {
		t.Error("opened with another master key")
	}
	for _, bad := range [][]byte{nil, {sealedV2}, a[:20], append([]byte{1}, a[1:]...)} {
		if _, err := s.openFor("ctx-a", bad); err == nil {
			t.Errorf("malformed record %d bytes accepted", len(bad))
		}
	}
}
