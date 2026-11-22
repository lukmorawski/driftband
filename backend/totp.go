package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP is defined over HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ----- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s step) -----
// Works with authenticator apps and hardware TOTP tokens alike: both are
// provisioned from the same base32 secret (QR code or manual entry).

const (
	totpStep   = 30 // seconds per time step
	totpDigits = 6
	totpWindow = 1 // accept ±1 step of clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTotpSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func totpCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000), nil
}

// verifyTotp checks code against secret within ±totpWindow steps. Steps at or
// before lastStep are rejected so an intercepted code cannot be replayed.
// Returns the matched step to persist as the new lastStep.
func verifyTotp(secret, code string, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	now := time.Now().Unix() / totpStep
	for d := int64(-totpWindow); d <= totpWindow; d++ {
		step := now + d
		if step <= lastStep {
			continue
		}
		want, err := totpCode(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func totpURI(email, secret string) string {
	return "otpauth://totp/" + url.PathEscape("Driftband:"+email) +
		"?secret=" + secret + "&issuer=Driftband&algorithm=SHA1&digits=6&period=30"
}

// ----- the secret at rest -----
// users.totp_secret holds the secret sealed (see secrets.go) as text:
// "enc:" followed by the base64 of the sealed record, bound to the user.
// Whoever reads the database cannot generate codes, and a value copied to
// another account does not open there. Values written by earlier versions
// (the base32 secret itself) are sealed at startup.

const totpSealedPrefix = "enc:"

func totpContext(userID int64) string { return "totp_secret:user:" + strconv.FormatInt(userID, 10) }

func (a *App) sealTotp(userID int64, secret string) (string, error) {
	sealed, err := a.sealer.sealFor(totpContext(userID), []byte(secret))
	if err != nil {
		return "", err
	}
	return totpSealedPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// openTotp returns the base32 secret of a stored value. An error means the
// value cannot be used (changed in the database, or SECRET_KEY replaced):
// no code may be accepted then.
func (a *App) openTotp(userID int64, stored string) (string, error) {
	rest, ok := strings.CutPrefix(stored, totpSealedPrefix)
	if !ok {
		return stored, nil // not sealed yet
	}
	sealed, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil {
		return "", err
	}
	plain, err := a.sealer.openFor(totpContext(userID), sealed)
	if err != nil {
		return "", err
	}
	if len(plain) == 0 {
		return "", errors.New("empty secret")
	}
	return string(plain), nil
}

// migrateTotpSecrets seals the secrets stored in clear by earlier versions.
func (a *App) migrateTotpSecrets(ctx context.Context) {
	rows, err := a.db.Query(ctx, `SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret NOT LIKE $1`, totpSealedPrefix+"%")
	if err != nil {
		log.Printf("secrets: cannot list two-factor secrets to seal: %v", err)
		return
	}
	type row struct {
		id     int64
		secret string
	}
	var todo []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.secret) == nil {
			todo = append(todo, r)
		}
	}
	rows.Close()
	done := 0
	for _, r := range todo {
		sealed, err := a.sealTotp(r.id, r.secret)
		if err != nil {
			continue
		}
		// Only if the value is still the one that was read.
		if tag, err := a.db.Exec(ctx, `UPDATE users SET totp_secret = $1 WHERE id = $2 AND totp_secret = $3`, sealed, r.id, r.secret); err == nil && tag.RowsAffected() == 1 {
			done++
		}
	}
	if done > 0 {
		log.Printf("secrets: sealed %d two-factor secret(s)", done)
	}
}

// ----- handlers -----

// handleTotpSetup starts enrollment: generates a fresh secret (password
// confirmation required) and returns it with the otpauth:// URI. 2FA is not
// active until the user proves possession via handleTotpEnable.
func (a *App) handleTotpSetup(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	if !a.checkPassword(w, r, u, in.Password, "account.2fa_setup", "password is incorrect") {
		return
	}
	var enabled bool
	if err := a.db.QueryRow(ctx, `SELECT totp_enabled FROM users WHERE id = $1`, u.ID).Scan(&enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if enabled {
		writeErr(w, http.StatusConflict, "two-factor is already enabled; disable it first")
		return
	}
	secret := newTotpSecret()
	sealed, err := a.sealTotp(u.ID, secret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encrypt failed")
		return
	}
	if _, err := a.db.Exec(ctx,
		`UPDATE users SET totp_secret = $1, totp_last_step = 0 WHERE id = $2`, sealed, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.2fa_setup", "enrollment started")
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth": totpURI(u.Email, secret)})
}

// handleTotpEnable finishes enrollment by verifying a code from the device.
func (a *App) handleTotpEnable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	var secret *string
	var enabled bool
	var lastStep int64
	if err := a.db.QueryRow(ctx,
		`SELECT totp_secret, totp_enabled, totp_last_step FROM users WHERE id = $1`, u.ID).
		Scan(&secret, &enabled, &lastStep); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if enabled {
		writeErr(w, http.StatusConflict, "two-factor is already enabled")
		return
	}
	if secret == nil || *secret == "" {
		writeErr(w, http.StatusBadRequest, "start setup first")
		return
	}
	codeKey := "totp-user:" + strconv.FormatInt(u.ID, 10)
	if a.limiter.blocked(codeKey, maxFailsPerAccount) {
		a.audit(ctx, u, clientIP(r), "denied.account.2fa_enable", "too many wrong codes")
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	plain, err := a.openTotp(u.ID, *secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "start setup again")
		return
	}
	step, ok := verifyTotp(plain, in.Code, lastStep)
	if !ok {
		a.limiter.fail(codeKey)
		a.deny(w, r, "account.2fa_enable", "invalid code, try again")
		return
	}
	a.limiter.clear(codeKey)
	if _, err := a.db.Exec(ctx,
		`UPDATE users SET totp_enabled = true, totp_last_step = $1 WHERE id = $2`, step, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.2fa_enable", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTotpDisable turns 2FA off. Password (not a code) confirms the action,
// so a user who lost their device can still recover from a signed-in session.
func (a *App) handleTotpDisable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	if !a.checkPassword(w, r, u, in.Password, "account.2fa_disable", "password is incorrect") {
		return
	}
	if _, err := a.db.Exec(ctx,
		`UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_last_step = 0 WHERE id = $1`, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.2fa_disable", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
