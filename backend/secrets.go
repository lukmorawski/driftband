package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// sealer encrypts what must not be readable in the database: notification
// channels (addresses, accounts, bot tokens, webhook URLs, passwords) and
// security-key credentials. The master key comes from SECRET_KEY (32 bytes,
// hex or base64); without it a random key is generated once and kept in
// app_settings, which protects against leaked API responses but not against
// a full database dump. Set SECRET_KEY in production to keep the key out of
// the database.
//
// Records are sealed with sealFor: every record gets its own random salt,
// the record key is derived from the master key and that salt (HKDF-SHA256)
// and the data is encrypted with AES-256-GCM under a random nonce. The
// record's context (what it is and whom it belongs to) is authenticated with
// it, so a sealed value copied to another row does not open there.
type sealer struct {
	key  []byte      // master key
	aead cipher.AEAD // master key used directly: the format before salted records
}

const (
	sealedV2    = 0x02 // version byte of a salted record
	sealSaltLen = 16
	sealInfo    = "driftband sealed record v2"
)

func newSealer(ctx context.Context, db *pgxpool.Pool) (*sealer, error) {
	key, err := parseKey(os.Getenv("SECRET_KEY"))
	if err != nil {
		return nil, err
	}
	if key == nil {
		var stored string
		if db.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = 'secret_key'`).Scan(&stored) == nil {
			key, _ = hex.DecodeString(stored)
		}
		if len(key) != 32 {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			// Another instance may race us; keep whichever key landed first.
			_, _ = db.Exec(ctx, `INSERT INTO app_settings (key, value) VALUES ('secret_key', $1) ON CONFLICT DO NOTHING`, hex.EncodeToString(key))
			_ = db.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = 'secret_key'`).Scan(&stored)
			key, _ = hex.DecodeString(stored)
			log.Printf("secrets: SECRET_KEY not set; using a generated key stored in the database")
		}
	}
	return sealerFromKey(key)
}

func sealerFromKey(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{key: key, aead: aead}, nil
}

// recordAEAD derives the cipher of one record from the master key and the
// record's salt.
func (s *sealer) recordAEAD(salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, s.key, salt, sealInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealFor encrypts plain for the record described by context. Layout:
// version (1) | salt (16) | nonce (12) | ciphertext and tag.
func (s *sealer) sealFor(context string, plain []byte) ([]byte, error) {
	salt := make([]byte, sealSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := s.recordAEAD(salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{sealedV2}, salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, []byte(context)), nil
}

// openFor decrypts a value sealed with sealFor for the same context.
func (s *sealer) openFor(context string, sealed []byte) ([]byte, error) {
	if len(sealed) < 1+sealSaltLen || sealed[0] != sealedV2 {
		return nil, errors.New("not a sealed record")
	}
	aead, err := s.recordAEAD(sealed[1 : 1+sealSaltLen])
	if err != nil {
		return nil, err
	}
	rest := sealed[1+sealSaltLen:]
	if len(rest) < aead.NonceSize() {
		return nil, errors.New("sealed record too short")
	}
	return aead.Open(nil, rest[:aead.NonceSize()], rest[aead.NonceSize():], []byte(context))
}

func parseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("SECRET_KEY must be 32 bytes, hex or base64 encoded")
}

// seal and open are the format before salted records (the master key used
// directly). They remain for reading rows written by older versions, which
// are re-sealed with sealFor at startup, and for the tests of that upgrade.
func (s *sealer) seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}

func (s *sealer) open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value too short")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], nil)
}
