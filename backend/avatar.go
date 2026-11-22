package main

// Profile pictures. An upload is untrusted input, so the stored picture is
// never the uploaded file: the server checks what the file really is,
// refuses anything that would be expensive to decode, decodes it, and
// stores its own small re-encoded copy.
//
//   - at most 5 MB, and only JPEG, PNG, GIF or WebP, recognised by the
//     file's signature; the declared type must agree with it;
//   - the dimensions are read from the header first and bounded, so a few
//     kilobytes cannot expand into gigabytes of pixels (decompression bomb);
//   - one picture is decoded at a time, and uploads are rate limited;
//   - the result is a 256 x 256 JPEG (or PNG when it has transparency):
//     metadata such as GPS position, extra frames and anything appended to
//     the file are gone.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif" // decoders registered for image.Decode
	"image/jpeg"
	"image/png"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	avatarMaxBytes   = 5 << 20         // uploaded file
	avatarMaxSide    = 8192            // pixels per side
	avatarMaxPixels  = 4096 * 4096     // total pixels (about 16.8 megapixels)
	avatarMinSide    = 32              // smaller pictures are not worth showing
	avatarSize       = 256             // stored picture: avatarSize x avatarSize
	avatarUploadsMax = 20              // uploads per user in a rate window
	avatarBodyLimit  = 7<<20 + 256<<10 // JSON body: base64 of 5 MB plus slack
)

// avatarSlot lets one picture be decoded at a time: decoding the largest
// accepted picture takes tens of megabytes.
var avatarSlot = make(chan struct{}, 1)

var avatarTypes = map[string]string{ // image.Decode format -> media type
	"jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp",
}

// sniffImage recognises the accepted formats by their signature.
func sniffImage(b []byte) string {
	switch {
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "jpeg"
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return "png"
	case len(b) >= 6 && (string(b[:6]) == "GIF87a" || string(b[:6]) == "GIF89a"):
		return "gif"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "webp"
	}
	return ""
}

// avatarError is a refusal the user can act on.
type avatarError struct {
	code int
	msg  string
}

func (e *avatarError) Error() string { return e.msg }

// makeAvatar validates an uploaded picture and returns the stored form.
func makeAvatar(ctx context.Context, raw []byte, declared string) (data []byte, mime, detail string, err error) {
	if len(raw) > avatarMaxBytes {
		return nil, "", "", &avatarError{http.StatusRequestEntityTooLarge, "the picture is larger than 5 MB"}
	}
	format := sniffImage(raw)
	if format == "" {
		return nil, "", "", &avatarError{http.StatusUnsupportedMediaType, "only JPEG, PNG, GIF and WebP pictures are accepted"}
	}
	if declared = strings.ToLower(strings.TrimSpace(declared)); declared != avatarTypes[format] {
		return nil, "", "", &avatarError{http.StatusUnsupportedMediaType, "the file is not the kind of picture it claims to be"}
	}
	// Header only: nothing is decompressed yet.
	cfg, cfgFormat, cerr := image.DecodeConfig(bytes.NewReader(raw))
	if cerr != nil || cfgFormat != format {
		return nil, "", "", &avatarError{http.StatusBadRequest, "the picture cannot be read"}
	}
	if cfg.Width < avatarMinSide || cfg.Height < avatarMinSide {
		return nil, "", "", &avatarError{http.StatusBadRequest, fmt.Sprintf("the picture is too small (at least %d x %d pixels)", avatarMinSide, avatarMinSide)}
	}
	if cfg.Width > avatarMaxSide || cfg.Height > avatarMaxSide || int64(cfg.Width)*int64(cfg.Height) > avatarMaxPixels {
		return nil, "", "", &avatarError{http.StatusBadRequest, "the picture has too many pixels (at most 4096 x 4096)"}
	}

	select {
	case avatarSlot <- struct{}{}:
		defer func() { <-avatarSlot }()
	case <-ctx.Done():
		return nil, "", "", &avatarError{http.StatusServiceUnavailable, "busy, try again"}
	}
	src, derr := decodeImage(raw)
	if derr != nil {
		return nil, "", "", &avatarError{http.StatusBadRequest, "the picture cannot be read"}
	}
	// Centre square, scaled to the stored size, then turned upright the way
	// the camera recorded it (the crop is central, so the order is free).
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	crop := image.Rect(0, 0, side, side).Add(image.Pt(b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2))
	dst := image.NewNRGBA(image.Rect(0, 0, avatarSize, avatarSize))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, crop, draw.Src, nil)
	if format == "jpeg" {
		dst = orient(dst, exifOrientation(raw))
	}

	var out bytes.Buffer
	mime = "image/jpeg"
	if opaque(dst) {
		err = jpeg.Encode(&out, dst, &jpeg.Options{Quality: 88})
	} else {
		mime = "image/png"
		err = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, dst)
	}
	if err != nil {
		return nil, "", "", err
	}
	detail = fmt.Sprintf("%s %dx%d, %d KB", format, cfg.Width, cfg.Height, (len(raw)+1023)/1024)
	return out.Bytes(), mime, detail, nil
}

// decodeImage decodes with a guard: a decoder bug on a crafted file must
// not take the request down with a panic.
func decodeImage(raw []byte) (img image.Image, err error) {
	defer func() {
		if recover() != nil {
			img, err = nil, errors.New("decoder failed")
		}
	}()
	img, _, err = image.Decode(bytes.NewReader(raw))
	return img, err
}

func opaque(img *image.NRGBA) bool {
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] != 0xFF {
			return false
		}
	}
	return true
}

// exifOrientation reads the Orientation tag (1-8) of a JPEG, 1 when there is
// none. Every offset is bounds-checked; anything odd means "upright".
func exifOrientation(b []byte) int {
	for i := 2; i+4 <= len(b) && b[i] == 0xFF; {
		marker, size := b[i+1], int(binary.BigEndian.Uint16(b[i+2:]))
		if marker == 0xDA || size < 2 || i+2+size > len(b) { // start of scan: no more headers
			return 1
		}
		seg := b[i+4 : i+2+size]
		i += 2 + size
		if marker != 0xE1 || len(seg) < 14 || string(seg[:6]) != "Exif\x00\x00" {
			continue
		}
		t := seg[6:]
		var bo binary.ByteOrder
		switch string(t[:2]) {
		case "II":
			bo = binary.LittleEndian
		case "MM":
			bo = binary.BigEndian
		default:
			return 1
		}
		off := int(bo.Uint32(t[4:8]))
		if off < 8 || off+2 > len(t) {
			return 1
		}
		n := int(bo.Uint16(t[off:]))
		for e := 0; e < n; e++ {
			p := off + 2 + e*12
			if p+12 > len(t) {
				return 1
			}
			if bo.Uint16(t[p:]) == 0x0112 {
				if v := int(bo.Uint16(t[p+8:])); v >= 1 && v <= 8 {
					return v
				}
				return 1
			}
		}
		return 1
	}
	return 1
}

// orient returns the square picture turned according to an EXIF orientation.
func orient(src *image.NRGBA, o int) *image.NRGBA {
	if o <= 1 || o > 8 {
		return src
	}
	n := src.Bounds().Dx()
	dst := image.NewNRGBA(src.Bounds())
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var sx, sy int
			switch o {
			case 2: // mirrored
				sx, sy = n-1-x, y
			case 3: // upside down
				sx, sy = n-1-x, n-1-y
			case 4:
				sx, sy = x, n-1-y
			case 5:
				sx, sy = y, x
			case 6: // camera turned right
				sx, sy = y, n-1-x
			case 7:
				sx, sy = n-1-y, n-1-x
			case 8: // camera turned left
				sx, sy = n-1-y, x
			}
			dst.SetNRGBA(x, y, src.NRGBAAt(sx, sy))
		}
	}
	return dst
}

// ----- handlers -----

// handleAvatarSet stores the signed-in user's profile picture. Body:
// {"type": "image/png", "data": "<base64 of the file>"}.
func (a *App) handleAvatarSet(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	key := "avatar-user:" + strconv.FormatInt(u.ID, 10)
	if a.limiter.blocked(key, avatarUploadsMax) {
		a.audit(r.Context(), u, clientIP(r), "denied.account.avatar_set", "too many uploads")
		writeErr(w, http.StatusTooManyRequests, "too many uploads, try again later")
		return
	}
	a.limiter.fail(key) // counts every upload, accepted or not
	if r.ContentLength > avatarBodyLimit {
		writeErr(w, http.StatusRequestEntityTooLarge, "the picture is larger than 5 MB")
		return
	}
	var in struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if err := readJSONLimit(r, &in, avatarBodyLimit); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "the picture is larger than 5 MB")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil || len(raw) == 0 {
		writeErr(w, http.StatusBadRequest, "data must be the base64-encoded file")
		return
	}
	ctx := r.Context()
	data, mime, detail, err := makeAvatar(ctx, raw, in.Type)
	if err != nil {
		var ae *avatarError
		if errors.As(err, &ae) {
			a.audit(ctx, u, clientIP(r), "denied.account.avatar_set", ae.msg)
			writeErr(w, ae.code, ae.msg)
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not process the picture")
		return
	}
	sum := sha256.Sum256(data)
	etag := hex.EncodeToString(sum[:8])
	if _, err := a.db.Exec(ctx, `
		INSERT INTO user_avatars (user_id, mime, data, etag) VALUES ($1,$2,$3,$4)
		ON CONFLICT (user_id) DO UPDATE SET mime = EXCLUDED.mime, data = EXCLUDED.data, etag = EXCLUDED.etag, updated_at = now()`,
		u.ID, mime, data, etag); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.avatar_set", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "avatar": etag})
}

func (a *App) handleAvatarRemove(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if _, err := a.db.Exec(r.Context(), `DELETE FROM user_avatars WHERE user_id = $1`, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.audit(r.Context(), u, clientIP(r), "account.avatar_remove", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAvatarGet serves the picture of a user of the caller's organization.
// The bytes are the server's own re-encoding, sent with their real type.
func (a *App) handleAvatarGet(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var mime, etag string
	var data []byte
	if err := a.db.QueryRow(r.Context(), `
		SELECT av.mime, av.data, av.etag FROM user_avatars av JOIN users t ON t.id = av.user_id
		WHERE av.user_id = $1 AND t.org_id = $2`, id, u.OrgID).Scan(&mime, &data, &etag); err != nil {
		writeErr(w, http.StatusNotFound, "no picture")
		return
	}
	h := w.Header()
	h.Set("ETag", `"`+etag+`"`)
	// The UI asks with ?v=<etag>: that address never changes its content.
	if r.URL.Query().Get("v") == etag {
		h.Set("Cache-Control", "private, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "private, no-cache")
	}
	if strings.Contains(r.Header.Get("If-None-Match"), `"`+etag+`"`) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", mime)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("Content-Security-Policy", "default-src 'none'")
	_, _ = w.Write(data)
}
