package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

var ErrInvalid = errors.New("invalid receipt")

// canonical performs additional protocol restrictions before RFC 8785. In
// particular, integers outside the interoperable I-JSON range are not rounded
// into a different repository ID, size, count, or timestamp by binary64.
func canonical(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := jsonValue(d, 0); err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	return out, nil
}

func jsonValue(d *json.Decoder, depth int) error {
	if depth > 128 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrInvalid
				}
				seen[name] = true
				if err := jsonValue(d, depth+1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if err := jsonValue(d, depth+1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case json.Number:
		if len(v) > 128 {
			return ErrInvalid
		}
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || math.Abs(f) > 9007199254740991 {
			return ErrInvalid
		}
		if math.Abs(f) == 9007199254740991 {
			exact, ok := new(big.Rat).SetString(string(v))
			if !ok || new(big.Rat).Abs(exact).Cmp(new(big.Rat).SetInt64(9007199254740991)) > 0 {
				return ErrInvalid
			}
		}
		// Nonzero values must not disappear into zero through exponent underflow.
		if f == 0 {
			mantissa := strings.Split(strings.ToLower(string(v)), "e")[0]
			if strings.ContainsAny(mantissa, "123456789") {
				return ErrInvalid
			}
		}
	}
	return nil
}

func canonicalValue(v any) ([]byte, error) {
	if !validStrings(reflect.ValueOf(v)) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonical(raw)
}
func hashBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func valueDigest(v any) (string, error) {
	raw, err := canonicalValue(v)
	if err != nil {
		return "", err
	}
	return hashBytes(raw), nil
}
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}
func validSHA(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 20 && s == strings.ToLower(s)
}

func strictDecode(raw []byte, target any) error {
	fields := json.NewDecoder(bytes.NewReader(raw))
	fields.UseNumber()
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer || typedFields(fields, typ.Elem(), 0) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

// Digest commits to the canonical published envelope, not to unsigned GitHub
// comment correlations. It validates JSON but does not authenticate a signer.
func Digest(raw []byte) (string, error) {
	c, err := canonical(raw)
	if err != nil {
		return "", err
	}
	return hashBytes(c), nil
}

func Verify(raw []byte, keys map[string]ed25519.PublicKey) (Payload, error) {
	var p Payload
	if len(raw) > MaxReceiptBytes {
		return p, ErrInvalid
	}
	c, err := canonical(raw)
	if err != nil || !bytes.Equal(c, raw) {
		return p, ErrInvalid
	}
	var envelope Envelope
	if err := strictDecode(raw, &envelope); err != nil {
		return p, err
	}
	sig := envelope.Signature
	key, ok := keys[sig.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize || sig.Algorithm != "Ed25519" || sig.Encoding != "base64" {
		return p, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(sig.Value)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != sig.Value {
		return p, ErrInvalid
	}
	payload, err := canonical(envelope.Payload)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return p, ErrInvalid
	}
	if err := strictDecode(payload, &p); err != nil {
		return Payload{}, err
	}
	if p.Schema != 1 || !validJobID(p.JobID) || p.AttemptID == "" || p.AttemptID != p.Approval.AttemptID || !validDigest(p.InputDigest) {
		return Payload{}, ErrInvalid
	}
	if (p.Details == nil) == (p.Manifest == nil) {
		return Payload{}, ErrInvalid
	}
	if p.Manifest != nil && (!validDigest(p.Manifest.SHA256) || p.Manifest.SizeBytes <= 0 || p.Manifest.SizeBytes > maxManifestBytes || p.Manifest.URL != manifestURL(p.JobID, p.Manifest.SHA256)) {
		return Payload{}, ErrInvalid
	}
	return p, nil
}

// ParsePrivateKey accepts unencrypted PKCS#8 PEM, raw Ed25519 seed/private bytes,
// or base64 seed/private bytes. Expanded private keys must contain the correct
// public half; arbitrary 64-byte strings are not accepted as private keys.
func ParsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrInvalid
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
		return checkedPrivate(ed)
	}
	if len(raw) == ed25519.SeedSize || len(raw) == ed25519.PrivateKeySize {
		return checkedPrivate(raw)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, ErrInvalid
	}
	return checkedPrivate(decoded)
}
func checkedPrivate(raw []byte) (ed25519.PrivateKey, error) {
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if !bytes.Equal(key, raw) {
		return nil, ErrInvalid
	}
	return key, nil
}

// encoding/json repairs invalid UTF-8 in Go strings; evidence must never be
// silently repaired before signing.
func validStrings(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return true
		}
		return validStrings(v.Elem())
	case reflect.String:
		return utf8.ValidString(v.String())
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() && !validStrings(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return true
		}
		for i := range v.Len() {
			if !validStrings(v.Index(i)) {
				return false
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if !validStrings(iter.Key()) || !validStrings(iter.Value()) {
				return false
			}
		}
	}
	return true
}

// encoding/json's struct matching is case-insensitive. The receipt protocol is
// not: alternate spellings must not alias a second value onto a signed field.
func typedFields(d *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 128 {
		return ErrInvalid
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage(nil)) {
		return jsonValue(d, depth)
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return ErrInvalid
			}
			var field reflect.Type
			switch typ.Kind() {
			case reflect.Map:
				field = typ.Elem()
			case reflect.Struct:
				for i := range typ.NumField() {
					f := typ.Field(i)
					if !f.IsExported() {
						continue
					}
					tag := strings.Split(f.Tag.Get("json"), ",")[0]
					if tag == "-" {
						continue
					}
					if tag == "" {
						tag = f.Name
					}
					if name == tag {
						field = f.Type
						break
					}
				}
			}
			if field == nil {
				return ErrInvalid
			}
			if err := typedFields(d, field, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		if typ.Kind() != reflect.Slice && typ.Kind() != reflect.Array {
			return ErrInvalid
		}
		for d.More() {
			if err := typedFields(d, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
