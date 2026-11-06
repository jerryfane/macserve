package testflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// refreshBefore is how close to expiry a keyring JWT is replaced.
const refreshBefore = 60 * time.Second

// tokenSource holds the current short-lived App Store Connect JWT that the
// keyring relay signed (POST <keyring>/<role>/_keyring/sign/appstoreconnect,
// empty body, answering {"token","expires_at"}). The Apple key stays in the
// keyring; only the JWT is held here, and only App Store Connect sees it.
type tokenSource struct {
	url     string
	http    *http.Client
	now     func() time.Time
	retry   retryPolicy
	token   string
	expires time.Time
}

// keyringError is a failure to obtain a JWT; it is never retried as an App
// Store Connect failure (tokenSource retries the relay itself).
type keyringError struct{ err error }

func (e *keyringError) Error() string { return "keyring: " + e.err.Error() }
func (e *keyringError) Unwrap() error { return e.err }

// get returns a JWT valid for more than refreshBefore, refreshing it first
// when needed.
func (t *tokenSource) get(ctx context.Context) (string, error) {
	if t.token != "" && t.expires.Sub(t.now()) > refreshBefore {
		return t.token, nil
	}
	for attempt := 1; ; attempt++ {
		token, expires, err := t.sign(ctx)
		if err == nil {
			t.token, t.expires = token, expires
			return token, nil
		}
		if !transient(err) || attempt >= t.retry.attempts || ctx.Err() != nil {
			return "", &keyringError{err}
		}
		if err := t.retry.wait(ctx, attempt, 0); err != nil {
			return "", err
		}
	}
}

// invalidate drops the current JWT after App Store Connect refused it.
func (t *tokenSource) invalidate() {
	t.token, t.expires = "", time.Time{}
}

func (t *tokenSource) sign(ctx context.Context) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, http.NoBody)
	if err != nil {
		return "", time.Time{}, err
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", time.Time{}, stripURL(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, &statusError{service: "keyring", method: http.MethodPost, route: "_keyring/sign/appstoreconnect", status: resp.StatusCode}
	}
	var signed struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		return "", time.Time{}, errors.New("invalid sign response")
	}
	expires, err := time.Parse(time.RFC3339, signed.ExpiresAt)
	if err != nil || signed.Token == "" || len(signed.Token) > 8192 || strings.ContainsFunc(signed.Token, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return "", time.Time{}, errors.New("invalid sign response")
	}
	if !expires.After(t.now()) {
		return "", time.Time{}, fmt.Errorf("signed token already expired at %s", expires.Format(time.RFC3339))
	}
	return signed.Token, expires, nil
}
