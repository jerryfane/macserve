package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/controllerk/store"
)

// Client-cancel provenance. Agents can share one principal's token (through
// the keyring), so the principal alone cannot say who sent a cancel. The
// keyring forwards the caller's own headers without its credentials and adds
// no role header, so the controller records what it can see: the TCP peer, the
// caller's User-Agent, any forwarding headers and the names of any X-Keyring-*
// headers. Matched by time, method and path, the keyring's audit log names the
// role.
const (
	// provenanceLogBytes bounds each header value on the controller log line.
	provenanceLogBytes = 256
	// The detail suffix bounds keep it, worst case, at 424 bytes: room for
	// at least 88 bytes of the client's reason within store.MaxCancelDetailBytes.
	provenanceRemoteBytes  = 64
	provenanceAgentBytes   = 128
	provenanceForwardBytes = 96
	keyringHeaderPrefix    = "X-Keyring-"
)

// cancelProvenance is who sent a client cancel, as far as the controller sees;
// every field is sanitized and bounded.
type cancelProvenance struct {
	remote, userAgent, forwardedFor, forwarded string
	// keyring names the X-Keyring-* headers present, never their values: the
	// keyring's role token and router proof travel in such headers.
	keyring string
}

func clientCancelProvenance(r *http.Request) cancelProvenance {
	var keyring []string
	for name := range r.Header {
		if len(name) > len(keyringHeaderPrefix) && strings.EqualFold(name[:len(keyringHeaderPrefix)], keyringHeaderPrefix) {
			keyring = append(keyring, name)
		}
	}
	sort.Strings(keyring)
	header := func(name string) string {
		return sanitizeProvenance(strings.Join(r.Header.Values(name), ", "), provenanceLogBytes)
	}
	return cancelProvenance{
		remote:       sanitizeProvenance(r.RemoteAddr, provenanceLogBytes),
		userAgent:    header("User-Agent"),
		forwardedFor: header("X-Forwarded-For"),
		forwarded:    header("Forwarded"),
		keyring:      sanitizeProvenance(strings.Join(keyring, ","), provenanceLogBytes),
	}
}

// detail is the client's reason followed by " [via remote=… ua=…]", with xff
// and forwarded when present, within store.MaxCancelDetailBytes: the reason is
// cut, never the provenance.
func (c cancelProvenance) detail(reason string) string {
	suffix := "[via remote=" + boundUTF8(c.remote, provenanceRemoteBytes) + " ua=" + strconv.Quote(boundUTF8(c.userAgent, provenanceAgentBytes))
	if c.forwardedFor != "" {
		suffix += " xff=" + strconv.Quote(boundUTF8(c.forwardedFor, provenanceForwardBytes))
	}
	if c.forwarded != "" {
		suffix += " forwarded=" + strconv.Quote(boundUTF8(c.forwarded, provenanceForwardBytes))
	}
	suffix += "]"
	if reason == "" {
		return suffix
	}
	suffix = " " + suffix
	return boundUTF8(reason, store.MaxCancelDetailBytes-len(suffix)) + suffix
}

// sanitizeProvenance makes a caller-supplied value safe to log and quote: it
// replaces invalid UTF-8 and every non-printable rune (newlines, control and
// format characters) with '?', and quotes and backslashes, so quoting never
// lengthens it, then bounds it to max bytes.
func sanitizeProvenance(value string, max int) string {
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '"':
			return '\''
		case r == '\\':
			return '/'
		case r == utf8.RuneError || !unicode.IsPrint(r):
			return '?'
		}
		return r
	}, value)
	return boundUTF8(value, max)
}

// boundUTF8 cuts s to at most max bytes at a rune boundary.
func boundUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
