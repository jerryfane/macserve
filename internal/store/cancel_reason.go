package store

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/model"
)

// A job's cancel reason: why its cancellation was first requested. Rows
// cancelled before this column, and jobs never cancelled, read back with none.
const cancelReasonSchema = `
ALTER TABLE jobs ADD COLUMN cancel_reason BLOB;
PRAGMA user_version=6;
`

const (
	// MaxCancelDetailBytes bounds a cancel reason's detail; longer detail is
	// cut at a UTF-8 boundary rather than refusing the cancellation.
	MaxCancelDetailBytes = 512
	maxCancelBlockers    = 32
	maxCancelBlocker     = 128
)

// validCancelReason refuses an unknown source and a malformed principal or
// blocker. Detail is bounded when recorded, never refused, so diagnostics
// cannot block a cancellation.
func validCancelReason(cause model.CancelReason) bool {
	if !cause.Source.Valid() || cause.Principal != "" && !validOpaque(cause.Principal, 256) || len(cause.Blockers) > maxCancelBlockers {
		return false
	}
	for _, blocker := range cause.Blockers {
		if !validOpaque(blocker, maxCancelBlocker) {
			return false
		}
	}
	return true
}

// cancelReasonBytes is the cancel_reason column value recording cause at now.
func cancelReasonBytes(cause model.CancelReason, now time.Time) ([]byte, error) {
	if !validCancelReason(cause) {
		return nil, ErrInvalid
	}
	cause.At = now.UTC()
	cause.Detail = boundUTF8(strings.ToValidUTF8(cause.Detail, "\uFFFD"), MaxCancelDetailBytes)
	return json.Marshal(cause)
}

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
