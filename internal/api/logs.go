package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/store"
)

func logCursor(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, store.ErrInvalid
	}
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil || n < 0 {
		return 0, store.ErrInvalid
	}
	return n, nil
}
func cursor(sequence int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(sequence, 10)))
}

// displayText strips terminal controls from the rendered view. Raw log records
// remain unchanged in SQLite and in separately sealed evidence.
func displayText(text string) string {
	var out strings.Builder
	state := byte(0)
	for _, c := range text {
		switch state {
		case 1:
			switch c {
			case '[':
				state = 2
			case ']', 'P', 'X', '^', '_':
				state = 3
			default:
				state = 0
			}
			continue
		case 2:
			if c >= 0x40 && c <= 0x7e {
				state = 0
			}
			continue
		case 3:
			if c == 7 || c == 0x9c {
				state = 0
			} else if c == 27 {
				state = 4
			}
			continue
		case 4:
			if c == '\\' {
				state = 0
			} else {
				state = 3
			}
			continue
		}
		if c == 27 {
			state = 1
			continue
		}
		if c == 0x9b {
			state = 2
			continue
		}
		if c == 0x9d {
			state = 3
			continue
		}
		if c == '\n' || c == '\t' || c >= 32 && !(c >= 127 && c <= 159) {
			out.WriteRune(c)
		}
	}
	return out.String()
}
func (h *handler) logs(w http.ResponseWriter, r *http.Request, job model.Job) {
	after, err := logCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, err)
		return
	}
	limit, err := intQuery(r, "limit_bytes", store.MaxLogRecordBytes, store.MaxLogPageBytes)
	if err != nil {
		writeError(w, err)
		return
	}
	records, next, truncated, err := h.Store.Logs(r.Context(), job.ID, after, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	// Read terminal state before the page: a transition after that snapshot may
	// delay eof by one poll but can never hide the final records.
	eof := false
	if job.State.Terminal() {
		pending, _, _, err := h.Store.Logs(r.Context(), job.ID, next, store.MaxLogRecordBytes)
		if err != nil {
			writeError(w, err)
			return
		}
		eof = len(pending) == 0
	}
	for i := range records {
		records[i].Text = displayText(records[i].Text)
	}
	writeJSON(w, 200, map[string]any{"records": records, "next_cursor": cursor(next), "eof": eof, "truncated": truncated})
}

func (h *handler) stream(w http.ResponseWriter, r *http.Request, job model.Job) {
	after, err := logCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, err)
		return
	}
	if value := r.Header.Get("Last-Event-ID"); value != "" {
		after, err = strconv.ParseInt(value, 10, 64)
		if err != nil || after < 0 {
			writeError(w, store.ErrInvalid)
			return
		}
	}
	rc := http.NewResponseController(w)
	send := func(event string, seq int64, data any) bool {
		if err := rc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return false
		}
		body, err := json.Marshal(data)
		if err != nil {
			return false
		}
		if seq > 0 {
			if _, err = fmt.Fprintf(w, "id: %d\n", seq); err != nil {
				return false
			}
		}
		if _, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	connected := false
	poll := time.NewTicker(250 * time.Millisecond)
	defer poll.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		principal, err := h.Store.Authenticate(r.Context(), bearer(r))
		if err != nil || !principal.HasScope("jobs:read") || !principal.AllowsRepository(job.Request.Repo) {
			return
		}
		current, err := h.Store.Get(r.Context(), job.ID)
		if err != nil {
			return
		}
		records, next, truncated, err := h.Store.Logs(r.Context(), job.ID, after, store.MaxLogRecordBytes)
		if err != nil {
			if !connected {
				writeError(w, err)
			}
			return
		}
		if !connected {
			// Check byte retention before committing the SSE response so expired
			// evidence has the same HTTP 410 contract as paged logs.
			if err := rc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				writeError(w, errUnavailable)
				return
			}
			defer rc.SetWriteDeadline(time.Time{})
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Accel-Buffering", "no")
			if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil || rc.Flush() != nil {
				return
			}
			connected = true
		}
		for _, record := range records {
			record.Text = displayText(record.Text)
			if !send("log", record.Seq, record) {
				return
			}
		}
		after = next
		if current.State.Terminal() && len(records) == 0 {
			send("terminal", 0, map[string]any{"state": current.State, "next_cursor": cursor(after), "truncated": truncated})
			return
		}
		if len(records) > 0 {
			continue
		}
		select {
		case <-r.Context().Done():
			return
		case <-poll.C:
		case <-heartbeat.C:
			if !send("heartbeat", 0, map[string]any{"next_cursor": cursor(after)}) {
				return
			}
		}
	}
}
