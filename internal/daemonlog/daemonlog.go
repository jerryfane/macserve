// Package daemonlog timestamps the stderr of the macserve and
// macserve-controller daemons.
package daemonlog

import (
	"bytes"
	"io"
	"log"
	"sync"
	"time"
)

// daemonTimeLayout is RFC 3339 in UTC with milliseconds.
const daemonTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// Stderr returns stderr with every line prefixed by its RFC 3339 UTC
// time in milliseconds, and installs it as the standard logger's output with
// no prefix of its own. The worker, controller and maintenance daemons call it
// once their arguments parse, so each line they or their packages write to
// stderr carries the time; help and usage output stays unprefixed.
func Stderr(stderr io.Writer) io.Writer {
	w := &stampWriter{out: stderr, now: time.Now, lineStart: true}
	log.SetFlags(0)
	log.SetOutput(w)
	return w
}

// stampWriter prefixes each line with the time of the write that begins it.
// A write may carry several lines or part of one; it is passed on in one
// underlying write.
type stampWriter struct {
	mu        sync.Mutex
	out       io.Writer
	now       func() time.Time
	lineStart bool
	buf       []byte
}

func (w *stampWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = w.buf[:0]
	var stamp []byte
	for rest := p; len(rest) > 0; {
		if w.lineStart {
			if stamp == nil {
				stamp = w.now().UTC().AppendFormat(make([]byte, 0, len(daemonTimeLayout)+1), daemonTimeLayout)
				stamp = append(stamp, ' ')
			}
			w.buf = append(w.buf, stamp...)
		}
		end := bytes.IndexByte(rest, '\n') + 1
		if end == 0 {
			end = len(rest)
		}
		w.buf = append(w.buf, rest[:end]...)
		w.lineStart = rest[end-1] == '\n'
		rest = rest[end:]
	}
	if _, err := w.out.Write(w.buf); err != nil {
		return 0, err
	}
	return len(p), nil
}
