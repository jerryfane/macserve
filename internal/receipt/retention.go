package receipt

import (
	"context"
	"errors"
	"io"
	"strings"
)

// Prune removes only signer-addressed blobs whose durable job metadata has
// expired. The controller supplies its authoritative retained-job lookup.
func (s *Signer) Prune(ctx context.Context, retained func(string) (bool, error)) error {
	if retained == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	directory, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			stem, ok := strings.CutSuffix(name, ".json")
			if !ok {
				continue
			}
			jobID := ""
			for _, marker := range []string{"-input-", "-manifest-"} {
				index := strings.LastIndex(stem, marker)
				if index > 0 && validJobID(stem[:index]) && validDigest(stem[index+len(marker):]) {
					jobID = stem[:index]
					break
				}
			}
			if jobID == "" {
				continue
			}
			keep, err := retained(jobID)
			if err != nil {
				return err
			}
			if !keep {
				if err := s.root.Remove(name); err != nil {
					return err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return directory.Sync()
		}
		if readErr != nil {
			return readErr
		}
	}
}
