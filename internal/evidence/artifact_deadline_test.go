package evidence

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

type cancelArtifactWrite struct{ cancel context.CancelFunc }

func (w cancelArtifactWrite) Write(data []byte) (int, error) { w.cancel(); return len(data), nil }

func TestArtifactCopyStopsAfterCancellation(t *testing.T) {
	root := t.TempDir()
	artifactFile(t, root, "output", strings.Repeat("evidence", 1024))
	file, err := os.Open(filepath.Join(root, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector := artifactCollector{ctx: ctx, limits: Limits{MaxTotalBytes: 1 << 20, MaxFileBytes: 1 << 20, MaxEntries: 10}, buffer: make([]byte, 128)}
	err = collector.copyFile(cancelArtifactWrite{cancel}, file, before)
	offset, seekErr := file.Seek(0, io.SeekCurrent)
	if seekErr != nil {
		t.Fatal(seekErr)
	}
	if !errors.Is(err, context.Canceled) || offset >= before.Size() {
		t.Fatalf("cancelled copy consumed remaining evidence: err=%v offset=%d size=%d", err, offset, before.Size())
	}
	dest := artifactExportDir(t)
	artifacts, err := Collect(ctx, root, []model.ArtifactRule{{Path: "output", Required: true}}, dest, Limits{}, time.Now())
	if !errors.Is(err, context.Canceled) || artifacts != nil {
		t.Fatalf("cancelled collection sealed evidence: %+v %v", artifacts, err)
	}
	assertNoExports(t, dest)
}
