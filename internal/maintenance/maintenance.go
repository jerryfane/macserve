package maintenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/jerryfane/macserve/internal/hostguard"
)

type Config struct {
	ControllerConfig     string   `json:"controller_config"`
	WorkerConfig         string   `json:"worker_config"`
	QualificationFile    string   `json:"qualification_file"`
	BoundaryEvidenceFile string   `json:"boundary_evidence_file"`
	CoexistingAnchors    []string `json:"coexisting_anchors,omitempty"`
	CoexistingServices   []string `json:"coexisting_services,omitempty"`
	IntervalSeconds      int      `json:"interval_seconds"`
	path                 string
}

func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func protectedRead(path string) ([]byte, error) {
	if err := hostguard.RootConfig(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("protected input too large")
	}
	return data, nil
}
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := protectedRead(path)
	if err != nil {
		return c, err
	}
	if err = decode(data, &c); err != nil {
		return c, err
	}
	c.path = path
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 10
	}
	if c.IntervalSeconds < 5 || c.IntervalSeconds > 15 {
		return c, errors.New("unsupported maintenance interval")
	}
	if err := ValidateCoexistenceConfig(&c); err != nil {
		return c, err
	}
	for _, p := range []string{c.ControllerConfig, c.WorkerConfig, c.QualificationFile, c.BoundaryEvidenceFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return c, errors.New("maintenance paths must be clean and absolute")
		}
	}
	return c, nil
}
