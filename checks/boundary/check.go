package boundary

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ManifestFile is the classification file at the module root.
const ManifestFile = "BOUNDARY.json"

// Check loads root/BOUNDARY.json, classifies files and applies the C/G
// source rules. It returns the classes and every violation found.
func Check(root string, files []File) (map[string]string, []string, error) {
	m, err := LoadManifest(filepath.Join(root, ManifestFile))
	if err != nil {
		return nil, nil, err
	}
	classes, problems := m.ClassifyFiles(files)
	if len(problems) > 0 {
		// Source rules depend on a complete classification.
		return classes, problems, nil
	}
	source, err := CheckSources(root, m, classes)
	if err != nil {
		return classes, nil, err
	}
	return classes, source, nil
}

// TrackedFiles lists the git index of the repository at root: the same
// path and mode set that the release tree (and the admin carry proof) sees.
// Unmerged entries are rejected.
func TrackedFiles(root string) ([]File, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "--stage", "-z")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %v: %s", err, stderr.String())
	}
	var files []File
	for _, entry := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if entry == "" {
			continue
		}
		meta, file, ok := strings.Cut(entry, "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 {
			return nil, fmt.Errorf("git ls-files: malformed entry %q", entry)
		}
		if fields[2] != "0" {
			return nil, fmt.Errorf("%s: unmerged index entry", file)
		}
		files = append(files, File{Path: file, Mode: fields[0]})
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("git ls-files: no tracked files under %s", root)
	}
	return files, nil
}
