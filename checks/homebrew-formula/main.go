// Command homebrew-formula renders assets/homebrew/macserve.rb.tmpl for one
// release tag, taking the digest of macserve-darwin-arm64 from that release's
// SHA256SUMS. It only reads its inputs and writes the formula to stdout.
//
//	go run ./checks/homebrew-formula -tag v0.1.28 -sums SHA256SUMS > macserve.rb
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/template"
)

const asset = "macserve-darwin-arm64"

// Go's ^ and $ without (?m) match only at the start and end of the text, so a
// value with a newline or any other junk around it is refused.
var (
	tagPattern  = regexp.MustCompile(`^v([0-9]+\.[0-9]+\.[0-9]+)$`)
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
	shaPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type formula struct {
	Repo, Tag, Version, SHA256 string
}

func main() {
	tmplPath := flag.String("template", "assets/homebrew/macserve.rb.tmpl", "formula template")
	sumsPath := flag.String("sums", "", "release SHA256SUMS")
	tag := flag.String("tag", "", "release tag (vMAJOR.MINOR.PATCH)")
	repo := flag.String("repo", "jerryfane/macserve", "GitHub OWNER/NAME")
	flag.Parse()
	if err := run(*tmplPath, *sumsPath, *tag, *repo, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "homebrew-formula:", err)
		os.Exit(1)
	}
}

func run(tmplPath, sumsPath, tag, repo string, out io.Writer) error {
	if sumsPath == "" {
		return errors.New("-sums is required")
	}
	source, err := os.ReadFile(tmplPath)
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sha, err := assetDigest(sums)
	if err != nil {
		return err
	}
	rendered, err := render(string(source), formula{Repo: repo, Tag: tag, SHA256: sha})
	if err != nil {
		return err
	}
	_, err = out.Write(rendered)
	return err
}

// assetDigest returns the digest listed for macserve-darwin-arm64. It refuses
// a missing, duplicated or malformed entry instead of guessing.
func assetDigest(sums []byte) (string, error) {
	var found []string
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		digest, name, ok := strings.Cut(line, "  ")
		if !ok {
			digest, name, ok = strings.Cut(line, " *")
		}
		if !ok {
			return "", fmt.Errorf("malformed SHA256SUMS line %q", line)
		}
		if name == asset {
			found = append(found, digest)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("SHA256SUMS has no %s entry", asset)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("SHA256SUMS lists %s %d times", asset, len(found))
	}
}

func render(source string, f formula) ([]byte, error) {
	m := tagPattern.FindStringSubmatch(f.Tag)
	if m == nil {
		return nil, fmt.Errorf("invalid tag %q (want vMAJOR.MINOR.PATCH)", f.Tag)
	}
	f.Version = m[1]
	if !repoPattern.MatchString(f.Repo) {
		return nil, fmt.Errorf("invalid repository %q", f.Repo)
	}
	if !shaPattern.MatchString(f.SHA256) {
		return nil, fmt.Errorf("invalid sha256 %q (want 64 lowercase hex digits)", f.SHA256)
	}
	tmpl, err := template.New("formula").Option("missingkey=error").Parse(source)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, f); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
