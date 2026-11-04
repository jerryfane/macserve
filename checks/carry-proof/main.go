// Command carry-proof builds a release's carry-proof.json: the mechanical
// proof, checked by macserve upgrade and macserve qualify carry, that a
// release changes no boundary (B) path over its predecessor release.
//
//	go run ./checks/carry-proof -repo OWNER/REPO -tag vX.Y.Z [-prev vX.Y.Z] \
//	  -binary-sha256 HEX -rebuilt-sha256 HEX -out carry-proof.json [-git DIR]
//
// It classifies every path changed between the predecessor tag (default: the
// highest lower vX.Y.Z tag) and the tag by the predecessor's BOUNDARY.json,
// default-deny, and refuses any B or unlisted path, symlink or submodule
// change, or a changed BOUNDARY.json. It requires the codeload source archive
// of both tags to be exactly their git trees, the full boundary check to pass
// on the tag's source, and a successful CI run on the tag commit (GitHub API,
// GH_TOKEN). The predecessor's binary digest comes from its published
// SHA256SUMS.
//
// A release that cannot carry still publishes: the command then writes no
// file, prints "no carry proof: REASON" and exits 0. It exits 1 on an
// operational failure (git, or a binary that differs from the rebuild) and 2
// on a usage error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv, httpGet))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, get fetcher) int {
	fs := flag.NewFlagSet("carry-proof", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var p params
	var out string
	fs.StringVar(&p.repo, "repo", "", "GitHub OWNER/REPO")
	fs.StringVar(&p.tag, "tag", "", "release tag vX.Y.Z")
	fs.StringVar(&p.prev, "prev", "", "predecessor tag (default: the highest lower vX.Y.Z tag)")
	fs.StringVar(&p.binary, "binary-sha256", "", "sha256 of this release's "+releaseAsset)
	fs.StringVar(&p.rebuilt, "rebuilt-sha256", "", "sha256 of the independent rebuild")
	fs.StringVar(&out, "out", "", "carry-proof.json to write")
	fs.StringVar(&p.gitDir, "git", ".", "git repository holding both tags")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(msg string) int {
		fmt.Fprintln(stderr, "carry-proof:", msg)
		return 2
	}
	switch {
	case fs.NArg() != 0:
		return usage("unexpected arguments")
	case !repoRE.MatchString(p.repo):
		return usage("-repo must be OWNER/REPO")
	case p.tag == "":
		return usage("-tag is required")
	case p.prev != "" && !semver.MatchString(p.prev):
		return usage("-prev must be vX.Y.Z")
	case !hex64.MatchString(p.binary) || !hex64.MatchString(p.rebuilt):
		return usage("-binary-sha256 and -rebuilt-sha256 must be 64 lowercase hex")
	case out == "":
		return usage("-out is required")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "carry-proof: %s already exists or is unreadable (%v)\n", out, err)
		return 1
	}
	p.token = getenv("GH_TOKEN")
	p.get = get

	proof, err := generate(ctx, p)
	var data []byte
	if err == nil {
		data, err = encodeProof(proof)
	}
	var r *refusal
	switch {
	case errors.As(err, &r):
		fmt.Fprintln(stdout, "no carry proof:", r.reason)
		return 0
	case err != nil:
		fmt.Fprintln(stderr, "carry-proof:", err)
		return 1
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintln(stderr, "carry-proof:", err)
		return 1
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out)
		fmt.Fprintln(stderr, "carry-proof:", err)
		return 1
	}
	fmt.Fprintf(stdout, "carry proof %s: %s -> %s, classes %s\n", out, proof.From.Tag, proof.To.Tag, strings.Join(proof.ClassesPresent, ","))
	return 0
}
