// Command release-manifest creates, signs and verifies a macserve release's
// release-manifest.json and release-manifest.json.sig (carry contract,
// schema macserve-release-manifest/1).
//
//	release-manifest carry-base -tag vX.Y.Z [-git DIR]
//	release-manifest create -tag vX.Y.Z -commit SHA -dist DIR -out FILE \
//	  [-base-tag vX.Y.Z -base-sums FILE [-base-manifest FILE]] [-git DIR]
//	release-manifest sign -manifest FILE -pub FILE -out FILE.sig
//	release-manifest verify -pub FILE -manifest FILE -sig FILE \
//	  [-tag vX.Y.Z] [-commit SHA] [-kind full|controller-carry] [-sums FILE] \
//	  [-macserve FILE] [-controller FILE]
//	release-manifest keygen -seed-out FILE -pub-out FILE
//
// carry-base prints the base tag of a controller-carry tag (the annotated
// tag's "Macserve-Carry-Base: vX.Y.Z" line), or nothing for a full release.
//
// create writes the canonical manifest for the tag. Without -base-tag the
// release is kind full: both digests are of the binaries in -dist. With
// -base-tag it is kind controller-carry and is refused unless -dist's root
// binary is base_tag's published one (by -base-sums), every changed path is
// class K, C, G or T in base_tag's BOUNDARY.json, `go list -deps
// ./cmd/macserve` (release build settings) reads the same main-module files,
// dependency modules, go.mod and go.sum in both trees, the store schema
// version (`macserve-controller version --json` of each tree) is equal, and
// the full boundary check passes on the new tree.
//
// sign reads the key from MACSERVE_RELEASE_SIGNING_KEY (standard base64 of
// the raw 32-byte Ed25519 seed), refuses unless its public key equals -pub,
// and writes base64 of the raw 64-byte signature over the exact manifest
// bytes, then a newline.
//
// verify checks the signature over the exact manifest bytes with -pub, then
// parses the manifest strictly (canonical bytes only), then every optional
// expectation given. It prints one summary line and exits 0, or exits 1
// naming the first failure. All commands exit 2 on a usage error.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

const usageText = `usage:
  release-manifest carry-base -tag vX.Y.Z [-git DIR]
  release-manifest create -tag vX.Y.Z -commit SHA -dist DIR -out FILE [-base-tag vX.Y.Z -base-sums FILE [-base-manifest FILE]] [-git DIR]
  release-manifest sign -manifest FILE -pub FILE -out FILE.sig   (key in $MACSERVE_RELEASE_SIGNING_KEY)
  release-manifest verify -pub FILE -manifest FILE -sig FILE [-tag vX.Y.Z] [-commit SHA] [-kind full|controller-carry] [-sums FILE] [-macserve FILE] [-controller FILE]
  release-manifest keygen -seed-out FILE -pub-out FILE
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("release-manifest "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "release-manifest %s: %s\n", cmd, msg)
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "release-manifest %s: %v\n", cmd, err)
		return 1
	}
	switch cmd {
	case "carry-base":
		tag := fs.String("tag", "", "release tag")
		git := fs.String("git", ".", "git repository")
		if fs.Parse(args) != nil {
			return 2
		}
		if fs.NArg() != 0 || *tag == "" {
			return usage("-tag is required")
		}
		base, err := carryBase(gitRepo{dir: *git}, *tag)
		if err != nil {
			return fail(err)
		}
		if base != "" {
			fmt.Fprintln(stdout, base)
		}
		return 0

	case "create":
		var p createParams
		var out string
		fs.StringVar(&p.tag, "tag", "", "release tag vX.Y.Z")
		fs.StringVar(&p.commit, "commit", "", "commit CI built (the tag's commit)")
		fs.StringVar(&p.dist, "dist", "", "directory holding the release binaries as published")
		fs.StringVar(&p.baseTag, "base-tag", "", "controller-carry: the full release whose root binary is republished")
		fs.StringVar(&p.baseSums, "base-sums", "", "controller-carry: base tag's verified SHA256SUMS")
		fs.IntVar(&p.binarySchema, "controller-store-schema-version", 0, "store_schema_version the release controller binary's version --json printed (0: not checked)")
		fs.StringVar(&p.baseManifest, "base-manifest", "", "controller-carry: base tag's release-manifest.json, when it published one")
		fs.StringVar(&p.gitDir, "git", ".", "git repository holding the tags")
		fs.StringVar(&out, "out", "", "release-manifest.json to write")
		if fs.Parse(args) != nil {
			return 2
		}
		switch {
		case fs.NArg() != 0:
			return usage("unexpected arguments")
		case p.tag == "" || p.commit == "" || p.dist == "" || out == "":
			return usage("-tag, -commit, -dist and -out are required")
		case (p.baseTag == "") != (p.baseSums == ""):
			return usage("-base-tag and -base-sums go together")
		case p.baseTag == "" && p.baseManifest != "":
			return usage("-base-manifest needs -base-tag")
		}
		p.now, p.list, p.schema, p.check = time.Now(), goListDeps, controllerSchema, boundaryCheck
		m, err := create(ctx, p)
		var data []byte
		if err == nil {
			data, err = Encode(m)
		}
		var r *refusal
		if errors.As(err, &r) {
			fmt.Fprintf(stderr, "release-manifest create: refusing to create a %s manifest: %s\n", m.Kind, r.reason)
			return 1
		} else if err != nil {
			return fail(err)
		}
		if err := writeNew(out, data, 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "%s: %s %s base_tag %s store_schema_version %d\n", out, m.Tag, m.Kind, m.BaseTag, m.StoreSchemaVersion)
		return 0

	case "sign":
		manifest := fs.String("manifest", "", "release-manifest.json")
		pubFile := fs.String("pub", "", "pinned public key the signing key must match")
		out := fs.String("out", "", "signature file to write")
		if fs.Parse(args) != nil {
			return 2
		}
		if fs.NArg() != 0 || *manifest == "" || *pubFile == "" || *out == "" {
			return usage("-manifest, -pub and -out are required")
		}
		secret := getenv(SigningKeyEnv)
		if secret == "" {
			return fail(fmt.Errorf("%s is empty", SigningKeyEnv))
		}
		key, err := ParseSeed([]byte(secret))
		if err != nil {
			return fail(err)
		}
		pub, err := readPublicKey(*pubFile)
		if err != nil {
			return fail(err)
		}
		if !pub.Equal(key.Public()) {
			return fail(fmt.Errorf("%s is the key %s, not the pinned %s (%s)", SigningKeyEnv, KeyID(key.Public().(ed25519.PublicKey)), KeyID(pub), *pubFile))
		}
		data, err := os.ReadFile(*manifest)
		if err != nil {
			return fail(err)
		}
		sig, err := Sign(key, data)
		if err != nil {
			return fail(err)
		}
		if err := writeNew(*out, sig, 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "%s: signed with key %s\n", *out, KeyID(pub))
		return 0

	case "verify":
		pubFile := fs.String("pub", "", "public key: base64 of the raw 32 bytes")
		manifest := fs.String("manifest", "", "release-manifest.json")
		sigFile := fs.String("sig", "", "release-manifest.json.sig")
		tag := fs.String("tag", "", "require this tag")
		commit := fs.String("commit", "", "require this commit")
		kind := fs.String("kind", "", "require this kind")
		sums := fs.String("sums", "", "require SHA256SUMS to list both binary digests")
		root := fs.String("macserve", "", "require this file's sha256 to be binaries.macserve")
		controller := fs.String("controller", "", "require this file's sha256 to be binaries.macserve-controller")
		if fs.Parse(args) != nil {
			return 2
		}
		if fs.NArg() != 0 || *pubFile == "" || *manifest == "" || *sigFile == "" {
			return usage("-pub, -manifest and -sig are required")
		}
		if *kind != "" && *kind != KindFull && *kind != KindCarry {
			return usage("-kind must be full or controller-carry")
		}
		m, err := verifyFiles(verifyParams{pub: *pubFile, manifest: *manifest, sig: *sigFile, tag: *tag, commit: *commit, kind: *kind, sums: *sums, root: *root, controller: *controller})
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "verified %s: tag %s commit %s kind %s base_tag %s macserve %s macserve-controller %s store_schema_version %d\n",
			*manifest, m.Tag, m.Commit, m.Kind, m.BaseTag, m.Binaries.Macserve.SHA256, m.Binaries.Controller.SHA256, m.StoreSchemaVersion)
		return 0

	case "keygen":
		seedOut := fs.String("seed-out", "", "secret seed file to write (0600)")
		pubOut := fs.String("pub-out", "", "public key file to write")
		if fs.Parse(args) != nil {
			return 2
		}
		if fs.NArg() != 0 || *seedOut == "" || *pubOut == "" {
			return usage("-seed-out and -pub-out are required")
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fail(err)
		}
		if err := writeNew(*seedOut, EncodeKey(key.Seed()), 0o600); err != nil {
			return fail(err)
		}
		if err := writeNew(*pubOut, EncodeKey(pub), 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "key %s: seed %s, public key %s\n", KeyID(pub), *seedOut, *pubOut)
		return 0
	}
	fmt.Fprint(stderr, usageText)
	return 2
}

type verifyParams struct {
	pub, manifest, sig      string
	tag, commit, kind, sums string
	root, controller        string
}

// verifyFiles is `verify`: signature first, then strict parse, then each
// expectation given.
func verifyFiles(v verifyParams) (Manifest, error) {
	pub, err := readPublicKey(v.pub)
	if err != nil {
		return Manifest{}, err
	}
	data, err := readLimited(v.manifest, maxManifest)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := readLimited(v.sig, maxKeyFile)
	if err != nil {
		return Manifest{}, err
	}
	m, err := Verify(pub, data, sig)
	if err != nil {
		return m, err
	}
	if v.commit != "" && m.Commit != v.commit {
		return m, fmt.Errorf("manifest commit %s, want %s", m.Commit, v.commit)
	}
	if v.tag != "" && m.Tag != v.tag {
		return m, fmt.Errorf("manifest tag %s, want %s", m.Tag, v.tag)
	}
	if v.kind != "" && m.Kind != v.kind {
		return m, fmt.Errorf("manifest kind %s, want %s", m.Kind, v.kind)
	}
	if v.sums != "" {
		sums, err := readLimited(v.sums, 1<<20)
		if err != nil {
			return m, err
		}
		for asset, want := range map[string]string{RootAsset: m.Binaries.Macserve.SHA256, ControllerAsset: m.Binaries.Controller.SHA256} {
			got, err := sumsDigest(sums, asset)
			if err != nil {
				return m, err
			}
			if got != want {
				return m, fmt.Errorf("SHA256SUMS lists %s %s, manifest %s", asset, got, want)
			}
		}
	}
	for file, want := range map[string]string{v.root: m.Binaries.Macserve.SHA256, v.controller: m.Binaries.Controller.SHA256} {
		if file == "" {
			continue
		}
		got, err := fileDigest(file)
		if err != nil {
			return m, err
		}
		if got != want {
			return m, fmt.Errorf("%s has sha256 %s, manifest %s", file, got, want)
		}
	}
	return m, nil
}

func readPublicKey(file string) (ed25519.PublicKey, error) {
	data, err := readLimited(file, maxKeyFile)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}

// readLimited reads a regular file of at most limit bytes.
func readLimited(file string, limit int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", file, limit)
	}
	return data, nil
}

// writeNew creates file (never overwriting) with data.
func writeNew(file string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(file)
		return fmt.Errorf("%s: %v", filepath.Base(file), err)
	}
	return nil
}
