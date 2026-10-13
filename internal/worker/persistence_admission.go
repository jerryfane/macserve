package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// inspectRegistrationAdmission is a read-only native replay boundary. The census
// function may substitute a captured account census in read-only qualification;
// production always uses a fresh backgroundCensus. No code bytes are opened.
func inspectRegistrationAdmission(ctx context.Context, options Options, expected PersistenceManifest, census func(context.Context, Options) (BTMCensus, error)) error {
	observe := func(ctx context.Context, options Options) (string, BTMCensus, error) {
		build, diagnostic, err := inspectCommand(ctx, nil, "/usr/bin/sw_vers", "-buildVersion")
		if err != nil || strings.TrimSpace(diagnostic) != "" || strings.TrimSpace(build) == "" {
			return "", BTMCensus{}, errors.New("OS build unavailable")
		}
		current, err := census(ctx, options)
		return strings.TrimSpace(build), current, err
	}
	return checkRegistrationAdmission(ctx, options, expected, registrationWriterPolicy, observe, registrationACLCommand)
}

func checkRegistrationAdmission(ctx context.Context, options Options, expected PersistenceManifest, policy func(context.Context, Options) (registrationWriters, error), observe func(context.Context, Options) (string, BTMCensus, error), acl func(context.Context, registrationWriters, ...string) error) error {
	writers, err := policy(ctx, options)
	if err != nil {
		return err
	}
	build, current, err := observe(ctx, options)
	if err != nil {
		return err
	}
	if err := matchPersistenceCensus(expected, build, current); err != nil {
		return err
	}
	return inspectRegistrationRoots(ctx, expected, writers, acl)
}

func matchPersistenceCensus(expected PersistenceManifest, build string, current BTMCensus) error {
	before, _ := json.Marshal(expected.Census)
	after, _ := json.Marshal(current)
	if expected.OSBuild != build || !bytes.Equal(before, after) {
		return fmt.Errorf("%w: background registration census or OS build changed", ErrContamination)
	}
	return nil
}

// Only each accepted registration ROOT and its ancestors are checked. Nested
// registered bundles are roots too; unrelated descendants, executable content,
// signing and recursive ACLs belong exclusively to the full attestation scan.
func inspectRegistrationRoots(ctx context.Context, expected PersistenceManifest, writers registrationWriters, acl func(context.Context, registrationWriters, ...string) error) error {
	seen := make(map[string]bool, len(expected.Code))
	for _, code := range expected.Code {
		ancestry, err := registrationPath(code.Path, true, writers)
		if err != nil {
			return err
		}
		for _, entry := range ancestry {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !seen[entry.path] {
				if err := acl(ctx, writers, "-ldeb", entry.path); err != nil {
					return err
				}
				seen[entry.path] = true
			}
		}
		if err := recheckRegistrationPath(ancestry, writers); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func verifyHotPersistence(ctx context.Context, options Options, inspect func(context.Context, Options, PersistenceManifest) error) (result error) {
	defer func() {
		if result != nil && !errors.Is(result, errPersistenceAttestationRevoked) {
			result = errors.Join(result, revokePersistenceAttestation(options, result))
		}
	}()
	var expected PersistenceManifest
	var accepted []byte
	err := withAttestationLock(options, func(_ *os.Root) error {
		record, _, err := readAttestation(options)
		if err != nil {
			return err
		}
		if !record.Valid {
			return errPersistenceAttestationRevoked
		}
		expected, accepted, err = readPersistence(options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		binding, err := attestationBinding(options, accepted)
		if err != nil {
			return err
		}
		if record.Binding != binding {
			return errors.New("persistence attestation binding changed")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := inspect(ctx, options, expected); err != nil {
		return err
	}
	return withAttestationLock(options, func(_ *os.Root) error {
		record, _, err := readAttestation(options)
		if err != nil {
			return err
		}
		_, after, err := readPersistence(options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		binding, err := attestationBinding(options, after)
		if err != nil {
			return err
		}
		if !record.Valid {
			return errPersistenceAttestationRevoked
		}
		if record.Binding != binding || !bytes.Equal(accepted, after) {
			return errors.New("persistence authority changed during admission")
		}
		return ctx.Err()
	})
}
