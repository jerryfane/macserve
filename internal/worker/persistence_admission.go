package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// inspectRegistrationAdmission is a read-only native replay boundary. The census
// function may substitute a captured account census in read-only qualification;
// production always uses a fresh backgroundCensus. No code bytes are opened.
func inspectRegistrationAdmission(ctx context.Context, options Options, expected PersistenceManifest, census func(context.Context, Options) (BTMCensus, error)) error {
	observe := func(ctx context.Context, options Options) (string, BTMCensus, error) {
		build, diagnostic, err := inspectCommand(ctx, nil, "/usr/bin/sw_vers", "-buildVersion")
		if err != nil || strings.TrimSpace(diagnostic) != "" || strings.TrimSpace(build) == "" {
			return "", BTMCensus{}, errors.Join(err, errors.New("OS build unavailable"))
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
// A probe its deadline cut short (ErrACLCensusUnavailable) observed nothing:
// the census starts again with a fresh allocation, at most rootACLAttempts
// in all and always within the caller's deadline. Each attempt takes a fresh
// ancestry snapshot and probes every path of it: a verdict of an earlier
// attempt is never reused, as the path may name another directory by then.
// Any other failure, or positive evidence, ends it at once.
func inspectRegistrationRoots(ctx context.Context, expected PersistenceManifest, writers registrationWriters, acl func(context.Context, registrationWriters, ...string) error) error {
	for attempt := 1; ; attempt++ {
		err := inspectRegistrationRootsOnce(ctx, expected, writers, acl)
		if attempt == rootACLAttempts || !errors.Is(err, ErrACLCensusUnavailable) || ctx.Err() != nil {
			return err
		}
	}
}

// rootACLAttempts bounds the hot root/ancestor ACL census: a cut attempt is
// retried once, each attempt with hotInspectionShare, always within the
// caller's deadline. Studio, 2026-11-13: with four lanes building beside
// the periodic full scan, one 2s allocation expired and failed a job's lane
// admission; 2026-11-14/15, six lanes at load 20-35: three 2s allocations
// in a row expired, again and again (#150).
const rootACLAttempts = 2

// hotInspectionShare is the allocation of each bounded multi-command step
// of the hot persistence inspection: an attempt of the registered
// root/ancestor ACL census, and each authority bracket of
// verifyHotPersistence (the lock, the protected-input ACL inspections and
// the reads of the persistence authority and its attestation), each one
// ls per path. At six lanes and load 20-35 (Studio v0.1.56, 2026-11-14/15)
// both kinds of step expired at their former 2s again and again: seven
// refusals in 23 minutes, and a bare "context deadline exceeded" from a
// bracket left a job's cleanup unverified. Single steps of the same host
// exceeded 5s at times (the worker's 5s memory samples expired 49 times in
// four days, never twice in a row), so a step of a dozen commands gets 10s,
// and an inspection still cut short is retried once
// (hotPersistenceAttempts).
const hotInspectionShare = 10 * time.Second

// inspectRegistrationRootsOnce is one attempt.
func inspectRegistrationRootsOnce(ctx context.Context, expected PersistenceManifest, writers registrationWriters, acl func(context.Context, registrationWriters, ...string) error) error {
	// All root and ancestor ACL probes of an attempt share one allocation,
	// not one per path.
	ctx, cancel := context.WithTimeout(ctx, hotInspectionShare)
	defer cancel()
	seen := make(map[string]bool, len(expected.Code))
	for _, code := range expected.Code {
		ancestry, err := registrationPath(code.Path, true, writers)
		if err != nil {
			return err
		}
		for _, entry := range ancestry {
			if err := ctx.Err(); err != nil {
				return aclCensusCut(err)
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
	return aclCensusCut(ctx.Err())
}

// aclCensusCut is ErrACLCensusUnavailable for a census its deadline ended,
// else err.
func aclCensusCut(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrACLCensusUnavailable
	}
	return err
}

// inspectionCut returns err marked as ErrACLCensusUnavailable, with its own
// text, when it is only a bounded admission or finalization inspection its
// deadline cut short, with no evidence beside it: it observed nothing, so it
// is inconclusive, never clean and never a finding. That is
//   - a registered tree ACL census cut short (ErrACLCensusUnavailable; see
//     registrationACLCommand for the exec.ErrWaitDelay case) or a hostguard
//     protected-input ACL inspection of the persistence authority killed at
//     its deadline (hostguard.ErrACLInspectionCut, "cannot inspect protected
//     input ACL: signal: killed: context deadline exceeded"), #148;
//   - any other inspection that ended at its deadline (#150, Studio v0.1.56,
//     six lanes at load 20-35): the bare "context deadline exceeded" of a
//     persistence authority bracket whose 2s ran out between its commands
//     (17:24:21Z), the end of a final account barrier its finalization
//     budget no longer covered (00:08:28Z), or "exec: WaitDelay expired
//     before I/O complete" of a dsmemberutil probe whose output did not
//     close within 100 ms, with "registration service account memberships
//     unavailable" (17:33:42Z).
//
// Contamination, a drain (an unattributed process), a fenced recovery, and
// anything else, a census that ran and failed or found a problem included,
// is nil. The caller decides which deadline counts: at a job's admission
// only the inspection's own, never the job's.
func inspectionCut(err error) error {
	switch {
	case err == nil || errors.Is(err, ErrContamination) || errors.Is(err, ErrDrain) || errors.Is(err, ErrRecovery):
		return nil
	case errors.Is(err, ErrACLCensusUnavailable):
		return err
	case errors.Is(err, hostguard.ErrACLInspectionCut) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, exec.ErrWaitDelay):
		return inspectionCutError{err}
	}
	return nil
}

// inspectionCutError is an inspection its deadline cut short, reported as
// ErrACLCensusUnavailable with its own text.
type inspectionCutError struct{ error }

func (c inspectionCutError) Is(target error) bool { return target == ErrACLCensusUnavailable }
func (c inspectionCutError) Unwrap() error        { return c.error }

func verifyHotPersistence(ctx context.Context, options Options, inspect func(context.Context, Options, PersistenceManifest) error) (result error) {
	ctx, cancel := context.WithTimeout(ctx, persistenceAdmissionTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, persistenceAdmissionContextKey{}, true)
	var revision string
	checked := false
	defer func() {
		if checked && errors.Is(result, ErrContamination) {
			// Positive observations survive caller cancellation, but cleanup has
			// its own short bound and cannot revoke a newer successful scan.
			revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			result = errors.Join(result, revokePersistenceAttestationRevision(revokeCtx, options, revision, result))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	var expected PersistenceManifest
	var accepted []byte
	// Each authority bracket includes protected-path ACL inspection (one ls
	// per ancestor of three paths) as well as locking and reading: each gets
	// hotInspectionShare of the hot budget, of which only the wait for the
	// lock itself is bounded by persistenceAttestationLockTimeout.
	beforeCtx, cancelBefore := context.WithTimeout(ctx, hotInspectionShare)
	err := withAttestationLockContext(beforeCtx, options, func(_ *os.Root) error {
		record, _, err := readAttestationContext(beforeCtx, options)
		if err != nil {
			return err
		}
		revision, checked = record.Revision, true
		if !record.Valid {
			return errPersistenceAttestationRevoked
		}
		expected, accepted, err = readPersistenceContext(beforeCtx, options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		binding, err := attestationBinding(options, accepted)
		if err != nil {
			return err
		}
		if record.Binding != binding {
			return fmt.Errorf("%w: persistence attestation binding changed", ErrContamination)
		}
		return beforeCtx.Err()
	})
	cancelBefore()
	if err != nil {
		return err
	}
	if err := inspect(ctx, options, expected); err != nil {
		return err
	}
	afterCtx, cancelAfter := context.WithTimeout(ctx, hotInspectionShare)
	defer cancelAfter()
	return withAttestationLockContext(afterCtx, options, func(_ *os.Root) error {
		record, _, err := readAttestationContext(afterCtx, options)
		if err != nil {
			return err
		}
		_, after, err := readPersistenceContext(afterCtx, options.PersistencePath, options.JobUID)
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
			return fmt.Errorf("%w: persistence authority changed during admission", ErrContamination)
		}
		return afterCtx.Err()
	})
}
