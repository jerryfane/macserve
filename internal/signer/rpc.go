package signer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jerryfane/macserve/internal/peercred"
)

// Artifact names under which the controller stores a signed job's outputs.
const (
	IPAArtifact     = "App.ipa"
	ReceiptArtifact = "signer-receipt.json"
)

// RPC bounds. A request line carries a base64 receipt of at most
// receipt.MaxReceiptBytes; a response header carries the signer receipt.
const (
	maxRequestBytes  = 128 << 10
	maxResponseBytes = 256 << 10
	// MaxIPABytes bounds a signed ipa, like the archive artifact budget.
	MaxIPABytes = 5 << 30
)

// Request is one controller → signer signing request, sent as a single JSON
// line on a fresh connection. Receipt is the job's exact signed receipt
// envelope bytes; ArchivePath and ManifestPath are the job's
// App.xcarchive.tar and signing-manifest.json copies, direct children of the
// signer's configured inbox, readable by the signer through the RPC group.
type Request struct {
	JobID        string `json:"job_id"`
	Receipt      []byte `json:"receipt"`
	ArchivePath  string `json:"archive_path"`
	ManifestPath string `json:"manifest_path"`
}

// response is the signer's JSON header line. On success IPASize bytes of the
// signed ipa follow the line on the same connection.
type response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Receipt   []byte `json:"receipt,omitempty"`
	IPASHA256 string `json:"ipa_sha256,omitempty"`
	IPASize   int64  `json:"ipa_size,omitempty"`
}

// Result is a successful signing: the signer receipt envelope bytes and the
// identity of the ipa streamed to the caller's writer.
type Result struct {
	Receipt   []byte
	IPASHA256 string
	IPASize   int64
}

// RefusalError is a signer's reasoned refusal of a request; the request is
// not retryable without a change of inputs or signer policy.
type RefusalError struct{ Reason string }

func (e *RefusalError) Error() string { return "signer refused: " + e.Reason }

// Client calls the signer over its Unix socket. Every connection must be
// served by SignerUID (peer credentials), so a socket another account
// managed to bind is never trusted with a receipt or believed for an ipa.
type Client struct {
	Socket    string
	SignerUID uint32
	// Timeout bounds one signing call; zero means 30 minutes.
	Timeout time.Duration
}

// Sign sends req and streams the signed ipa to ipa, verifying its size and
// SHA-256 against the signer's header before returning.
func (c *Client) Sign(ctx context.Context, req Request, ipa io.Writer) (Result, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	uid, err := peercred.UID(conn)
	if err != nil {
		return Result{}, err
	}
	if uid != c.SignerUID {
		return Result{}, fmt.Errorf("signer socket peer UID %d is not the signer", uid)
	}
	line, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	if len(line) >= maxRequestBytes {
		return Result{}, errors.New("signing request too large")
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return Result{}, err
	}
	reader := bufio.NewReaderSize(conn, 64<<10)
	header, err := readLine(reader, maxResponseBytes)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, fmt.Errorf("signer response: %w", err)
	}
	var resp response
	if err := strictJSON(header, &resp); err != nil {
		return Result{}, fmt.Errorf("signer response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unspecified"
		}
		return Result{}, &RefusalError{Reason: resp.Error}
	}
	if len(resp.Receipt) == 0 || resp.IPASize <= 0 || resp.IPASize > MaxIPABytes || !sha64(resp.IPASHA256) {
		return Result{}, errors.New("signer response lacks a receipt or ipa identity")
	}
	hash := sha256.New()
	copied, err := io.Copy(io.MultiWriter(ipa, hash), io.LimitReader(reader, resp.IPASize))
	if err != nil {
		return Result{}, err
	}
	if copied != resp.IPASize || hex.EncodeToString(hash.Sum(nil)) != resp.IPASHA256 {
		return Result{}, errors.New("signed ipa does not match the signer's size and digest")
	}
	return Result{Receipt: resp.Receipt, IPASHA256: resp.IPASHA256, IPASize: resp.IPASize}, nil
}

// readLine reads one newline-terminated line of at most max bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > max {
			return nil, errors.New("line too long")
		}
		if err == nil {
			return line[:len(line)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// strictJSON decodes exactly one JSON value with no unknown fields.
func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func sha64(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}
