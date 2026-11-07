package controller

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/worker"
)

var (
	ErrNotReady = errors.New("evidence not ready")
	ErrExpired  = errors.New("evidence bytes expired")
	// ErrReceiptRefused is a definitive refusal by the receipt authority:
	// the same inputs will never be signed. The Seal hook wraps it so
	// completion records an unsuccessful terminal result, keeping the
	// worker's cleanup proof, instead of leaving the job unfinished.
	ErrReceiptRefused = errors.New("receipt refused")
)

type SourceProvider interface {
	Prepare(context.Context, model.Job) (source.Descriptor, error)
	Remove(string) error
}
type Status struct {
	Service     model.ServiceState `json:"service"`
	WorkerReady bool               `json:"worker_ready"`
	Quiescent   bool               `json:"quiescent"`
	ActiveJob   string             `json:"active_job,omitempty"`
	Gate        health.GateState   `json:"gate"`
}
type Options struct {
	Root, Socket     string
	BrokerUID        uint32
	Store            *store.Store
	Source           SourceProvider
	Gate             func(context.Context) (health.GateState, error)
	BeforeDispatch   func(context.Context, model.Job) error
	HeartbeatTimeout time.Duration
	CleanupTimeout   time.Duration
	DeliveryTimeout  time.Duration
	SourceTimeout    time.Duration
	Now              func() time.Time
	// Seal obtains the job's receipt for the normalized result. It receives
	// the worker's exact result and signed build seal, which the keyholder
	// verifies before it signs.
	Seal          func(context.Context, model.Job, worker.Result, Sealing) (json.RawMessage, error)
	PruneReceipts func(context.Context) error
	// Signer signs succeeded ios_archive jobs; nil refuses signing.
	Signer *SignerOptions
}

// Sealing is the worker's own report of a job: its exact result and the
// root worker's build seal over it.
type Sealing struct {
	Worker worker.Result
	Seal   buildseal.Envelope
}

type Completion struct {
	InputDigest string          `json:"input_digest"`
	Result      worker.Result   `json:"result"`
	Receipt     json.RawMessage `json:"receipt,omitempty"`
	// Seal is the worker's build seal; completions recorded before seals
	// have none.
	Seal *buildseal.Envelope `json:"seal,omitempty"`
}
