package controller

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
	"time"
)

var (
	ErrNotReady = errors.New("evidence not ready")
	ErrExpired  = errors.New("evidence bytes expired")
)

type SourceProvider interface {
	Prepare(context.Context, model.Job) (source.Descriptor, error)
	Remove(string) error
}
type GateState struct {
	Ready        bool     `json:"ready"`
	CancelActive bool     `json:"cancel_active"`
	Blockers     []string `json:"blockers"`
	FreeBytes    int64    `json:"free_bytes"`
	UsedBytes    int64    `json:"used_bytes"`
}
type Status struct {
	Service     model.ServiceState `json:"service"`
	WorkerReady bool               `json:"worker_ready"`
	Quiescent   bool               `json:"quiescent"`
	ActiveJob   string             `json:"active_job,omitempty"`
	Gate        GateState          `json:"gate"`
}
type Options struct {
	Root, Socket     string
	BrokerUID        uint32
	Store            *store.Store
	Source           SourceProvider
	Gate             func(context.Context) (GateState, error)
	HeartbeatTimeout time.Duration
	CleanupTimeout   time.Duration
	DeliveryTimeout  time.Duration
	SourceTimeout    time.Duration
	Now              func() time.Time
	Seal             func(context.Context, model.Job, worker.Result) (json.RawMessage, error)
}
type Completion struct {
	InputDigest string          `json:"input_digest"`
	Result      worker.Result   `json:"result"`
	Receipt     json.RawMessage `json:"receipt,omitempty"`
}
