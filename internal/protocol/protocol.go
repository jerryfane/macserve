// Package protocol defines the private, peer-UID-authenticated worker transport.
package protocol

import (
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

const (
	Prefix         = "/worker/v1"
	EpochHeader    = "X-Macserve-Epoch"
	LeaseHeader    = "X-Macserve-Lease"
	ArtifactHeader = "X-Macserve-Artifact"
)

type Registration struct {
	Epoch     string `json:"epoch"`
	Quiescent bool   `json:"quiescent"`
}

type Lease struct {
	Job    model.Job     `json:"job"`
	Token  string        `json:"token"`
	Source worker.Source `json:"source"`
}

type Heartbeat struct {
	Cancel   bool      `json:"cancel"`
	Deadline time.Time `json:"deadline"`
}

type Stage struct {
	State model.State `json:"state"`
}

type Log struct {
	Stream string `json:"stream"`
	Data   []byte `json:"data"`
}

// Completion is the worker's final report: its result and the root
// worker's signed build seal over that result, which the controller passes
// to the keyholder unchanged.
type Completion struct {
	Result worker.Result      `json:"result"`
	Seal   buildseal.Envelope `json:"seal"`
}
