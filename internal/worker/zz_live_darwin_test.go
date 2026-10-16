//go:build darwin

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestProbeLive(t *testing.T) {
	stage := os.Getenv("PROBE_STAGE")
	if stage == "" {
		t.Skip()
	}
	ctx := context.Background()
	uid := 501
	agents := nativeAgents{}
	samples, err := identityProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	switch stage {
	case "describe":
		var b GUIBaseline
		b.JobUID, b.Boot = uint32(uid), "x"
		for _, f := range strings.Split(os.Getenv("PROBE_PIDS"), ",") {
			pid, _ := strconv.Atoi(f)
			for _, s := range samples {
				if s.pid == pid {
					b.Processes = append(b.Processes, ProcessIdentity{PID: pid, Start: s.start})
				}
			}
		}
		b = describeServices(ctx, agents, uid, b)
		for _, p := range b.Processes {
			fmt.Printf("PROVENANCE pid=%d %+v\n", p.PID, p.Service)
		}
		if err := validateBaseline(b, uint32(uid), "x"); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(b)
		os.WriteFile("/tmp/baseline.json", data, 0o600)
	case "check":
		var b GUIBaseline
		data, _ := os.ReadFile("/tmp/baseline.json")
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatal(err)
		}
		scope := processScope{uid: uid, baseline: b, agents: agents}
		residual, err := scope.residual(ctx, samples)
		if err != nil {
			fmt.Println("RESIDUAL ERROR", err)
			return
		}
		want, _ := strconv.Atoi(os.Getenv("PROBE_PID"))
		found := false
		for _, p := range residual {
			if p.pid == want {
				found = true
			}
		}
		facts, ferr := agents.process(want)
		fmt.Printf("CHECK %s pid=%d residual=%v facts=%+v err=%v\n", os.Getenv("PROBE_NAME"), want, found, facts, ferr)
	}
}
