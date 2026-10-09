package pfctl

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadRejectsMutationAndBroadQueries(t *testing.T) {
	for _, args := range [][]string{{"-f", "/tmp/policy"}, {"-e"}, {"-d"}, {"-F", "all"}, {"-a", "peer", "-f", "/tmp/policy"}, {"-a", "*", "-sr"}, {"-a", "", "-sn"}, {"-a", "../peer", "-sr"}, {"-a", "peer", "-vvsr"}, {"-s", "info"}, {"-v", "-s", "Anchors"}} {
		_, err := read(context.Background(), func(context.Context, ...string) (Output, error) {
			t.Fatal("unsafe command reached process boundary")
			return Output{}, nil
		}, args...)
		if err == nil {
			t.Fatalf("unsafe command accepted: %v", args)
		}
	}
}

func TestReadOpaqueRulesAndDiagnostics(t *testing.T) {
	for _, args := range [][]string{{"-sr"}, {"-sn"}, {"-a", "com.example/peer", "-sr"}, {"-a", "com.example/peer", "-sn"}} {
		for _, tc := range []struct {
			name string
			out  Output
			err  error
			ok   bool
		}{
			{"opaque", Output{Stdout: "unfamiliar rules without newline"}, nil, true},
			{"empty", Output{}, nil, true},
			{"ALTQ", Output{Stderr: "No ALTQ support in kernel\nALTQ related functions disabled\n"}, nil, true},
			{"missing diagnostic", Output{Stderr: "pfctl: DIOCGETRULES: Invalid argument\n"}, nil, false},
			{"missing anchor", Output{Stderr: "Anchor 'com.example/peer' not found.\n"}, nil, false},
			{"permission", Output{}, errors.New("permission denied"), false},
			{"unknown diagnostic", Output{Stderr: "partial read\n"}, nil, false},
			{"oversized stdout", Output{Stdout: strings.Repeat("x", (1<<20)+1)}, nil, false},
			{"oversized stderr", Output{Stderr: strings.Repeat("x", 8193)}, nil, false},
		} {
			out, err := read(context.Background(), func(context.Context, ...string) (Output, error) { return tc.out, tc.err }, args...)
			if (err == nil) != tc.ok {
				t.Fatalf("%v %s: %v", args, tc.name, err)
			}
			if tc.ok && out != tc.out {
				t.Fatal("opaque measurement bytes changed")
			}
		}
	}
}

func TestReadHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, err := read(ctx, func(context.Context, ...string) (Output, error) { cancel(); return Output{}, nil }, "-sr")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read accepted: %v", err)
	}
}

func TestNativeOutputCannotBypassBound(t *testing.T) {
	out := boundedBuffer{limit: 16}
	_, err := io.Copy(&out, io.LimitReader(strings.NewReader(strings.Repeat("x", 1024)), 1024))
	if err == nil || len(out.String()) > 16 {
		t.Fatal("native output bypassed bound")
	}
}
