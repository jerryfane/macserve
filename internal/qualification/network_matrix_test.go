package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkMatrixConcurrencyBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := Challenge{TCP: []string{"tcp-1", "tcp-2", "tcp-3"}, UDP: []string{"udp-1", "udp-2", "udp-3"}, Allow: []string{"allow-1", "allow-2"}}
	entered := make(chan struct{}, 20)
	release := make(chan struct{})
	var active, peak atomic.Int32
	transport := func(ctx context.Context, _ string) (bool, string) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
			return true, "fixture"
		case <-ctx.Done():
			return false, ctx.Err().Error()
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := networkMatrix(ctx, c, "digest", "job", transport, func(ctx context.Context, target string, _ Packet) (bool, string) {
			return transport(ctx, target)
		})
		done <- err
	}()
	for range 16 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("matrix failed to fill its 16-worker window")
		}
	}
	select {
	case <-entered:
		t.Error("more than 16 transports entered before release")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 16 || active.Load() != 0 {
		t.Fatalf("peak=%d active after return=%d", peak.Load(), active.Load())
	}
}

func TestNetworkMatrixSerialEvidenceOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := Challenge{TCP: []string{"blocked", "reachable"}, UDP: []string{"echo", "silent"}, Allow: []string{"authorized"}}
	udpEntered := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	receipts := make(map[string]Packet)
	tcp := func(ctx context.Context, target string) (bool, string) {
		// Force UDP to execute before the first TCP rows complete.
		select {
		case <-udpEntered:
		case <-ctx.Done():
			return false, ctx.Err().Error()
		}
		return target != "blocked", "fixture " + target
	}
	udp := func(_ context.Context, target string, p Packet) (bool, string) {
		once.Do(func() { close(udpEntered) })
		mu.Lock()
		receipts[p.Nonce] = p
		mu.Unlock()
		return target == "echo", "fixture " + target
	}
	got, err := networkMatrix(ctx, c, "challenge-digest", "job", tcp, udp)
	if err != nil {
		t.Fatal(err)
	}
	var want []Result
	for _, target := range c.TCP {
		for attempt := 1; attempt <= 3; attempt++ {
			want = append(want, Result{"network_reachability", target, attempt, target != "blocked", "TCP: fixture " + target, ""})
		}
	}
	seen := make(map[string]bool)
	for _, target := range c.UDP {
		for attempt := 1; attempt <= 3; attempt++ {
			if len(got) <= len(want) {
				t.Fatal("missing UDP evidence")
			}
			nonce := got[len(want)].Nonce
			if nonce == "" || seen[nonce] {
				t.Fatalf("missing or duplicate nonce %q", nonce)
			}
			seen[nonce] = true
			if receipts[nonce] != (Packet{"challenge-digest", "job", attempt, nonce}) {
				t.Fatalf("row nonce does not match transmitted packet: %+v", receipts[nonce])
			}
			want = append(want, Result{"network_reachability", target, attempt, target == "echo", "UDP: fixture " + target, nonce})
		}
	}
	for _, target := range c.Allow {
		want = append(want, Result{"network_reachability", target, 1, true, "authorized TCP endpoint: fixture " + target, ""})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parallel evidence differs from serial fixture:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestNetworkMatrixCancellationJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := Challenge{}
	for i := range 130 {
		c.TCP = append(c.TCP, fmt.Sprintf("target-%d", i))
	}
	entered := make(chan struct{}, 16)
	exiting := make(chan struct{}, 16)
	release := make(chan struct{})
	defer close(release)
	var active atomic.Int32
	tcp := func(ctx context.Context, _ string) (bool, string) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		exiting <- struct{}{}
		<-release
		return false, ctx.Err().Error()
	}
	done := make(chan []Result, 1)
	go func() {
		rows, _ := networkMatrix(ctx, c, "digest", "job", tcp, nil)
		done <- rows
	}()
	for range 16 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	cancel()
	for range 16 {
		select {
		case <-exiting:
		case <-time.After(time.Second):
			t.Fatal("workers ignored cancellation")
		}
	}
	select {
	case <-done:
		t.Fatal("matrix returned with live workers")
	default:
	}
	// Unblock every worker without closing the deferred cleanup channel twice.
	for range 16 {
		release <- struct{}{}
	}
	select {
	case rows := <-done:
		if len(rows) != 390 || active.Load() != 0 {
			t.Fatalf("rows=%d active=%d", len(rows), active.Load())
		}
		for _, row := range rows {
			if row.Success || row.Detail != "TCP: context canceled" {
				t.Fatalf("cancellation evidence lost: %+v", row)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("canceled matrix did not drain")
	}
}

func TestUDPProbeCancellationClosesRead(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
			}
			defer cancel()
			done := make(chan bool, 1)
			packet := Packet{"digest", "job", 2, "nonce"}
			go func() {
				ok, _ := udpProbe(ctx, listener.LocalAddr().String(), packet)
				done <- ok
			}()
			_ = listener.SetReadDeadline(time.Now().Add(time.Second))
			var buffer [2048]byte
			n, _, err := listener.ReadFrom(buffer[:])
			if err != nil {
				t.Fatal(err)
			}
			var received Packet
			if err := json.Unmarshal(buffer[:n], &received); err != nil || received != packet {
				t.Fatalf("packet changed: %+v, %v", received, err)
			}
			if !deadline {
				cancel()
			}
			select {
			case ok := <-done:
				if ok {
					t.Fatal("unanswered canceled probe passed")
				}
			case <-time.After(time.Second):
				t.Fatal("UDP read ignored cancellation/deadline and retained its two-second timeout")
			}
		})
	}
}
