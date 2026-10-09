package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
)

func TestCompleteTCPMatrixAndMissingRows(t *testing.T) {
	e := deploy.Environment{TailnetIP: "100.64.0.7", HostAddresses: []string{"100.64.0.7", "192.0.2.5"}, ProtectedPorts: []uint16{8080, 9000}}
	targets, err := tcpTargets(e)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:8080", "127.0.0.1:9000", "[::1]:8080", "[::1]:9000", "100.64.0.7:8080", "100.64.0.7:9000", "192.0.2.5:8080", "192.0.2.5:9000"}
	slices.Sort(targets)
	slices.Sort(want)
	if !slices.Equal(targets, want) {
		t.Fatalf("target coverage: %v", targets)
	}
	var r Report
	for _, target := range targets {
		for attempt := 1; attempt <= 3; attempt++ {
			r.Results = append(r.Results, Result{Category: "tcp_denial", Target: target, Attempt: attempt, Success: true})
		}
	}
	if ok, _ := rows(r, "tcp_denial", targets, 3); !ok {
		t.Fatal("complete matrix rejected")
	}
	r.Results = r.Results[:len(r.Results)-1]
	if ok, _ := rows(r, "tcp_denial", targets, 3); ok {
		t.Fatal("missing IPv6/host attempt accepted")
	}
	r.Results = append(r.Results, r.Results[0])
	if ok, _ := rows(r, "tcp_denial", targets, 3); ok {
		t.Fatal("duplicate substituted for missing attempt")
	}
}
func TestEndpointListsAreExplicitLiteralAndUnique(t *testing.T) {
	for _, s := range []string{"", "localhost:80", "127.0.0.1:0", "127.0.0.1:080", "0.0.0.0:80", "[ff02::1]:80", "127.0.0.1:80,127.0.0.1:80"} {
		if _, e := endpoints(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, e := endpoints("127.0.0.1:8080,[::1]:9000"); e != nil {
		t.Fatal(e)
	}
}
func TestTCPRefusalIsNotDenialAndLiveServiceFailsDenial(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if ok, detail := tcpProbe(ctx, address, false); !ok {
		t.Fatalf("live authorized control: %s", detail)
	}
	if ok, _ := tcpProbe(ctx, address, true); ok {
		t.Fatal("live service accepted as denied")
	}
	listener.Close()
	if ok, _ := tcpProbe(ctx, address, true); ok {
		t.Fatal("connection refused accepted as PF denial")
	}
}
func TestActualUDPReceiverObservesOwnerAndJobNonces(t *testing.T) {
	conn, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Receipts{ChallengeSHA256: strings.Repeat("a", 64), Started: time.Now().UTC()}
	done := make(chan struct{})
	go func() { receiveUDP(ctx, conn, &r); close(done) }()
	owner := Packet{Challenge: r.ChallengeSHA256, Role: "owner", Attempt: 1, Nonce: strings.Repeat("b", 64)}
	if ok, detail := udpProbe(ctx, conn.LocalAddr().String(), owner); !ok {
		t.Fatalf("owner controlled receiver: %s", detail)
	}
	job := Packet{Challenge: r.ChallengeSHA256, Role: "job", Attempt: 1, Nonce: strings.Repeat("c", 64)}
	if ok, _ := udpProbe(ctx, conn.LocalAddr().String(), job); ok {
		t.Fatal("delivered job datagram accepted as denial")
	}
	cancel()
	<-done
	if r.Error != "" || len(r.Packets) != 2 || r.Packets[0].Packet != owner || r.Packets[1].Packet != job {
		t.Fatalf("real receiver evidence: %+v", r)
	}
}
func TestUDPReceiverRejectsOtherChallenge(t *testing.T) {
	conn, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Receipts{ChallengeSHA256: strings.Repeat("a", 64)}
	done := make(chan struct{})
	go func() { receiveUDP(ctx, conn, &r); close(done) }()
	client, e := net.Dial("udp", conn.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	packet, _ := json.Marshal(Packet{Challenge: strings.Repeat("d", 64), Role: "owner", Attempt: 1, Nonce: strings.Repeat("b", 64)})
	if _, e = client.Write(packet); e != nil {
		t.Fatal(e)
	}
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 2048)
	if _, e = client.Read(buf); e == nil {
		t.Fatal("unrelated challenge echoed")
	}
	cancel()
	<-done
	if len(r.Packets) != 0 {
		t.Fatal("unrelated challenge recorded")
	}
}
func receiptFixture() (Challenge, Report, Report, []Receipts) {
	now := time.Now().UTC()
	hash := strings.Repeat("a", 64)
	c := Challenge{UDP: []string{"127.0.0.1:9000"}}
	j := Report{ChallengeSHA256: hash, Started: now, Finished: now.Add(time.Minute)}
	o := j
	r := Receipts{Listen: c.UDP[0], Started: now.Add(-time.Second), Finished: now.Add(2 * time.Minute)}
	for n := 1; n <= 3; n++ {
		jn := fmt.Sprintf("%064x", n)
		on := fmt.Sprintf("%064x", n+100)
		j.Results = append(j.Results, Result{Category: "udp_denial", Target: c.UDP[0], Attempt: n, Success: true, Nonce: jn})
		o.Results = append(o.Results, Result{Category: "udp_denial", Target: c.UDP[0], Attempt: n, Success: true, Nonce: on})
		r.Packets = append(r.Packets, Received{Packet: Packet{Challenge: hash, Role: "owner", Attempt: n, Nonce: on}, At: now.Add(time.Second), Peer: "127.0.0.1:1234"})
	}
	return c, j, o, []Receipts{r}
}
func TestReceiptsRequireCoverageFreshnessAndNoDelivery(t *testing.T) {
	c, j, o, r := receiptFixture()
	if ok, n := validateReceipts(c, j, o, r); !ok || n != 0 {
		t.Fatal("valid controlled observations rejected")
	}
	tests := map[string]func(*Challenge, *Report, *Report, *[]Receipts){
		"missing receiver": func(_ *Challenge, _ *Report, _ *Report, r *[]Receipts) { *r = nil },
		"missing nonce":    func(_ *Challenge, _ *Report, _ *Report, r *[]Receipts) { (*r)[0].Packets = (*r)[0].Packets[:2] },
		"replayed nonce":   func(_ *Challenge, _ *Report, _ *Report, r *[]Receipts) { (*r)[0].Packets[1] = (*r)[0].Packets[0] },
		"wrong challenge":  func(_ *Challenge, _ *Report, _ *Report, r *[]Receipts) { (*r)[0].Packets[0].Packet.Challenge = "old" },
		"wrong attempt":    func(_ *Challenge, _ *Report, _ *Report, r *[]Receipts) { (*r)[0].Packets[0].Packet.Attempt = 3 },
		"late receiver":    func(_ *Challenge, j *Report, _ *Report, r *[]Receipts) { (*r)[0].Started = j.Started.Add(time.Second) },
		"delivered job nonce": func(_ *Challenge, j *Report, _ *Report, r *[]Receipts) {
			(*r)[0].Packets = append((*r)[0].Packets, Received{Packet: Packet{Challenge: j.ChallengeSHA256, Role: "job", Attempt: 1, Nonce: j.Results[0].Nonce}, At: j.Started})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c, j, o, r := receiptFixture()
			mutate(&c, &j, &o, &r)
			ok, n := validateReceipts(c, j, o, r)
			if ok && n == 0 {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
}
func TestPFLabelCoverage(t *testing.T) {
	text := "macserve-protected 10 3 192 0 0 3 192\nmacserve-private 1 0 0 0 0 0 0\nmacserve-host 1 0 0 0 0 0 0\nmacserve-default-deny 1 0 0 0 0 0 0\n"
	counters, e := parseCounters(text)
	if e != nil {
		t.Fatal(e)
	}
	if counters["macserve-protected"] != 3 {
		t.Fatal("packet counter not selected")
	}
	if _, e = parseCounters(strings.Replace(text, "macserve-host", "other", 1)); e == nil {
		t.Fatal("missing mandatory PF label accepted")
	}
	if _, e = parseCounters("macserve-protected 3\n"); e == nil {
		t.Fatal("unknown format accepted")
	}
}
func TestReportBindingAndExpiration(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	c := Challenge{Schema: 1, ID: strings.Repeat("a", 64), Created: now, Expires: now.Add(lifetime), Environment: deploy.Environment{JobUID: 502, OwnerUID: 501}}
	r := Report{Schema: 1, ChallengeSHA256: "current", Role: "job", UID: 502, Groups: []int{502}, Started: now.Add(time.Second), Finished: now.Add(2 * time.Second)}
	if e := checkReport(r, c, "current", "job"); e != nil {
		t.Fatal(e)
	}
	if e := checkReport(r, c, "other", "job"); e == nil {
		t.Fatal("cross-session report accepted")
	}
	r.Role = "owner"
	if e := checkReport(r, c, "current", "job"); e == nil {
		t.Fatal("cross-role report accepted")
	}
	if e := fresh(c, c.Expires); e == nil {
		t.Fatal("expired challenge accepted")
	}
	if e := fresh(c, c.Created.Add(-time.Second)); e == nil {
		t.Fatal("future challenge accepted")
	}
}
func TestMissingAutomaticAndLifecycleCategoriesNeverPass(t *testing.T) {
	c := Challenge{Environment: deploy.Environment{OwnerUser: "example-owner", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}, OwnerCanary: "/Users/example-owner/private/canary", TCP: []string{"127.0.0.1:8080"}, UDP: []string{"127.0.0.1:9000"}, Allow: []string{"192.0.2.1:443"}, Socket: "/private/worker.sock", PrivatePaths: []string{"/private/store"}}
	categories := aggregate(c, Report{}, Report{}, nil, Snapshot{}, Snapshot{})
	for name, cat := range categories {
		if cat.Status == "pass" {
			t.Errorf("missing %s passed", name)
		}
	}
	for _, name := range []string{"fast_switch", "reboot", "delegated_boundary"} {
		if categories[name].Status != "pending" {
			t.Errorf("%s is not pending", name)
		}
	}
	homes := homeTargets(c)
	if !slices.Contains(homes, "/Users/example-owner") || !slices.Contains(homes, c.OwnerCanary) {
		t.Fatal("owner home itself or canary omitted")
	}
}
func TestArtifactSnapshotsRefuseSymlinksAndReplacement(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "report.json")
	if e = saveNew(p, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = saveNew(p, []byte("replacement"), 0600); e == nil {
		t.Fatal("report silently overwritten")
	}
	b, e := readArtifact(p, os.Getuid())
	if e != nil || string(b) != "original" {
		t.Fatalf("snapshot %q %v", b, e)
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e = readArtifact(link, os.Getuid()); e == nil {
		t.Fatal("symlink input accepted")
	}
	if _, e = readArtifact(dir, os.Getuid()); e == nil {
		t.Fatal("directory artifact accepted")
	}
	if e = saveNew(filepath.Join(dir, "oversized"), make([]byte, maxArtifact+1), 0600); e == nil {
		t.Fatal("unbounded artifact written")
	}
}
func TestStrictJSONRejectsAmbiguityAndUnknownData(t *testing.T) {
	for _, raw := range []string{`{"schema":1,"schema":2}`, `{"schema":1,"unknown":true}`, `{"schema":1} {"schema":2}`, `{"schema":1,"results":[{"success":true,"success":false}]}`} {
		var r Report
		if e := decode([]byte(raw), &r); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
func TestPolicyStageChangesOnlyPolicyDigest(t *testing.T) {
	raw := []byte(`{"policy_sha256":"old","job_uid":502,"principals":[{"opaque":"keep"}],"github":null}`)
	updated, e := policyConfig(raw, "new")
	if e != nil {
		t.Fatal(e)
	}
	var before, after map[string]json.RawMessage
	if e = json.Unmarshal(raw, &before); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(updated, &after); e != nil {
		t.Fatal(e)
	}
	delete(before, "policy_sha256")
	delete(after, "policy_sha256")
	var a, b any
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	json.Unmarshal(x, &a)
	json.Unmarshal(y, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("unrelated controller setting changed")
	}
	if _, e = policyConfig([]byte(`{"job_uid":502}`), "new"); e == nil {
		t.Fatal("missing old policy accepted")
	}
}
func TestRuntimePinsRejectUnavailableOrWrongBuild(t *testing.T) {
	raw := []byte(`{"runtimes":[{"identifier":"runtime","buildversion":"23A1","isAvailable":true,"supportedDeviceTypes":[{"identifier":"phone"}]}]}`)
	pins := []model.Simulator{{Runtime: "runtime", RuntimeBuild: "23A1", DeviceType: "phone"}}
	if !runtimePins(raw, pins) {
		t.Fatal("matching pins rejected")
	}
	pins[0].RuntimeBuild = "23A2"
	if runtimePins(raw, pins) {
		t.Fatal("wrong build accepted")
	}
	pins[0].RuntimeBuild = "23A1"
	if runtimePins([]byte(strings.Replace(string(raw), "true", "false", 1)), pins) {
		t.Fatal("unavailable runtime accepted")
	}
}
func TestUnapprovedCandidateCannotProduceHealthyMaintenance(t *testing.T) {
	q := qualification(maintenance.Observation{JobUID: 502, Boot: strings.Repeat("a", 64)})
	raw, e := unapproved(q)
	if e != nil {
		t.Fatal(e)
	}
	var loaded maintenance.Qualification
	if e = decode(raw, &loaded); e != nil {
		t.Fatal(e)
	}
	if !loaded.ApprovedAt.IsZero() {
		t.Fatal("candidate manufactured approval")
	}
	if _, e = maintenance.Evaluate(time.Now().UTC(), loaded, maintenance.BoundaryEvidence{}, maintenance.Observation{}); e == nil {
		t.Fatal("candidate accepted as healthy")
	}
}
func TestTCPPacketsCannotSatisfyUDPDenyEvidence(t *testing.T) {
	var text strings.Builder
	index := 0
	for _, proto := range []string{"tcp", "udp"} {
		for _, label := range denyLabels {
			packets := 0
			if proto == "tcp" {
				packets = 12
			}
			fmt.Fprintf(&text, "@%d block drop out log quick inet proto %s from any to any user = 502 label %q\n  [ Evaluations: 24 Packets: %d Bytes: 100 States: 0 ]\n", index, proto, label, packets)
			index++
		}
	}
	counters, e := protocolCounters(text.String())
	if e != nil {
		t.Fatal(e)
	}
	before := Snapshot{ProtocolCounters: map[string]uint64{}}
	after := Snapshot{ProtocolCounters: counters}
	for key := range counters {
		before.ProtocolCounters[key] = 0
	}
	if delta, ok := protocolDelta(before, after, "tcp"); !ok || delta != 48 {
		t.Fatalf("TCP delta %d %v", delta, ok)
	}
	if delta, ok := protocolDelta(before, after, "udp"); !ok || delta != 0 {
		t.Fatalf("TCP traffic credited to UDP: %d %v", delta, ok)
	}
	malformed := strings.Replace(text.String(), "proto udp", "proto icmp", 1)
	if _, e = protocolCounters(malformed); e == nil {
		t.Fatal("unattributable protocol accepted")
	}
	after.ProtocolCounters["tcp/macserve-protected"] = 0
	before.ProtocolCounters["tcp/macserve-protected"] = 1
	if _, ok := protocolDelta(before, after, "tcp"); ok {
		t.Fatal("reset protocol counter accepted")
	}
}
func TestSittingBindingsRejectDeploymentOrProfileChanges(t *testing.T) {
	c := Challenge{EnvironmentSHA256: "reviewed", Observation: maintenance.Observation{JobUID: 502, PolicySHA256: "policy", Profiles: map[string]string{"profile": "pin"}}, TCP: []string{"127.0.0.1:8080"}, UDP: []string{"127.0.0.1:9000"}, Allow: []string{"192.0.2.1:443"}}
	other := c
	other.EnvironmentSHA256 = "different"
	if compatibleSitting(c, other) {
		t.Fatal("different deployment admitted")
	}
	other = c
	other.Observation.Profiles = map[string]string{"profile": "new-pin"}
	if compatibleSitting(c, other) {
		t.Fatal("changed recipe admitted")
	}
	other = c
	other.TCP = nil
	if compatibleSitting(c, other) {
		t.Fatal("narrowed target matrix admitted")
	}
}

func TestTCPMatrixCapacityRefusesRatherThanTruncates(t *testing.T) {
	e := deploy.Environment{TailnetIP: "100.64.0.7", ProtectedPorts: make([]uint16, 513)}
	for i := range e.ProtectedPorts {
		e.ProtectedPorts[i] = uint16(i + 1)
	}
	if targets, err := tcpTargets(e); err == nil || targets != nil {
		t.Fatal("oversized matrix was allocated or silently narrowed")
	}
}

func TestOwnerCanaryControlsRequireBeforeAndAfter(t *testing.T) {
	c, j, o, receipts := receiptFixture()
	c.OwnerCanary = "/Users/exampleowner/canary"
	receipts[0].OwnerBefore = OwnerCanaryControl{Path: c.OwnerCanary, At: receipts[0].Started, Readable: true}
	receipts[0].OwnerAfter = OwnerCanaryControl{Path: c.OwnerCanary, At: receipts[0].Finished, Readable: true}
	if ok, n := ownerCanaryControls(c, j, o, receipts); !ok || n != 2 {
		t.Fatal("valid before/after controls rejected")
	}
	original := receipts[0]
	cases := map[string]func(*Receipts){
		"before too late":   func(r *Receipts) { r.OwnerBefore.At = j.Started.Add(time.Second) },
		"after too early":   func(r *Receipts) { r.OwnerAfter.At = j.Finished.Add(-time.Second) },
		"before unreadable": func(r *Receipts) { r.OwnerBefore.Readable = false },
		"after unreadable":  func(r *Receipts) { r.OwnerAfter.Readable = false },
		"different canary":  func(r *Receipts) { r.OwnerAfter.Path = "/Users/exampleowner/other" },
		"outside receiver":  func(r *Receipts) { r.OwnerBefore.At = r.Started.Add(-time.Second) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := original
			change(&r)
			if ok, _ := ownerCanaryControls(c, j, o, []Receipts{r}); ok {
				t.Fatal("unproven owner before/after accepted")
			}
		})
	}
	if ok, _ := ownerCanaryControls(c, j, o, nil); ok {
		t.Fatal("missing controls accepted")
	}
}

func TestFilesystemProbesRejectSpecialFilesWithoutBlocking(t *testing.T) {
	for name, probe := range map[string]func(string, bool) (bool, string){"denial": deniedRead, "control": readable} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "owned-fifo")
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan bool, 1)
			go func() { ok, _ := probe(path, false); done <- ok }()
			select {
			case ok := <-done:
				if ok {
					t.Fatal("special file accepted as permission denial or readable canary")
				}
			case <-time.After(2 * time.Second):
				// Release the old blocking reader before reporting the regression.
				writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = writer.Write([]byte("x"))
				writer.Close()
				if err != nil {
					t.Fatal(err)
				}
				<-done
				t.Fatal("filesystem probe blocked on an unsupported special file")
			}
		})
	}
}

func TestFilesystemProbesDistinguishDenialFromMissingAndReadablePaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nonsecret-canary")
	if err := os.WriteFile(path, []byte("nonsecret"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		list bool
	}{{path, false}, {dir, true}} {
		if ok, detail := readable(item.path, item.list); !ok {
			t.Fatal(detail)
		}
		if ok, _ := deniedRead(item.path, item.list); ok {
			t.Fatal("readable target counted as denied")
		}
	}
	if ok, _ := deniedRead(filepath.Join(dir, "missing"), false); ok {
		t.Fatal("missing file counted as permission denial")
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if ok, _ := readable(link, false); ok {
		t.Fatal("canary alias followed")
	}
	if os.Geteuid() == 0 {
		return
	}
	defer os.Chmod(dir, 0700)
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		list bool
	}{{path, false}, {dir, true}} {
		if ok, detail := deniedRead(item.path, item.list); !ok {
			t.Fatal(detail)
		}
	}
}
