package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
)

func TestCompleteTCPMatrix(t *testing.T) {
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
func TestTCPObservesConnectionsAndRefusals(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if ok, detail := tcpProbe(ctx, address); !ok {
		t.Fatalf("live authorized control: %s", detail)
	}
	listener.Close()
	if ok, _ := tcpProbe(ctx, address); ok {
		t.Fatal("connection refused reported as reachable")
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
	if ok, _ := udpProbe(ctx, conn.LocalAddr().String(), job); !ok {
		t.Fatal("delivered job datagram not reported as reachable")
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
		j.Results = append(j.Results, Result{Category: "network_reachability", Target: c.UDP[0], Attempt: n, Success: true, Nonce: jn})
		o.Results = append(o.Results, Result{Category: "network_reachability", Target: c.UDP[0], Attempt: n, Success: true, Nonce: on})
		r.Packets = append(r.Packets, Received{Packet: Packet{Challenge: hash, Role: "owner", Attempt: n, Nonce: on}, At: now.Add(time.Second), Peer: "127.0.0.1:1234"})
	}
	return c, j, o, []Receipts{r}
}
func TestReportBindingAndExpiration(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	c := Challenge{Schema: 3, ID: strings.Repeat("a", 64), Created: now, Expires: now.Add(lifetime), Environment: deploy.Environment{JobUID: 502, OwnerUID: 501}}
	r := Report{Schema: 3, ChallengeSHA256: "current", Role: "job", UID: 502, Groups: []int{502}, Started: now.Add(time.Second), Finished: now.Add(2 * time.Second)}
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
	categories := aggregate(c, Report{}, Report{}, nil)
	for name, cat := range categories {
		if cat.Status == "pass" {
			t.Errorf("missing %s passed", name)
		}
	}
	for _, name := range []string{"fast_switch", "reboot"} {
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
func TestSittingBindingsRejectDeploymentOrProfileChanges(t *testing.T) {
	c := Challenge{EnvironmentSHA256: "reviewed", Observation: maintenance.Observation{JobUID: 502, Profiles: map[string]string{"profile": "pin"}}, TCP: []string{"127.0.0.1:8080"}, UDP: []string{"127.0.0.1:9000"}, Allow: []string{"192.0.2.1:443"}}
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

func TestObservationBindingsPreserveNonNetworkBoundaries(t *testing.T) {
	before := maintenance.Observation{JobUID: 502, Boot: "boot", BaselineSHA256: "baseline", Profiles: map[string]string{"profile": "pin"}, IdentityValid: true, BaselineValid: true}
	if !sameObservation(before, before) {
		t.Fatal("unchanged non-network observation refused")
	}
	for name, mutate := range map[string]func(*maintenance.Observation){
		"uid":               func(o *maintenance.Observation) { o.JobUID++ },
		"boot":              func(o *maintenance.Observation) { o.Boot = "rebooted" },
		"baseline":          func(o *maintenance.Observation) { o.BaselineSHA256 = "changed" },
		"profile":           func(o *maintenance.Observation) { o.Profiles = map[string]string{"profile": "changed"} },
		"identity validity": func(o *maintenance.Observation) { o.IdentityValid = false },
		"baseline validity": func(o *maintenance.Observation) { o.BaselineValid = false },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			mutate(&after)
			if sameObservation(before, after) {
				t.Fatal("changed non-network boundary admitted")
			}
		})
	}
	prior := Challenge{EnvironmentSHA256: "reviewed", Observation: before}
	next := prior
	next.Observation.Boot = "rebooted"
	next.Observation.BaselineSHA256 = "fresh baseline"
	if !compatibleSitting(prior, next) {
		t.Fatal("lifecycle refused a new boot and fresh baseline")
	}
	next.Observation.JobUID++
	if compatibleSitting(prior, next) {
		t.Fatal("lifecycle accepted changed job identity")
	}
}

func TestObservationRejectsRemovedInterfaceBinding(t *testing.T) {
	var c Challenge
	if err := decode([]byte(`{"schema":3,"observation":{"job_uid":502}}`), &c); err != nil {
		t.Fatal(err)
	}
	if err := decode([]byte(`{"schema":3,"observation":{"job_uid":502,"interfaces_sha256":"legacy"}}`), &c); err == nil {
		t.Fatal("legacy interface binding accepted in current challenge")
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
	receipts[0].Listen = ""
	receipts[0].OwnerBefore = OwnerCanaryControl{Path: c.OwnerCanary, At: receipts[0].Started, Readable: true}
	receipts[0].OwnerAfter = OwnerCanaryControl{Path: c.OwnerCanary, At: receipts[0].Finished, Readable: true}
	if ok, n := ownerCanaryControls(c, j, o, receipts); !ok || n != 2 {
		t.Fatal("valid before/after controls rejected")
	}
	original := receipts[0]
	cases := map[string]func(*Receipts){
		"network-bound controls": func(r *Receipts) { r.Listen = c.UDP[0] },
		"before too late":        func(r *Receipts) { r.OwnerBefore.At = j.Started.Add(time.Second) },
		"after too early":        func(r *Receipts) { r.OwnerAfter.At = j.Finished.Add(-time.Second) },
		"before unreadable":      func(r *Receipts) { r.OwnerBefore.Readable = false },
		"after unreadable":       func(r *Receipts) { r.OwnerAfter.Readable = false },
		"different canary":       func(r *Receipts) { r.OwnerAfter.Path = "/Users/exampleowner/other" },
		"outside receiver":       func(r *Receipts) { r.OwnerBefore.At = r.Started.Add(-time.Second) },
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

func phaseOneFixture() (Challenge, Report, Report, []Receipts) {
	now := time.Now().UTC()
	c := Challenge{
		Environment: deploy.Environment{OwnerUser: "example-owner", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"},
		OwnerCanary: "/Users/example-owner/private/canary",
		Socket:      "/private/worker.sock", PrivatePaths: []string{"/private/store"},
		TCP: []string{"127.0.0.1:8080", "[::1]:8080", "100.64.0.7:8080", "192.0.2.5:8080"},
	}
	j := Report{Started: now, Finished: now.Add(time.Minute)}
	o := j
	for _, path := range homeTargets(c) {
		row := Result{Category: "owner_home_denial", Target: path, Attempt: 1, Success: true}
		j.Results = append(j.Results, row)
		o.Results = append(o.Results, row)
	}
	for _, path := range append([]string{c.Socket}, c.PrivatePaths...) {
		j.Results = append(j.Results, Result{Category: "unix_socket_boundary", Target: path, Attempt: 1, Success: true})
	}
	j.Results = append(j.Results, Result{Category: "tool_profiles", Target: c.Environment.DeveloperDir, Attempt: 1, Success: true})
	receipt := Receipts{Started: now.Add(-time.Second), Finished: now.Add(2 * time.Minute)}
	receipt.OwnerBefore = OwnerCanaryControl{Path: c.OwnerCanary, At: receipt.Started, Readable: true}
	receipt.OwnerAfter = OwnerCanaryControl{Path: c.OwnerCanary, At: receipt.Finished, Readable: true}
	return c, j, o, []Receipts{receipt}
}

func TestNetworkObservationsNeverBlockApproval(t *testing.T) {
	for _, outcome := range []string{"reachable", "unreachable", "missing", "UDP received", "receiver failed"} {
		t.Run(outcome, func(t *testing.T) {
			c, j, o, receipts := phaseOneFixture()
			if outcome != "missing" {
				for _, target := range c.TCP {
					for attempt := 1; attempt <= 3; attempt++ {
						row := Result{Category: "network_reachability", Target: target, Attempt: attempt, Success: outcome != "unreachable", Detail: outcome}
						j.Results = append(j.Results, row)
						o.Results = append(o.Results, row)
					}
				}
			}
			if outcome == "UDP received" {
				c.UDP = []string{"127.0.0.1:9000"}
				row := Result{Category: "network_reachability", Target: c.UDP[0], Attempt: 1, Success: true, Nonce: strings.Repeat("a", 64)}
				j.Results = append(j.Results, row)
				receipts = append(receipts, Receipts{Listen: c.UDP[0], Started: j.Started, Finished: j.Finished,
					Packets: []Received{{Packet: Packet{Role: "job", Attempt: 1, Nonce: row.Nonce}, At: j.Started}}})
			}
			if outcome == "receiver failed" {
				receipts = append(receipts, Receipts{Error: "bind: address already in use"})
			}
			if e := validateReceiptPackets(j, o, receipts); e != nil {
				t.Fatal(e)
			}
			v := Candidate{Categories: aggregate(c, j, o, receipts)}
			if e := readyAutomatic(v); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"fast_switch", "reboot"} {
				v.Categories[name] = Category{Status: "pass"}
			}
			if e := readyApproval(v); e != nil {
				t.Fatal(e)
			}
			network := v.Categories["network_reachability"]
			if network.Status != networkStatus || network.Probe.Status != networkStatus {
				t.Fatalf("network observation claimed enforcement: %+v", network)
			}
			if outcome == "UDP received" && network.Probe.CanaryReceipts != 1 {
				t.Fatal("delivered job packet not preserved as observation")
			}
		})
	}
}

func TestNonNetworkFailuresStillBlockApproval(t *testing.T) {
	for _, category := range []string{"unix_socket_boundary", "owner_home_denial", "tool_profiles", "owner_unaffected", "fast_switch", "reboot"} {
		t.Run(category, func(t *testing.T) {
			c, j, o, receipts := phaseOneFixture()
			if category == "owner_unaffected" {
				receipts[0].OwnerAfter.Readable = false
			} else {
				for i := range j.Results {
					if j.Results[i].Category == category {
						j.Results[i].Success = false
					}
				}
			}
			v := Candidate{Categories: aggregate(c, j, o, receipts)}
			for _, name := range []string{"fast_switch", "reboot"} {
				if name != category {
					v.Categories[name] = Category{Status: "pass"}
				}
			}
			if e := readyApproval(v); e == nil {
				t.Fatalf("%s failure admitted", category)
			}
		})
	}
}

func TestOldChallengeAndReportSchemasRejected(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	c := Challenge{Schema: 3, ID: strings.Repeat("a", 64), Created: now, Expires: now.Add(lifetime), Environment: deploy.Environment{JobUID: 502}}
	r := Report{Schema: 3, ChallengeSHA256: "current", Role: "job", UID: 502, Groups: []int{502}, Started: now, Finished: now.Add(time.Second)}
	if e := fresh(c, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := checkReport(r, c, "current", "job"); e != nil {
		t.Fatal(e)
	}
	for _, schema := range []int{1, 2} {
		old := c
		old.Schema = schema
		if e := fresh(old, now.Add(time.Second)); e == nil {
			t.Fatalf("schema %d challenge admitted", schema)
		}
		oldReport := r
		oldReport.Schema = schema
		if e := checkReport(oldReport, c, "current", "job"); e == nil {
			t.Fatalf("schema %d report admitted", schema)
		}
	}
}

func TestReceiptIntegrityDoesNotRequireDelivery(t *testing.T) {
	_, job, owner, receipts := receiptFixture()
	if e := validateReceiptPackets(job, owner, receipts); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Received){
		func(p *Received) { p.Packet.Challenge = "other" },
		func(p *Received) { p.Packet.Role = "unreviewed" },
		func(p *Received) { p.Packet.Nonce = strings.Repeat("f", 64) },
		func(p *Received) { p.At = receipts[0].Finished.Add(time.Second) },
	} {
		packet := receipts[0].Packets[0]
		mutate(&packet)
		r := receipts[0]
		r.Packets = []Received{packet}
		if e := validateReceiptPackets(job, owner, []Receipts{r}); e == nil {
			t.Fatal("unbound receipt packet admitted")
		}
	}
	receipts[0].Packets = nil
	receipts[0].Error = "receiver unavailable"
	if e := validateReceiptPackets(job, owner, receipts); e != nil {
		t.Fatalf("missing delivery became an enforcement gate: %v", e)
	}
}
