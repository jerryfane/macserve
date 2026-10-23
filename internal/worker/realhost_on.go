//go:build macserve_realhost

package worker

// Real-host harness seams (v0.1.16), compiled only with -tags
// macserve_realhost and set only by realhost_harness_test.go, which runs the
// production engine on the Mac Studio as the owner account:
//   - realhostBaseline replaces the protected reset record (root-owned, so
//     unreadable as the owner) with a validated in-memory baseline;
//   - realhostToolchainUID judges the toolchain policy for the dedicated job
//     account, because the owner is an administrator and the policy refuses
//     every administrator job UID by design.
var (
	realhostBaseline     *GUIBaseline
	realhostToolchainUID uint32
)

func harnessBaseline() (GUIBaseline, bool) {
	if realhostBaseline == nil {
		return GUIBaseline{}, false
	}
	return *realhostBaseline, true
}

func toolchainPolicyUID(uid uint32) uint32 {
	if realhostToolchainUID != 0 {
		return realhostToolchainUID
	}
	return uid
}
