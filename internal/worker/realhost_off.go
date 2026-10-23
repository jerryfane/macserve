//go:build !macserve_realhost

package worker

// Release builds have no real-host harness seam (see realhost_on.go): the
// baseline is always the protected reset record, and toolchain policy is
// always judged for the configured job UID. Both stubs inline away.

func harnessBaseline() (GUIBaseline, bool) { return GUIBaseline{}, false }

func toolchainPolicyUID(uid uint32) uint32 { return uid }
