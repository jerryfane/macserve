package worker

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// appleManagedAgentBundle recognizes only a recorded gui/user LaunchAgent
// whose definition and executable are in the same Apple-managed app. This is
// not a systemPath extension or an admission rule for unselected processes.
// The filesystem and launch proof is checked by verifiedAppleManagedAgent.
func appleManagedAgentBundle(s LaunchdService) string {
	const root = "/Library/Apple/System/Library/"
	if (s.Domain != "gui" && s.Domain != "user") || s.Owner != 0 ||
		!strings.HasPrefix(s.Path, root) || filepath.Clean(s.Path) != s.Path ||
		filepath.Clean(s.Executable) != s.Executable || codeRunner(s.Executable) {
		return ""
	}
	i := strings.Index(s.Path[len(root):], ".app/Contents/Resources/")
	if i < 0 {
		return ""
	}
	bundle := s.Path[:len(root)+i+len(".app")]
	if filepath.Dir(s.Path) != bundle+"/Contents/Resources" ||
		filepath.Base(s.Path) != s.Label+".plist" ||
		!strings.HasPrefix(s.Executable, bundle+"/Contents/") {
		return ""
	}
	return bundle
}

// verifiedAppleManagedAgent binds the audited record to an immutable app's
// launch definition on every initial description and relaunch. Root ownership
// alone is insufficient: both files and all ancestors through /Library/Apple
// must be SIP-restricted, non-symlinks and not group/other writable.
func verifiedAppleManagedAgent(ctx context.Context, agents agentInspector, s LaunchdService, snapshot launchctlprint.Snapshot, facts agentProcess, bundle string) bool {
	for i, leaf := range [2]string{s.Path, s.Executable} {
		if agents.restricted(leaf) != nil {
			return false
		}
		stop := "/Library"
		if i == 1 {
			// The definition's walk already checked Contents and its ancestors.
			stop = bundle + "/Contents"
		}
		for dir := filepath.Dir(leaf); dir != stop; dir = filepath.Dir(dir) {
			if agents.restrictedDirectory(dir) != nil {
				return false
			}
		}
	}
	data, err := agents.plist(ctx, s.Path)
	if err != nil {
		return false
	}
	program, argv, multiple, err := agentPlist(data, s.Label)
	if err != nil || multiple || snapshot.Original != "" || program != s.Executable ||
		program != snapshot.Program || facts.program != program || facts.argv != strings.Join(argv, "\x00") {
		return false
	}
	arguments := snapshot.Arguments
	if arguments == nil {
		arguments = []string{snapshot.Program}
	}
	return slices.Equal(arguments, argv)
}
