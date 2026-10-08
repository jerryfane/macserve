package maintenance

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("probe output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func pfCommand(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	out := boundedBuffer{limit: 1 << 20}
	diagnostic := boundedBuffer{limit: 8192}
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		return "", err
	}
	// The stock macOS PF build may emit only these two harmless ALTQ notices.
	text := strings.TrimSpace(diagnostic.String())
	if text != "" && text != "No ALTQ support in kernel\nALTQ related functions disabled" {
		return "", errors.New("unrecognized PF diagnostic")
	}
	return out.String(), ctx.Err()
}

// pfctl(8) documents recursive '*' -sr and -v -s Interfaces. The BSD
// print_iface format prints ' (skip)' only with -v; -vv adds counters.
// Unknown output is refused rather than treated as filtering enabled.
func loopbackFiltered(text string) bool { return text == "lo0\n" }
func pfEnabled(text string) bool {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return false
	}
	return strings.HasPrefix(lines[0], "Status: Enabled for ") && strings.Contains(lines[0], "Debug:")
}
func observePF(ctx context.Context, o *Observation) error {
	status, err := pfCommand(ctx, "-s", "info")
	if err != nil {
		return err
	}
	o.PFEnabled = pfEnabled(status)
	if !o.PFEnabled {
		return errors.New("PF not verifiably enabled")
	}
	interfaces, err := pfCommand(ctx, "-i", "lo0", "-v", "-s", "Interfaces")
	if err != nil {
		return err
	}
	o.LoopbackFiltered = loopbackFiltered(interfaces)
	if !o.LoopbackFiltered {
		return errors.New("loopback filtering not verifiable")
	}
	root, err := pfCommand(ctx, "-a", "*", "-sr")
	if err != nil {
		return err
	}
	anchor, err := pfCommand(ctx, "-a", "org.macserve", "-sr")
	if err != nil {
		return err
	}
	// Dynamic tables/interfaces can change effective policy without changing rule
	// text. This initial observer supports only literal static addresses.
	if strings.TrimSpace(anchor) == "" || !strings.Contains(root, "anchor \"org.macserve\"") || strings.ContainsAny(root, "<(") || strings.ContainsAny(anchor, "<(") {
		return errors.New("missing anchor or unsupported dynamic PF rules")
	}
	// NAT/rdr can redirect before filtering. Require empty translation output on
	// every observation, including no opaque anchor calls. Do not infer that
	// '-a *' expands translation anchors: the BSD pfctl_show_nat printer does not
	// recurse, unlike its filter-rule printer. Harmless-looking stock anchors are
	// therefore unsupported, not evidence that their translation rules are empty.
	// https://github.com/freebsd/freebsd-src/blob/stable/10/sbin/pfctl/pfctl.c#L1012-L1048
	nat, err := pfCommand(ctx, "-a", "*", "-sn")
	if err != nil {
		return err
	}
	if strings.TrimSpace(nat) != "" {
		return errors.New("translation rules require unsupported qualification")
	}
	o.RootRulesSHA256 = digest([]byte(root))
	o.AnchorRulesSHA256 = digest([]byte(anchor))
	return nil
}
