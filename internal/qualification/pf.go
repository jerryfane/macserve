package qualification

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var denyLabels = []string{"macserve-protected", "macserve-private", "macserve-host", "macserve-default-deny"}
var ruleLabel = regexp.MustCompile(`\blabel "([^"]+)"`)
var ruleProtocol = regexp.MustCompile(`\bproto (tcp|udp)\b`)
var packetCount = regexp.MustCompile(`\bPackets:\s*([0-9]+)\b`)

// PF expands protocol/address sets into individual rules. Per-rule counters,
// unlike the aggregate -s labels output, prevent TCP traffic from satisfying the
// UDP evidence requirement (or vice versa). Unknown formats fail closed.
func protocolCounters(text string) (map[string]uint64, error) {
	out := map[string]uint64{}
	pending := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@") {
			if pending != "" {
				return nil, errors.New("PF rule missing packet counter")
			}
			label := ruleLabel.FindStringSubmatch(line)
			if len(label) == 0 || !slices.Contains(denyLabels, label[1]) {
				continue
			}
			protocol := ruleProtocol.FindStringSubmatch(line)
			if len(protocol) != 2 || !strings.Contains(line, " block drop out ") {
				return nil, errors.New("labeled deny rule is not a supported outbound TCP/UDP drop")
			}
			pending = protocol[1] + "/" + label[1]
			continue
		}
		if pending != "" {
			count := packetCount.FindStringSubmatch(line)
			if len(count) == 0 {
				continue
			}
			n, e := strconv.ParseUint(count[1], 10, 64)
			if e != nil {
				return nil, e
			}
			if ^uint64(0)-out[pending] < n {
				return nil, errors.New("PF counter overflow")
			}
			out[pending] += n
			pending = ""
		}
	}
	if pending != "" {
		return nil, errors.New("PF rule missing packet counter")
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, label := range denyLabels {
			if _, ok := out[proto+"/"+label]; !ok {
				return nil, fmt.Errorf("missing labeled %s deny counter %s", proto, label)
			}
		}
	}
	return out, nil
}
func protocolDelta(before, after Snapshot, protocol string) (int64, bool) {
	var total uint64
	for _, label := range denyLabels {
		a, ok := before.ProtocolCounters[protocol+"/"+label]
		b, ok2 := after.ProtocolCounters[protocol+"/"+label]
		if !ok || !ok2 || b < a || b-a > uint64(^uint64(0)>>1)-total {
			return 0, false
		}
		total += b - a
	}
	return int64(total), true
}
func pfDiagnostic(text string) bool {
	text = strings.TrimSpace(text)
	return text == "" || text == "No ALTQ support in kernel\nALTQ related functions disabled"
}
