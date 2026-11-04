package plan

import "strings"

// ModeApply is the Mode of `macserve setup` without --plan.
const ModeApply = "apply"

// Mode selects "plan" when any argument names the plan flag in a spelling
// the flag package accepts (-plan, --plan, -plan=...), and ModeApply
// otherwise. Anything that might be --plan goes to the read-only plan,
// which parses it fully; apply refuses --plan as well.
func Mode(args []string) string {
	for _, a := range args {
		name, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if strings.HasPrefix(a, "-") && name == "plan" {
			return "plan"
		}
	}
	return ModeApply
}
