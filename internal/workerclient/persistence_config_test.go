package workerclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkerConfigurationRequiresSeparatePersistenceAuthority(t *testing.T) {
	const valid = `{"socket":"/service/controller.sock","controller_uid":503,"owner_uid":501,"job_uid":502,"job_gid":502,"root":"/service/control","export_root":"/service/exports","workspace_root":"/service/workspaces","helper_path":"/service/bin/macserve","baseline_path":"/service/control/gui-baseline.json","persistence_path":"/service/control/reviewed-persistence.json"}`
	for name, data := range map[string]string{
		"missing":        strings.Replace(valid, `,"persistence_path":"/service/control/reviewed-persistence.json"`, "", 1),
		"baseline-alias": strings.Replace(valid, `"persistence_path":"/service/control/reviewed-persistence.json"`, `"persistence_path":"/service/control/gui-baseline.json"`, 1),
		"job-writable":   strings.Replace(valid, `"persistence_path":"/service/control/reviewed-persistence.json"`, `"persistence_path":"/service/workspaces/reviewed-persistence.json"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var config Config
			if err := json.Unmarshal([]byte(data), &config); err != nil {
				t.Fatal(err)
			}
			if _, err := normalize(config); err == nil {
				t.Fatal("configuration can authorize execution without a separate protected persistence authority")
			}
		})
	}
}
