package deploy

import (
	"encoding/xml"
	"strconv"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/worker"
)

func TestRenderedMaintenanceExitTimeOutExceedsPersistenceOperation(t *testing.T) {
	environment, assets := fixture(t)
	rendered, err := renderAssets(environment, assets)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		XMLName xml.Name `xml:"plist"`
		Dict    struct {
			Nodes []struct {
				XMLName xml.Name
				Text    string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(rendered["launchd/org.macserve.maintenance.plist.tmpl"], &document); err != nil {
		t.Fatal(err)
	}
	found := 0
	for i, node := range document.Dict.Nodes {
		if node.XMLName.Local == "key" && node.Text == "ExitTimeout" {
			t.Fatal("launchd ignores misspelled ExitTimeout; use documented ExitTimeOut")
		}
		if node.XMLName.Local != "key" || node.Text != "ExitTimeOut" {
			continue
		}
		found++
		if i+1 >= len(document.Dict.Nodes) || document.Dict.Nodes[i+1].XMLName.Local != "integer" {
			t.Fatal("rendered launchd ExitTimeOut is not an integer")
		}
		seconds, err := strconv.Atoi(document.Dict.Nodes[i+1].Text)
		if err != nil {
			t.Fatal(err)
		}
		shutdown := time.Duration(seconds) * time.Second
		if shutdown != 600*time.Second || shutdown <= worker.PersistenceOperationTimeout || shutdown <= worker.PersistenceFullScanTimeout {
			t.Fatalf("rendered shutdown deadline truncates scan/publication: shutdown=%v operation=%v collector=%v", shutdown, worker.PersistenceOperationTimeout, worker.PersistenceFullScanTimeout)
		}
	}
	if found != 1 {
		t.Fatalf("rendered launchd must have exactly one shutdown deadline, found %d", found)
	}
}
