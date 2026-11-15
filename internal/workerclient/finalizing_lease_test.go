package workerclient

import (
	"testing"

	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// The controller's default finalizing lease outlasts the worker's longest
// finalization (worker.FinalizationTimeout) and this client's delivery of the
// completion after it (protocol.DeliveryTimeout), with heartbeat grace to
// spare, for every kind (an ios_archive job's archive evidence runs in its
// own window besides). Both sides derive their budgets from these constants
// (#152 review r1); a lease shorter than their sum expires mid-delivery and
// fences the epoch as unconfirmed cleanup.
func TestControllerFinalizingLeaseCoversFinalizationAndDelivery(t *testing.T) {
	for _, kind := range []model.Kind{model.Build, model.UnitTest, model.SimulatorUITest, model.SimulatorScript, model.IOSArchive} {
		worst := worker.FinalizationTimeout + protocol.DeliveryTimeout
		if kind == model.IOSArchive {
			worst += worker.ArchiveEvidenceTimeout
		}
		if lease := controller.FinalizingWindow(controller.Options{}, kind); lease <= worst {
			t.Fatalf("%s: controller finalizing lease %v does not outlast finalization and delivery %v", kind, lease, worst)
		}
	}
}
