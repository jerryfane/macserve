package workerclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// A consumer lease's test products are requested before its source and
// handed to the engine as streamed; a failed request reaches the engine as
// a reader that fails, so the engine (not the client) fails the job. A
// lease that consumes nothing never requests products.
func TestConsumerLeaseStreamsProductsToTheEngine(t *testing.T) {
	ref := model.ProductsRef{ProducerJobID: "j_producer", SHA256: strings.Repeat("c", 64), Xctestrun: "App.xctestrun"}
	consumer := model.Request{Repo: "acme/app", SHA: strings.Repeat("a", 40), Kind: model.SimulatorUITest, Profile: fixtureUITest.ID, Xcode: fixtureUITest.Xcode, Shard: "smoke", Products: &ref}
	for _, tc := range []struct {
		name     string
		request  model.Request
		status   int
		wantPath []string
		want     string
		wantErr  bool
	}{
		{"consumer", consumer, http.StatusOK, []string{"products", "source"}, "sealed products", false},
		{"evicted", consumer, http.StatusGone, []string{"products", "source"}, "", true},
		{"plain build", fixtureRequest, http.StatusOK, []string{"source"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
				switch name {
				case "products", "source":
					mu.Lock()
					paths = append(paths, name)
					mu.Unlock()
					if name == "products" {
						w.WriteHeader(tc.status)
						if tc.status == http.StatusOK {
							io.WriteString(w, "sealed products")
						}
						return
					}
					w.Write([]byte("source"))
				case "heartbeat":
					json.NewEncoder(w).Encode(protocol.Heartbeat{Deadline: time.Now().Add(time.Minute)})
				default:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			engine := &fakeExecutor{execute: func(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error) {
				return worker.Result{State: model.Failed, CleanupOK: true}, nil
			}}
			client, err := NewWithChecks(cfg, engine, testChecks)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			deadline := time.Now().Add(10 * time.Second)
			lease := protocol.Lease{Job: admittedJob(t, "j_test", client.epoch, &deadline, tc.request), Token: "lease"}
			if _, err := client.execute(context.Background(), lease); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(paths, ",") != strings.Join(tc.wantPath, ",") {
				t.Fatalf("requests %v, want %v", paths, tc.wantPath)
			}
			if string(engine.products) != tc.want || (engine.productsErr != nil) != tc.wantErr {
				t.Fatalf("engine read products %q err %v", engine.products, engine.productsErr)
			}
		})
	}
}
