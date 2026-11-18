package workerclient

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/jerryfane/macserve/internal/protocol"
)

// products requests a consumer lease's sealed test products. It returns the
// response body for the engine, which hashes and verifies every byte
// (worker importTestProducts), and the function that closes it. A failed
// request returns a reader that fails with its error, so the engine fails
// the job cleanly ("test products: ...") instead of the client failing it
// unexecuted.
func (c *Client) products(ctx context.Context, lease protocol.Lease, epoch string) (io.Reader, func()) {
	req, err := c.request(ctx, http.MethodGet, "/jobs/"+lease.Job.ID+"/products", epoch, lease.Token, nil)
	if err != nil {
		return failedReader{err}, func() {}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return failedReader{fmt.Errorf("unavailable: %w", err)}, func() {}
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return failedReader{fmt.Errorf("unavailable: %w", statusError(resp))}, func() {}
	}
	return resp.Body, func() { resp.Body.Close() }
}

// failedReader fails every read with its error.
type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }
