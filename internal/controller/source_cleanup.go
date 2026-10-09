package controller

import (
	"context"
	"errors"
)

// removeSource keeps a durable obligation across failures and crashes. The
// provider performs its existing ID-confined, protected filesystem removal.
func (c *Controller) removeSource(id string) error {
	ctx := context.Background()
	if err := c.options.Store.RequireSourceCleanup(ctx, id); err != nil {
		return err
	}
	if err := c.options.Source.Remove(id); err != nil {
		return err
	}
	return c.options.Store.ConfirmSourceCleanup(ctx, id)
}

// Retry only terminal exports. Its caller excludes evidence writers (or is
// startup before publication), and checks the owner's maintenance permission.
func (c *Controller) retrySourceCleanup(ctx context.Context) error {
	ids, err := c.options.Store.PendingSourceCleanup(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !safeID(id) {
			err = errors.Join(err, errors.New("unsafe source cleanup job ID"))
			continue
		}
		err = errors.Join(err, c.removeSource(id))
	}
	return err
}

func cleanupAllowed(gate GateState) bool {
	if gate.Ready {
		return true
	}
	if len(gate.Blockers) == 0 {
		return false
	}
	for _, blocker := range gate.Blockers {
		switch blocker {
		case "disk_emergency", "disk_reservation_unavailable", "service_disk_budget_exceeded", "service_disk_reservation_unavailable":
		default:
			return false
		}
	}
	return true
}
