//go:build !darwin

package maintenance

// leaveBackgroundScheduling has no meaning off Darwin; Run refuses there anyway.
func leaveBackgroundScheduling() error { return nil }
