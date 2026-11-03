package maintenance

import "time"

// healthLifetime is how long one published observation stays valid. With a
// 10 s probe cadence it must outlast two consecutive inconclusive probes (seen
// on the Studio under build load: the third probe then starts at +30 s and
// finishes within its 8 s bound), and stay within the controller's 45 s
// acceptance window (internal/controller/guards.go).
const healthLifetime = 40 * time.Second
