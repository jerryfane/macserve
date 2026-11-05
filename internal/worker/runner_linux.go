//go:build linux

package worker

import "context"

func backgroundCommand(executable string, args []string) (string, []string) {
	wrapped := make([]string, 0, 3+len(args))
	wrapped = append(wrapped, "-n", "10", executable)
	wrapped = append(wrapped, args...)
	return "/usr/bin/nice", wrapped
}

// memoryProcesses charges RSS on Linux, which has no phys_footprint; this
// development platform reports every UID and observe selects the worker's.
func memoryProcesses(ctx context.Context, _ int) ([]processSample, error) {
	samples, err := sampleProcesses(ctx)
	for i := range samples {
		samples[i].footprintKiB = samples[i].rssKiB
	}
	return samples, err
}
