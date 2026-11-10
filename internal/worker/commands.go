package worker

import (
	"context"
	"io"
	"time"
)

// run executes command and records it in its job's result while that job
// runs (see Engine.recorder). The command argv is immutable after
// construction; retain it rather than copying every invocation's slice.
func (e *Engine) run(ctx context.Context, command Command, stdout, stderr io.Writer) (ProcessResult, error) {
	recording := e.recorder(command.JobID)
	var started time.Time
	if recording != nil {
		started = e.options.Now().UTC()
	}
	result, err := e.options.Runner.Run(ctx, command, stdout, stderr)
	if recording != nil {
		args := command.Args
		if args == nil {
			args = []string{}
		}
		recording.Commands = append(recording.Commands, ExecutedCommand{Executable: command.Executable, Args: args, StartedAt: started, FinishedAt: e.options.Now().UTC(), ExitCode: result.ExitCode, Signal: result.Signal})
		recording.PeakMemoryMiB = max(recording.PeakMemoryMiB, result.PeakMemoryMiB)
		recording.HostPeakMemoryMiB = max(recording.HostPeakMemoryMiB, result.HostPeakMemoryMiB)
	}
	return result, err
}
