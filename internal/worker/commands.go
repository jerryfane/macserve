package worker

import (
	"context"
	"io"
	"time"
)

// run is called only while Engine.mu is held. The command argv is immutable
// after construction; retain it rather than copying every invocation's slice.
func (e *Engine) run(ctx context.Context, command Command, stdout, stderr io.Writer) (ProcessResult, error) {
	var started time.Time
	if e.recording != nil {
		started = e.options.Now().UTC()
	}
	result, err := e.options.Runner.Run(ctx, command, stdout, stderr)
	if e.recording != nil {
		args := command.Args
		if args == nil {
			args = []string{}
		}
		e.recording.Commands = append(e.recording.Commands, ExecutedCommand{Executable: command.Executable, Args: args, StartedAt: started, FinishedAt: e.options.Now().UTC(), ExitCode: result.ExitCode, Signal: result.Signal})
		e.recording.PeakMemoryMiB = max(e.recording.PeakMemoryMiB, result.PeakMemoryMiB)
	}
	return result, err
}
