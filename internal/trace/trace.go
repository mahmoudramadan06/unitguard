package trace

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Run executes argv under strace -f and returns the parsed Observation of
// the whole process tree. The traced command is given up to duration to
// run; remaining time kills it, which is expected for daemons: the goal is
// to observe startup and early steady-state behavior, not to run to exit.
func Run(ctx context.Context, argv []string, duration time.Duration) (Observation, error) {
	if len(argv) == 0 {
		return Observation{}, fmt.Errorf("observe needs a command to trace")
	}
	if _, err := exec.LookPath("strace"); err != nil {
		return Observation{}, fmt.Errorf("strace not found: install strace to use observe")
	}
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	straceArgv := append([]string{
		"-f",                                 // follow children
		"-qq",                                // quieter attach/detach noise
		"-e", "trace=%file,%process,network", // file, process and network calls
		"--", argv[0],
	}, argv[1:]...)
	cmd := exec.CommandContext(ctx, "strace", straceArgv...)
	cmd.Stdout = nil // service output is not what we collect
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return Observation{}, err
	}
	if err := cmd.Start(); err != nil {
		return Observation{}, fmt.Errorf("starting strace: %w", err)
	}
	obs := Parse(stderr)
	waitErr := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		// Killed on the observation clock: expected for daemons.
		return obs, nil
	}
	if waitErr != nil {
		return obs, fmt.Errorf("traced command failed: %w", waitErr)
	}
	return obs, nil
}
