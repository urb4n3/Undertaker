package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// RunResult holds the output of a subprocess execution.
type RunResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	TimedOut bool
}

// Run executes a command with args and a timeout. If timeoutSec <= 0, defaults to 120s.
// The command is killed if it exceeds the timeout.
func Run(binary string, args []string, timeoutSec int) (*RunResult, error) {
	if timeoutSec <= 0 {
		timeoutSec = 120
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &RunResult{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		return result, fmt.Errorf("command timed out after %ds", timeoutSec)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			// Non-zero exit is not necessarily fatal — caller decides.
			return result, nil
		}
		return result, fmt.Errorf("executing %s: %w", binary, err)
	}

	return result, nil
}
