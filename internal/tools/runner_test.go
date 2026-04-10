package tools

import (
	"testing"
)

func TestRunNonexistentBinary(t *testing.T) {
	result, err := Run("/nonexistent/binary", []string{"--version"}, 5)
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
	// Result may or may not be nil depending on the error.
	_ = result
}

func TestRunTimeout(t *testing.T) {
	// Use a command that will take longer than the timeout.
	// On Windows, "ping -n 10 127.0.0.1" takes ~10 seconds.
	result, err := Run("ping", []string{"-n", "10", "127.0.0.1"}, 1)
	if err == nil {
		t.Error("expected timeout error")
	}
	if result != nil && !result.TimedOut {
		t.Error("expected TimedOut=true")
	}
}

func TestRunSuccessfulCommand(t *testing.T) {
	// Run a simple command that should succeed.
	result, err := Run("cmd", []string{"/c", "echo", "hello"}, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Stdout) == 0 {
		t.Error("expected stdout output")
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}
