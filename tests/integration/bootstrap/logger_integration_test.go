package bootstrap_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/amirhossein-jamali/auth-guardian/internal/bootstrap"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupLogger_Development(t *testing.T) {
	// Save current env and restore after test
	prevEnv := os.Getenv("ENV")
	defer func() {
		err := os.Setenv("ENV", prevEnv)
		if err != nil {
			t.Logf("Failed to restore ENV: %v", err)
		}
	}()

	// Ensure we're in development mode
	err := os.Setenv("ENV", "development")
	require.NoError(t, err, "Failed to set ENV")

	// Create a minimal config
	cfg := &config.Config{
		Logger: config.LoggerConfig{
			EnableAudit: true,
		},
	}

	// Initialize loggers
	appLogger, auditLogger := bootstrap.SetupLogger(cfg)

	// Verify loggers were created
	require.NotNil(t, appLogger, "Application logger should not be nil")
	require.NotNil(t, auditLogger, "Audit logger should not be nil when enabled")

	// Test application logger - we can only verify it doesn't panic
	t.Log("Testing development mode application logger")
	appLogger.Debug("debug message", map[string]any{"test": true})
	appLogger.Info("info message", map[string]any{"test": true})
	appLogger.Warn("warn message", map[string]any{"test": true})
	appLogger.Error("error message", map[string]any{"test": true})

	// Test audit logger - we can only verify it doesn't panic
	t.Log("Testing development mode audit logger")
	ctx := context.Background()
	err = auditLogger.LogSecurityEvent(ctx, "login", map[string]any{
		"userId": "test-user",
		"ip":     "127.0.0.1",
		"result": "success",
	})
	assert.NoError(t, err)
}

func TestSetupLogger_Production(t *testing.T) {
	// Save current env and restore after test
	prevEnv := os.Getenv("ENV")
	defer func() {
		err := os.Setenv("ENV", prevEnv)
		if err != nil {
			t.Logf("Failed to restore ENV: %v", err)
		}
	}()

	// Set production mode
	err := os.Setenv("ENV", "production")
	require.NoError(t, err, "Failed to set ENV")

	// Create a minimal config
	cfg := &config.Config{
		Logger: config.LoggerConfig{
			EnableAudit: true,
		},
	}

	// Initialize loggers
	appLogger, auditLogger := bootstrap.SetupLogger(cfg)

	// Verify loggers were created
	require.NotNil(t, appLogger, "Application logger should not be nil")
	require.NotNil(t, auditLogger, "Audit logger should not be nil when enabled")

	// Test application logger - we can only verify it doesn't panic
	t.Log("Testing production mode application logger")
	appLogger.Info("test info message", map[string]any{"test": true})

	// Test audit logger in production mode
	t.Log("Testing production mode audit logger")
	ctx := context.Background()
	err = auditLogger.LogSecurityEvent(ctx, "audit-action", map[string]any{
		"userId": "test-user",
		"source": "integration-test",
		"result": "success",
	})
	assert.NoError(t, err)

	// Test flush on the audit logger
	err = auditLogger.Flush()
	assert.NoError(t, err)
}

func TestSetupLogger_AuditDisabled(t *testing.T) {
	// Create a config with audit disabled
	cfg := &config.Config{
		Logger: config.LoggerConfig{
			EnableAudit: false,
		},
	}

	// Initialize loggers
	appLogger, auditLogger := bootstrap.SetupLogger(cfg)

	// Verify application logger was created but audit logger is nil
	require.NotNil(t, appLogger, "Application logger should not be nil")
	assert.Nil(t, auditLogger, "Audit logger should be nil when disabled")

	// Ensure the app logger still works
	t.Log("Testing app logger with audit disabled")
	appLogger.Debug("debug message", nil)
	// If we get here without panicking, the test passes
}

func TestFatalError(t *testing.T) {
	// Skip if we don't want to run this test
	if os.Getenv("SKIP_EXIT_TESTS") == "1" {
		t.Skip("Skipping test that calls os.Exit")
	}

	// Get the path to the current test binary
	testBinary, err := os.Executable()
	require.NoError(t, err, "Could not get path to test binary")

	// Run the test in a subprocess with the TEST_FATAL_ERROR flag
	// This allows us to test FatalError without terminating the main test process
	cmd := exec.Command(testBinary, "-test.run=TestFatalErrorSubprocess")
	cmd.Env = append(os.Environ(), "TEST_FATAL_ERROR=1", "GO_TEST_MODE=subprocess")

	// Capture stderr to verify the error message
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Run the subprocess
	err = cmd.Run()

	// The subprocess should exit with status 1
	var exitErr *exec.ExitError
	ok := errors.As(err, &exitErr)
	assert.True(t, ok, "Expected an exit error")
	assert.Equal(t, 1, exitErr.ExitCode(), "Expected exit code 1")

	// Verify the error message was logged
	stderrOutput := stderr.String()
	assert.True(t, strings.Contains(stderrOutput, "test fatal error") ||
		strings.Contains(stderrOutput, "assert.AnError"),
		"Expected error message not found in output: %s", stderrOutput)
}

// This function is run as a subprocess by TestFatalError
func TestFatalErrorSubprocess(t *testing.T) {
	if os.Getenv("GO_TEST_MODE") != "subprocess" || os.Getenv("TEST_FATAL_ERROR") != "1" {
		return
	}

	bootstrap.FatalError("test fatal error", assert.AnError)

	// We should never reach this point
	t.Fatal("FatalError did not exit the process")
}
