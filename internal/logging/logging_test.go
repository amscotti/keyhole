package logging_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/logging"
)

func TestNewBuildsJSONLoggerToFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "out.log")
	logger, err := logging.New(config.LoggingConfig{Level: "info", Format: "json", Output: logFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger.Info("hello", zap.String("key", "val"))
	if err := logger.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), `"key":"val"`) {
		t.Errorf("expected JSON field in output: %s", data)
	}
	if !strings.Contains(string(data), `"msg":"hello"`) {
		t.Errorf("expected msg field in output: %s", data)
	}
}

func TestNewBuildsConsoleLogger(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "out.log")
	logger, err := logging.New(config.LoggingConfig{Level: "debug", Format: "console", Output: logFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger.Info("hi")
	if err := logger.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "hi") {
		t.Errorf("expected message in console output: %s", data)
	}
}

func TestNewRejectsUnknownFormat(t *testing.T) {
	t.Parallel()
	if _, err := logging.New(config.LoggingConfig{Level: "info", Format: "xml", Output: "stdout"}); err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

func TestNewRejectsBadLevel(t *testing.T) {
	t.Parallel()
	if _, err := logging.New(config.LoggingConfig{Level: "verbose", Format: "json", Output: "stdout"}); err == nil {
		t.Fatal("expected error for bad level, got nil")
	}
}
