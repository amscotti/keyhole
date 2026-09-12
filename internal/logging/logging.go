// Package logging wires up structured logging for Keyhole.
//
// It builds a *zap.Logger from the [logging] config block — JSON (Datadog-
// friendly) for production, console for local dev. Request logging deliberately
// never logs header values at all, so there is no redaction helper to misuse:
// secrets arrive only via environment variables and stay out of the log.
package logging

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/amscotti/keyhole/internal/config"
)

// New builds a *zap.Logger from cfg. Format "json" (the default) is the
// production encoder; "console" is human-readable for local dev. Output "stdout"
// (the default) streams to os.Stdout; any other value is treated as a file path
// (created or appended).
func New(cfg config.LoggingConfig) (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		return nil, fmt.Errorf("logging: invalid level %q: %w", cfg.Level, err)
	}

	encoder, err := newEncoder(cfg.Format)
	if err != nil {
		return nil, err
	}
	writeSyncer, err := newWriteSyncer(cfg.Output)
	if err != nil {
		return nil, err
	}

	// The output handle (e.g. a log file) is owned for the process lifetime;
	// logger.Sync flushes buffered writes, the OS reclaims the handle at exit.
	core := zapcore.NewCore(encoder, zapcore.Lock(writeSyncer), level)
	return zap.New(core), nil
}

func newEncoder(format string) (zapcore.Encoder, error) {
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.MessageKey = "msg"

	switch strings.ToLower(format) {
	case "", "json":
		encCfg.EncodeLevel = zapcore.LowercaseLevelEncoder
		return zapcore.NewJSONEncoder(encCfg), nil
	case "console":
		encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
		return zapcore.NewConsoleEncoder(encCfg), nil
	default:
		return nil, fmt.Errorf("logging: unknown format %q (want json or console)", format)
	}
}

func newWriteSyncer(output string) (zapcore.WriteSyncer, error) {
	switch strings.ToLower(output) {
	case "", "stdout":
		return zapcore.AddSync(os.Stdout), nil
	case "stderr":
		return zapcore.AddSync(os.Stderr), nil
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("logging: open %s: %w", output, err)
		}
		return zapcore.AddSync(f), nil
	}
}
