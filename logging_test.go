package bkind

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {
	// the empty string is the unset variable, and "warning" is the spelling people
	// reach for; everything else is exactly the four names
	ok := map[string]slog.Level{
		"":        slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		" info ":  slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"Warn":    slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for raw, want := range ok {
		got, err := ParseLevel(raw)
		require.NoError(t, err, "level %q", raw)
		require.Equal(t, want, got, "level %q", raw)
	}

	for _, raw := range []string{"verbose", "trace", "fatal", "5", "infoo"} {
		_, err := ParseLevel(raw)
		require.Error(t, err, "level %q must not resolve", raw)
		require.Contains(t, err.Error(), "debug, info, warn or error")
	}
}

func TestParseFormat(t *testing.T) {
	ok := map[string]string{
		"":       LogFormatText,
		"text":   LogFormatText,
		"TEXT":   LogFormatText,
		" json ": LogFormatJSON,
	}
	for raw, want := range ok {
		got, err := ParseFormat(raw)
		require.NoError(t, err, "format %q", raw)
		require.Equal(t, want, got, "format %q", raw)
	}

	for _, raw := range []string{"logfmt", "console", "yaml"} {
		_, err := ParseFormat(raw)
		require.Error(t, err, "format %q must not resolve", raw)
		require.Contains(t, err.Error(), "text or json")
	}
}

func TestNewLoggerFiltersByLevel(t *testing.T) {
	var buf bytes.Buffer

	logger, err := NewLogger(&buf, slog.LevelWarn, LogFormatText)
	require.NoError(t, err)

	logger.Debug("debug line")
	logger.Info("info line")
	logger.Warn("warn line")
	logger.Error("error line")

	out := buf.String()
	// the two below the threshold are not "quietly written": the handler never sees
	// them, which is the whole point of a level
	require.NotContains(t, out, "debug line")
	require.NotContains(t, out, "info line")

	require.Contains(t, out, "level=WARN")
	require.Contains(t, out, `msg="[bkind] warn line"`)
	require.Contains(t, out, "level=ERROR")
	require.Contains(t, out, `msg="[bkind] error line"`)

	// one record per line, in the order they were logged
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "warn line")
	require.Contains(t, lines[1], "error line")
}

func TestNewLoggerJSON(t *testing.T) {
	var buf bytes.Buffer

	logger, err := NewLogger(&buf, slog.LevelDebug, LogFormatJSON)
	require.NoError(t, err)

	// attributes have to survive the format change: that is what a log shipper reads
	logger.Debug("upgraded", "client", "203.0.113.7", "n", 2)

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record), "output must be one JSON object per line")

	require.Equal(t, "DEBUG", record["level"])
	require.Equal(t, "[bkind] upgraded", record["msg"])
	require.Equal(t, "203.0.113.7", record["client"])
	require.EqualValues(t, 2, record["n"])
	require.Contains(t, record, "time")
}

func TestNewLoggerRejectsUnknownFormat(t *testing.T) {
	// a format typo is a startup error, not a silent fall back to text
	_, err := NewLogger(&bytes.Buffer{}, slog.LevelInfo, "logfmt")
	require.Error(t, err)
}

func TestNewLoggerNilWriterGoesToStderr(t *testing.T) {
	// nothing to assert about the destination without touching os.Stderr; what
	// matters is that a nil writer is not a panic
	logger, err := NewLogger(nil, slog.LevelInfo, LogFormatText)
	require.NoError(t, err)
	require.NotNil(t, logger)
}

func TestDefaultLoggerIsInstalled(t *testing.T) {
	// NewRelay's default has to be a real logger, and it must not be slog.Default():
	// an embedder calling slog.SetDefault would otherwise redirect the relay's lines
	require.NotNil(t, DefaultLogger())
	require.NotNil(t, NewRelay().Logger)
}

func TestZeroRelayLogDoesNotPanic(t *testing.T) {
	// a Relay built by hand rather than by NewRelay has no logger; the accessor is
	// what keeps the websocket error paths from panicking
	var rl Relay
	require.NotNil(t, rl.log())

	rl.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	require.Same(t, rl.Logger, rl.log())
}
