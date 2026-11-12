package bkind

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// logPrefix marks every record this package writes. It stays inside the message
// rather than in an attribute of its own, because that is where it was before the
// logger became configurable and because a mixed journal (relay, reverse proxy,
// database) is easier to read when the source is the first thing on the line.
const logPrefix = "[bkind] "

// The log formats NewLogger accepts. They name the slog handler the records go
// through, not a file extension: both write to the writer they are given.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// ParseLevel turns a level name into the slog level of the same rank. Names are
// matched case-insensitively, "warning" is accepted as a synonym of "warn", and
// the empty string reads as "info" so an unset variable needs no default here.
// There is no numeric form: the four names below are the whole vocabulary, so a
// typo fails at startup instead of quietly selecting a level.
func ParseLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q: want debug, info, warn or error", raw)
	}
}

// ParseFormat normalizes a format name. As with ParseLevel, the empty string is
// the default, so a missing setting and an explicit one behave the same.
func ParseFormat(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", LogFormatText:
		return LogFormatText, nil
	case LogFormatJSON:
		return LogFormatJSON, nil
	default:
		return "", fmt.Errorf("unknown format %q: want text or json", raw)
	}
}

// NewLogger builds a logger at the given level and format, writing to w. A level
// below the configured one costs an Enabled check and nothing else, which is what
// makes it safe to leave debug records in the request path.
//
// The writer is the caller's business: this process only ever writes to stderr and
// lets journald or the container runtime own rotation, but an embedder can hand in
// a file or an in-memory buffer.
func NewLogger(w io.Writer, level slog.Level, format string) (*slog.Logger, error) {
	normalized, err := ParseFormat(format)
	if err != nil {
		return nil, err
	}
	if w == nil {
		w = os.Stderr
	}
	return slog.New(newHandler(w, level, normalized)), nil
}

// DefaultLogger is what NewRelay installs and what a caller falls back to when it
// has not resolved a configuration yet: text on stderr, level info. It is
// deliberately not slog.Default(), so one embedder calling slog.SetDefault cannot
// silently redirect or silence another's relay.
func DefaultLogger() *slog.Logger {
	return slog.New(newHandler(os.Stderr, slog.LevelInfo, LogFormatText))
}

func newHandler(w io.Writer, level slog.Level, format string) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: prefixRecord,
	}
	if format == LogFormatJSON {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// prefixRecord puts logPrefix in front of the message and leaves every other
// attribute alone. groups is empty only for records at the top level, which is
// where "msg" lives: an attribute that happens to be named "msg" inside a group is
// not a message and must not be rewritten.
func prefixRecord(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.MessageKey {
		a.Value = slog.StringValue(logPrefix + a.Value.String())
	}
	return a
}

// log is never nil. NewRelay installs a logger, but a Relay assembled by hand — a
// zero value, or a literal in someone's tests — would otherwise panic on the first
// websocket error instead of reporting it.
func (rl *Relay) log() *slog.Logger {
	if rl.Logger != nil {
		return rl.Logger
	}
	return slog.Default()
}
