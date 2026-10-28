package policies

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is a time span as config data. A bare JSON number is seconds (3600,
// 172800); a string is a Go duration ("75h", "1h30m"), a day count ("2d") or an
// ISO-8601 duration ("P3D", "PT75H", "P3DT12H30M"). Whichever notation an
// operator writes, the printed document renders one canonical form, so a config
// that mixes notations still diffs cleanly.
//
// The zero Duration is "not set", not "zero seconds": a limit of 0 means the
// check is off.
type Duration struct {
	time.Duration
}

// ParseDuration accepts every notation the config does and rejects everything
// else at load time, so a typo in a policy file is a startup error, not a limit
// that silently did not apply.
func ParseDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, fmt.Errorf("empty duration")
	}

	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}

	// "2d": a day count, which Go's parser does not take
	if matches := daysRe.FindStringSubmatch(raw); matches != nil {
		days, err := strconv.Atoi(matches[1])
		if err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}

	if d, err := parseISODuration(raw); err == nil {
		return d, nil
	} else if strings.HasPrefix(raw, "P") {
		return 0, fmt.Errorf("%q is not an ISO-8601 duration (P3D, PT75H, P3DT12H)", raw)
	}

	return 0, fmt.Errorf("%q is not a duration (75h, 2d, P3D or seconds)", raw)
}

var daysRe = regexp.MustCompile(`^(\d+)\s*[dD]$`)

var isoDurationRe = regexp.MustCompile(`^P(\d+(?:\.\d+)?[Dd])?(T(?:(\d+(?:\.\d+)?)[Hh])?(?:(\d+(?:\.\d+)?)[Mm])?(?:(\d+(?:\.\d+)?)[Ss])?)?$`)

// parseISODuration reads the subset of ISO-8601 that has days and a time part:
// P3D, PT75H, PT30M, P3DT12H30M. Weeks (P1W) and months are not time spans a
// relay can act on, so they are refused.
func parseISODuration(raw string) (time.Duration, error) {
	m := isoDurationRe.FindStringSubmatch(strings.ToUpper(raw))
	if m == nil {
		return 0, fmt.Errorf("not an ISO-8601 duration")
	}

	var total time.Duration
	if m[1] != "" {
		days, err := strconv.ParseFloat(strings.TrimSuffix(strings.ToUpper(m[1]), "D"), 64)
		if err != nil {
			return 0, err
		}
		total += time.Duration(days * 24 * float64(time.Hour))
	}
	for _, part := range []struct {
		raw  string
		unit time.Duration
	}{
		{m[3], time.Hour},
		{m[4], time.Minute},
		{m[5], time.Second},
	} {
		if part.raw == "" {
			continue
		}
		value, err := strconv.ParseFloat(part.raw, 64)
		if err != nil {
			return 0, err
		}
		total += time.Duration(value * float64(part.unit))
	}

	if total == 0 {
		return 0, fmt.Errorf("ISO-8601 duration is zero")
	}
	return total, nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.canonical())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		d.Duration = 0
		return nil
	}

	// a bare number is seconds: max_age_of_event: 3600
	if raw[0] != '"' {
		seconds, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("%s is not a duration: a bare number is seconds, a string is \"75h\", \"2d\" or \"P3D\"", raw)
		}
		d.Duration = time.Duration(seconds * float64(time.Second))
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	parsed, err := ParseDuration(text)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// String renders the canonical form, which is what the relay prints and logs.
func (d Duration) String() string { return d.canonical() }

// canonical renders the duration the way the printed document shows it: whole
// days as "3d", whole hours as "75h", and so on down to seconds.
func (d Duration) canonical() string {
	switch {
	case d.Duration == 0:
		return "0s"
	case d.Duration%(24*time.Hour) == 0:
		return strconv.FormatInt(int64(d.Duration/(24*time.Hour)), 10) + "d"
	case d.Duration%time.Hour == 0:
		return strconv.FormatInt(int64(d.Duration/time.Hour), 10) + "h"
	case d.Duration%time.Minute == 0:
		return strconv.FormatInt(int64(d.Duration/time.Minute), 10) + "m"
	case d.Duration%time.Second == 0:
		return strconv.FormatInt(int64(d.Duration/time.Second), 10) + "s"
	default:
		return d.Duration.String()
	}
}

// Size is a byte count as config data: a bare JSON number is bytes (4096), a
// string is "4KB", "512B", "2MB" (1024-based, like every other byte count in
// this relay: "4KB" is 4096, not 4000). The zero Size means no limit.
type Size struct {
	Bytes int
}

var sizeRe = regexp.MustCompile(`^(?i)(\d+)\s*(b|kib|kb|mib|mb|gib|gb)$`)

func (s Size) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Bytes)
}

func (s *Size) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		s.Bytes = 0
		return nil
	}

	if raw[0] != '"' {
		bytes, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("%s is not a size: a bare number is bytes, a string is \"4KB\" or \"512B\"", raw)
		}
		s.Bytes = bytes
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	m := sizeRe.FindStringSubmatch(text)
	if m == nil {
		return fmt.Errorf("%q is not a size (4KB, 512B, 2MB or a byte count)", text)
	}

	value, err := strconv.Atoi(m[1])
	if err != nil {
		return err
	}
	switch strings.ToLower(m[2]) {
	case "b":
		s.Bytes = value
	case "kib", "kb":
		s.Bytes = value * 1024
	case "mib", "mb":
		s.Bytes = value * 1024 * 1024
	case "gib", "gb":
		s.Bytes = value * 1024 * 1024 * 1024
	}
	return nil
}
