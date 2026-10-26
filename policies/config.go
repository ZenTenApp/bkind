package policies

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ZenTenApp/bkind"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
)

// Config is the whole policy set of a relay as data. Every limit, kind and rate
// limit that used to be a literal in a wiring file lives here, so the same binary
// can serve a Kind-4 DM relay, a NIP-17 gift-wrap relay or a single-kind relay
// without a code change.
//
// Load it with LoadConfig, which layers the defaults, a JSON file (BKIND_CONFIG),
// inline JSON (BKIND_CONFIG_JSON) and BKIND_* environment overrides, in that order.
// The zero value is not usable; DefaultConfig is.
type Config struct {
	Kinds      KindRules       `json:"kinds"`
	Expiration ExpirationRules `json:"expiration"`
	Tags       TagRules        `json:"tags"`
	Content    ContentRules    `json:"content"`
	Auth       AuthRules       `json:"auth"`
	Count      CountRules      `json:"count"`
	Validation ValidationRules `json:"validation"`
	Filters    FilterRules     `json:"filters"`
	RateLimits []RateLimit     `json:"rate_limits"`
	NIP11      NIP11Rules      `json:"nip11"`
	Negentropy bool            `json:"negentropy"`
}

// ExpirationRules is NIP-40: whether an "expiration" tag is mandatory and how far
// in the future it may point.
type ExpirationRules struct {
	Required bool   `json:"required"`
	Max      string `json:"max"`

	max time.Duration
}

// MaxDuration returns the parsed Max, which Validate fills in.
func (e ExpirationRules) MaxDuration() time.Duration { return e.max }

// TagRules is the shape of the tag list and the tags an event must carry.
type TagRules struct {
	// Required names the tags an event must carry exactly once, with a non-empty
	// value. An empty list means no mandatory tags.
	Required []string `json:"required"`
	// Max is the maximum number of tags on an event.
	Max int `json:"max"`
	// MaxNameLen and MaxValueLen bound every tag name and every tag value.
	MaxNameLen  int `json:"max_name_len"`
	MaxValueLen int `json:"max_value_len"`
}

// ContentRules is the payload limit, in bytes of event content.
type ContentRules struct {
	Max int `json:"max"`
}

// AuthRules is NIP-42. When Required is set, both writes and reads must be
// authenticated and the write author must equal the authenticated key.
type AuthRules struct {
	Required bool `json:"required"`
}

// CountRules is NIP-45. Reject keeps COUNT refused, which is the only safe answer
// for private events; setting it to false serves COUNT and advertises NIP-45.
type CountRules struct {
	Reject bool `json:"reject"`
}

// ValidationRules selects the per-kind structural validators. ShapeKinds is
// intersected with kinds.allowed, so a kind the relay does not serve is simply not
// validated; naming a kind that has no registered validator is an error.
type ValidationRules struct {
	ShapeKinds []uint16 `json:"shape_kinds"`
}

// FilterRules are the request-shape policies.
type FilterRules struct {
	RejectEmpty  bool `json:"reject_empty"`
	RejectSearch bool `json:"reject_search"`
}

// RateLimit is one token bucket. Scope is event, filter or connection; Key is ip,
// authed or pubkey. Connection limits only support the ip key.
type RateLimit struct {
	Scope    string `json:"scope"`
	Key      string `json:"key"`
	Tokens   int    `json:"tokens"`
	Interval string `json:"interval"`
	Max      int    `json:"max"`

	interval time.Duration
}

func (r RateLimit) String() string {
	return fmt.Sprintf("%s/%s %d per %s (burst %d)", r.Scope, r.Key, r.Tokens, r.Interval, r.Max)
}

// intervalDuration returns the parsed interval, which Validate fills in.
func (r RateLimit) intervalDuration() time.Duration { return r.interval }

// NIP11Rules is the relay information document. SupportedNIPs and the limitation
// document are derived from the rest of the Config, so advertising a feature the
// relay does not have takes a deliberate ExtraNIPs entry.
type NIP11Rules struct {
	Name string `json:"name"`
	// Description defaults to a sentence generated from the kind list.
	Description      string `json:"description"`
	MaxMessageLength int    `json:"max_message_length"`
	MaxSubscriptions int    `json:"max_subscriptions"`
	MaxFilters       int    `json:"max_filters"`
	MaxLimit         int    `json:"max_limit"`
	// ExtraNIPs is appended to the derived supported_nips list.
	ExtraNIPs []int `json:"extra_nips"`
}

// DefaultConfig is the policy set of the reference relay in examples/bkind: NIP-04
// direct messages plus the two utility kinds needed to operate them, authenticated,
// expiring, size-limited, and rate-limited per npub and per ip.
//
// The rate limits are opinionated; a test that does not want them should set
// cfg.RateLimits = nil before wiring.
func DefaultConfig() Config {
	return Config{
		Kinds: KindRules{
			Allowed:               []uint16{4, 5, 62},
			RecipientVisible:      []uint16{4},
			AuthorOnly:            []uint16{5, 62},
			AllowEphemeral:        false,
			RejectUnservedFilters: true,
		},
		Expiration: ExpirationRules{Required: true, Max: "75h"},
		Tags: TagRules{
			Required:    []string{"client"},
			Max:         16,
			MaxNameLen:  64,
			MaxValueLen: 256,
		},
		Content:    ContentRules{Max: 4096},
		Auth:       AuthRules{Required: true},
		Count:      CountRules{Reject: true},
		Validation: ValidationRules{ShapeKinds: []uint16{4, 5, 62}},
		Filters:    FilterRules{RejectEmpty: true, RejectSearch: true},
		RateLimits: []RateLimit{
			{Scope: "event", Key: "authed", Tokens: 30, Interval: "1h", Max: 60},
			{Scope: "event", Key: "authed", Tokens: 200, Interval: "24h", Max: 400},
			{Scope: "event", Key: "ip", Tokens: 60, Interval: "1h", Max: 120},
			{Scope: "event", Key: "ip", Tokens: 400, Interval: "24h", Max: 800},
			{Scope: "filter", Key: "authed", Tokens: 60, Interval: "1h", Max: 120},
			{Scope: "filter", Key: "authed", Tokens: 400, Interval: "24h", Max: 800},
			{Scope: "filter", Key: "ip", Tokens: 120, Interval: "1h", Max: 240},
			{Scope: "filter", Key: "ip", Tokens: 800, Interval: "24h", Max: 1600},
			{Scope: "connection", Key: "ip", Tokens: 120, Interval: "1h", Max: 240},
		},
		NIP11: NIP11Rules{
			Name:             "B Kind",
			MaxMessageLength: 12 * 1024,
			MaxSubscriptions: 10,
			MaxFilters:       4,
			MaxLimit:         500,
		},
		Negentropy: false,
	}
}

// LoadConfig builds the configuration for a relay: defaults, then the JSON file
// named by BKIND_CONFIG, then the inline JSON in BKIND_CONFIG_JSON, then the scalar
// BKIND_* overrides, then Validate.
//
// lookup is os.LookupEnv in production and a map in tests.
func LoadConfig(lookup func(string) (string, bool)) (Config, error) {
	cfg := DefaultConfig()

	strict, err := envBool(lookup, "BKIND_CONFIG_STRICT", false)
	if err != nil {
		return cfg, err
	}

	if path, ok := lookup("BKIND_CONFIG"); ok && path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("BKIND_CONFIG: %w", err)
		}
		if cfg, err = cfg.withJSON(data, strict); err != nil {
			return cfg, fmt.Errorf("BKIND_CONFIG (%s): %w", path, err)
		}
	}

	if inline, ok := lookup("BKIND_CONFIG_JSON"); ok && strings.TrimSpace(inline) != "" {
		merged, err := cfg.withJSON([]byte(inline), strict)
		if err != nil {
			return cfg, fmt.Errorf("BKIND_CONFIG_JSON: %w", err)
		}
		cfg = merged
	}

	if err := cfg.ApplyEnv(lookup); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// WithJSON merges a JSON document onto the receiver. Fields absent from the
// document keep their current value, so a file only has to name what it changes.
// A rate_limits array replaces the whole list, because a half-merged list of token
// buckets would be a trap. When the document replaces kinds.allowed, the visibility
// classes and shape validators of the kinds it dropped are pruned with it, exactly
// as BKIND_KINDS does.
//
// Use WithStrictJSON when the document must stand on its own.
func (c Config) WithJSON(data []byte) (Config, error) {
	return c.withJSON(data, false)
}

// WithStrictJSON is WithJSON for an explicit configuration: every field must be
// present in the document, so what the relay does is what the file says rather than
// what the file did not mention. It is what BKIND_CONFIG_STRICT turns on, and it is
// the right mode for a config kept in version control.
//
// The document still starts from the receiver, so c.WithStrictJSON is normally called
// on the zero Config (or on DefaultConfig, which is the same once every field is
// present). Completeness is checked against the JSON, not against the receiver: a
// field that is present but null or zero is still a mistake, and Validate says so.
func (c Config) WithStrictJSON(data []byte) (Config, error) {
	return c.withJSON(data, true)
}

// JSON renders the configuration as the canonical document WithStrictJSON accepts:
// every field spelled out, in a stable order, so it can be diffed, reviewed and fed
// back. This is what the relay prints for -print-config.
func (c Config) JSON() ([]byte, error) {
	out := c
	// a nil slice and an empty one mean the same thing; print the empty one so the
	// document reads as "none" instead of "null"
	out.Kinds.Allowed = nonNil(c.Kinds.Allowed)
	out.Kinds.RecipientVisible = nonNil(c.Kinds.RecipientVisible)
	out.Kinds.AuthorOnly = nonNil(c.Kinds.AuthorOnly)
	out.Tags.Required = nonNil(c.Tags.Required)
	out.Validation.ShapeKinds = nonNil(c.Validation.ShapeKinds)
	out.NIP11.ExtraNIPs = nonNil(c.NIP11.ExtraNIPs)
	out.RateLimits = nonNil(c.RateLimits)

	indented, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return collapseScalarContainers(indented), nil
}

func nonNil[E any](s []E) []E {
	if s == nil {
		return []E{}
	}
	return s
}

var (
	// an array whose every line is a bare scalar: [4, 5, 62], ["client"]
	scalarArray = regexp.MustCompile(`\[\n(?:\s+[^\[\]{}\n]*\n)+\s*\]`)
	// an object whose every line is "key": scalar — one rate limit
	scalarObject = regexp.MustCompile(`\{\n(?:\s+"[^"\n]*": [^\[\]{}\n]*\n)+\s*\}`)
)

// collapseScalarContainers rewrites the parts of an indented document that read better
// on one line — a list of kinds, a single token bucket — so the printed config looks
// like the config a person writes. It runs on the encoder's own output, and both
// patterns only match containers opened at the end of a line and closed on their own
// line, which a JSON string cannot imitate (a string cannot contain a raw newline), so
// no value can be mistaken for structure.
func collapseScalarContainers(document []byte) []byte {
	document = scalarArray.ReplaceAllFunc(document, func(match []byte) []byte {
		return joinLines(match, "[", "]", ", ")
	})
	document = scalarObject.ReplaceAllFunc(document, func(match []byte) []byte {
		return joinLines(match, "{", "}", ", ")
	})
	return document
}

// joinLines folds an indented container into "open first, second close", keeping the
// order and the scalars exactly as the encoder wrote them.
func joinLines(match []byte, open, close, sep string) []byte {
	inner := strings.TrimSuffix(strings.TrimPrefix(string(match), open+"\n"), "\n"+strings.Repeat(" ", 0))
	// drop the closing bracket's own indentation, which is the last line
	if index := strings.LastIndex(inner, "\n"); index >= 0 {
		inner = inner[:index]
	}

	parts := make([]string, 0, 4)
	for _, line := range strings.Split(inner, "\n") {
		// the encoder terminates every line but the last with a comma; the join puts
		// the separators back
		parts = append(parts, strings.TrimSuffix(strings.TrimSpace(line), ","))
	}

	out := open + strings.Join(parts, sep)
	return []byte(out + close)
}

func (c Config) withJSON(data []byte, strict bool) (Config, error) {
	if strict {
		if err := checkComplete(data); err != nil {
			return c, err
		}
	}

	// a lenient first pass, only to learn whether kinds.allowed was given
	var patch struct {
		Kinds struct {
			Allowed *[]uint16 `json:"allowed"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(data, &patch); err == nil && patch.Kinds.Allowed != nil {
		c.SetKinds(*patch.Kinds.Allowed)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid JSON: %w", err)
	}
	return c, nil
}

// ApplyEnv overrides the scalar settings from the environment. Structured values
// (the kind sets, the rate limits) are reachable through BKIND_CONFIG_JSON; the
// variables here are the ones worth setting on a command line.
func (c *Config) ApplyEnv(lookup func(string) (string, bool)) error {
	if raw, ok := lookup("BKIND_KINDS"); ok && strings.TrimSpace(raw) != "" {
		kinds, err := parseKinds("BKIND_KINDS", raw)
		if err != nil {
			return err
		}
		c.SetKinds(kinds)
	}
	if raw, ok := lookup("BKIND_RECIPIENT_VISIBLE_KINDS"); ok && strings.TrimSpace(raw) != "" {
		kinds, err := parseKinds("BKIND_RECIPIENT_VISIBLE_KINDS", raw)
		if err != nil {
			return err
		}
		c.Kinds.RecipientVisible = kinds
	}
	if raw, ok := lookup("BKIND_AUTHOR_ONLY_KINDS"); ok && strings.TrimSpace(raw) != "" {
		kinds, err := parseKinds("BKIND_AUTHOR_ONLY_KINDS", raw)
		if err != nil {
			return err
		}
		c.Kinds.AuthorOnly = kinds
	}
	if raw, ok := lookup("BKIND_SHAPE_KINDS"); ok && strings.TrimSpace(raw) != "" {
		kinds, err := parseKinds("BKIND_SHAPE_KINDS", raw)
		if err != nil {
			return err
		}
		c.Validation.ShapeKinds = kinds
	}

	var err error
	if c.Kinds.AllowEphemeral, err = envBool(lookup, "BKIND_ALLOW_EPHEMERAL", c.Kinds.AllowEphemeral); err != nil {
		return err
	}
	if c.Kinds.RejectUnservedFilters, err = envBool(lookup, "BKIND_REJECT_UNSERVED_FILTERS", c.Kinds.RejectUnservedFilters); err != nil {
		return err
	}
	if c.Expiration.Required, err = envBool(lookup, "BKIND_REQUIRE_EXPIRATION", c.Expiration.Required); err != nil {
		return err
	}
	if c.Auth.Required, err = envBool(lookup, "BKIND_REQUIRE_AUTH", c.Auth.Required); err != nil {
		return err
	}
	if c.Count.Reject, err = envBool(lookup, "BKIND_REJECT_COUNT", c.Count.Reject); err != nil {
		return err
	}
	if c.Negentropy, err = envBool(lookup, "BKIND_NEGENTROPY", c.Negentropy); err != nil {
		return err
	}
	if c.Filters.RejectEmpty, err = envBool(lookup, "BKIND_REJECT_EMPTY_FILTERS", c.Filters.RejectEmpty); err != nil {
		return err
	}
	if c.Filters.RejectSearch, err = envBool(lookup, "BKIND_REJECT_SEARCH", c.Filters.RejectSearch); err != nil {
		return err
	}

	if raw, ok := lookup("BKIND_MAX_EXPIRATION"); ok && raw != "" {
		c.Expiration.Max = raw
	}
	if raw, ok := lookup("BKIND_REQUIRED_TAGS"); ok {
		c.Tags.Required = splitList(raw)
	}
	if c.Tags.Max, err = envInt(lookup, "BKIND_MAX_TAGS", c.Tags.Max); err != nil {
		return err
	}
	if c.Tags.MaxNameLen, err = envInt(lookup, "BKIND_MAX_TAG_NAME", c.Tags.MaxNameLen); err != nil {
		return err
	}
	if c.Tags.MaxValueLen, err = envInt(lookup, "BKIND_MAX_TAG_VALUE", c.Tags.MaxValueLen); err != nil {
		return err
	}
	if c.Content.Max, err = envInt(lookup, "BKIND_MAX_CONTENT", c.Content.Max); err != nil {
		return err
	}
	if c.NIP11.MaxMessageLength, err = envInt(lookup, "BKIND_MAX_MESSAGE_LENGTH", c.NIP11.MaxMessageLength); err != nil {
		return err
	}
	if c.NIP11.MaxSubscriptions, err = envInt(lookup, "BKIND_MAX_SUBSCRIPTIONS", c.NIP11.MaxSubscriptions); err != nil {
		return err
	}
	if c.NIP11.MaxFilters, err = envInt(lookup, "BKIND_MAX_FILTERS", c.NIP11.MaxFilters); err != nil {
		return err
	}
	if c.NIP11.MaxLimit, err = envInt(lookup, "BKIND_MAX_LIMIT", c.NIP11.MaxLimit); err != nil {
		return err
	}

	if raw, ok := lookup("BKIND_NAME"); ok {
		c.NIP11.Name = raw
	}
	if raw, ok := lookup("BKIND_DESCRIPTION"); ok {
		c.NIP11.Description = raw
	}

	return nil
}

// SetKinds replaces the allowlist and drops the visibility classes and shape
// validators of kinds that are no longer served, so narrowing the allowlist cannot
// leave a stale class behind. The environment and the command line both go through
// it.
func (c *Config) SetKinds(kinds []uint16) {
	c.Kinds.Allowed = kinds
	c.Kinds.RecipientVisible = intersectKinds(c.Kinds.RecipientVisible, kinds)
	c.Kinds.AuthorOnly = intersectKinds(c.Kinds.AuthorOnly, kinds)
	c.Validation.ShapeKinds = intersectKinds(c.Validation.ShapeKinds, kinds)
}

// Validate checks the configuration and fills in the parsed durations. It is run by
// LoadConfig and again by Wire, so a Config built in code cannot skip it.
func (c *Config) Validate() error {
	// nil and empty are the same setting; normalizing keeps a config parsed from
	// JSON comparable to one built in code
	if len(c.Kinds.RecipientVisible) == 0 {
		c.Kinds.RecipientVisible = nil
	}
	if len(c.Kinds.AuthorOnly) == 0 {
		c.Kinds.AuthorOnly = nil
	}
	if len(c.Tags.Required) == 0 {
		c.Tags.Required = nil
	}
	if len(c.Validation.ShapeKinds) == 0 {
		c.Validation.ShapeKinds = nil
	}
	if len(c.RateLimits) == 0 {
		c.RateLimits = nil
	}
	if len(c.NIP11.ExtraNIPs) == 0 {
		c.NIP11.ExtraNIPs = nil
	}

	if err := c.Kinds.Validate(); err != nil {
		return err
	}

	if c.Expiration.Required || c.Expiration.Max != "" {
		if c.Expiration.Max == "" {
			return fmt.Errorf("expiration.max is empty")
		}
		max, err := time.ParseDuration(c.Expiration.Max)
		if err != nil || max <= 0 {
			return fmt.Errorf("expiration.max %q is not a positive duration", c.Expiration.Max)
		}
		c.Expiration.max = max
	}

	seenTags := map[string]bool{}
	for _, name := range c.Tags.Required {
		if name == "" {
			return fmt.Errorf("tags.required contains an empty tag name")
		}
		if seenTags[name] {
			return fmt.Errorf("tags.required names %q twice", name)
		}
		seenTags[name] = true
	}
	if c.Tags.Max <= 0 {
		return fmt.Errorf("tags.max must be positive")
	}
	if c.Tags.MaxNameLen <= 0 || c.Tags.MaxValueLen <= 0 {
		return fmt.Errorf("tags.max_name_len and tags.max_value_len must be positive")
	}
	if c.Content.Max <= 0 {
		return fmt.Errorf("content.max must be positive")
	}

	for _, kind := range c.Validation.ShapeKinds {
		if !c.Kinds.Has(kind) {
			return fmt.Errorf("validation.shape_kinds contains kind %d, which is not in kinds.allowed", kind)
		}
		if ShapeValidator(kind) == nil {
			return fmt.Errorf("validation.shape_kinds contains kind %d, which has no registered shape validator", kind)
		}
	}

	for i := range c.RateLimits {
		rl := &c.RateLimits[i]
		switch rl.Scope {
		case "event", "filter", "connection":
		default:
			return fmt.Errorf("rate_limits[%d]: scope %q must be event, filter or connection", i, rl.Scope)
		}
		switch rl.Key {
		case "ip", "authed", "pubkey":
		default:
			return fmt.Errorf("rate_limits[%d]: key %q must be ip, authed or pubkey", i, rl.Key)
		}
		if rl.Scope == "connection" && rl.Key != "ip" {
			return fmt.Errorf("rate_limits[%d]: connection limits only support the ip key", i)
		}
		if rl.Tokens <= 0 || rl.Max <= 0 {
			return fmt.Errorf("rate_limits[%d]: tokens and max must be positive", i)
		}
		interval, err := time.ParseDuration(rl.Interval)
		if err != nil || interval <= 0 {
			return fmt.Errorf("rate_limits[%d]: interval %q is not a positive duration", i, rl.Interval)
		}
		rl.interval = interval
	}

	if c.NIP11.MaxMessageLength <= 0 || c.NIP11.MaxSubscriptions <= 0 ||
		c.NIP11.MaxFilters <= 0 || c.NIP11.MaxLimit <= 0 {
		return fmt.Errorf("nip11 limits must be positive")
	}
	for _, nip := range c.NIP11.ExtraNIPs {
		if nip <= 0 {
			return fmt.Errorf("nip11.extra_nips contains %d, which is not a NIP number", nip)
		}
	}

	return nil
}

// Wire installs the whole policy set on a relay. Every gate that decides which
// kinds are served is derived from the same Config, so the write policy, the filter
// overwrite, the read policy, COUNT, live delivery and NIP-11 cannot disagree.
//
// It does not touch the store, the expiration sweeper or ServiceURL: those stay
// explicit in the wiring file.
func (c Config) Wire(relay *bkind.Relay) error {
	if err := c.Validate(); err != nil {
		return err
	}

	relay.Negentropy = c.Negentropy

	// ---------------------------------------------------------------- writes
	writePolicies := []func(context.Context, *nostr.Event) (bool, string){
		c.Kinds.RestrictKind(),
	}
	if c.Auth.Required {
		writePolicies = append(writePolicies, RequireAuthedAuthor)
	}
	if c.Expiration.Required {
		writePolicies = append(writePolicies, RequireExpiration(c.Expiration.MaxDuration()))
	}
	for _, name := range c.Tags.Required {
		writePolicies = append(writePolicies, RequireTag(name))
	}
	// the size limits come before the per-kind shape rules: an oversized event
	// should hear about its size, not about a tag it never got to write
	writePolicies = append(writePolicies,
		MaxContentLen(c.Content.Max),
		TagShapeLimits(c.Tags.Max, c.Tags.MaxNameLen, c.Tags.MaxValueLen),
	)
	for _, kind := range c.Validation.ShapeKinds {
		writePolicies = append(writePolicies, ShapeValidator(kind))
	}

	for _, rl := range c.RateLimits {
		if rl.Scope != "event" {
			continue
		}
		switch rl.Key {
		case "ip":
			writePolicies = append(writePolicies, EventIPRateLimiter(rl.Tokens, rl.intervalDuration(), rl.Max))
		case "authed":
			writePolicies = append(writePolicies, EventAuthedPubKeyRateLimiter(rl.Tokens, rl.intervalDuration(), rl.Max))
		case "pubkey":
			writePolicies = append(writePolicies, EventPubKeyRateLimiter(rl.Tokens, rl.intervalDuration(), rl.Max))
		}
	}
	relay.RejectEvent = append(relay.RejectEvent, writePolicies...)

	// ----------------------------------------------------------------- reads
	relay.OverwriteFilter = append(relay.OverwriteFilter, c.Kinds.OverwriteFilters())

	readPolicies := make([]func(context.Context, nostr.Filter) (bool, string), 0, len(c.RateLimits)+4)
	if c.Auth.Required {
		readPolicies = append(readPolicies, MustAuth)
	}
	readPolicies = append(readPolicies, c.Kinds.ReadFilter)
	if c.Filters.RejectEmpty {
		readPolicies = append(readPolicies, NoEmptyFilters)
	}
	if c.Filters.RejectSearch {
		readPolicies = append(readPolicies, NoSearchQueries)
	}
	for _, rl := range c.RateLimits {
		if rl.Scope != "filter" {
			continue
		}
		switch rl.Key {
		case "ip":
			readPolicies = append(readPolicies, FilterIPRateLimiter(rl.Tokens, rl.intervalDuration(), rl.Max))
		case "authed":
			readPolicies = append(readPolicies, FilterAuthedPubKeyRateLimiter(rl.Tokens, rl.intervalDuration(), rl.Max))
		}
	}
	relay.RejectFilter = append(relay.RejectFilter, readPolicies...)

	if c.Count.Reject {
		countPolicies := make([]func(context.Context, nostr.Filter) (bool, string), 0, 2)
		if c.Auth.Required {
			countPolicies = append(countPolicies, MustAuth)
		}
		countPolicies = append(countPolicies, c.Kinds.RejectCount)
		relay.RejectCountFilter = append(relay.RejectCountFilter, countPolicies...)
	}

	// live delivery does not re-run the filter policies
	relay.PreventBroadcast = append(relay.PreventBroadcast, c.Kinds.PreventBroadcast)

	var rejectConnection []func(*http.Request) bool
	for _, rl := range c.RateLimits {
		if rl.Scope == "connection" {
			rejectConnection = append(rejectConnection, ConnectionRateLimiter(rl.Tokens, rl.intervalDuration(), rl.Max))
		}
	}
	relay.RejectConnection = append(relay.RejectConnection, rejectConnection...)

	// --------------------------------------------------------------- NIP-11
	return c.applyNIP11(relay)
}

// applyNIP11 derives the information document from the configuration.
func (c Config) applyNIP11(relay *bkind.Relay) error {
	relay.Info.Name = c.NIP11.Name
	relay.Info.Description = c.NIP11.Description
	if relay.Info.Description == "" {
		relay.Info.Description = c.Kinds.defaultDescription()
	}

	nips := map[int]bool{11: true}
	for _, kind := range c.Kinds.Sorted() {
		switch kind {
		case 4:
			nips[4] = true // encrypted direct messages
		case 5:
			nips[9] = true // event deletion
		case 62:
			nips[62] = true // request to vanish
		}
	}
	if c.Expiration.Required {
		nips[40] = true
	}
	if c.Auth.Required {
		nips[42] = true
	}
	if !c.Count.Reject {
		nips[45] = true
	}
	if c.Negentropy {
		nips[77] = true
	}
	for _, nip := range c.NIP11.ExtraNIPs {
		nips[nip] = true
	}

	supported := make([]any, 0, len(nips))
	for nip := range nips {
		supported = append(supported, nip)
	}
	slices.SortFunc(supported, func(a, b any) int {
		return a.(int) - b.(int)
	})
	relay.Info.SupportedNIPs = supported

	// HandleNIP11 adds 9, 45 and 77 on its own when the store has DeleteEvent,
	// CountEvents or Negentropy wired. Those are facts about the wiring, not about
	// what this relay will actually answer — a COUNT is refused here — so the served
	// document keeps exactly the derived list.
	relay.OverwriteRelayInformation = append(relay.OverwriteRelayInformation,
		func(ctx context.Context, r *http.Request, info nip11.RelayInformationDocument) nip11.RelayInformationDocument {
			info.SupportedNIPs = supported
			return info
		})

	relay.Info.Limitation = &nip11.RelayLimitationDocument{
		MaxMessageLength: c.NIP11.MaxMessageLength,
		MaxEventTags:     c.Tags.Max,
		MaxContentLength: c.Content.Max,
		MaxSubscriptions: c.NIP11.MaxSubscriptions,
		MaxFilters:       c.NIP11.MaxFilters,
		MaxLimit:         c.NIP11.MaxLimit,
		AuthRequired:     c.Auth.Required,
		RestrictedWrites: c.Auth.Required,
	}

	return nil
}

// defaultDescription is generated from the kind list, so the NIP-11 document cannot
// claim "Kind 4 only" after the allowlist changed.
func (k KindRules) defaultDescription() string {
	var parts []string
	for _, kind := range k.Sorted() {
		switch kind {
		case 4:
			parts = append(parts, "Kind 4 direct messages")
		case 5:
			parts = append(parts, "Kind 5 deletions")
		case 62:
			parts = append(parts, "Kind 62 vanish requests")
		default:
			parts = append(parts, fmt.Sprintf("Kind %d events", kind))
		}
	}
	return strings.Join(parts, ", ") + " only."
}

func splitList(raw string) []string {
	out := make([]string, 0, 2)
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseKinds(name, raw string) ([]uint16, error) {
	out := make([]uint16, 0, 4)
	for _, item := range splitList(raw) {
		kind, err := strconv.ParseUint(item, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a kind number", name, item)
		}
		out = append(out, uint16(kind))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no kinds given", name)
	}
	return out, nil
}

func intersectKinds(have, keep []uint16) []uint16 {
	out := make([]uint16, 0, len(have))
	for _, kind := range have {
		for _, k := range keep {
			if kind == k {
				out = append(out, kind)
				break
			}
		}
	}
	return out
}

func envBool(lookup func(string) (string, bool), key string, fallback bool) (bool, error) {
	raw, ok := lookup(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s: %q is not a boolean", key, raw)
	}
	return value, nil
}

func envInt(lookup func(string) (string, bool), key string, fallback int) (int, error) {
	raw, ok := lookup(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s: %q is not a number", key, raw)
	}
	return value, nil
}

// strictSections is the JSON schema an explicit configuration has to satisfy: every
// field of every section must be present. It is written out by hand rather than
// reflected so that adding a field to Config without adding it here is a compile-time
// neighbour in the same file, not a silent gap — TestStrictSchemaCoversEveryField
// keeps the two honest.
var strictSections = map[string][]string{
	"kinds":      {"allowed", "recipient_visible", "author_only", "allow_ephemeral", "reject_unserved_filters"},
	"expiration": {"required", "max"},
	"tags":       {"required", "max", "max_name_len", "max_value_len"},
	"content":    {"max"},
	"auth":       {"required"},
	"count":      {"reject"},
	"validation": {"shape_kinds"},
	"filters":    {"reject_empty", "reject_search"},
	"nip11":      {"name", "description", "max_message_length", "max_subscriptions", "max_filters", "max_limit", "extra_nips"},
}

// strictTopLevel is the set of keys the document itself must carry.
var strictTopLevel = []string{
	"kinds", "expiration", "tags", "content", "auth", "count", "validation",
	"filters", "rate_limits", "nip11", "negentropy",
}

// strictRateLimitKeys is the shape of every entry of rate_limits.
var strictRateLimitKeys = []string{"scope", "key", "tokens", "interval", "max"}

// checkComplete reports the first field a strict-mode document leaves out. It works
// on the raw JSON because presence is exactly what a decoded struct loses: an absent
// "auth.required" and an explicit false decode to the same value, and for a relay the
// difference between "I chose this" and "I never said" is the whole point.
func checkComplete(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if top == nil {
		return fmt.Errorf("incomplete configuration: the document is empty, but strict mode requires every field (start from -print-config)")
	}

	for _, key := range strictTopLevel {
		if _, ok := top[key]; !ok {
			return missingField(key)
		}
	}

	for section, keys := range strictSections {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(top[section], &fields); err != nil {
			return fmt.Errorf("incomplete configuration: %q must be an object with every field", section)
		}
		for _, key := range keys {
			if _, ok := fields[key]; !ok {
				return missingField(section + "." + key)
			}
		}
	}

	var limits []map[string]json.RawMessage
	if err := json.Unmarshal(top["rate_limits"], &limits); err != nil {
		return fmt.Errorf("incomplete configuration: %q must be an array", "rate_limits")
	}
	for i, entry := range limits {
		for _, key := range strictRateLimitKeys {
			if _, ok := entry[key]; !ok {
				return missingField(fmt.Sprintf("rate_limits[%d].%s", i, key))
			}
		}
	}

	return nil
}

func missingField(name string) error {
	return fmt.Errorf("incomplete configuration: %q is missing, and strict mode (BKIND_CONFIG_STRICT) requires every field — run with -print-config to get a complete document", name)
}
