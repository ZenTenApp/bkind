package policies

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is the whole policy set of a relay as data, keyed by kind. Every limit
// that used to be a relay-wide section is a field of the kind it belongs to, so
// the same binary can serve a NIP-04 DM relay, a NIP-17 gift-wrap relay or a
// single-kind backup relay without a code change.
//
// Load it with LoadConfig, which layers the defaults, a JSON file (BKIND_CONFIG),
// inline JSON (BKIND_CONFIG_JSON) and BKIND_KINDS, in that order. The zero value
// is not usable; DefaultConfig is.
//
// The document may spell the kinds section as "kind" or "kinds", and the rules
// may live under "rules" or directly at the top level keyed by kind number;
// everything else is canonical.
type Config struct {
	Kinds       KindWhitelist        `json:"kinds"`
	Rules       map[string]*KindRule `json:"rules"`
	Filters     FilterRules          `json:"filters"`
	Reads       ReadsRules           `json:"reads"`
	Connections ConnectionsRules     `json:"connections"`
	Count       CountRules           `json:"count"`
	NIP11       NIP11Rules           `json:"nip11"`
	Negentropy  bool                 `json:"negentropy"`
}

// KindWhitelist is what the relay serves at all.
type KindWhitelist struct {
	// Whitelist is the complete set of kinds the relay accepts and serves.
	Whitelist []uint16 `json:"whitelist"`
	// AllowEphemeral lets every ephemeral kind (20000-29999) through without
	// listing each one.
	AllowEphemeral bool `json:"allow_ephemeral"`
	// RejectUnservedFilters makes a REQ naming a kind outside the whitelist
	// fail with a reason instead of being silently narrowed.
	RejectUnservedFilters bool `json:"reject_unserved_filters"`
}

// KindRule is everything the relay does with one kind, on the write side and on
// the read side. A kind in the whitelist without a rule is served with the
// strictest defaults (authenticated writes, author-only reads); a rule that is
// present but leaves a field zero means "no restriction" for that field — an
// explicit zero is a choice, an absent rule is not.
type KindRule struct {
	// Description documents the kind for the operator; it is not sent anywhere.
	Description string `json:"description"`
	// Write is who may publish this kind.
	Write WriteGate `json:"write"`
	// Read is who may query this kind, and whether its events are privileged.
	Read ReadGate `json:"read"`
	// RequireAuth is NIP-42: publishing requires authentication and the author
	// must be the authenticated key.
	RequireAuth bool `json:"require_auth"`
	// MaxSize is the content limit in bytes. Zero means unlimited.
	MaxSize Size `json:"max_size"`
	// MaxExpiration caps how far a NIP-40 "expiration" tag may point. Zero means
	// no cap.
	MaxExpiration Duration `json:"max_expiration"`
	// MaxAge rejects events created_at further in the past than this. Zero
	// means no limit.
	MaxAge Duration `json:"max_age_of_event"`
	// MaxFutureAge rejects events created_at further in the future than this —
	// the clock-skew allowance. Zero means no limit.
	MaxFutureAge Duration `json:"max_age_event_in_future"`
	// PTag names the "p" tag rule; "hex" requires exactly one "p" tag with a
	// valid pubkey that is not the author, which is also what makes a
	// privileged kind recipient-visible. Empty means no p rule.
	PTag string `json:"p_tag"`
	// RequiredTags must each appear exactly once with a non-empty value.
	// "expiration" here means a mandatory NIP-40 tag.
	RequiredTags []string `json:"required_tags"`
	// TagPatterns bounds tag values: tag name -> regular expression. A pattern
	// only checks tags that appear; requiring one is RequiredTags' job.
	TagPatterns map[string]string `json:"tag_patterns"`
	// TagLimits bounds the tag list itself.
	TagLimits TagLimits `json:"tag_limits"`
	// RateLimits bounds writes of this kind.
	RateLimits []RateLimit `json:"rate_limits"`
	// Shape runs the registered structural validator for this kind
	// (policies/kinds.go), when there is one.
	Shape bool `json:"shape"`
	// Errors overrides the rejection messages with templates:
	// "blocked: event exceeds size limit ({size} > {limit})".
	Errors map[string]string `json:"errors"`
}

// ruleAliases are the short field names accepted for their canonical twins, so
// a summary-style document ("size_limit", "must_have_tags") and the full one
// ("max_size", "required_tags") are the same config.
var ruleAliases = map[string]string{
	"size_limit":          "max_size",
	"max_expiry_duration": "max_expiration",
	"must_have_tags":      "required_tags",
	"identifier_regex":    "tag_patterns",
	"privileged":          "read",
}

// UnmarshalJSON decodes a kind rule, refusing unknown fields and alias/canonical
// conflicts. It merges: a field absent from the document keeps its current
// value, which is what makes a partial file a patch.
func (r *KindRule) UnmarshalJSON(data []byte) error {
	if strings.TrimSpace(string(data)) == "null" {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	for alias, canonical := range ruleAliases {
		if _, ok := raw[alias]; ok {
			if _, ok := raw[canonical]; ok {
				return fmt.Errorf("a kind rule has both %q and %q, which are the same setting", alias, canonical)
			}
		}
	}

	for _, key := range sortedKeys(raw) {
		if err := r.applyField(key, raw[key]); err != nil {
			return err
		}
	}
	return nil
}

func (r *KindRule) applyField(key string, value json.RawMessage) error {
	// "privileged" is the alias of read.privileged, and "identifier_regex"
	// the alias of tag_patterns.d — both are shaped differently from their
	// canonical twins, so they are handled before the remap
	if key == "privileged" {
		return json.Unmarshal(value, &r.Read.Privileged)
	}
	if key == "identifier_regex" {
		var pattern string
		if err := json.Unmarshal(value, &pattern); err != nil {
			return err
		}
		if r.TagPatterns == nil {
			r.TagPatterns = map[string]string{}
		}
		r.TagPatterns["d"] = pattern
		return nil
	}
	if alias, ok := ruleAliases[key]; ok {
		key = alias
	}

	switch key {
	case "description":
		return json.Unmarshal(value, &r.Description)
	case "write":
		return strictUnmarshal(value, &r.Write)
	case "read":
		return strictUnmarshal(value, &r.Read)
	case "require_auth":
		return json.Unmarshal(value, &r.RequireAuth)
	case "max_size":
		return json.Unmarshal(value, &r.MaxSize)
	case "max_expiration":
		return json.Unmarshal(value, &r.MaxExpiration)
	case "max_age_of_event":
		return json.Unmarshal(value, &r.MaxAge)
	case "max_age_event_in_future":
		return json.Unmarshal(value, &r.MaxFutureAge)
	case "p_tag":
		return json.Unmarshal(value, &r.PTag)
	case "required_tags":
		r.RequiredTags = nil
		return strictUnmarshal(value, &r.RequiredTags)
	case "tag_patterns":
		r.TagPatterns = nil
		return strictUnmarshal(value, &r.TagPatterns)
	case "tag_limits":
		return strictUnmarshal(value, &r.TagLimits)
	case "rate_limits":
		r.RateLimits = nil
		return strictUnmarshal(value, &r.RateLimits)
	case "shape":
		return json.Unmarshal(value, &r.Shape)
	case "errors":
		r.Errors = nil
		return strictUnmarshal(value, &r.Errors)
	default:
		return fmt.Errorf("unknown field %q in a kind rule", key)
	}
}

func sortedKeys(raw map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// FilterRules are the request-shape policies.
type FilterRules struct {
	RejectEmpty  bool `json:"reject_empty"`
	RejectSearch bool `json:"reject_search"`
}

// ReadsRules bounds REQs. Read limits are relay-wide because a filter can span
// kinds; write limits live on the kind.
type ReadsRules struct {
	RateLimits []RateLimit `json:"rate_limits"`
}

// ConnectionsRules bounds connects per IP.
type ConnectionsRules struct {
	RateLimits []RateLimit `json:"rate_limits"`
}

// CountRules is NIP-45. Reject keeps COUNT refused, which is the only safe answer
// for private events; setting it to false serves COUNT and advertises NIP-45.
type CountRules struct {
	Reject bool `json:"reject"`
}

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

// DefaultConfig is the policy set of the reference relay in examples/bkind:
// NIP-04 direct messages plus the two utility kinds needed to operate them,
// authenticated, expiring, size-limited, and rate-limited per npub and per ip.
//
// The rate limits are opinionated; a test that does not want them should clear
// them before wiring.
func DefaultConfig() Config {
	writeLimits := []RateLimit{
		{Scope: "npub", Limit: 30, Window: Duration{time.Hour}},
		{Scope: "npub", Limit: 200, Window: Duration{24 * time.Hour}},
		{Scope: "ip", Limit: 60, Window: Duration{time.Hour}},
		{Scope: "ip", Limit: 400, Window: Duration{24 * time.Hour}},
	}
	dmTags := TagLimits{MaxTags: 16, MaxNameChars: 64, MaxValueChars: 256}

	rule := func(description, pTag string) *KindRule {
		return &KindRule{
			Description:   description,
			Write:         WriteGate{Allow: AllowList{"*"}},
			Read:          ReadGate{Allow: AllowList{"*"}, Privileged: true},
			RequireAuth:   true,
			MaxSize:       Size{Bytes: 4096},
			MaxExpiration: Duration{75 * time.Hour},
			RequiredTags:  []string{"expiration", "client"},
			PTag:          pTag,
			TagLimits:     dmTags,
			RateLimits:    writeLimits,
			Shape:         true,
		}
	}

	return Config{
		Kinds: KindWhitelist{
			Whitelist:             []uint16{4, 5, 62},
			RejectUnservedFilters: true,
		},
		Rules: map[string]*KindRule{
			"4":  rule("NIP-04 direct messages", "hex"),
			"5":  rule("NIP-09 deletion requests", ""),
			"62": rule("NIP-62 vanish requests", ""),
		},
		Filters: FilterRules{RejectEmpty: true, RejectSearch: true},
		Reads: ReadsRules{RateLimits: []RateLimit{
			{Scope: "npub", Limit: 60, Window: Duration{time.Hour}},
			{Scope: "npub", Limit: 400, Window: Duration{24 * time.Hour}},
			{Scope: "ip", Limit: 120, Window: Duration{time.Hour}},
			{Scope: "ip", Limit: 800, Window: Duration{24 * time.Hour}},
		}},
		Connections: ConnectionsRules{RateLimits: []RateLimit{
			{Scope: "ip", Limit: 120, Window: Duration{time.Hour}},
		}},
		Count: CountRules{Reject: true},
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
// named by BKIND_CONFIG, then the inline JSON in BKIND_CONFIG_JSON, then
// BKIND_KINDS, then Validate.
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
// A rules map merges per kind: a rule for a kind already configured patches that
// kind's rule, a rule for a new kind adds it. A document that replaces
// kinds.whitelist prunes the rules of the kinds it drops, exactly as SetKinds
// does.
//
// Use WithStrictJSON when the document must stand on its own.
func (c Config) WithJSON(data []byte) (Config, error) {
	return c.withJSON(data, false)
}

// WithStrictJSON is WithJSON for an explicit configuration: every field must be
// present in the document, so what the relay does is what the file says rather
// than what the file did not mention. It is what BKIND_CONFIG_STRICT turns on,
// and it is the right mode for a config kept in version control.
//
// Completeness is checked against the JSON, not against the receiver: a field
// that is present but zero means "off", and that is a choice the document made.
func (c Config) WithStrictJSON(data []byte) (Config, error) {
	return c.withJSON(data, true)
}

// JSON renders the configuration as the canonical document WithStrictJSON
// accepts: every field spelled out, in a stable order, so it can be diffed,
// reviewed and fed back. This is what the relay prints for -print-config.
func (c Config) JSON() ([]byte, error) {
	// the rules are pointers; clone them so the nil-to-empty normalization below
	// cannot reach back into the receiver
	out := c
	out.Rules = make(map[string]*KindRule, len(c.Rules))
	for key, rule := range c.Rules {
		if rule == nil {
			continue
		}
		clone := *rule
		clone.RequiredTags = nonNil(clone.RequiredTags)
		clone.RateLimits = nonNil(clone.RateLimits)
		clone.TagPatterns = nonNilMap(clone.TagPatterns)
		clone.Errors = nonNilMap(clone.Errors)
		clone.Write.Allow = nonNil(clone.Write.Allow)
		clone.Read.Allow = nonNil(clone.Read.Allow)
		out.Rules[key] = &clone
	}

	out.Kinds.Whitelist = nonNil(out.Kinds.Whitelist)
	out.Reads.RateLimits = nonNil(out.Reads.RateLimits)
	out.Connections.RateLimits = nonNil(out.Connections.RateLimits)
	out.NIP11.ExtraNIPs = nonNil(out.NIP11.ExtraNIPs)

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

func nonNilMap[E any](m map[string]E) map[string]E {
	if m == nil {
		return map[string]E{}
	}
	return m
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

// normalizeDocument folds the accepted synonyms into the canonical shape: "kind"
// becomes "kinds", and top-level kind-number keys become entries of "rules". It
// runs before anything else, so strict mode, the completeness check and the
// decoder all see one document.
func normalizeDocument(data []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if top == nil {
		return data, nil
	}

	// "kind" is accepted as a synonym of "kinds"
	if raw, ok := top["kind"]; ok {
		if _, exists := top["kinds"]; exists {
			return nil, fmt.Errorf("the document has both \"kind\" and \"kinds\": name the section once")
		}
		top["kinds"] = raw
		delete(top, "kind")
	}

	// kind-number keys at the top level are rules: {"4": {...}} means rules.4
	var merged map[string]json.RawMessage
	if raw, ok := top["rules"]; ok {
		if err := json.Unmarshal(raw, &merged); err != nil {
			return nil, fmt.Errorf("rules must be an object keyed by kind number: %w", err)
		}
	}
	moved := false
	for key := range top {
		if slices.Contains([]string{"rules", "kinds", "filters", "reads", "connections", "count", "nip11", "negentropy"}, key) {
			continue
		}
		if _, err := strconv.ParseUint(key, 10, 16); err != nil {
			continue // an unknown non-numeric key: the decoder will name it
		}
		if merged == nil {
			merged = map[string]json.RawMessage{}
		}
		if _, exists := merged[key]; exists {
			return nil, fmt.Errorf("kind %s is defined twice in the document", key)
		}
		merged[key] = top[key]
		delete(top, key)
		moved = true
	}
	if moved || len(merged) > 0 {
		body, err := json.Marshal(merged)
		if err != nil {
			return nil, err
		}
		top["rules"] = body
	}

	return json.Marshal(top)
}

func (c Config) withJSON(data []byte, strict bool) (Config, error) {
	normalized, err := normalizeDocument(data)
	if err != nil {
		return c, err
	}

	if strict {
		if err := checkComplete(normalized); err != nil {
			return c, err
		}
	}

	// a lenient first pass, only to learn whether the whitelist was replaced
	var patch struct {
		Kinds struct {
			Whitelist *[]uint16 `json:"whitelist"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(normalized, &patch); err == nil && patch.Kinds.Whitelist != nil {
		c.pruneRules(*patch.Kinds.Whitelist)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(normalized, &top); err != nil {
		return c, fmt.Errorf("invalid JSON: %w", err)
	}

	// the rules merge by hand: the encoding/json map layer decodes every entry
	// onto a fresh zero value, which would turn a patch into a wipe. Merging
	// here keeps "absent field keeps its value" true for a rule that already
	// exists, while a rule for a new kind starts from zero.
	if raw, ok := top["rules"]; ok && strings.TrimSpace(string(raw)) != "null" {
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return c, fmt.Errorf("rules must be an object keyed by kind number: %w", err)
		}
		if c.Rules == nil {
			c.Rules = map[string]*KindRule{}
		}
		for _, key := range sortedKeys(entries) {
			rule, exists := c.Rules[key]
			if !exists || rule == nil {
				rule = &KindRule{}
				c.Rules[key] = rule
			}
			if err := json.Unmarshal(entries[key], rule); err != nil {
				return c, fmt.Errorf("rules.%s: %w", key, err)
			}
		}
		delete(top, "rules")
		normalized, err = json.Marshal(top)
		if err != nil {
			return c, err
		}
	}

	dec := json.NewDecoder(bytes.NewReader(normalized))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid JSON: %w", err)
	}
	return c, nil
}

// ApplyEnv overrides the settings worth a command line: the whitelist (which
// prunes the rules of the kinds it drops) and the NIP-11 name and description.
// Everything else belongs in the document.
func (c *Config) ApplyEnv(lookup func(string) (string, bool)) error {
	if raw, ok := lookup("BKIND_KINDS"); ok && strings.TrimSpace(raw) != "" {
		kinds, err := parseKinds("BKIND_KINDS", raw)
		if err != nil {
			return err
		}
		c.SetKinds(kinds)
	}
	if raw, ok := lookup("BKIND_NAME"); ok {
		c.NIP11.Name = raw
	}
	if raw, ok := lookup("BKIND_DESCRIPTION"); ok {
		c.NIP11.Description = raw
	}
	return nil
}

// SetKinds replaces the whitelist and drops the rules of kinds that are no
// longer served, so narrowing the whitelist cannot leave a stale rule behind.
// The environment and the command line both go through it.
func (c *Config) SetKinds(kinds []uint16) {
	c.Kinds.Whitelist = kinds
	c.pruneRules(kinds)
}

// pruneRules deletes the rules of kinds outside keep. Keys that are not kind
// numbers are left alone: Validate names them.
func (c *Config) pruneRules(keep []uint16) {
	for key := range c.Rules {
		kind, err := strconv.ParseUint(key, 10, 16)
		if err != nil {
			continue
		}
		if !slices.Contains(keep, uint16(kind)) {
			delete(c.Rules, key)
		}
	}
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
