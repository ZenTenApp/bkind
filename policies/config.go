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

// Config is the whole policy set of a relay as data. The per-kind settings —
// limits, gates, tag rules, write rate limits — appear twice in the document:
// once at the top level, where they are the defaults every kind starts from,
// and once inside "rules", where a kind overrides what it needs. Everything
// else (the whitelist, request-shape filters, read and connection limits, COUNT,
// NIP-11) is relay-wide and appears once.
//
// Load it with LoadConfig, which layers the defaults, a JSON file (BKIND_CONFIG),
// inline JSON (BKIND_CONFIG_JSON) and BKIND_KINDS, in that order. The zero value
// is not usable; DefaultConfig is.
//
// The document may spell the kinds section as "kind" or "kinds", and the rules
// may live under "rules" or directly at the top level keyed by kind number;
// everything else is canonical.
type Config struct {
	Kinds KindWhitelist `json:"kinds"`

	// The per-kind settings at the top level are the defaults: a field a kind's
	// rule does not name keeps the value set here.
	RuleSettings

	// Rules overrides the defaults per kind, keyed by kind number. A rule names
	// only what it changes.
	Rules map[string]*KindRule `json:"rules"`

	Filters          FilterRules `json:"filters"`
	ReadLimits       []RateLimit `json:"read_limits"`
	ConnectionLimits []RateLimit `json:"connection_limits"`
	Count            CountRules  `json:"count"`
	NIP11            NIP11Rules  `json:"nip11"`
	Negentropy       bool        `json:"negentropy"`
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

// RuleSettings is the set of per-kind settings. It is embedded twice: in KindRule,
// where it is one kind's rule, and in Config, where the same fields are the
// defaults every rule starts from. One struct means one decoder, one strict
// schema and one set of field names — a setting cannot be spellable in a rule
// but not in the defaults.
type RuleSettings struct {
	// Write is who may publish the kind.
	Write WriteGate `json:"write"`
	// Read is who may query it, and whether its events are privileged.
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
	// RateLimits bounds writes of the kind. Read and connection limits are
	// relay-wide: a REQ spans kinds.
	RateLimits []RateLimit `json:"rate_limits"`
	// Errors overrides the rejection messages with templates:
	// "blocked: event exceeds size limit ({size} > {limit})".
	Errors map[string]string `json:"errors"`
}

// ruleFieldNames is the canonical order and the complete set of the per-kind
// settings. It drives the printed document, the strict schema and the field
// coverage test, so a field cannot be added to RuleSettings and forgotten.
var ruleFieldNames = []string{
	"write", "read", "require_auth", "max_size", "max_expiration", "max_age_of_event",
	"max_age_event_in_future", "p_tag", "required_tags", "tag_patterns", "tag_limits",
	"rate_limits", "errors",
}

// ruleOnlyNames are the settings that belong to one kind and are never
// inherited from the defaults: "shape" runs a validator registered for a
// specific kind (policies/kinds.go), so a default would only ever be wrong for
// the next kind somebody whitelists.
var ruleOnlyNames = []string{"shape"}

// KindRule is one kind's override of the defaults. It lives in the "rules"
// object, and it names only the settings that differ: everything else is
// inherited from the top level.
//
// A KindRule built in Go (with no JSON behind it) has no notion of "absent", so
// it is fully explicit: every field it holds is the value, zeros included. That
// is the right reading of a struct literal, and it is what the tests and a
// hand-wired Config rely on.
type KindRule struct {
	// Description documents the kind for the operator; it is not sent anywhere,
	// and it has no default.
	Description string `json:"description"`

	RuleSettings

	// Shape runs the registered structural validator for this kind
	// (policies/kinds.go), when there is one. It is rule-local: it is not
	// inherited from the defaults, because a validator belongs to one kind.
	Shape bool `json:"shape"`

	// present holds the settings the document actually named, by canonical
	// name. A nil map means "everything is present": a rule built in Go.
	present map[string]bool
}

// nonZero reports whether a setting holds something, which is how a rule
// mutated in Go is read: Go has no way to say "absent", so a setting that holds
// a value was meant, and one that holds nothing defers to the defaults. A
// document does not need this — it says exactly which settings it names, zeros
// included, and those always win.
func (r *KindRule) nonZero(name string) bool {
	switch name {
	case "write":
		return len(r.Write.Allow) > 0
	case "read":
		return len(r.Read.Allow) > 0 || r.Read.Privileged
	case "require_auth":
		return r.RequireAuth
	case "max_size":
		return r.MaxSize.Bytes != 0
	case "max_expiration":
		return r.MaxExpiration.Duration != 0
	case "max_age_of_event":
		return r.MaxAge.Duration != 0
	case "max_age_event_in_future":
		return r.MaxFutureAge.Duration != 0
	case "p_tag":
		return r.PTag != ""
	case "required_tags":
		return len(r.RequiredTags) > 0
	case "tag_patterns":
		return len(r.TagPatterns) > 0
	case "tag_limits":
		return r.TagLimits.set()
	case "rate_limits":
		return len(r.RateLimits) > 0
	case "shape":
		return r.Shape
	case "errors":
		return len(r.Errors) > 0
	}
	return false
}

// set records that the document named a setting, so a later resolve knows what
// to inherit and what to override.
func (r *KindRule) set(name string) bool {
	if r.present == nil {
		return true
	}
	return r.present[name]
}

func (r *KindRule) mark(name string) {
	if r.present == nil {
		r.present = map[string]bool{}
	}
	r.present[name] = true
}

// field returns the setting under its canonical name, for merging and printing.
func (r *KindRule) field(name string) any {
	switch name {
	case "write":
		return WriteGate{Allow: nonNil(r.Write.Allow)}
	case "read":
		return ReadGate{Allow: nonNil(r.Read.Allow), Privileged: r.Read.Privileged}
	case "require_auth":
		return r.RequireAuth
	case "max_size":
		return r.MaxSize
	case "max_expiration":
		return r.MaxExpiration
	case "max_age_of_event":
		return r.MaxAge
	case "max_age_event_in_future":
		return r.MaxFutureAge
	case "p_tag":
		return r.PTag
	case "required_tags":
		return r.RequiredTags
	case "tag_patterns":
		return r.TagPatterns
	case "tag_limits":
		return r.TagLimits
	case "rate_limits":
		return r.RateLimits
	case "errors":
		return r.Errors
	}
	return nil
}

// setField assigns the setting under its canonical name from a decoded value.
func (r *KindRule) setField(name string, value json.RawMessage) error {
	switch name {
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
	case "errors":
		r.Errors = nil
		return strictUnmarshal(value, &r.Errors)
	}
	return fmt.Errorf("unknown field %q in a kind rule", name)
}

// MarshalJSON prints a rule as the document writes it: the description, then the
// settings the rule names, in canonical order. A rule that came from Go has no
// presence information, so it prints in full — the document is then explicit
// about every setting instead of leaning on a default.
func (r KindRule) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')

	wrote := false
	write := func(name string, value any) error {
		if wrote {
			out.WriteByte(',')
		}
		wrote = true
		key, err := marshalNoEscape(name)
		if err != nil {
			return err
		}
		out.Write(key)
		out.WriteByte(':')
		encoded, err := marshalNoEscape(value)
		if err != nil {
			return err
		}
		out.Write(encoded)
		return nil
	}

	if r.present == nil || r.present["description"] {
		if err := write("description", r.Description); err != nil {
			return nil, err
		}
	}
	for _, name := range ruleFieldNames {
		if !r.set(name) {
			continue
		}
		if err := write(name, r.field(name)); err != nil {
			return nil, err
		}
	}
	for _, name := range ruleOnlyNames {
		if !r.set(name) {
			continue
		}
		if err := write(name, r.Shape); err != nil {
			return nil, err
		}
	}

	out.WriteByte('}')
	return out.Bytes(), nil
}

// UnmarshalJSON decodes a kind rule, refusing unknown fields and alias/canonical
// conflicts, and records which settings were named. It merges: a setting absent
// from the document keeps what the receiver already had, which is what makes a
// partial file a patch.
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

func (r *KindRule) applyField(key string, value json.RawMessage) error {
	// "privileged" is the alias of read.privileged, and "identifier_regex"
	// the alias of tag_patterns.d — both are shaped differently from their
	// canonical twins, so they are handled before the remap
	if key == "privileged" {
		r.mark("read")
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
		r.mark("tag_patterns")
		return nil
	}
	if alias, ok := ruleAliases[key]; ok {
		key = alias
	}

	if key == "description" {
		r.mark("description")
		return json.Unmarshal(value, &r.Description)
	}
	if key == "shape" {
		r.mark("shape")
		return json.Unmarshal(value, &r.Shape)
	}
	if !slices.Contains(ruleFieldNames, key) {
		return fmt.Errorf("unknown field %q in a kind rule", key)
	}

	r.mark(key)
	return r.setField(key, value)
}

// resolve returns the effective rule: the defaults, with every setting this rule
// names laid over them. A rule with no presence information (built in Go) is
// fully explicit and is returned as is.
func (r *KindRule) resolve(defaults *KindRule) *KindRule {
	if r == nil {
		return defaults.clone()
	}
	if r.present == nil {
		return r
	}

	out := defaults.clone()
	out.Description = r.Description
	for _, name := range append(append([]string{}, ruleFieldNames...), ruleOnlyNames...) {
		if !r.set(name) && !r.nonZero(name) {
			continue
		}
		switch name {
		case "shape":
			out.Shape = r.Shape
		case "write":
			out.Write = r.Write
		case "read":
			out.Read = r.Read
		case "require_auth":
			out.RequireAuth = r.RequireAuth
		case "max_size":
			out.MaxSize = r.MaxSize
		case "max_expiration":
			out.MaxExpiration = r.MaxExpiration
		case "max_age_of_event":
			out.MaxAge = r.MaxAge
		case "max_age_event_in_future":
			out.MaxFutureAge = r.MaxFutureAge
		case "p_tag":
			out.PTag = r.PTag
		case "required_tags":
			out.RequiredTags = r.RequiredTags
		case "tag_patterns":
			out.TagPatterns = r.TagPatterns
		case "tag_limits":
			out.TagLimits = r.TagLimits
		case "rate_limits":
			out.RateLimits = r.RateLimits
		case "errors":
			// messages merge one by one, so a kind can reword a single
			// rejection without repeating the default table
			merged := make(map[string]string, len(out.Errors)+len(r.Errors))
			for k, v := range out.Errors {
				merged[k] = v
			}
			for k, v := range r.Errors {
				merged[k] = v
			}
			if len(merged) == 0 {
				merged = nil
			}
			out.Errors = merged
		}
	}
	return out
}

// clone copies a rule deeply enough that a resolved rule cannot be mutated back
// into the defaults through a shared slice or map.
func (r *KindRule) clone() *KindRule {
	if r == nil {
		return &KindRule{}
	}
	out := *r
	out.present = nil
	out.RequiredTags = append([]string(nil), r.RequiredTags...)
	out.RateLimits = append([]RateLimit(nil), r.RateLimits...)
	out.TagPatterns = copyMap(r.TagPatterns)
	out.Errors = copyMap(r.Errors)
	out.Write.Allow = append(AllowList(nil), r.Write.Allow...)
	out.Read.Allow = append(AllowList(nil), r.Read.Allow...)
	return &out
}

// sortedKeys returns the keys of a decoded object in a stable order, so a
// document's settings are applied — and rejected — deterministically.
func sortedKeys(raw map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func copyMap[V any](in map[string]V) map[string]V {
	if in == nil {
		return nil
	}
	out := make(map[string]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// defaults is the top-level rule settings as a rule: what every kind starts from.
func (c Config) defaults() *KindRule {
	return &KindRule{RuleSettings: c.RuleSettings}
}

// EffectiveRule returns what the relay actually does with a kind: the defaults
// with the kind's own settings laid over them. A whitelisted kind without a rule
// is served with exactly the defaults.
func (c Config) EffectiveRule(kind uint16) *KindRule {
	return c.Rules[strconv.Itoa(int(kind))].resolve(c.defaults())
}

// EffectiveRules is EffectiveRule for the whole whitelist.
func (c Config) EffectiveRules() map[uint16]*KindRule {
	out := make(map[uint16]*KindRule, len(c.Kinds.Whitelist))
	for _, kind := range c.Kinds.Whitelist {
		out[kind] = c.EffectiveRule(kind)
	}
	return out
}

// FilterRules are the request-shape policies.
type FilterRules struct {
	RejectEmpty  bool `json:"reject_empty"`
	RejectSearch bool `json:"reject_search"`
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
// The rules are the point of the shape: one defaults block holds the whole DM
// policy, and each kind names only what makes it different.
func DefaultConfig() Config {
	return Config{
		Kinds: KindWhitelist{
			Whitelist:             []uint16{4, 5, 62},
			RejectUnservedFilters: true,
		},
		RuleSettings: RuleSettings{
			Write:         WriteGate{Allow: AllowList{"*"}},
			Read:          ReadGate{Allow: AllowList{"*"}, Privileged: true},
			RequireAuth:   true,
			MaxSize:       Size{Bytes: 4096},
			MaxExpiration: Duration{75 * time.Hour},
			PTag:          "hex",
			RequiredTags:  []string{"expiration", "client"},
			TagLimits:     TagLimits{MaxTags: 16, MaxNameChars: 64, MaxValueChars: 256},
			RateLimits: []RateLimit{
				{Scope: "npub", Limit: 30, Window: Duration{time.Hour}},
				{Scope: "npub", Limit: 200, Window: Duration{24 * time.Hour}},
				{Scope: "ip", Limit: 60, Window: Duration{time.Hour}},
				{Scope: "ip", Limit: 400, Window: Duration{24 * time.Hour}},
			},
		},
		Rules: map[string]*KindRule{
			// the DM kind needs nothing beyond the defaults but its name and its
			// validator
			"4": mustRule(`{"description": "NIP-04 direct messages", "shape": true}`),
			// the utility kinds have no "p" recipient
			"5":  mustRule(`{"description": "NIP-09 deletion requests", "p_tag": "", "shape": true}`),
			"62": mustRule(`{"description": "NIP-62 vanish requests", "p_tag": "", "shape": true}`),
		},
		Filters: FilterRules{RejectEmpty: true, RejectSearch: true},
		ReadLimits: []RateLimit{
			{Scope: "npub", Limit: 60, Window: Duration{time.Hour}},
			{Scope: "npub", Limit: 400, Window: Duration{24 * time.Hour}},
			{Scope: "ip", Limit: 120, Window: Duration{time.Hour}},
			{Scope: "ip", Limit: 800, Window: Duration{24 * time.Hour}},
		},
		ConnectionLimits: []RateLimit{
			{Scope: "ip", Limit: 120, Window: Duration{time.Hour}},
		},
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

// mustRule builds a rule from its JSON, so a rule written in Go records which
// settings it named exactly like one read from a file. Without that, every rule
// in DefaultConfig would have to repeat the whole defaults block to override
// one field.
func mustRule(document string) *KindRule {
	var rule KindRule
	if err := json.Unmarshal([]byte(document), &rule); err != nil {
		panic(fmt.Sprintf("policies: bad built-in rule %s: %v", document, err))
	}
	return &rule
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

// WithJSON merges a JSON document onto the receiver. Settings absent from the
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
// The top level must be complete — the defaults are what the rules inherit from,
// so a missing default is a missing answer. A rule body may be sparse: that is
// what "everything else is inherited" means.
func (c Config) WithStrictJSON(data []byte) (Config, error) {
	return c.withJSON(data, true)
}

// JSON renders the configuration as the canonical document WithStrictJSON
// accepts: every default spelled out, every rule with exactly the settings it
// overrides, in a stable order, so it can be diffed, reviewed and fed back. This
// is what the relay prints for -print-config.
func (c Config) JSON() ([]byte, error) {
	// a nil slice and an empty one mean the same thing; print the empty one so the
	// document reads as "none" instead of "null"
	out := c
	out.Kinds.Whitelist = nonNil(out.Kinds.Whitelist)
	out.RequiredTags = nonNil(out.RequiredTags)
	out.RateLimits = nonNil(out.RateLimits)
	out.TagPatterns = nonNilMap(out.TagPatterns)
	out.Errors = nonNilMap(out.Errors)
	out.Write.Allow = nonNil(out.Write.Allow)
	out.Read.Allow = nonNil(out.Read.Allow)
	out.ReadLimits = nonNil(out.ReadLimits)
	out.ConnectionLimits = nonNil(out.ConnectionLimits)
	out.NIP11.ExtraNIPs = nonNil(out.NIP11.ExtraNIPs)

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		return nil, err
	}
	return collapseScalarContainers(bytes.TrimRight(buffer.Bytes(), "\n")), nil
}

// marshalNoEscape encodes without HTML escaping, so a rejection template keeps
// the "<" a client will show ("{size} > {limit}") instead of "\u003e".
func marshalNoEscape(v any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
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

// documentSections are the relay-wide keys of the document: everything that is
// not a per-kind default. A key outside this set and outside ruleFieldNames is
// either a kind number at the top level or a typo.
var documentSections = []string{
	"rules", "kinds", "filters", "read_limits", "connection_limits", "count", "nip11", "negentropy",
}

// normalizeDocument folds the accepted synonyms into the canonical shape: "kind"
// becomes "kinds", and top-level kind-number keys become entries of "rules". It
// runs before anything else, so strict mode, the completeness check and the
// decoder all see one document. The per-kind default fields at the top level are
// left where they are: they are the defaults, not a section.
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
		if slices.Contains(documentSections, key) || slices.Contains(ruleFieldNames, key) {
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
	// exists, while a rule for a new kind starts from nothing (and inherits the
	// defaults at resolve time).
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
				rule = &KindRule{present: map[string]bool{}}
				c.Rules[key] = rule
			}
			if rule.present == nil {
				// a rule that came from Go is fully explicit; a patch makes it a
				// delta again, starting from what it names now
				rule.present = map[string]bool{}
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
