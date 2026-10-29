package policies

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Config is the whole policy set of a relay as data.
//
// The document itself has one shape: kind number -> that kind's whole rule, and
// nothing else. A kind is served exactly when it has a rule, so the document is
// the served set.
//
// Loading is layering of documents, and only that:
//
//   - a document replaces the document that came before it, so BKIND_CONFIG and
//     BKIND_CONFIG_JSON are whole policy files, not patches;
//   - inside a document there is no inheritance. Every per-kind setting lives in
//     the kind's own rule, and a rule says everything the relay does with that
//     kind. A setting a rule leaves out is inactive: no limit, no cap, no tag
//     rule, nobody.
//
// Nothing about the per-kind policy is written in Go. The document a relay starts
// from when no configuration is supplied is default.json, embedded at build time:
// the reference relay is a file you can read, diff and copy, not a struct literal.
// The relay-wide half (filters, limits, COUNT, NIP-11, negentropy) is not in the
// document at all: Settings carries it, defaulted in Go and moved by flags.
type Config struct {
	// Rules is the whole document: one complete rule per served kind, keyed by
	// kind number. Nothing else is in it — a kind is served exactly when it has
	// a rule, and there is no separate whitelist to keep in step with.
	Rules map[string]*KindRule

	// Settings are the relay-wide policies. They are not part of the document:
	// the file says which kinds the relay serves and how, and everything else is
	// a flag, an environment variable or the Go defaults below.
	Settings Settings
}

// Settings is the relay-wide half of the policy set: everything that is not a
// property of one kind. None of it is written in the document, so a document is
// exactly a set of kinds and nothing else.
type Settings struct {
	// Filters are the request-shape policies.
	Filters FilterRules
	// ReadLimits bound REQs, relay-wide: one REQ spans kinds.
	ReadLimits []RateLimit
	// ConnectionLimits bound connections, per ip.
	ConnectionLimits []RateLimit
	// Count is NIP-45; Reject keeps COUNT refused.
	Count CountRules
	// NIP11 is the relay information document.
	NIP11 NIP11Rules
	// Negentropy is NIP-77 set reconciliation.
	Negentropy bool
	// RejectUnservedFilters makes a REQ naming an unserved kind fail with a
	// reason instead of being silently narrowed.
	RejectUnservedFilters bool
}

// DefaultSettings is the relay-wide policy of a relay that was given no flags:
// the values the reference relay used to spell in its document.
func DefaultSettings() Settings {
	return Settings{
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
			MaxMessageLength: 12288,
			MaxSubscriptions: 10,
			MaxFilters:       4,
			MaxLimit:         500,
		},
		RejectUnservedFilters: true,
	}
}

// RuleSettings is the per-kind policy of one kind. It is embedded in KindRule
// and appears nowhere else: there are no top-level per-kind defaults, so a
// setting written here is the only value that kind has.
//
// Every zero value below is a meaning, not a fallback: no limit, no cap, no tag
// rule, nobody (an empty allow list is not "anyone" — that is "*").
type RuleSettings struct {
	// Write is who may publish the kind. An empty allow list means nobody.
	Write WriteGate `json:"write"`
	// Read is who may query it, and whether its events are privileged.
	Read ReadGate `json:"read"`
	// RequireAuth is NIP-42: publishing requires authentication and the author
	// must be the authenticated key.
	RequireAuth bool `json:"require_auth"`
	// MaxEventSize bounds the whole event as a client sends it: the JSON of the
	// event itself, id and signature included, without the ["EVENT", ...]
	// envelope. Zero means no limit.
	MaxEventSize Size `json:"max_event_size"`
	// MaxEventContentSize bounds the content alone, which is the part a client
	// chooses freely. Zero means no limit. It is what NIP-11 advertises as
	// max_content_length.
	MaxEventContentSize Size `json:"max_event_content_size"`
	// MaxExpiration caps how far a NIP-40 "expiration" tag may point. Zero means
	// no cap.
	MaxExpiration Duration `json:"max_expiration"`
	// MaxAge rejects events created_at further in the past than this. Zero
	// means no limit.
	MaxAge Duration `json:"max_age_of_event"`
	// MaxFutureAge rejects events created_at further in the future than this —
	// the clock-skew allowance. Zero means no limit.
	MaxFutureAge Duration `json:"max_age_event_in_future"`
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

// KindRule is one kind's complete rule: what the kind is, in a sentence, and
// every per-kind setting.
//
// It is a plain struct on purpose. A rule read from a document and a rule built
// in Go are the same thing, and there is nothing to reconcile between them: no
// "was this field mentioned" bookkeeping, because there is nothing to inherit.
//
// The structural validator of a kind is not a setting: it runs whenever one is
// registered for the kind (policies/kinds.go), because a relay should not be able
// to serve a kind it does not know how to check. The validator itself is code — a
// document cannot carry code — so there is nothing here to switch on.
type KindRule struct {
	// Description is required: one sentence saying what this kind is. It is for
	// the operator (logs, reviews, the document itself) and is not sent anywhere.
	Description string `json:"description"`

	RuleSettings
}

// defaultDocument is the reference relay as data: the policy set of
// examples/bkind, spelled in full.
//
//go:embed default.json
var defaultDocument []byte

// DefaultDocument returns a copy of the document a relay starts from when no
// configuration is supplied. It is the same bytes as policies/default.json.
func DefaultDocument() []byte {
	return append([]byte(nil), defaultDocument...)
}

// DefaultConfig is the configuration of a relay that was given no configuration
// at all: DefaultDocument, parsed and validated. It carries no policy of its
// own — the values are the file's — so `-print-config` on an unconfigured relay
// prints the file back.
//
// It panics if the embedded document does not parse or validate, which would be
// a bug in the release, not in a deployment.
func DefaultConfig() Config {
	cfg, err := parseConfig(DefaultDocument())
	if err != nil {
		panic(fmt.Sprintf("policies: the embedded default.json is not usable: %v", err))
	}
	return cfg
}

// LoadConfig builds the configuration for a relay: the embedded default document,
// then the JSON file named by BKIND_CONFIG, then the inline JSON in
// BKIND_CONFIG_JSON, then BKIND_KINDS and BKIND_NAME/BKIND_DESCRIPTION, then
// Validate.
//
// Each document replaces the sections it names; see Config. There is no strict
// mode and no completeness switch: a document is never wrong for saying less,
// it only says less.
//
// lookup is os.LookupEnv in production and a map in tests.
func LoadConfig(lookup func(string) (string, bool)) (Config, error) {
	cfg := DefaultConfig()

	if path, ok := lookup("BKIND_CONFIG"); ok && path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("BKIND_CONFIG: %w", err)
		}
		if cfg, err = cfg.WithJSON(data); err != nil {
			return cfg, fmt.Errorf("BKIND_CONFIG (%s): %w", path, err)
		}
	}

	if inline, ok := lookup("BKIND_CONFIG_JSON"); ok && strings.TrimSpace(inline) != "" {
		merged, err := cfg.WithJSON([]byte(inline))
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

// parseConfig reads one document into a Config with the default settings: the
// document is only the kinds, so the relay-wide half comes from Go. The document
// is the served set, so Validate is what decides whether that is a relay.
func parseConfig(data []byte) (Config, error) {
	cfg := Config{Rules: map[string]*KindRule{}, Settings: DefaultSettings()}
	if err := cfg.applyJSON(data); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// WithJSON applies a document over the receiver: the document is the whole kind
// set, so the kinds it names are served and every other kind is not.
//
// A rule is not patched field by field, and neither is the kind set. It is one
// kind's whole policy, and half of one policy layered on half of another is
// exactly the kind of quiet answer this configuration format exists to avoid: to
// change one setting of a kind, name the whole rule.
func (c Config) WithJSON(data []byte) (Config, error) {
	out := c
	// the rules map is shared by the value copy, and applying a document replaces
	// and removes entries: give the result a map of its own so the receiver is
	// never edited by a call that returned a new Config
	out.Rules = make(map[string]*KindRule, len(c.Rules))
	for key, rule := range c.Rules {
		out.Rules[key] = rule
	}
	if err := out.applyJSON(data); err != nil {
		return c, err
	}
	if err := out.Validate(); err != nil {
		return c, err
	}
	return out, nil
}

// applyJSON makes one document the receiver's kind set. The decoder refuses
// unknown fields at every level, so a typo is an error wherever it sits; a rule a
// document names is a fresh value, which is the "replace, never patch" rule, and
// it comes from the decoder rather than from bookkeeping.
func (c *Config) applyJSON(data []byte) error {
	document, err := decodeDocument(data)
	if err != nil {
		return err
	}
	c.Rules = document
	return nil
}

// decodeDocument reads a policy document: kind number -> whole rule, and nothing
// else. It is the one place that knows the document's shape, so Validate, WithJSON
// and LoadConfig all agree on it.
//
// The top level is decoded as raw values first, so a key that is not a kind number
// is reported as such instead of as a field error inside whatever it holds.
func decodeDocument(data []byte) (map[string]*KindRule, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	document := make(map[string]*KindRule, len(raw))
	for key, value := range raw {
		if _, err := strconv.ParseUint(key, 10, 16); err != nil {
			return nil, fmt.Errorf("document has key %q, which is not a kind number: the document is one rule per kind and nothing else", key)
		}
		if string(bytes.TrimSpace(value)) == "null" {
			return nil, fmt.Errorf("document has a null rule for kind %s: a kind is served by a rule, so there is nothing to delete", key)
		}

		var rule KindRule
		ruleDecoder := json.NewDecoder(bytes.NewReader(value))
		ruleDecoder.DisallowUnknownFields()
		if err := ruleDecoder.Decode(&rule); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		document[key] = &rule
	}
	return document, nil
}

// Validate checks the configuration and normalizes it (nil and empty are the
// same setting). It is run by parseConfig, WithJSON and Wire, so a Config built
// in code cannot skip it.
func (c *Config) Validate() error {
	if len(c.Rules) == 0 {
		return fmt.Errorf("the document is empty: the relay would serve nothing")
	}
	if len(c.Settings.NIP11.ExtraNIPs) == 0 {
		c.Settings.NIP11.ExtraNIPs = nil
	}
	if len(c.Settings.ReadLimits) == 0 {
		c.Settings.ReadLimits = nil
	}
	if len(c.Settings.ConnectionLimits) == 0 {
		c.Settings.ConnectionLimits = nil
	}

	k := c.KindRules()
	if err := k.Validate(); err != nil {
		return err
	}

	for _, key := range sortedRuleKeys(c.Rules) {
		kind64, err := strconv.ParseUint(key, 10, 16)
		if err != nil {
			return fmt.Errorf("document has key %q, which is not a kind number", key)
		}
		kind := uint16(kind64)
		rule := c.Rules[key]
		if rule.Description == "" {
			return fmt.Errorf("rules[%d].description is empty: every served kind says what it is", kind)
		}
		if err := validateFields(&rule.RuleSettings, fmt.Sprintf("rules[%d]", kind)); err != nil {
			return err
		}
	}

	if err := validateRateLimits("read_limits", c.Settings.ReadLimits, "npub", "ip"); err != nil {
		return err
	}
	if err := validateRateLimits("connection_limits", c.Settings.ConnectionLimits, "ip"); err != nil {
		return err
	}

	if c.Settings.NIP11.MaxMessageLength <= 0 || c.Settings.NIP11.MaxSubscriptions <= 0 ||
		c.Settings.NIP11.MaxFilters <= 0 || c.Settings.NIP11.MaxLimit <= 0 {
		return fmt.Errorf("nip11 limits must be positive")
	}
	for _, nip := range c.Settings.NIP11.ExtraNIPs {
		if nip <= 0 {
			return fmt.Errorf("nip11.extra_nips contains %d, which is not a NIP number", nip)
		}
	}

	return nil
}

func sortedRuleKeys(rules map[string]*KindRule) []string {
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// validateFields checks one kind's settings.
func validateFields(f *RuleSettings, where string) error {
	// nil and empty are the same setting, and both mean "none" or "nobody"
	if len(f.RequiredTags) == 0 {
		f.RequiredTags = nil
	}
	if len(f.RateLimits) == 0 {
		f.RateLimits = nil
	}
	if len(f.TagPatterns) == 0 {
		f.TagPatterns = nil
	}
	if len(f.Errors) == 0 {
		f.Errors = nil
	}

	if f.MaxEventSize.Bytes < 0 {
		return fmt.Errorf("%s: max_event_size cannot be negative", where)
	}
	if f.MaxEventContentSize.Bytes < 0 {
		return fmt.Errorf("%s: max_event_content_size cannot be negative", where)
	}
	if f.MaxExpiration.Duration < 0 || f.MaxAge.Duration < 0 || f.MaxFutureAge.Duration < 0 {
		return fmt.Errorf("%s: durations cannot be negative", where)
	}

	if err := validateAllow(where+".write.allow", f.Write.Allow); err != nil {
		return err
	}
	if err := validateAllow(where+".read.allow", f.Read.Allow); err != nil {
		return err
	}

	seenTags := map[string]bool{}
	for _, name := range f.RequiredTags {
		if name == "" {
			return fmt.Errorf("%s: required_tags contains an empty tag name", where)
		}
		if seenTags[name] {
			return fmt.Errorf("%s: required_tags names %q twice", where, name)
		}
		seenTags[name] = true
	}

	for name, pattern := range f.TagPatterns {
		if name == "" {
			return fmt.Errorf("%s: tag_patterns has an empty tag name", where)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%s: tag_patterns[%q]: %q is not a valid regular expression: %v", where, name, pattern, err)
		}
	}

	if f.TagLimits.set() {
		if f.TagLimits.MaxTags <= 0 || f.TagLimits.MaxNameChars <= 0 || f.TagLimits.MaxValueChars <= 0 {
			return fmt.Errorf("%s: tag_limits: when any limit is set, all three must be positive", where)
		}

		// a tag budget smaller than the tags the rule demands itself is a relay
		// that rejects everything: better to say so at startup than to let an
		// operator wonder why nothing publishes
		mandatory := f.RequiredTags
		if len(mandatory) > f.TagLimits.MaxTags {
			return fmt.Errorf("%s: tag_limits.max_tags is %d but %s must be present, so no event could be accepted",
				where, f.TagLimits.MaxTags, quoteList(mandatory))
		}
	}

	if err := validateRateLimits(where+".rate_limits", f.RateLimits, "npub", "ip"); err != nil {
		return err
	}

	for key := range f.Errors {
		if !errorMessageKeys[key] {
			return fmt.Errorf("%s: errors has key %q, which is not one of %s", where, key, strings.Join(sortedErrorKeys(), ", "))
		}
	}

	return nil
}

// quoteList renders tags for a rejection message: `"p", "expiration" and "client"`.
func quoteList(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, strconv.Quote(name))
	}
	switch len(quoted) {
	case 0:
		return "no tag"
	case 1:
		return quoted[0]
	default:
		return strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
	}
}

func sortedErrorKeys() []string {
	keys := make([]string, 0, len(errorMessageKeys))
	for key := range errorMessageKeys {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// validateAllow checks an allow list: "*" alone, or pubkeys. An empty list is
// valid and means nobody.
func validateAllow(name string, allow []string) error {
	if len(allow) == 0 {
		return nil
	}
	if slices.Contains(allow, "*") {
		if len(allow) > 1 {
			return fmt.Errorf("%s: \"*\" cannot be combined with specific pubkeys", name)
		}
		return nil
	}
	for _, key := range allow {
		if !nostr.IsValidPublicKey(key) {
			return fmt.Errorf("%s: %q is not a valid pubkey", name, key)
		}
	}
	return nil
}

func validateRateLimits(name string, limits []RateLimit, scopes ...string) error {
	for i, rl := range limits {
		if !slices.Contains(scopes, rl.Scope) {
			return fmt.Errorf("%s[%d]: scope %q must be %s", name, i, rl.Scope, strings.Join(scopes, " or "))
		}
		if rl.Limit <= 0 {
			return fmt.Errorf("%s[%d]: limit must be positive", name, i)
		}
		if rl.Window.Duration <= 0 {
			return fmt.Errorf("%s[%d]: window %q is not a positive duration", name, i, rl.Window.canonical())
		}
	}
	return nil
}

// Rule returns the kind's rule. A kind the document gave no rule has an empty
// one: nobody may publish it and nobody may read it, which is what "the document
// did not say" has to mean when there is nothing to inherit from.
func (c Config) Rule(kind uint16) *KindRule {
	if rule, ok := c.Rules[strconv.Itoa(int(kind))]; ok && rule != nil {
		return rule
	}
	return &KindRule{}
}

// RulesByKind is Rule for every kind the document serves.
func (c Config) RulesByKind() map[uint16]*KindRule {
	out := make(map[uint16]*KindRule, len(c.Rules))
	for _, kind := range c.KindNumbers() {
		out[kind] = c.Rule(kind)
	}
	return out
}

// KindNumbers is the served set: the document's keys, sorted. It is derived from
// the rules themselves, so there is no whitelist to keep in step with them.
func (c Config) KindNumbers() []uint16 {
	out := make([]uint16, 0, len(c.Rules))
	for key, rule := range c.Rules {
		if rule == nil {
			continue
		}
		kind, err := strconv.ParseUint(key, 10, 16)
		if err != nil {
			continue // Validate names it
		}
		out = append(out, uint16(kind))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// FilterRules are the request-shape policies. They are relay-wide settings, not
// document fields.
type FilterRules struct {
	RejectEmpty  bool
	RejectSearch bool
}

// CountRules is NIP-45. Reject keeps COUNT refused, which is the only safe answer
// for private events; setting it to false serves COUNT and advertises NIP-45.
type CountRules struct {
	Reject bool
}

// NIP11Rules is the relay information document. SupportedNIPs and the limitation
// document are derived from the rest of the Config, so advertising a feature the
// relay does not have takes a deliberate ExtraNIPs entry.
//
// The four positive limits are the only values Go insists on: zero would forbid
// every frame or every subscription, so the Go defaults state them and flags can
// move them.
type NIP11Rules struct {
	Name string
	// Description is generated from the kind list when left empty.
	Description      string
	MaxMessageLength int
	MaxSubscriptions int
	MaxFilters       int
	MaxLimit         int
	// ExtraNIPs is appended to the derived supported_nips list.
	ExtraNIPs []int
}

// JSON renders the configuration as the canonical document a relay reads back:
// every kind's rule in full, and nothing else. This is what the relay prints for
// -print-config, and it is byte-identical to policies/default.json for an
// unconfigured relay.
func (c Config) JSON() ([]byte, error) {
	// a nil slice and an empty one mean the same thing, and "none" reads better
	// than "null" — but an empty allow list is printed as [] because that is what
	// it means: nobody
	document := make(map[string]*KindRule, len(c.Rules))
	for key, rule := range c.Rules {
		if rule == nil {
			continue
		}
		printed := *rule
		printed.Write.Allow = nonNil(printed.Write.Allow)
		printed.Read.Allow = nonNil(printed.Read.Allow)
		printed.RequiredTags = nonNil(printed.RequiredTags)
		printed.RateLimits = nonNil(printed.RateLimits)
		printed.TagPatterns = nonNilMap(printed.TagPatterns)
		printed.Errors = nonNilMap(printed.Errors)
		document[key] = &printed
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return collapseScalarContainers(bytes.TrimRight(buffer.Bytes(), "\n")), nil
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

// ApplyEnv overrides the settings worth a command line: which kinds are served
// (BKIND_KINDS prunes the rules of the kinds it drops) and the NIP-11 name and
// description. Everything else belongs in the document or in the Go defaults.
func (c *Config) ApplyEnv(lookup func(string) (string, bool)) error {
	if raw, ok := lookup("BKIND_KINDS"); ok && strings.TrimSpace(raw) != "" {
		kinds, err := parseKinds("BKIND_KINDS", raw)
		if err != nil {
			return err
		}
		c.SetKinds(kinds)
	}
	if raw, ok := lookup("BKIND_NAME"); ok {
		c.Settings.NIP11.Name = raw
	}
	if raw, ok := lookup("BKIND_DESCRIPTION"); ok {
		c.Settings.NIP11.Description = raw
	}
	return nil
}

// SetKinds narrows the served set to kinds and drops the rules it leaves out, so
// narrowing what is served cannot leave a stale rule behind. The environment and
// the command line both go through it.
func (c *Config) SetKinds(kinds []uint16) {
	c.pruneRules(kinds)
}

// pruneRules deletes the rules of kinds outside keep.
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
