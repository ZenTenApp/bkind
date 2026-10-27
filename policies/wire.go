package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ZenTenApp/bkind"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
)

// Validate checks the configuration and normalizes it (nil and empty are the
// same setting). It is run by LoadConfig and again by Wire, so a Config built
// in code cannot skip it.
func (c *Config) Validate() error {
	if len(c.Kinds.Whitelist) == 0 {
		c.Kinds.Whitelist = nil
	}
	if len(c.NIP11.ExtraNIPs) == 0 {
		c.NIP11.ExtraNIPs = nil
	}
	if len(c.ReadLimits) == 0 {
		c.ReadLimits = nil
	}
	if len(c.ConnectionLimits) == 0 {
		c.ConnectionLimits = nil
	}

	k := c.KindRules()
	if err := k.Validate(); err != nil {
		return err
	}

	// the defaults must themselves be a sane rule: they are what every kind
	// starts from, and a kind that overrides nothing relies on them entirely
	if err := validateFields(&c.RuleSettings, "the top-level defaults"); err != nil {
		return err
	}

	// every rule must be for a served kind, and its effective value — defaults
	// plus its own settings — must make sense
	for _, key := range sortedRuleKeys(c.Rules) {
		if _, err := strconv.ParseUint(key, 10, 16); err != nil {
			return fmt.Errorf("rules has key %q, which is not a kind number", key)
		}
		kind, _ := strconv.ParseUint(key, 10, 16)
		if !k.Has(uint16(kind)) {
			return fmt.Errorf("rules has kind %d, which kinds.whitelist does not include", kind)
		}
		if c.Rules[key] == nil {
			return fmt.Errorf("rules[%d] is null", kind)
		}
		effective := c.EffectiveRule(uint16(kind))
		if err := validateFields(&effective.RuleSettings, fmt.Sprintf("rules[%d] resolved over the defaults", kind)); err != nil {
			return err
		}
		if effective.Shape && ShapeValidator(uint16(kind)) == nil {
			return fmt.Errorf("rules[%d]: shape is true but kind %d has no registered shape validator", kind, kind)
		}
		_ = effective
	}

	for kind, rule := range c.EffectiveRules() {
		if rule.Shape && ShapeValidator(kind) == nil {
			return fmt.Errorf("kind %d resolves with shape: true but has no registered shape validator", kind)
		}
	}

	if err := validateRateLimits("read_limits", c.ReadLimits, "npub", "ip"); err != nil {
		return err
	}
	if err := validateRateLimits("connection_limits", c.ConnectionLimits, "ip"); err != nil {
		return err
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

func errBadPTag(value string) error {
	return fmt.Errorf("p_tag %q must be \"hex\" or empty", value)
}

func sortedRuleKeys(rules map[string]*KindRule) []string {
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// validateFields checks one set of per-kind settings, whatever it came from: the
// top-level defaults or a rule resolved over them.
func validateFields(f *RuleSettings, where string) error {
	// nil and empty are the same setting; normalizing keeps a parsed config
	// comparable to one built in code
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

	if f.PTag != "" && f.PTag != "hex" {
		return fmt.Errorf("%s: %w", where, errBadPTag(f.PTag))
	}
	if f.MaxSize.Bytes < 0 {
		return fmt.Errorf("%s: max_size cannot be negative", where)
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

func sortedErrorKeys() []string {
	keys := make([]string, 0, len(errorMessageKeys))
	for key := range errorMessageKeys {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// validateAllow checks an allow list: "*" alone, or pubkeys.
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

// KindRules derives the gate set every read path answers from. A kind's
// effective rule decides its visibility class: privileged with a "hex" p rule is
// recipient-visible (author and "p"), privileged without one is author-only,
// unprivileged is public within the reader list. A whitelisted kind without a
// rule of its own gets exactly the defaults.
func (c Config) KindRules() KindRules {
	access := make(map[uint16]kindAccess, len(c.Kinds.Whitelist))
	for kind, rule := range c.EffectiveRules() {
		acc := kindAccess{visibility: visibilityAuthorOnly, requireAuth: true}
		if rule != nil {
			switch {
			case rule.Read.Privileged && rule.PTag == "hex":
				acc.visibility = visibilityRecipient
			case rule.Read.Privileged:
				acc.visibility = visibilityAuthorOnly
			default:
				acc.visibility = visibilityPublic
			}
			acc.requireAuth = rule.RequireAuth || rule.Read.Privileged
			if !rule.Read.Allow.Anyone() {
				acc.readers = rule.Read.Allow
			}
		}
		access[kind] = acc
	}
	return newKindRules(c.Kinds.Whitelist, c.Kinds.AllowEphemeral, c.Kinds.RejectUnservedFilters, access)
}

// writePolicy is the per-kind write gate: the checks of the event's own
// effective rule, in the order a client can act on.
func (c Config) writePolicy() func(context.Context, *nostr.Event) (bool, string) {
	byKind := make(map[uint16][]eventCheck, len(c.Kinds.Whitelist))
	for kind, rule := range c.EffectiveRules() {
		if rule == nil {
			continue
		}
		byKind[kind] = rule.checks(kind)
	}

	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		// RestrictKind has already rejected unserved kinds, so a miss here is a
		// whitelisted kind: it runs the defaults
		checks, ok := byKind[uint16(evt.Kind)]
		if !ok {
			return false, ""
		}
		for _, check := range checks {
			if reject, msg := check(ctx, evt); reject {
				return true, msg
			}
		}
		return false, ""
	}
}

// Wire installs the whole policy set on a relay. Every gate that decides which
// kinds are served is derived from the same Config, so the write policy, the
// filter overwrite, the read policy, COUNT, live delivery and NIP-11 cannot
// disagree.
//
// It does not touch the store, the expiration sweeper or ServiceURL: those stay
// explicit in the wiring file.
func (c Config) Wire(relay *bkind.Relay) error {
	if err := c.Validate(); err != nil {
		return err
	}

	k := c.KindRules()

	relay.Negentropy = c.Negentropy

	// ---------------------------------------------------------------- writes
	relay.RejectEvent = append(relay.RejectEvent,
		k.RestrictKind(),
		c.writePolicy(),
	)

	// ----------------------------------------------------------------- reads
	relay.OverwriteFilter = append(relay.OverwriteFilter, k.OverwriteFilters())

	readPolicies := make([]func(context.Context, nostr.Filter) (bool, string), 0, 4)
	readPolicies = append(readPolicies, k.ReadFilter)
	if c.Filters.RejectEmpty {
		readPolicies = append(readPolicies, NoEmptyFilters)
	}
	if c.Filters.RejectSearch {
		readPolicies = append(readPolicies, NoSearchQueries)
	}
	for _, rl := range c.ReadLimits {
		switch rl.Scope {
		case "npub":
			readPolicies = append(readPolicies, FilterAuthedPubKeyRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit))
		case "ip":
			readPolicies = append(readPolicies, FilterIPRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit))
		}
	}
	relay.RejectFilter = append(relay.RejectFilter, readPolicies...)

	if c.Count.Reject {
		relay.RejectCountFilter = append(relay.RejectCountFilter, k.ReadFilter)
	}

	// live delivery does not re-run the filter policies
	relay.PreventBroadcast = append(relay.PreventBroadcast, k.PreventBroadcast)

	var rejectConnection []func(*http.Request) bool
	for _, rl := range c.ConnectionLimits {
		rejectConnection = append(rejectConnection, ConnectionRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit))
	}
	relay.RejectConnection = append(relay.RejectConnection, rejectConnection...)

	// --------------------------------------------------------------- NIP-11
	return c.applyNIP11(relay, k)
}

// applyNIP11 derives the information document from the configuration.
func (c Config) applyNIP11(relay *bkind.Relay, k KindRules) error {
	relay.Info.Name = c.NIP11.Name
	relay.Info.Description = c.NIP11.Description
	if relay.Info.Description == "" {
		relay.Info.Description = c.defaultDescription(k)
	}

	anyExpiration, anyAuth, maxTags, maxContent := false, false, 0, 0
	for _, rule := range c.EffectiveRules() {
		if rule == nil {
			continue
		}
		if slices.Contains(rule.RequiredTags, "expiration") || rule.MaxExpiration.Duration > 0 {
			anyExpiration = true
		}
		if rule.RequireAuth {
			anyAuth = true
		}
		if rule.TagLimits.MaxTags > maxTags {
			maxTags = rule.TagLimits.MaxTags
		}
		if rule.MaxSize.Bytes > maxContent {
			maxContent = rule.MaxSize.Bytes
		}
	}

	nips := map[int]bool{11: true}
	for _, kind := range k.Sorted() {
		switch kind {
		case 4:
			nips[4] = true // encrypted direct messages
		case 5:
			nips[9] = true // event deletion
		case 62:
			nips[62] = true // request to vanish
		}
	}
	if anyExpiration {
		nips[40] = true
	}
	if anyAuth {
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
		MaxEventTags:     maxTags,
		MaxContentLength: maxContent,
		MaxSubscriptions: c.NIP11.MaxSubscriptions,
		MaxFilters:       c.NIP11.MaxFilters,
		MaxLimit:         c.NIP11.MaxLimit,
		AuthRequired:     anyAuth,
		RestrictedWrites: anyAuth,
	}

	return nil
}

// defaultDescription is generated from the kind list, so the NIP-11 document
// cannot claim "Kind 4 only" after the whitelist changed.
func (c Config) defaultDescription(k KindRules) string {
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

// strictSections is the JSON schema an explicit configuration has to satisfy:
// every field of every relay-wide section must be present. It is written out by
// hand rather than reflected so that adding a field to Config without adding it
// here is a compile-time neighbour in the same file, not a silent gap —
// TestStrictSchemaCoversEveryField keeps the two honest.
var strictSections = map[string][]string{
	"kinds":   {"whitelist", "allow_ephemeral", "reject_unserved_filters"},
	"filters": {"reject_empty", "reject_search"},
	"count":   {"reject"},
	"nip11":   {"name", "description", "max_message_length", "max_subscriptions", "max_filters", "max_limit", "extra_nips"},
}

// strictTopLevel is every key an explicit document must carry: the relay-wide
// sections and the per-kind defaults. A rule body is deliberately not on this
// list — a rule says only what it changes, and the defaults are what it changes
// them from.
var strictTopLevel = append(append([]string{}, documentSections...), ruleFieldNames...)

// strictRuleKeys is the complete set of settings a rule body may name. It is the
// same list as the defaults: one set of names, two places to use it.
var strictRuleKeys = ruleFieldNames

// strictGateKeys is the shape of the write and read gates.
var strictGateKeys = map[string][]string{
	"write": {"allow"},
	"read":  {"allow", "privileged"},
}

// strictTagLimitKeys is the shape of a tag_limits object.
var strictTagLimitKeys = []string{"max_tags", "max_tag_name_chars", "max_tag_value_chars"}

// strictRateLimitKeys is the shape of every entry of a rate_limits list.
var strictRateLimitKeys = []string{"scope", "limit", "window"}

// checkComplete reports the first field a strict-mode document leaves out. It
// works on the raw JSON because presence is exactly what a decoded struct
// loses: an absent "require_auth" and an explicit false decode to the same
// value, and for a relay the difference between "I chose this" and "I never
// said" is the whole point.
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

	// a rule body is sparse by design, but it must be an object, and every
	// setting it names must be a setting
	var rules map[string]json.RawMessage
	if err := json.Unmarshal(top["rules"], &rules); err != nil {
		return fmt.Errorf("incomplete configuration: %q must be an object keyed by kind number", "rules")
	}
	for _, key := range sortedKeys(rules) {
		if err := checkRuleKnown(key, rules[key]); err != nil {
			return err
		}
	}

	// the same for the rate limit lists, whose entries sit inside arrays
	for _, name := range []string{"read_limits", "connection_limits"} {
		var limits []map[string]json.RawMessage
		if err := json.Unmarshal(top[name], &limits); err != nil {
			return fmt.Errorf("incomplete configuration: %q must be an array", name)
		}
		for i, entry := range limits {
			for _, field := range strictRateLimitKeys {
				if _, ok := entry[field]; !ok {
					return missingField(fmt.Sprintf("%s[%d].%s", name, i, field))
				}
			}
		}
	}
	if raw, ok := top["rate_limits"]; ok && strings.TrimSpace(string(raw)) != "null" {
		var limits []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &limits); err != nil {
			return fmt.Errorf("incomplete configuration: %q must be an array", "rate_limits")
		}
		for i, entry := range limits {
			for _, field := range strictRateLimitKeys {
				if _, ok := entry[field]; !ok {
					return missingField(fmt.Sprintf("rate_limits[%d].%s", i, field))
				}
			}
		}
	}

	return nil
}

// checkRuleKnown refuses a rule body that names something that is not a setting,
// and checks the completeness of the objects nested in it.
func checkRuleKnown(kind string, body json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return fmt.Errorf("incomplete configuration: rules.%s must be an object", kind)
	}
	for name := range fields {
		canonical := name
		if alias, ok := ruleAliases[name]; ok {
			canonical = alias
		}
		if canonical != "description" && !slices.Contains(ruleFieldNames, canonical) && !slices.Contains(ruleOnlyNames, canonical) {
			return fmt.Errorf("unknown field %q in rules.%s", name, kind)
		}
	}

	for gate, keys := range strictGateKeys {
		raw, ok := fields[gate]
		if !ok {
			continue
		}
		var g map[string]json.RawMessage
		if err := json.Unmarshal(raw, &g); err != nil {
			return fmt.Errorf("incomplete configuration: rules.%s.%s must be an object", kind, gate)
		}
		for _, name := range keys {
			if _, ok := g[name]; !ok {
				return missingField("rules." + kind + "." + gate + "." + name)
			}
		}
	}

	if raw, ok := fields["tag_limits"]; ok {
		var limits map[string]json.RawMessage
		if err := json.Unmarshal(raw, &limits); err != nil {
			return fmt.Errorf("incomplete configuration: rules.%s.tag_limits must be an object", kind)
		}
		for _, name := range strictTagLimitKeys {
			if _, ok := limits[name]; !ok {
				return missingField("rules." + kind + ".tag_limits." + name)
			}
		}
	}

	if raw, ok := fields["rate_limits"]; ok {
		var limits []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &limits); err != nil {
			return fmt.Errorf("incomplete configuration: rules.%s.rate_limits must be an array", kind)
		}
		for i, entry := range limits {
			for _, name := range strictRateLimitKeys {
				if _, ok := entry[name]; !ok {
					return missingField(fmt.Sprintf("rules.%s.rate_limits[%d].%s", kind, i, name))
				}
			}
		}
	}

	return nil
}

func missingField(name string) error {
	return fmt.Errorf("incomplete configuration: %q is missing, and strict mode (BKIND_CONFIG_STRICT) requires every field — run with -print-config to get a complete document", name)
}
