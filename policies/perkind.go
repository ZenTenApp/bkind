package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// eventCheck is one write policy of one kind: reject with a message, or pass.
type eventCheck func(context.Context, *nostr.Event) (bool, string)

// AllowList is who may do a thing: "*" for anyone, or an explicit list of
// pubkeys. An absent or empty list means anyone, so a rule that only says what
// is limited does not have to repeat "and everyone may try".
type AllowList []string

// Anyone reports whether the list is open: no list, or the "*" wildcard.
func (g AllowList) Anyone() bool {
	return len(g) == 0 || (len(g) == 1 && g[0] == "*")
}

// Includes reports whether pubkey passes the list. An open list includes
// everyone.
func (g AllowList) Includes(pubkey string) bool {
	return g.Anyone() || slices.Contains(g, pubkey)
}

func (g *AllowList) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		return nil
	}

	// "*" is the common case; a list is the escape hatch
	if raw[0] == '"' {
		var name string
		if err := json.Unmarshal(data, &name); err != nil {
			return err
		}
		*g = AllowList{name}
		return nil
	}

	var keys []string
	if err := strictUnmarshal(data, &keys); err != nil {
		return fmt.Errorf("allow must be \"*\" or a list of pubkeys: %w", err)
	}
	*g = keys
	return nil
}

// WriteGate is who may publish a kind.
type WriteGate struct {
	Allow AllowList `json:"allow"`
}

// ReadGate is the read side of a kind: who may query it, and whether the events
// are privileged. Privileged events are only visible to their author (and, when
// the kind carries a "p" tag, its recipient); unprivileged events are public
// within the allow list.
type ReadGate struct {
	Allow      AllowList `json:"allow"`
	Privileged bool      `json:"privileged"`
}

// TagLimits is the shape of the tag list of a kind.
type TagLimits struct {
	MaxTags       int `json:"max_tags"`
	MaxNameChars  int `json:"max_tag_name_chars"`
	MaxValueChars int `json:"max_tag_value_chars"`
}

// set reports whether any limit is configured. A zero TagLimits means "no
// check", not "zero tags allowed".
func (t TagLimits) set() bool {
	return t.MaxTags > 0 || t.MaxNameChars > 0 || t.MaxValueChars > 0
}

// RateLimit is one token bucket in the per-kind dialect: limit events per
// window, per scope. Scope is "npub" (the author's key) or "ip". Where the
// entry sits decides what it limits: under a kind rule it limits writes of that
// kind, under "reads" it limits REQs, under "connections" it limits connects.
// The bucket size is the limit itself — the dialect has no separate burst field.
type RateLimit struct {
	Scope  string   `json:"scope"`
	Limit  int      `json:"limit"`
	Window Duration `json:"window"`
}

// strictUnmarshal decodes with unknown fields refused, so a typo inside a
// nested rule object is an error like a typo anywhere else.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// errorMessageKeys are the rejection templates a kind rule can override. The
// keys are stable API: a client can rely on the default wording changing
// between versions, but not on which rejections exist.
var errorMessageKeys = map[string]bool{
	"write_denied":  true,
	"auth_required": true,
	"too_old":       true,
	"in_future":     true,
	"expiration":    true,
	"missing_tag":   true,
	"p_tag":         true,
	"tag_pattern":   true,
	"max_size":      true,
	"tag_limits":    true,
	"rate_limited":  true,
	"shape":         true,
}

// render fills the {placeholders} of a custom rejection message: "blocked: event
// exceeds size limit ({size} > {limit})".
func render(tpl string, vars map[string]string) string {
	out := tpl
	for key, value := range vars {
		out = strings.ReplaceAll(out, "{"+key+"}", value)
	}
	return out
}

// withTemplate wraps a check so a rejection uses the rule's custom message when
// it has one, and the built-in message when it does not.
func (r *KindRule) withTemplate(key string, inner eventCheck, vars func(*nostr.Event) map[string]string) eventCheck {
	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		reject, msg := inner(ctx, evt)
		if !reject {
			return false, ""
		}
		tpl, ok := r.Errors[key]
		if !ok {
			return true, msg
		}

		values := vars(evt)
		if values == nil {
			values = map[string]string{}
		}
		// {detail} is always available: the built-in message, so a template can
		// wrap the specific reason instead of replacing it with a generic one
		if _, ok := values["detail"]; !ok {
			values["detail"] = msg
		}
		return true, render(tpl, values)
	}
}

// writeAllowCheck rejects events from keys outside the write gate.
func (r *KindRule) writeAllowCheck() eventCheck {
	if r.Write.Allow.Anyone() {
		return nil
	}
	inner := func(_ context.Context, evt *nostr.Event) (bool, string) {
		if !r.Write.Allow.Includes(evt.PubKey) {
			return true, "blocked: your key is not allowed to publish this kind on this relay"
		}
		return false, ""
	}
	return r.withTemplate("write_denied", inner, func(*nostr.Event) map[string]string { return nil })
}

// authCheck is NIP-42 for one kind: the author of the event must be the
// authenticated key.
func (r *KindRule) authCheck() eventCheck {
	if !r.RequireAuth {
		return nil
	}
	return r.withTemplate("auth_required", RequireAuthedAuthor, func(*nostr.Event) map[string]string { return nil })
}

// ageChecks bound created_at: not older than MaxAge, not further in the future
// than MaxFutureAge (clock skew, not time travel).
func (r *KindRule) ageChecks() (out []eventCheck) {
	if r.MaxAge.Duration > 0 {
		max := r.MaxAge
		inner := func(_ context.Context, evt *nostr.Event) (bool, string) {
			if nostr.Now()-evt.CreatedAt > nostr.Timestamp(max.Seconds()) {
				return true, fmt.Sprintf("invalid: event is too old (max %s)", max.canonical())
			}
			return false, ""
		}
		out = append(out, r.withTemplate("too_old", inner, func(*nostr.Event) map[string]string {
			return map[string]string{"limit": max.canonical()}
		}))
	}
	if r.MaxFutureAge.Duration > 0 {
		max := r.MaxFutureAge
		inner := func(_ context.Context, evt *nostr.Event) (bool, string) {
			if evt.CreatedAt-nostr.Now() > nostr.Timestamp(max.Seconds()) {
				return true, fmt.Sprintf("invalid: event is too far in the future (max %s)", max.canonical())
			}
			return false, ""
		}
		out = append(out, r.withTemplate("in_future", inner, func(*nostr.Event) map[string]string {
			return map[string]string{"limit": max.canonical()}
		}))
	}
	return out
}

// expirationEventCheck enforces NIP-40 for one kind. When required is set the
// event must carry exactly one valid "expiration" tag in the future; when max is
// set the tag, mandatory or not, may not point further ahead than max.
func expirationEventCheck(required bool, max time.Duration) eventCheck {
	maxSeconds := nostr.Timestamp(max.Seconds())

	return func(_ context.Context, evt *nostr.Event) (bool, string) {
		var raw string
		count := 0
		for _, tag := range evt.Tags {
			if len(tag) > 0 && tag[0] == "expiration" {
				count++
				if len(tag) > 1 {
					raw = tag[1]
				}
			}
		}

		switch {
		case count == 0:
			if !required {
				return false, ""
			}
			return true, `invalid: missing mandatory "expiration" tag`
		case count > 1:
			return true, `invalid: multiple "expiration" tags`
		}

		expiresAt, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return true, `invalid: "expiration" tag is not a unix timestamp`
		}

		now := nostr.Now()
		if nostr.Timestamp(expiresAt) <= now {
			return true, "invalid: event is already expired"
		}
		if max > 0 && nostr.Timestamp(expiresAt) > now+maxSeconds {
			return true, fmt.Sprintf("invalid: expiration is too far in the future (max %s)", Duration{max}.canonical())
		}

		return false, ""
	}
}

// expirationCheck is the NIP-40 rule of this kind: mandatory when "expiration"
// is in required_tags, capped by max_expiration either way.
func (r *KindRule) expirationCheck() eventCheck {
	required := slices.Contains(r.RequiredTags, "expiration")
	if !required && r.MaxExpiration.Duration <= 0 {
		return nil
	}
	max := r.MaxExpiration.Duration
	inner := expirationEventCheck(required, max)
	return r.withTemplate("expiration", inner, func(*nostr.Event) map[string]string {
		return map[string]string{"limit": Duration{max}.canonical()}
	})
}

// requiredTagChecks reject events that do not carry each required tag exactly
// once, with a non-empty value. "expiration" is enforced by expirationCheck,
// which knows it is a timestamp and not a label.
func (r *KindRule) requiredTagChecks() (out []eventCheck) {
	for _, name := range r.RequiredTags {
		if name == "expiration" {
			continue
		}
		inner := RequireTag(name)
		out = append(out, r.withTemplate("missing_tag", inner, func(*nostr.Event) map[string]string {
			return map[string]string{"tag": name}
		}))
	}
	return out
}

// pTagCheck enforces the "p" tag of a direct-message kind: exactly one, a valid
// pubkey, and not the author. It is what makes a privileged kind
// recipient-visible.
func (r *KindRule) pTagCheck() eventCheck {
	if r.PTag != "hex" {
		return nil
	}
	inner := func(_ context.Context, evt *nostr.Event) (bool, string) {
		count := 0
		for _, tag := range evt.Tags {
			if len(tag) == 0 || tag[0] != "p" {
				continue
			}
			count++
			if len(tag) < 2 || !nostr.IsValidPublicKey(tag[1]) {
				return true, `invalid: "p" tag must be a 64-character hex pubkey`
			}
			if tag[1] == evt.PubKey {
				return true, `invalid: events of this kind cannot be addressed to their own author`
			}
		}
		if count != 1 {
			return true, `invalid: events of this kind must have exactly one "p" tag`
		}
		return false, ""
	}
	return r.withTemplate("p_tag", inner, func(*nostr.Event) map[string]string { return nil })
}

// tagPatternCheck enforces the per-tag regular expressions: a "d" pattern of
// "^[0-9]{16}$" means every "d" tag value must match. Whether the tag must be
// present at all is required_tags' job; a pattern only bounds the values.
func (r *KindRule) tagPatternCheck() eventCheck {
	if len(r.TagPatterns) == 0 {
		return nil
	}

	// the patterns are compiled once per wiring, not once per event
	compiled := make(map[string]*regexp.Regexp, len(r.TagPatterns))
	for name, pattern := range r.TagPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// Validate refuses an invalid pattern before Wire can reach it
			continue
		}
		compiled[name] = re
	}

	inner := func(_ context.Context, evt *nostr.Event) (bool, string) {
		for _, tag := range evt.Tags {
			if len(tag) < 2 {
				continue
			}
			re, ok := compiled[tag[0]]
			if !ok {
				continue
			}
			if !re.MatchString(tag[1]) {
				return true, fmt.Sprintf("invalid: %q tag does not match its pattern %s", tag[0], re)
			}
		}
		return false, ""
	}
	return r.withTemplate("tag_pattern", inner, func(evt *nostr.Event) map[string]string {
		vars := map[string]string{}
		for _, tag := range evt.Tags {
			if len(tag) < 2 {
				continue
			}
			if pattern, ok := r.TagPatterns[tag[0]]; ok {
				if re := compiled[tag[0]]; re != nil && !re.MatchString(tag[1]) {
					vars["tag"], vars["pattern"], vars["value"] = tag[0], pattern, tag[1]
					break
				}
			}
		}
		return vars
	})
}

// maxSizeCheck is the content limit of this kind, in bytes of content.
func (r *KindRule) maxSizeCheck() eventCheck {
	if r.MaxSize.Bytes <= 0 {
		return nil
	}
	limit := r.MaxSize.Bytes
	inner := MaxContentLen(limit)
	return r.withTemplate("max_size", inner, func(evt *nostr.Event) map[string]string {
		return map[string]string{
			"size":  strconv.Itoa(len(evt.Content)),
			"limit": strconv.Itoa(limit),
		}
	})
}

// tagLimitsCheck is the tag-shape limit of this kind.
func (r *KindRule) tagLimitsCheck() eventCheck {
	if !r.TagLimits.set() {
		return nil
	}
	limits := r.TagLimits
	inner := TagShapeLimits(limits.MaxTags, limits.MaxNameChars, limits.MaxValueChars)
	return r.withTemplate("tag_limits", inner, func(_ *nostr.Event) map[string]string { return nil })
}

// shapeCheck runs the registered structural validator for this kind, such as
// ValidateKind4Shape. The validators are Go functions in the registry because a
// JSON document cannot carry code; the rule decides only whether it runs.
func (r *KindRule) shapeCheck(kind uint16) eventCheck {
	if !r.Shape {
		return nil
	}
	validator := ShapeValidator(kind)
	if validator == nil {
		return nil
	}
	inner := eventCheck(validator)
	return r.withTemplate("shape", inner, func(_ *nostr.Event) map[string]string { return nil })
}

// rateLimitChecks are the write limits of this kind, keyed by the author's
// npub or by the remote IP.
func (r *KindRule) rateLimitChecks() (out []eventCheck) {
	for _, rl := range r.RateLimits {
		var inner eventCheck
		switch rl.Scope {
		case "npub":
			inner = EventPubKeyRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit)
		case "ip":
			inner = EventIPRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit)
		default:
			continue // Validate refuses this; never reached
		}
		out = append(out, r.withTemplate("rate_limited", inner, func(*nostr.Event) map[string]string { return nil }))
	}
	return out
}

// checks assembles the write policy of one kind, in the order the rejections
// should reach a client: who may write, whether they are who they say, whether
// the event is on time, then what it must carry. The size limits come before
// the structural rules — an oversized event should hear about its size, not
// about a tag it never got to write — and the rate limits come last.
func (r *KindRule) checks(kind uint16) []eventCheck {
	out := []eventCheck{}
	if check := r.writeAllowCheck(); check != nil {
		out = append(out, check)
	}
	if check := r.authCheck(); check != nil {
		out = append(out, check)
	}
	out = append(out, r.ageChecks()...)
	if check := r.expirationCheck(); check != nil {
		out = append(out, check)
	}
	out = append(out, r.requiredTagChecks()...)
	if check := r.tagPatternCheck(); check != nil {
		out = append(out, check)
	}
	if check := r.maxSizeCheck(); check != nil {
		out = append(out, check)
	}
	if check := r.tagLimitsCheck(); check != nil {
		out = append(out, check)
	}
	if check := r.pTagCheck(); check != nil {
		out = append(out, check)
	}
	if check := r.shapeCheck(kind); check != nil {
		out = append(out, check)
	}
	out = append(out, r.rateLimitChecks()...)
	return out
}
