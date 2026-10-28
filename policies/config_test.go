package policies_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ZenTenApp/bkind"
	"github.com/ZenTenApp/bkind/policies"
	"github.com/nbd-wtf/go-nostr"
)

func envFunc(vars map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
}

// wire installs a config on a fresh relay and returns the relay (whose policy
// hooks are directly callable) and the derived gate set.
func wire(t *testing.T, cfg policies.Config) (*bkind.Relay, policies.KindRules) {
	t.Helper()
	relay := bkind.NewRelay()
	if err := cfg.Wire(relay); err != nil {
		t.Fatalf("failed to wire: %v", err)
	}
	return relay, cfg.KindRules()
}

// writePolicy returns the per-kind write gate of a wired relay: RejectEvent[0]
// is the whitelist gate, RejectEvent[1] the per-kind checks.
func writePolicy(relay *bkind.Relay) func(context.Context, *nostr.Event) (bool, string) {
	return relay.RejectEvent[len(relay.RejectEvent)-1]
}

func aliceCtx() context.Context {
	return bkind.WithAuthenticatedPubKey(context.Background(), aliceKey)
}

// nearExpiration is a valid NIP-40 tag inside the default 75h cap.
func nearExpiration() nostr.Tag {
	return nostr.Tag{"expiration", strconv.FormatInt(int64(nostr.Now()+3600), 10)}
}

// extraTags builds n filler tags, for the tag-count limits.
func extraTags(n int) nostr.Tags {
	tags := make(nostr.Tags, 0, n)
	for i := 0; i < n; i++ {
		tags = append(tags, nostr.Tag{"t", "filler"})
	}
	return tags
}

// the test keys are real pubkeys, because allow lists and "p" tags validate
// them as secp256k1 points, not just as hex
var (
	aliceSK     = nostr.GeneratePrivateKey()
	aliceKey, _ = nostr.GetPublicKey(aliceSK)
	bobSK       = nostr.GeneratePrivateKey()
	bobKey, _   = nostr.GetPublicKey(bobSK)
	carolSK     = nostr.GeneratePrivateKey()
	carolKey, _ = nostr.GetPublicKey(carolSK)
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := policies.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default config must be valid: %v", err)
	}

	if got := cfg.Kinds.Whitelist; len(got) != 3 || got[0] != 4 || got[1] != 5 || got[2] != 62 {
		t.Fatalf("default whitelist is %v, want [4 5 62]", got)
	}
	for _, kind := range []uint16{4, 5, 62} {
		rule := cfg.Rule(kind)
		if rule == nil {
			t.Fatalf("the default config has no rule for kind %d", kind)
		}
		if !rule.RequireAuth || !rule.Read.Privileged {
			t.Fatalf("kind %d must be authenticated and privileged: %+v", kind, rule)
		}
		if rule.MaxEventContentSize.Bytes != 4096 {
			t.Fatalf("kind %d max_event_content_size is %d, want 4096", kind, rule.MaxEventContentSize.Bytes)
		}
		if rule.MaxExpiration.Duration != 75*time.Hour {
			t.Fatalf("kind %d max_expiration is %v, want 75h", kind, rule.MaxExpiration.Duration)
		}
		if len(rule.RequiredTags) != 2 || rule.RequiredTags[0] != "expiration" || rule.RequiredTags[1] != "client" {
			t.Fatalf("kind %d required_tags are %v", kind, rule.RequiredTags)
		}
	}
	if cfg.Rule(4).PTag != "hex" {
		t.Fatal("kind 4 is the one kind with a p rule in the defaults")
	}
	if !cfg.Count.Reject || cfg.Negentropy {
		t.Fatalf("the default must stay COUNT-free and negentropy-free: %+v", cfg)
	}
}

// A document replaces the sections and the rules it names, and nothing else. A
// rule is never merged field by field into anything: it is one kind's whole
// policy, so what the document left out is zero.
func TestConfigDocumentReplacesWhatItNames(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"whitelist": [4, 1059]},
		"rules": {
			"4": {"max_event_content_size": 512},
			"1059": {"description": "gift wraps", "p_tag": "hex"}
		}
	}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if got := cfg.Kinds.Whitelist; len(got) != 2 || got[1] != 1059 {
		t.Fatalf("whitelist is %v, want [4 1059]", got)
	}

	// the rule is the document's rule, not a patch of the old one
	rule4 := cfg.Rule(4)
	if rule4.MaxEventContentSize.Bytes != 512 {
		t.Fatalf("kind 4 max_event_content_size is %d, want 512", rule4.MaxEventContentSize.Bytes)
	}
	if rule4.RequireAuth || rule4.MaxExpiration.Duration != 0 || rule4.PTag != "" || len(rule4.Write.Allow) != 0 {
		t.Fatalf("the named rule kept settings it did not say: %+v", rule4)
	}

	// a new kind is the same thing: only what the document says
	rule1059 := cfg.Rule(1059)
	if rule1059.PTag != "hex" || rule1059.Description != "gift wraps" || rule1059.RequireAuth {
		t.Fatalf("kind 1059 rule is %+v", rule1059)
	}

	// the rules of the kinds the new whitelist dropped are pruned
	for _, key := range []string{"5", "62"} {
		if cfg.Rules[key] != nil {
			t.Fatalf("kind %s still has a rule although it is no longer served", key)
		}
	}

	// sections absent from the document keep their previous value
	if cfg.ReadLimits == nil || cfg.NIP11.MaxLimit != 500 {
		t.Fatalf("untouched sections were lost: %+v", cfg)
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	_, err := policies.DefaultConfig().WithJSON([]byte(`{"contnet": {"max": 1}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a typo must be an error, got %v", err)
	}

	_, err = policies.DefaultConfig().WithJSON([]byte(`{"rules": {"4": {"size_limitt": 1}}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a typo inside a rule must be an error, got %v", err)
	}
}

// A document can take a rule away without taking the kind away: null means "this
// kind has no rule", and the kind is then served with the empty rule.
func TestNullRuleDeletes(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{"rules": {"4": null}}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if _, ok := cfg.Rules["4"]; ok {
		t.Fatalf("kind 4 still has a rule: %+v", cfg.Rules["4"])
	}
	if rule := cfg.Rule(4); !rule.Read.Allow.Nobody() || rule.RequireAuth {
		t.Fatalf("a deleted rule must read as the empty rule: %+v", rule)
	}

	// the kind is still served, and served to nobody
	relay, rules := wire(t, cfg)
	write := writePolicy(relay)
	evt := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "x"}
	if reject, _ := write(aliceCtx(), evt); !reject {
		t.Fatal("a kind with no rule must let nobody publish")
	}
	if _, msg := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{4}, Authors: []string{aliceKey}}); msg == "" {
		t.Fatal("a kind with no rule must let nobody read")
	}
}

// WithJSON returns a new Config: the one it was called on is not edited, even
// though applying a document prunes rules and replaces them.
func TestWithJSONLeavesTheReceiverAlone(t *testing.T) {
	base := policies.DefaultConfig()
	before := len(base.Rules)

	if _, err := base.WithJSON([]byte(`{"kinds": {"whitelist": [4]}, "rules": {"4": {"description": "only one"}}}`)); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(base.Rules) != before || base.Rule(4).Description == "only one" {
		t.Fatalf("WithJSON edited the receiver: %+v", base.Rules)
	}
}

// There is one spelling. The old summary dialect — "kind" for the section,
// kind numbers at the top level, and the short field names — is gone, and every
// one of those names is now an unknown field rather than a synonym.
func TestSummarySpellingsAreRejected(t *testing.T) {
	cases := map[string]string{
		`{"kind": {"whitelist": [4]}}`:                                      `unknown field "kind"`,
		`{"kinds": {"whitelist": [4]}, "4": {"max_event_content_size": 1}}`: `unknown field "4"`,
		`{"rules": {"4": {"size_limit": 4096}}}`:                            `unknown field "size_limit"`,
		`{"rules": {"4": {"must_have_tags": ["p"]}}}`:                       `unknown field "must_have_tags"`,
		`{"rules": {"4": {"max_expiry_duration": "P3D"}}}`:                  `unknown field "max_expiry_duration"`,
		`{"rules": {"4": {"identifier_regex": "^k$"}}}`:                     `unknown field "identifier_regex"`,
		`{"rules": {"4": {"privileged": true}}}`:                            `unknown field "privileged"`,
	}
	for document, want := range cases {
		_, err := policies.DefaultConfig().WithJSON([]byte(document))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s was not refused as %q: %v", document, want, err)
		}
	}
}

// The canonical spelling of the same rule: "kinds", "rules", "read.privileged",
// "max_event_content_size", "max_expiration" and "required_tags".
func TestCanonicalRuleSpelling(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"whitelist": [4, 1059]},
		"rules": {
			"4": {
				"description": "Nostr DM events",
				"read": {"allow": "*", "privileged": true},
				"max_event_content_size": "4KB",
				"max_age_of_event": 3600,
				"max_age_event_in_future": 60,
				"max_expiration": "72h",
				"required_tags": ["p", "expiration", "client"]
			}
		}
	}`))
	if err != nil {
		t.Fatalf("the canonical document does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the canonical document does not validate: %v", err)
	}

	rule := cfg.Rule(4)
	if rule.MaxEventContentSize.Bytes != 4096 {
		t.Fatalf("4KB did not parse: %d", rule.MaxEventContentSize.Bytes)
	}
	if rule.MaxExpiration.Duration != 72*time.Hour {
		t.Fatalf("72h did not parse: %v", rule.MaxExpiration.Duration)
	}
	if rule.MaxAge.Duration != time.Hour || rule.MaxFutureAge.Duration != time.Minute {
		t.Fatalf("the age window did not parse: %+v", rule)
	}
	if !rule.Read.Privileged {
		t.Fatal("read.privileged did not parse")
	}
	if !reflect.DeepEqual(rule.RequiredTags, []string{"p", "expiration", "client"}) {
		t.Fatalf("required_tags did not land: %v", rule.RequiredTags)
	}

	// a kind whitelisted with no rule of its own keeps the defaults
	if _, ok := cfg.Rules["1059"]; ok {
		t.Fatal("kind 1059 got a rule it was never given")
	}
}

func TestDurationAndSizeNotations(t *testing.T) {
	for _, tc := range []struct {
		json string
		want time.Duration
	}{
		{`3600`, time.Hour},
		{`"1h"`, time.Hour},
		{`"1d"`, 24 * time.Hour},
		{`"P3D"`, 72 * time.Hour},
		{`"PT75H"`, 75 * time.Hour},
		{`"P3DT12H"`, 84 * time.Hour},
		{`"1h30m"`, 90 * time.Minute},
	} {
		var d policies.Duration
		if err := json.Unmarshal([]byte(tc.json), &d); err != nil {
			t.Fatalf("%s does not parse: %v", tc.json, err)
		}
		if d.Duration != tc.want {
			t.Fatalf("%s parsed as %v, want %v", tc.json, d.Duration, tc.want)
		}
	}

	for _, tc := range []struct {
		json string
		want int
	}{
		{`4096`, 4096},
		{`"4KB"`, 4096},
		{`"4kb"`, 4096},
		{`"512B"`, 512},
		{`"2MB"`, 2 * 1024 * 1024},
	} {
		var s policies.Size
		if err := json.Unmarshal([]byte(tc.json), &s); err != nil {
			t.Fatalf("%s does not parse: %v", tc.json, err)
		}
		if s.Bytes != tc.want {
			t.Fatalf("%s parsed as %d, want %d", tc.json, s.Bytes, tc.want)
		}
	}

	// junk is refused at load, not at wire time
	var d policies.Duration
	if err := json.Unmarshal([]byte(`"75"`), &d); err == nil {
		t.Fatal(`"75" is not a duration and must be refused`)
	}
	if err := json.Unmarshal([]byte(`"P3W"`), &d); err == nil {
		t.Fatal(`"P3W" is not a supported ISO-8601 span`)
	}
	var s policies.Size
	if err := json.Unmarshal([]byte(`"4KM"`), &s); err == nil {
		t.Fatal(`"4KM" is not a size`)
	}
}

func TestConfigEnvOverrides(t *testing.T) {
	cfg, err := policies.LoadConfig(envFunc(map[string]string{
		"BKIND_KINDS": "4,1059",
		"BKIND_NAME":  "test relay",
	}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if got := cfg.Kinds.Whitelist; len(got) != 2 || got[0] != 4 || got[1] != 1059 {
		t.Fatalf("whitelist is %v", got)
	}
	// the rules of the dropped kinds were pruned with the whitelist
	for _, key := range []string{"5", "62"} {
		if cfg.Rules[key] != nil {
			t.Fatalf("kind %s kept its rule after the whitelist dropped it", key)
		}
	}
	if cfg.NIP11.Name != "test relay" {
		t.Fatalf("BKIND_NAME not applied: %q", cfg.NIP11.Name)
	}
}

func TestConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, []byte(`{"rules": {"4": {"max_event_content_size": 100}}, "nip11": {"name": "from file"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": path}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if cfg.Rule(4).MaxEventContentSize.Bytes != 100 || cfg.NIP11.Name != "from file" {
		t.Fatalf("file values not applied: %+v", cfg)
	}

	// the environment still wins over the file
	cfg, err = policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": path, "BKIND_KINDS": "4"}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if len(cfg.Kinds.Whitelist) != 1 || cfg.Kinds.Whitelist[0] != 4 {
		t.Fatalf("BKIND_KINDS did not override the file: %v", cfg.Kinds.Whitelist)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*policies.Config)
		reason string
	}{
		{
			name:   "no kinds",
			mutate: func(c *policies.Config) { c.Kinds.Whitelist = nil },
			reason: "serve nothing",
		},
		{
			name: "a rule for an unserved kind",
			mutate: func(c *policies.Config) {
				c.Rules["7"] = &policies.KindRule{}
			},
			reason: "kinds.whitelist does not include",
		},
		{
			name: "ephemeral kind without allow_ephemeral",
			mutate: func(c *policies.Config) {
				c.Kinds.Whitelist = []uint16{4, 20001}
			},
			reason: "ephemeral",
		},
		{
			name: "a rule key that is not a kind",
			mutate: func(c *policies.Config) {
				c.Rules["dm"] = &policies.KindRule{}
				c.Kinds.Whitelist = append(c.Kinds.Whitelist, 0)
				c.Rules["0"] = nil
				delete(c.Rules, "0")
				c.Kinds.Whitelist = c.Kinds.Whitelist[:len(c.Kinds.Whitelist)-1]
				c.Kinds.Whitelist = append([]uint16{}, c.Kinds.Whitelist...)
			},
			reason: "not a kind number",
		},
		{
			name: "a bad p_tag value",
			mutate: func(c *policies.Config) {
				c.Rules["4"].PTag = "base64"
			},
			reason: `must be "hex"`,
		},
		{
			name: "a bad write allow list",
			mutate: func(c *policies.Config) {
				c.Rules["4"].Write.Allow = policies.AllowList{"*", "abc"}
			},
			reason: `cannot be combined`,
		},
		{
			name: "a pubkey that is not a pubkey",
			mutate: func(c *policies.Config) {
				c.Rules["4"].Read.Allow = policies.AllowList{"not-hex"}
			},
			reason: "not a valid pubkey",
		},
		{
			name: "a duplicate required tag",
			mutate: func(c *policies.Config) {
				c.Rules["4"].RequiredTags = []string{"client", "client"}
			},
			reason: "twice",
		},
		{
			name: "a bad tag pattern",
			mutate: func(c *policies.Config) {
				c.Rules["4"].TagPatterns = map[string]string{"d": "["}
			},
			reason: "not a valid regular expression",
		},
		{
			name: "half a tag_limits",
			mutate: func(c *policies.Config) {
				c.Rules["4"].TagLimits = policies.TagLimits{MaxTags: 8}
			},
			reason: "all three must be positive",
		},
		{
			name: "a bad rate limit scope",
			mutate: func(c *policies.Config) {
				c.Rules["4"].RateLimits = []policies.RateLimit{{Scope: "read", Limit: 1, Window: policies.Duration{time.Hour}}}
			},
			reason: "must be npub or ip",
		},
		{
			name: "a zero rate limit window",
			mutate: func(c *policies.Config) {
				c.Rules["4"].RateLimits = []policies.RateLimit{{Scope: "ip", Limit: 1}}
			},
			reason: "not a positive duration",
		},
		{
			name: "a connection limit per npub",
			mutate: func(c *policies.Config) {
				c.ConnectionLimits = []policies.RateLimit{{Scope: "npub", Limit: 1, Window: policies.Duration{time.Hour}}}
			},
			reason: "scope \"npub\" must be ip",
		},
		{
			name: "shape without a validator",
			mutate: func(c *policies.Config) {
				c.Kinds.Whitelist = []uint16{4, 1}
				c.Rules["1"] = &policies.KindRule{Shape: true}
			},
			reason: "no registered shape validator",
		},
		{
			name: "an unknown error template key",
			mutate: func(c *policies.Config) {
				c.Rules["4"].Errors = map[string]string{"nope": "x"}
			},
			reason: "not one of",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policies.DefaultConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("expected %q, got %v", tc.reason, err)
			}
		})
	}
}

// A kind in the whitelist without a rule of its own is served with exactly the
// top-level defaults — that is what makes the defaults worth having. A rule that
// is built in Go and holds nothing is the opposite: fully explicit, so every
// setting is zero, which means "no restrictions".
// A kind the document gave no rule is served with the empty rule: nobody may
// publish it and nobody may read it. Once there is nothing to inherit from, that
// is what "the document did not say" has to mean.
func TestUnruledKindIsTheEmptyRule(t *testing.T) {
	cfg := policies.DefaultConfig()
	cfg.SetKinds([]uint16{4, 1059})

	relay, rules := wire(t, cfg)
	write := writePolicy(relay)

	evt := &nostr.Event{Kind: 1059, PubKey: aliceKey, Content: "x"}
	if reject, msg := write(aliceCtx(), evt); !reject {
		t.Fatalf("an unruled kind must let nobody publish it: %v %q", reject, msg)
	}
	if _, msg := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{1059}, Authors: []string{aliceKey}}); msg == "" {
		t.Fatal("an unruled kind must let nobody read it")
	}
	if !rules.PreventBroadcast(&bkind.WebSocket{AuthedPublicKey: aliceKey}, evt) {
		t.Fatal("live delivery must agree: an unruled kind goes to nobody")
	}

	// giving the kind a rule of its own is what opens it up
	cfg.Rules["1059"] = &policies.KindRule{RuleSettings: policies.RuleSettings{
		Write: policies.WriteGate{Allow: policies.AllowList{"*"}},
		Read:  policies.ReadGate{Allow: policies.AllowList{"*"}},
	}}
	relay, rules = wire(t, cfg)
	write = writePolicy(relay)
	if reject, _ := write(context.Background(), evt); reject {
		t.Fatal("an open rule must let anyone publish")
	}
	if reject, _ := rules.ReadFilter(context.Background(), nostr.Filter{Kinds: []int{1059}}); reject {
		t.Fatal("an open rule must let anyone read")
	}
	if rules.PreventBroadcast(&bkind.WebSocket{}, evt) {
		t.Fatal("an open rule must deliver to anyone")
	}
}

// The top-level settings are the defaults every kind starts from, and a rule
// names only what it changes — including an explicit zero, which means "off"
// rather than "inherit".
// A rule stands alone. Two kinds in one document can have unrelated policies, and
// neither learns anything from the other — there is no top-level block to
// inherit from and no presence bookkeeping to get wrong.
func TestRulesDoNotInherit(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"whitelist": [4, 37801]},
		"rules": {
			"4": {
				"description": "the DM rule, spelled out",
				"write": {"allow": "*"},
				"read": {"allow": "*", "privileged": true},
				"require_auth": true,
				"max_event_content_size": "4KB",
				"max_expiration": "75h",
				"p_tag": "hex",
				"required_tags": ["expiration", "client"]
			},
			"37801": {
				"description": "a backup kind with its own policy",
				"write": {"allow": "*"},
				"read": {"allow": "*", "privileged": true},
				"required_tags": ["d"]
			}
		}
	}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("failed to validate: %v", err)
	}

	dm := cfg.Rule(4)
	if dm.MaxEventContentSize.Bytes != 4096 || dm.MaxExpiration.Duration != 75*time.Hour || !dm.RequireAuth || dm.PTag != "hex" {
		t.Fatalf("kind 4 does not hold what its rule says: %+v", dm)
	}

	backup := cfg.Rule(37801)
	if backup.MaxEventContentSize.Bytes != 0 || backup.MaxExpiration.Duration != 0 || backup.RequireAuth || backup.PTag != "" {
		t.Fatalf("kind 37801 picked up settings it never named: %+v", backup)
	}
	if !reflect.DeepEqual(backup.RequiredTags, []string{"d"}) {
		t.Fatalf("kind 37801 required_tags are %v", backup.RequiredTags)
	}

	// and the relay does what the two rules say: the backup needs no expiration
	// and no p tag, the DM needs both
	relay, _ := wire(t, cfg)
	write := writePolicy(relay)
	plain := &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup", Tags: nostr.Tags{{"d", "vaultkey"}}}
	if reject, msg := write(aliceCtx(), plain); reject {
		t.Fatalf("kind 37801 does not demand an expiration or a p tag: %q", msg)
	}
	noExpiration := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "ciphertext", Tags: nostr.Tags{{"p", bobKey}, {"client", "x"}}}
	if reject, msg := write(aliceCtx(), noExpiration); !reject || !strings.Contains(msg, "expiration") {
		t.Fatalf("kind 4 holds its own expiration rule: %v %q", reject, msg)
	}
}

// "shape" runs a validator that belongs to one kind, so it is rule-local: a
// newly whitelisted kind must not inherit it and then fail for having no
// validator of its own.
func TestShapeIsNotInherited(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"whitelist": [4, 1059]},
		"rules": {"4": {"shape": true}}
	}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("whitelisting a kind without a validator must be legal: %v", err)
	}
	if !cfg.Rule(4).Shape {
		t.Fatal("kind 4 asked for its validator and did not get it")
	}
	if cfg.Rule(1059).Shape {
		t.Fatal("kind 1059 inherited a shape flag it cannot honour")
	}

	// asking for a validator that does not exist is still an error
	if _, err := policies.DefaultConfig().WithJSON([]byte(`{"rules": {"1059": {"shape": true}}, "kinds": {"whitelist": [1059]}}`)); err == nil || !strings.Contains(err.Error(), "shape") {
		t.Fatalf("a rule asking for a missing validator must be refused, got %v", err)
	}
}

func TestPerKindRulesDiffer(t *testing.T) {
	cfg := policies.DefaultConfig()
	// kind 4 keeps its mandatory expiration; kind 62 drops it
	cfg.Rules["62"].RequiredTags = []string{"client"}

	relay, _ := wire(t, cfg)
	write := writePolicy(relay)

	dm := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "ciphertext",
		Tags: nostr.Tags{{"p", bobKey}, {"client", "x"}}}
	if reject, msg := write(aliceCtx(), dm); !reject || !strings.Contains(msg, "expiration") {
		t.Fatalf("kind 4 must demand an expiration tag: %v %q", reject, msg)
	}

	vanish := &nostr.Event{Kind: 62, PubKey: aliceKey,
		Tags: nostr.Tags{{"client", "x"}, {"relay", "wss://x"}}}
	if reject, msg := write(aliceCtx(), vanish); reject {
		t.Fatalf("kind 62 must not demand an expiration tag anymore: %q", msg)
	}
}

func TestWriteAllowList(t *testing.T) {
	cfg := policies.DefaultConfig()
	cfg.Rules["4"].Write.Allow = policies.AllowList{aliceKey}

	relay, _ := wire(t, cfg)
	write := writePolicy(relay)

	dm := func(pubkey string) *nostr.Event {
		return &nostr.Event{Kind: 4, PubKey: pubkey, Content: "ciphertext",
			Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	}

	bobCtx := bkind.WithAuthenticatedPubKey(context.Background(), bobKey)
	if reject, msg := write(bobCtx, dm(bobKey)); !reject || !strings.HasPrefix(msg, "blocked:") {
		t.Fatalf("a key outside write.allow must be refused: %v %q", reject, msg)
	}
	if reject, _ := write(aliceCtx(), dm(aliceKey)); reject {
		t.Fatal("a key in write.allow must pass")
	}
}

func TestReaderAllowList(t *testing.T) {
	cfg := policies.DefaultConfig()
	cfg.Rules["4"].Read.Allow = policies.AllowList{aliceKey}

	relay, rules := wire(t, cfg)
	_ = relay

	// alice may read kind 4; bob, even querying only his own events, may not
	if reject, _ := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{4}, Authors: []string{aliceKey}}); reject {
		t.Fatal("alice is in read.allow and must pass")
	}
	bobCtx := bkind.WithAuthenticatedPubKey(context.Background(), bobKey)
	if reject, msg := rules.ReadFilter(bobCtx, nostr.Filter{Kinds: []int{4}, Authors: []string{bobKey}}); !reject || !strings.Contains(msg, "not allowed to read") {
		t.Fatalf("bob is outside read.allow and must be refused: %v %q", reject, msg)
	}

	// live delivery answers the same question the same way
	evt := &nostr.Event{Kind: 4, PubKey: bobKey, Tags: nostr.Tags{{"p", strings.Repeat("c", 64)}}}
	if rules.PreventBroadcast(&bkind.WebSocket{AuthedPublicKey: bobKey}, evt) != true {
		t.Fatal("broadcast and read must agree about read.allow")
	}
}

func TestAgeWindow(t *testing.T) {
	cfg := policies.DefaultConfig()
	cfg.Rules["4"].MaxAge = policies.Duration{time.Hour}
	cfg.Rules["4"].MaxFutureAge = policies.Duration{time.Minute}

	relay, _ := wire(t, cfg)
	write := writePolicy(relay)

	dm := func(createdAt nostr.Timestamp) *nostr.Event {
		return &nostr.Event{Kind: 4, PubKey: aliceKey, CreatedAt: createdAt, Content: "ciphertext",
			Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	}

	old := dm(nostr.Now() - 7200)
	if reject, msg := write(aliceCtx(), old); !reject || !strings.Contains(msg, "too old") {
		t.Fatalf("an event older than max_age_of_event must be refused: %v %q", reject, msg)
	}

	future := dm(nostr.Now() + 600)
	if reject, msg := write(aliceCtx(), future); !reject || !strings.Contains(msg, "future") {
		t.Fatalf("an event further ahead than max_age_event_in_future must be refused: %v %q", reject, msg)
	}

	if reject, _ := write(aliceCtx(), dm(nostr.Now())); reject {
		t.Fatal("an on-time event must pass the age window")
	}
}

func TestTagPatterns(t *testing.T) {
	cfg := policies.DefaultConfig()
	cfg.SetKinds([]uint16{4, 37801})
	cfg.Rules["37801"] = &policies.KindRule{
		Description: "master account backup",
		RuleSettings: policies.RuleSettings{
			Write:        policies.WriteGate{Allow: policies.AllowList{"*"}},
			Read:         policies.ReadGate{Allow: policies.AllowList{"*"}, Privileged: true},
			RequireAuth:  true,
			RequiredTags: []string{"d", "expiration", "client"},
			TagPatterns:  map[string]string{"d": "^vaultkey$"},
			TagLimits:    policies.TagLimits{MaxTags: 16, MaxNameChars: 64, MaxValueChars: 256},
		},
	}

	relay, _ := wire(t, cfg)
	write := writePolicy(relay)

	backup := func(d string) *nostr.Event {
		return &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup",
			Tags: nostr.Tags{{"d", d}, nearExpiration(), {"client", "x"}}}
	}

	if reject, _ := write(aliceCtx(), backup("vaultkey")); reject {
		t.Fatal("a d tag that matches its pattern must pass")
	}
	if reject, msg := write(aliceCtx(), backup("evil")); !reject || !strings.Contains(msg, "pattern") {
		t.Fatalf("a d tag that misses its pattern must be refused: %v %q", reject, msg)
	}
}

// The errors section replaces the built-in rejections with the operator's
// wording, placeholders filled.
func TestErrorTemplates(t *testing.T) {
	cfg := policies.DefaultConfig()
	cfg.Rules["4"].Errors = map[string]string{
		"max_size":    "blocked: event exceeds size limit ({size} > {limit})",
		"missing_tag": "invalid: missing required tag: {tag}",
	}

	relay, _ := wire(t, cfg)
	write := writePolicy(relay)

	big := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: strings.Repeat("x", 4097),
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	if reject, msg := write(aliceCtx(), big); !reject || msg != "blocked: event exceeds size limit (4097 > 4096)" {
		t.Fatalf("the custom max_size message was not rendered: %v %q", reject, msg)
	}

	missing := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "ciphertext",
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration()}}
	if reject, msg := write(aliceCtx(), missing); !reject || msg != "invalid: missing required tag: client" {
		t.Fatalf("the custom missing_tag message was not rendered: %v %q", reject, msg)
	}

	// {detail} carries the built-in message, so a template can wrap the reason
	// instead of replacing it
	detailed := policies.DefaultConfig()
	detailed.Rules["4"].Errors = map[string]string{"tag_limits": "invalid: {detail}"}
	relay, _ = wire(t, detailed)
	write = writePolicy(relay)
	tooManyTags := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "ciphertext",
		Tags: append(nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}, extraTags(20)...)}
	reject, msg := write(aliceCtx(), tooManyTags)
	if !reject {
		t.Fatal("an event with too many tags must be refused")
	}
	if !strings.Contains(msg, "too many tags") || !strings.HasPrefix(msg, "invalid: ") {
		t.Fatalf("{detail} did not carry the built-in reason: %q", msg)
	}

	// a rejection with no template keeps the built-in message
	untagged := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: strings.Repeat("x", 4097),
		Tags: nostr.Tags{{"p", bobKey}, {"client", "x"}}}
	if reject, msg := write(aliceCtx(), untagged); !reject || !strings.Contains(msg, "expiration") {
		t.Fatalf("the built-in expiration message must survive: %v %q", reject, msg)
	}
}

func TestKindRulesRejectUnservedFilters(t *testing.T) {
	_, rules := wire(t, policies.DefaultConfig())

	// a filter with no kinds means "every kind" and is expanded, not rejected
	f := nostr.Filter{}
	rules.OverwriteFilters()(context.Background(), &f)
	if len(f.Kinds) != 3 || f.LimitZero {
		t.Fatalf("empty kinds should be expanded to the whitelist, got %v", f.Kinds)
	}

	// an explicit kind outside the whitelist is left alone so the read policy
	// can explain itself instead of silently returning an empty EOSE
	f = nostr.Filter{Kinds: []int{1}}
	rules.OverwriteFilters()(context.Background(), &f)
	if len(f.Kinds) != 1 || f.Kinds[0] != 1 || f.LimitZero {
		t.Fatalf("an unserved kind was narrowed away instead of being rejected: %v", f)
	}

	// unless the relay opts into narrowing
	narrowing := rules
	narrowing.RejectUnservedFilters = false
	f = nostr.Filter{Kinds: []int{4, 1}}
	narrowing.OverwriteFilters()(context.Background(), &f)
	if len(f.Kinds) != 1 || f.Kinds[0] != 4 {
		t.Fatalf("narrowing was requested but the filter is %v", f.Kinds)
	}
	f = nostr.Filter{Kinds: []int{1}}
	narrowing.OverwriteFilters()(context.Background(), &f)
	if !f.LimitZero {
		t.Fatal("a filter with nothing left to query should be LimitZero")
	}
}

// Every gate has to answer the same question the same way, or a kind is
// accepted on write and invisible on read (or worse, the other way around).
func TestKindRulesGatesAgree(t *testing.T) {
	_, rules := wire(t, policies.DefaultConfig())
	ctx := aliceCtx()
	evt := func(kind int) *nostr.Event {
		return &nostr.Event{Kind: kind, PubKey: aliceKey, Tags: nostr.Tags{{"p", bobKey}}, Content: "ciphertext"}
	}

	tests := []struct {
		kind    int
		served  bool
		visible bool // author may read and receive it
	}{
		{4, true, true},
		{5, true, true},
		{62, true, true},
		{1, false, false},
		{7, false, false},
		{1059, false, false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("kind %d", tc.kind), func(t *testing.T) {
			// write: rejected exactly when the kind is not served
			if reject, _ := rules.RestrictKind()(ctx, evt(tc.kind)); reject == tc.served {
				t.Fatalf("kind %d: write gate served=%v but reject=%v", tc.kind, tc.served, reject)
			}

			// read and COUNT, with the filter pinned to the authenticated author
			filter := nostr.Filter{Kinds: []int{tc.kind}, Authors: []string{aliceKey}}
			readReject, _ := rules.ReadFilter(ctx, filter)
			countReject, _ := rules.RejectCount(ctx, filter)
			if readReject != countReject {
				t.Fatalf("kind %d: read and COUNT disagree", tc.kind)
			}
			if readReject == tc.served {
				t.Fatalf("kind %d: read gate served=%v but rejected=%v", tc.kind, tc.served, readReject)
			}

			// live delivery to the author
			prevented := rules.PreventBroadcast(&bkind.WebSocket{AuthedPublicKey: aliceKey}, evt(tc.kind))
			if prevented == tc.visible {
				t.Fatalf("kind %d: broadcast guard prevented=%v for the author", tc.kind, prevented)
			}

			// a third party never gets someone else's event
			if !rules.PreventBroadcast(&bkind.WebSocket{AuthedPublicKey: carolKey}, evt(tc.kind)) {
				t.Fatalf("kind %d: a third party would receive the event", tc.kind)
			}
		})
	}
}

func TestConfigWireDerivesNIP11(t *testing.T) {
	relay, _ := wire(t, policies.DefaultConfig())

	nips := map[float64]bool{}
	for _, nip := range relay.Info.SupportedNIPs {
		switch v := nip.(type) {
		case int:
			nips[float64(v)] = true
		case float64:
			nips[v] = true
		}
	}
	for _, want := range []float64{4, 9, 11, 40, 42, 62} {
		if !nips[want] {
			t.Fatalf("NIP-11 is missing %v: %v", want, relay.Info.SupportedNIPs)
		}
	}
	// COUNT is refused, so NIP-45 must not be advertised
	if nips[45] {
		t.Fatalf("NIP-11 advertises NIP-45 while COUNT is rejected: %v", relay.Info.SupportedNIPs)
	}
	if !strings.Contains(relay.Info.Description, "Kind 4") {
		t.Fatalf("the description does not mention what the relay serves: %q", relay.Info.Description)
	}
	if relay.Info.Limitation == nil || !relay.Info.Limitation.AuthRequired || !relay.Info.Limitation.RestrictedWrites {
		t.Fatalf("the limitation document is not derived from the rules: %+v", relay.Info.Limitation)
	}
	if relay.Info.Limitation.MaxEventTags != 16 || relay.Info.Limitation.MaxContentLength != 4096 {
		t.Fatalf("the limitation document is not derived from the rules' limits: %+v", relay.Info.Limitation)
	}

	// a relay that serves COUNT and only public kinds says so
	cfg := policies.DefaultConfig()
	cfg.Count.Reject = false
	cfg.Kinds.Whitelist = []uint16{1}
	cfg.Rules = map[string]*policies.KindRule{
		"1": {Description: "public notes"},
	}

	relay, _ = wire(t, cfg)
	found := map[float64]bool{}
	for _, nip := range relay.Info.SupportedNIPs {
		switch v := nip.(type) {
		case int:
			found[float64(v)] = true
		case float64:
			found[v] = true
		}
	}
	if !found[45] || found[42] || found[4] {
		t.Fatalf("derived supported_nips is wrong for a public note relay: %v", relay.Info.SupportedNIPs)
	}
	if relay.Info.Limitation.AuthRequired {
		t.Fatal("auth_required is still set although no kind requires auth")
	}
}

// The example file must stay a faithful, copyable description of the defaults,
// or it teaches users a config the binary does not ship.
func TestPrintedConfigIsTheExampleFile(t *testing.T) {
	data, err := os.ReadFile("../examples/bkind/bkind.example.json")
	if err != nil {
		t.Fatalf("failed to read the example config: %v", err)
	}

	printed, err := policies.DefaultConfig().JSON()
	if err != nil {
		t.Fatalf("failed to render the default config: %v", err)
	}

	// byte equality, not value equality: the example is a generated artifact, so the
	// file and the binary cannot drift in formatting either, and "copy this file" is
	// literally "copy the defaults"
	if string(printed)+"\n" != string(data) {
		t.Fatalf("bkind.example.json is not the printed default config;\n regenerate it with:\n  bkind -print-config > examples/bkind/bkind.example.json\ngot:\n%s", printed)
	}
}

// The printed document is the document: reading it back produces the same bytes,
// and a relay with no configuration at all reads it back to the same values.
func TestPrintedConfigRoundTrips(t *testing.T) {
	printed, err := policies.DefaultConfig().JSON()
	if err != nil {
		t.Fatalf("failed to render: %v", err)
	}

	cfg, err := policies.DefaultConfig().WithJSON(printed)
	if err != nil {
		t.Fatalf("the printed document does not parse: %v", err)
	}
	again, err := cfg.JSON()
	if err != nil {
		t.Fatalf("failed to render again: %v", err)
	}
	if string(again) != string(printed) {
		t.Fatalf("the printed document is not stable:\n%s\n---\n%s", printed, again)
	}

	// a zero Config can read it too, which is what makes it a complete document
	var zero policies.Config
	loaded, err := zero.WithJSON(printed)
	if err != nil {
		t.Fatalf("a zero config does not accept the document: %v", err)
	}
	want := policies.DefaultConfig()
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("the document does not mean the embedded default:\n got %+v\nwant %+v", loaded, want)
	}
}

// Every example document in the repository must load and validate, or the docs
// teach a config the binary refuses. Walks the directory, so a new example is
// covered the moment it is added.
func TestExampleConfigFilesValidate(t *testing.T) {
	paths, err := filepath.Glob("../examples/bkind/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 2 {
		t.Fatalf("expected the example documents, found %v", paths)
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		cfg, err := policies.DefaultConfig().WithJSON(data)
		if err != nil {
			t.Fatalf("%s does not parse: %v", path, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s does not validate: %v", path, err)
		}
		if _, err := cfg.JSON(); err != nil {
			t.Fatalf("%s does not render: %v", path, err)
		}
	}
}

// The NIP-17-style example: kinds 4 and 1059, both privileged, each with its own
// age window. It is a patch on the defaults, so what it does not name comes from
// the top level — this test pins which is which.
func TestNIP17ExampleResolves(t *testing.T) {
	data, err := os.ReadFile("../examples/bkind/bkind.nip17.example.json")
	if err != nil {
		t.Fatalf("failed to read the example: %v", err)
	}
	cfg, err := policies.DefaultConfig().WithJSON(data)
	if err != nil {
		t.Fatalf("the example does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the example does not validate: %v", err)
	}

	if got := cfg.Kinds.Whitelist; len(got) != 2 || got[0] != 4 || got[1] != 1059 {
		t.Fatalf("whitelist is %v, want [4 1059]", got)
	}

	dm, giftWrap := cfg.Rule(4), cfg.Rule(1059)
	for _, tc := range []struct {
		kind int
		rule *policies.KindRule
		age  time.Duration
	}{
		{4, dm, time.Hour},
		{1059, giftWrap, 48 * time.Hour},
	} {
		if tc.rule.MaxAge.Duration != tc.age {
			t.Fatalf("kind %d max_age_of_event is %v, want %v", tc.kind, tc.rule.MaxAge.Duration, tc.age)
		}
		if tc.rule.MaxFutureAge.Duration != time.Minute {
			t.Fatalf("kind %d max_age_event_in_future is %v", tc.kind, tc.rule.MaxFutureAge.Duration)
		}
		if tc.rule.MaxEventContentSize.Bytes != 4096 || tc.rule.MaxExpiration.Duration != 72*time.Hour {
			t.Fatalf("kind %d size/expiry is %+v", tc.kind, tc.rule)
		}
		if !tc.rule.Read.Privileged {
			t.Fatalf("kind %d must be privileged", tc.kind)
		}
		// inherited: the p rule that makes a privileged kind recipient-visible
		if tc.rule.PTag != "hex" {
			t.Fatalf("kind %d inherited no p rule: %q", tc.kind, tc.rule.PTag)
		}
		if len(tc.rule.RequiredTags) != 3 {
			t.Fatalf("kind %d required_tags are %v", tc.kind, tc.rule.RequiredTags)
		}
	}

	// both kinds are recipient-visible: author and "p" only
	_, rules := wire(t, cfg)
	for _, kind := range []int{4, 1059} {
		if _, msg := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{kind}, Authors: []string{bobKey}}); msg == "" {
			t.Fatalf("kind %d: a third party could read a privileged event", kind)
		}
		if reject, _ := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{kind}, Authors: []string{aliceKey}}); reject {
			t.Fatalf("kind %d: the author could not read their own event", kind)
		}
	}

	// the age window is enforced per kind: the same event is too old for a DM
	// and fine for a gift wrap
	relay, _ := wire(t, cfg)
	write := writePolicy(relay)
	threeHoursAgo := nostr.Now() - 3*3600
	evt := func(kind int) *nostr.Event {
		return &nostr.Event{Kind: kind, PubKey: aliceKey, CreatedAt: threeHoursAgo, Content: "x",
			Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	}
	if reject, msg := write(aliceCtx(), evt(4)); !reject || !strings.Contains(msg, "too old") {
		t.Fatalf("kind 4 accepted an event older than an hour: %v %q", reject, msg)
	}
	if reject, msg := write(aliceCtx(), evt(1059)); reject {
		t.Fatalf("kind 1059 refused an event inside its two-day window: %q", msg)
	}
}

// The verbose example: kinds 4 and 1059 spelled in full, with their own write
// limits and rejection wording. It is the "one document describes each kind"
// shape, so nothing about the two kinds may silently lean on a default.
func TestDMVerboseExampleResolves(t *testing.T) {
	data, err := os.ReadFile("../examples/bkind/bkind.dm-verbose.example.json")
	if err != nil {
		t.Fatalf("failed to read the example: %v", err)
	}
	cfg, err := policies.DefaultConfig().WithJSON(data)
	if err != nil {
		t.Fatalf("the example does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the example does not validate: %v", err)
	}

	// the top-level kind keys were folded into rules
	if len(cfg.Rules) != 2 || cfg.Rules["4"] == nil || cfg.Rules["1059"] == nil {
		t.Fatalf("the two kinds did not land in rules: %v", cfg.Rules)
	}

	for _, kind := range []uint16{4, 1059} {
		rule := cfg.Rule(kind)
		if !rule.Read.Privileged || !rule.RequireAuth || rule.PTag != "hex" {
			t.Fatalf("kind %d should be privileged, authenticated and recipient-visible: %+v", kind, rule)
		}
		if rule.MaxEventContentSize.Bytes != 4096 || rule.MaxExpiration.Duration != 75*time.Hour {
			t.Fatalf("kind %d size/expiry is %+v", kind, rule)
		}
		if rule.TagLimits.MaxTags != 32 || rule.TagLimits.MaxNameChars != 32 || rule.TagLimits.MaxValueChars != 128 {
			t.Fatalf("kind %d tag_limits are %+v", kind, rule.TagLimits)
		}
		if len(rule.RateLimits) != 4 {
			t.Fatalf("kind %d has %d write limits", kind, len(rule.RateLimits))
		}
		for i, want := range []struct {
			scope string
			limit int
		}{{"npub", 100}, {"npub", 1000}, {"ip", 300}, {"ip", 2500}} {
			got := rule.RateLimits[i]
			if got.Scope != want.scope || got.Limit != want.limit {
				t.Fatalf("kind %d rate_limits[%d] is %+v, want %v/%d", kind, i, got, want.scope, want.limit)
			}
		}
		if len(rule.Errors) != len(errorTemplateKeysForTest) {
			t.Fatalf("kind %d carries %d templates, want %d", kind, len(rule.Errors), len(errorTemplateKeysForTest))
		}
	}

	relay, _ := wire(t, cfg)
	write := writePolicy(relay)

	// the operator's wording reaches the client, placeholders filled
	dm := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: strings.Repeat("x", 4097),
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	if reject, msg := write(aliceCtx(), dm); !reject || msg != "blocked: event exceeds size limit (4097 > 4096)" {
		t.Fatalf("the max_size template did not apply: %v %q", reject, msg)
	}

	// the tag limit is theirs (32), not the default's (16)
	atLimit := &nostr.Event{Kind: 1059, PubKey: aliceKey, Content: "ciphertext",
		Tags: append(nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}, extraTags(29)...)}
	if reject, msg := write(aliceCtx(), atLimit); reject {
		t.Fatalf("32 tags is inside this relay's tag_limits: %q", msg)
	}
	overLimit := &nostr.Event{Kind: 1059, PubKey: aliceKey, Content: "ciphertext",
		Tags: append(nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}, extraTags(30)...)}
	if reject, msg := write(aliceCtx(), overLimit); !reject || !strings.HasPrefix(msg, "invalid: ") || !strings.Contains(msg, "too many tags") {
		t.Fatalf("33 tags must be refused with the {detail} template: %v %q", reject, msg)
	}
}

// max_event_size bounds the event as it goes on the wire, id, signature and
// every tag included; max_event_content_size bounds the content alone. They are
// separate settings: a small payload can still carry a huge tag, and a big
// payload may sit inside a generous event.
// max_event_size bounds the event as it goes on the wire, id, signature and
// every tag included; max_event_content_size bounds the content alone. They are
// separate settings: a small payload can still carry a huge tag, and a big
// payload may sit inside a generous event.
func TestEventSizeAndContentSizeAreSeparate(t *testing.T) {
	fatTag := strings.Repeat("t", 400)

	// a tight event budget, no content limit
	tight := policies.DefaultConfig()
	tight.Rules["4"].MaxEventSize = policies.Size{Bytes: 512}
	tight.Rules["4"].MaxEventContentSize = policies.Size{}

	relay, _ := wire(t, tight)
	write := writePolicy(relay)

	small := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "ciphertext",
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	if reject, msg := write(aliceCtx(), small); reject {
		t.Fatalf("an event inside the size budget must pass: %q", msg)
	}

	fat := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: "ciphertext",
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}, {"blob", fatTag}}}
	if reject, msg := write(aliceCtx(), fat); !reject || !strings.Contains(msg, "too large") || !strings.Contains(msg, "max 512") {
		t.Fatalf("a fat tag must be refused for the event size, not the content: %v %q", reject, msg)
	}
	if size, limit := policies.EventLen(fat), 512; size <= limit {
		t.Fatalf("the fixture is not over the budget: %d <= %d", size, limit)
	}

	// the content limit is the other axis, and leaving the event budget at zero
	// means "no event budget", not "somebody else's number"
	roomy := policies.DefaultConfig()
	roomy.Rules["4"].MaxEventSize = policies.Size{}
	roomy.Rules["4"].MaxEventContentSize = policies.Size{Bytes: 600}

	relay, _ = wire(t, roomy)
	write = writePolicy(relay)

	inside := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: strings.Repeat("x", 600),
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	if reject, msg := write(aliceCtx(), inside); reject {
		t.Fatalf("600 bytes of content is at the limit: %q", msg)
	}

	outside := &nostr.Event{Kind: 4, PubKey: aliceKey, Content: strings.Repeat("x", 601),
		Tags: nostr.Tags{{"p", bobKey}, nearExpiration(), {"client", "x"}}}
	if reject, msg := write(aliceCtx(), outside); !reject || !strings.Contains(msg, "content is too large") {
		t.Fatalf("601 bytes of content must be refused by the content limit: %v %q", reject, msg)
	}
}

// the templates the verbose example defines
var errorTemplateKeysForTest = []string{
	"auth_required", "max_size", "missing_tag", "p_tag", "expiration", "rate_limited", "tag_limits",
}

// The AppData example: addressable backup kinds, told apart by a "d" tag
// pattern. It is a patch on the reference defaults, and this test pins what it
// therefore inherits — including the parts a backup relay probably does not want
// (a required "p" tag, and a mandatory expiration capped at 75h).
func TestAppDataExampleResolves(t *testing.T) {
	data, err := os.ReadFile("../examples/bkind/bkind.appdata.example.json")
	if err != nil {
		t.Fatalf("failed to read the example: %v", err)
	}
	cfg, err := policies.DefaultConfig().WithJSON(data)
	if err != nil {
		t.Fatalf("the example does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the example does not validate: %v", err)
	}

	if got := cfg.Kinds.Whitelist; len(got) != 3 || got[1] != 37801 || got[2] != 37802 {
		t.Fatalf("whitelist is %v", got)
	}

	// the two backup kinds are told apart by their "d" regex, and nothing else
	for kind, pattern := range map[uint16]string{37801: "^vaultkey$", 37802: "^[0-9]{16}$"} {
		rule := cfg.Rule(kind)
		if rule.TagPatterns["d"] != pattern {
			t.Fatalf("kind %d tag_patterns[d] is %q, want %q", kind, rule.TagPatterns["d"], pattern)
		}
		if rule.MaxEventContentSize.Bytes != 4096 || !rule.Read.Privileged || !rule.RequireAuth {
			t.Fatalf("kind %d does not match its rule: %+v", kind, rule)
		}
		// inherited from the reference defaults, and worth knowing about
		if rule.PTag != "hex" {
			t.Fatalf("kind %d did not inherit the p rule: %q", kind, rule.PTag)
		}
		if rule.MaxExpiration.Duration != 75*time.Hour {
			t.Fatalf("kind %d did not inherit the 75h expiry cap: %v", kind, rule.MaxExpiration.Duration)
		}
	}

	// kind 5 has no rule here, so it keeps the reference rule for deletions
	deletion := cfg.Rule(5)
	if deletion.PTag != "" || !deletion.Shape {
		t.Fatalf("kind 5 should keep the reference deletion rule: %+v", deletion)
	}

	// a "d" value that misses the pattern is refused, and one that matches passes
	relay, _ := wire(t, cfg)
	write := writePolicy(relay)
	backup := func(kind int, d string) *nostr.Event {
		return &nostr.Event{Kind: kind, PubKey: aliceKey, Content: "backup",
			Tags: nostr.Tags{{"d", d}, {"p", bobKey}, nearExpiration(), {"client", "x"}}}
	}
	if reject, _ := write(aliceCtx(), backup(37801, "vaultkey")); reject {
		t.Fatal("the master backup's own d value must be accepted")
	}
	if reject, msg := write(aliceCtx(), backup(37801, "vaultkey2")); !reject || !strings.Contains(msg, "pattern") {
		t.Fatalf("a d value outside the master pattern must be refused: %v %q", reject, msg)
	}
	if reject, _ := write(aliceCtx(), backup(37802, "1234567890123456")); reject {
		t.Fatal("a 16-digit companion key must be accepted")
	}
	if reject, msg := write(aliceCtx(), backup(37802, "12345")); !reject || !strings.Contains(msg, "pattern") {
		t.Fatalf("a short companion key must be refused: %v %q", reject, msg)
	}
}

// The same document with the inherited constraints turned off produces a backup
// relay that behaves like one: no "p" tag demanded, no expiry demanded, and the
// "d" tag itself required.
// The same backup relay, written out: no "p" tag demanded, no expiry demanded,
// and the "d" tag itself required. Every line of that is in the rules, because
// there is nowhere else for it to be.
func TestAppDataExampleWithoutDMInheritance(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"whitelist": [5, 37801, 37802]},
		"rules": {
			"37801": {"description": "Master account backup event", "write": {"allow": "*"}, "read": {"allow": "*", "privileged": true}, "max_event_content_size": 4096, "required_tags": ["d", "client"], "tag_patterns": {"d": "^vaultkey$"}},
			"37802": {"description": "Associated account backup event", "write": {"allow": "*"}, "read": {"allow": "*", "privileged": true}, "max_event_content_size": 4096, "required_tags": ["d", "client"], "tag_patterns": {"d": "^[0-9]{16}$"}}
		}
	}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("failed to validate: %v", err)
	}

	relay, rules := wire(t, cfg)
	write := writePolicy(relay)

	// a backup with a d tag, no p tag and no expiration is accepted
	plain := &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup",
		Tags: nostr.Tags{{"d", "vaultkey"}, {"client", "x"}}}
	if reject, msg := write(aliceCtx(), plain); reject {
		t.Fatalf("a backup should not need a p tag or an expiration: %q", msg)
	}

	// and it stays private to its author: no p tag means author-only, not
	// recipient-visible
	if _, msg := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{37801}, Authors: []string{bobKey}}); msg == "" {
		t.Fatal("a third party could read someone else's backup")
	}
	if reject, _ := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{37801}, Authors: []string{aliceKey}}); reject {
		t.Fatal("the author must read their own backup")
	}

	// the d tag is now mandatory
	noD := &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup", Tags: nostr.Tags{{"client", "x"}}}
	if reject, msg := write(aliceCtx(), noD); !reject || !strings.Contains(msg, `"d"`) {
		t.Fatalf("a backup without a d tag must be refused: %v %q", reject, msg)
	}
}

// The verbose AppData example: the two backup kinds carry their own gates, tag
// budgets and rejection wording. "max_tags: 1" only makes sense once the top
// level stops demanding "p" and "expiration", which is what this file does.
func TestAppDataVerboseExampleResolves(t *testing.T) {
	data, err := os.ReadFile("../examples/bkind/bkind.appdata-verbose.example.json")
	if err != nil {
		t.Fatalf("failed to read the example: %v", err)
	}
	cfg, err := policies.DefaultConfig().WithJSON(data)
	if err != nil {
		t.Fatalf("the example does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the example does not validate: %v", err)
	}

	for kind, tc := range map[uint16]struct {
		pattern string
		value   string
	}{
		37801: {"^vaultkey$", "vaultkey"},
		37802: {"^[0-9]{16}$", "1234567890123456"},
	} {
		rule := cfg.Rule(kind)
		if rule.TagPatterns["d"] != tc.pattern {
			t.Fatalf("kind %d d pattern is %q", kind, rule.TagPatterns["d"])
		}
		if rule.TagLimits.MaxTags != 1 || len(rule.RequiredTags) != 1 || rule.RequiredTags[0] != "d" {
			t.Fatalf("kind %d tag budget is %+v with required %v", kind, rule.TagLimits, rule.RequiredTags)
		}
		if rule.PTag != "" {
			t.Fatalf("kind %d still demands a p tag: %q", kind, rule.PTag)
		}
		if len(rule.RateLimits) != 4 || len(rule.Errors) != 7 {
			t.Fatalf("kind %d lost its limits or templates: %d/%d", kind, len(rule.RateLimits), len(rule.Errors))
		}
	}

	relay, rules := wire(t, cfg)
	write := writePolicy(relay)

	// a backup is exactly one "d" tag plus content
	ok := &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup", Tags: nostr.Tags{{"d", "vaultkey"}}}
	if reject, msg := write(aliceCtx(), ok); reject {
		t.Fatalf("a bare backup event must be accepted: %q", msg)
	}

	// more than one tag breaks the budget, and the operator's template says so
	twoTags := &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup",
		Tags: nostr.Tags{{"d", "vaultkey"}, {"client", "x"}}}
	if reject, msg := write(aliceCtx(), twoTags); !reject || !strings.Contains(msg, "too many tags") {
		t.Fatalf("a second tag must be refused with {detail}: %v %q", reject, msg)
	}

	// the value length is theirs: 8 bytes for the master, 16 for the companion
	longMaster := &nostr.Event{Kind: 37801, PubKey: aliceKey, Content: "backup",
		Tags: nostr.Tags{{"d", "123456789"}}}
	if reject, msg := write(aliceCtx(), longMaster); !reject {
		t.Fatalf("a 9-byte master d value must be refused: %q", msg)
	}
	if reject, _ := write(aliceCtx(), &nostr.Event{Kind: 37802, PubKey: aliceKey, Content: "backup",
		Tags: nostr.Tags{{"d", "1234567890123456"}}}); reject {
		t.Fatal("a 16-byte companion d value must be accepted")
	}

	// no p tag means author-only, even though read.privileged is set
	if _, msg := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{37801}, Authors: []string{bobKey}}); msg == "" {
		t.Fatal("a third party could read someone else's backup")
	}
}

// A tag budget below the number of tags the rule itself demands is a relay that
// refuses every event, so it is a startup error rather than a surprise.
// A tag budget below the number of tags the rule itself demands is a relay that
// refuses every event, so it is a startup error rather than a surprise.
func TestTagBudgetMustFitRequiredTags(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			name: "a p rule and two required tags against max_tags: 1",
			json: `{"rules": {"4": {"p_tag": "hex", "required_tags": ["expiration", "client"],
			        "tag_limits": {"max_tags": 1, "max_tag_name_chars": 1, "max_tag_value_chars": 8}}}}`,
		},
		{
			name: "three required tags against max_tags: 2",
			json: `{"rules": {"4": {"required_tags": ["d", "client", "expiration"],
			        "tag_limits": {"max_tags": 2, "max_tag_name_chars": 2, "max_tag_value_chars": 8}}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policies.DefaultConfig().WithJSON([]byte(tc.json)); err == nil || !strings.Contains(err.Error(), "no event could be accepted") {
				t.Fatalf("expected the tag budget contradiction, got %v", err)
			}
		})
	}

	// a budget that fits is fine, which is how the verbose example passes
	ok := policies.DefaultConfig()
	ok.Rules["4"].TagLimits = policies.TagLimits{MaxTags: 3, MaxNameChars: 64, MaxValueChars: 256}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a budget equal to the mandatory tags must be accepted: %v", err)
	}
}

// The files under examples/bkind/invalid are configurations a relay must refuse
// at startup. Each one is a small, single-fault document, so the test can insist
// on the reason and not just on the failure — and every file in the directory has
// to be listed here, so adding a fixture without an expectation fails the build.
func TestInvalidExamplesFail(t *testing.T) {
	expectations := map[string]string{
		"bad-duration.json":            "not an ISO-8601 duration",
		"bad-regex.json":               "not a valid regular expression",
		"bad-scope.json":               `scope "npub" must be ip`,
		"bad-size.json":                "is not a size",
		"empty-whitelist.json":         "would serve nothing",
		"ephemeral-kind.json":          "ephemeral",
		"gate-conflict.json":           "cannot be combined",
		"missing-shape-validator.json": "no registered shape validator",
		// a two-tag budget against a mandatory "p", "expiration" and "client":
		// nothing could ever be published
		"tag-budget-impossible.json": "no event could be accepted",
		"unknown-error-key.json":     "not one of",
		"unknown-field.json":         `unknown field "contnet"`,
		"unserved-rule.json":         "kinds.whitelist does not include",
	}

	paths, err := filepath.Glob("../examples/bkind/invalid/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no invalid examples found")
	}

	for _, path := range paths {
		name := filepath.Base(path)
		reason, ok := expectations[name]
		if !ok {
			t.Fatalf("%s has no expected failure: add it to expectations", name)
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read %s: %v", path, err)
			}
			cfg, err := policies.DefaultConfig().WithJSON(data)
			if err == nil {
				err = cfg.Validate()
			}
			if err == nil {
				t.Fatalf("%s was accepted, but it must be refused", name)
			}
			if !strings.Contains(err.Error(), reason) {
				t.Fatalf("%s was refused for the wrong reason:\n got %v\nwant something containing %q", name, err, reason)
			}
		})
	}
}

func TestExampleConfigFileMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile("../examples/bkind/bkind.example.json")
	if err != nil {
		t.Fatalf("failed to read the example config: %v", err)
	}

	cfg, err := policies.DefaultConfig().WithJSON(data)
	if err != nil {
		t.Fatalf("the example config does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the example config does not validate: %v", err)
	}

	want := policies.DefaultConfig()
	if err := want.Validate(); err != nil {
		t.Fatalf("the defaults do not validate: %v", err)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("the example file drifted from the defaults:\n got %+v\nwant %+v", cfg, want)
	}
}
