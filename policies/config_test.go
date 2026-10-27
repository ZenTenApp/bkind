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
	for _, kind := range []string{"4", "5", "62"} {
		rule := cfg.Rules[kind]
		if rule == nil {
			t.Fatalf("the default config has no rule for kind %s", kind)
		}
		if !rule.RequireAuth || !rule.Read.Privileged {
			t.Fatalf("kind %s must be authenticated and privileged: %+v", kind, rule)
		}
		if rule.MaxSize.Bytes != 4096 {
			t.Fatalf("kind %s max_size is %d, want 4096", kind, rule.MaxSize.Bytes)
		}
		if rule.MaxExpiration.Duration != 75*time.Hour {
			t.Fatalf("kind %s max_expiration is %v, want 75h", kind, rule.MaxExpiration.Duration)
		}
		if len(rule.RequiredTags) != 2 || rule.RequiredTags[0] != "expiration" || rule.RequiredTags[1] != "client" {
			t.Fatalf("kind %s required_tags are %v", kind, rule.RequiredTags)
		}
	}
	if cfg.Rules["4"].PTag != "hex" {
		t.Fatal("kind 4 is the one kind with a p rule in the defaults")
	}
	if !cfg.Count.Reject || cfg.Negentropy {
		t.Fatalf("the default must stay COUNT-free and negentropy-free: %+v", cfg)
	}
}

func TestConfigFromJSONMerges(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"whitelist": [4, 1059]},
		"rules": {
			"4": {"max_size": 512},
			"1059": {"description": "gift wraps", "p_tag": "hex"}
		}
	}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if got := cfg.Kinds.Whitelist; len(got) != 2 || got[1] != 1059 {
		t.Fatalf("whitelist is %v, want [4 1059]", got)
	}

	// an existing rule is patched, not replaced: the fields the document does
	// not name keep their value
	rule4 := cfg.Rules["4"]
	if rule4.MaxSize.Bytes != 512 {
		t.Fatalf("kind 4 max_size is %d, want 512", rule4.MaxSize.Bytes)
	}
	if rule4.RequireAuth != true || rule4.MaxExpiration.Duration != 75*time.Hour || rule4.PTag != "hex" {
		t.Fatalf("the patch wiped fields it did not name: %+v", rule4)
	}

	// a rule for a new kind starts from zero: only what the document says
	rule1059 := cfg.Rules["1059"]
	if rule1059.PTag != "hex" || rule1059.Description != "gift wraps" {
		t.Fatalf("kind 1059 rule is %+v", rule1059)
	}
	if rule1059.RequireAuth || rule1059.MaxSize.Bytes != 0 {
		t.Fatalf("a new rule must not inherit the other kinds' limits: %+v", rule1059)
	}

	// the rules of the kinds the new whitelist dropped are pruned
	for _, key := range []string{"5", "62"} {
		if cfg.Rules[key] != nil {
			t.Fatalf("kind %s still has a rule although it is no longer served", key)
		}
	}

	// sections absent from the document keep their default
	if cfg.Reads.RateLimits == nil || cfg.NIP11.MaxLimit != 500 {
		t.Fatalf("untouched defaults were lost: %+v", cfg)
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

// The dialect has two spellings: the summary one ("size_limit",
// "must_have_tags", "identifier_regex", "privileged", "kind", a "rules"
// wrapper) and the full one ("max_size", "required_tags", "tag_patterns",
// "read.privileged", "kinds", kind keys at the top level). Both are the same
// config.
func TestKindRuleAliasesAndTopLevelKeys(t *testing.T) {
	terse := `{
		"kind": {"whitelist": [4, 1059]},
		"rules": {
			"4": {
				"description": "Nostr DM events",
				"privileged": true,
				"size_limit": 4096,
				"max_age_of_event": 3600,
				"max_age_event_in_future": 60,
				"max_expiry_duration": "P3D",
				"must_have_tags": ["p", "expiration", "client"]
			}
		}
	}`
	verbose := `{
		"kinds": {"whitelist": [4, 1059]},
		"4": {
			"description": "Nostr DM events",
			"read": {"allow": "*", "privileged": true},
			"max_size": "4KB",
			"max_age_of_event": 3600,
			"max_age_event_in_future": 60,
			"max_expiration": "72h",
			"required_tags": ["p", "expiration", "client"]
		}
	}`

	fromTerse, err := policies.DefaultConfig().WithJSON([]byte(terse))
	if err != nil {
		t.Fatalf("the terse document does not parse: %v", err)
	}
	fromVerbose, err := policies.DefaultConfig().WithJSON([]byte(verbose))
	if err != nil {
		t.Fatalf("the verbose document does not parse: %v", err)
	}

	if err := fromTerse.Validate(); err != nil {
		t.Fatalf("the terse document does not validate: %v", err)
	}
	if err := fromVerbose.Validate(); err != nil {
		t.Fatalf("the verbose document does not validate: %v", err)
	}

	// both documents mean the same rule, with the same numbers
	for _, cfg := range []policies.Config{fromTerse, fromVerbose} {
		rule := cfg.Rules["4"]
		if rule.MaxSize.Bytes != 4096 {
			t.Fatalf("4KB / 4096 did not parse: %d", rule.MaxSize.Bytes)
		}
		if rule.MaxExpiration.Duration != 72*time.Hour {
			t.Fatalf("P3D did not parse as 72h: %v", rule.MaxExpiration.Duration)
		}
		if rule.MaxAge.Duration != time.Hour || rule.MaxFutureAge.Duration != time.Minute {
			t.Fatalf("the age window did not parse: %+v", rule)
		}
		if !rule.Read.Privileged {
			t.Fatal("privileged / read.privileged did not parse")
		}
	}

	// top-level kind keys are folded into rules
	if _, ok := fromVerbose.Rules["4"]; !ok {
		t.Fatal("the top-level kind key was not folded into rules")
	}
	if _, ok := fromVerbose.Rules["1059"]; ok {
		t.Fatal("kind 1059 got a rule it was never given")
	}

	// an alias and its canonical name in the same rule is a conflict, not a
	// silent winner
	_, err = policies.DefaultConfig().WithJSON([]byte(`{"rules": {"4": {"size_limit": 1, "max_size": 2}}}`))
	if err == nil || !strings.Contains(err.Error(), "size_limit") {
		t.Fatalf("an alias conflict must be an error, got %v", err)
	}

	// and so is a kind defined twice
	_, err = policies.DefaultConfig().WithJSON([]byte(`{"4": {"max_size": 1}, "rules": {"4": {"max_size": 2}}}`))
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a kind defined twice must be an error, got %v", err)
	}

	// the backup-style spelling: identifier_regex is tag_patterns.d, and a kind
	// can carry a rule without being a DM at all
	backup := `{"kinds": {"whitelist": [5, 37801]}, "rules": {"37801": {
		"description": "Master account backup",
		"privileged": true,
		"size_limit": 4096,
		"identifier_regex": "^vaultkey$"
	}}}`
	cfg, err := policies.DefaultConfig().WithJSON([]byte(backup))
	if err != nil {
		t.Fatalf("the backup-style document does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the backup-style document does not validate: %v", err)
	}
	rule := cfg.Rules["37801"]
	if rule.TagPatterns["d"] != "^vaultkey$" || !rule.Read.Privileged || rule.MaxSize.Bytes != 4096 {
		t.Fatalf("identifier_regex / privileged / size_limit did not land: %+v", rule)
	}
	// kind 5 stays in the whitelist and keeps its default rule: this is a
	// patch on the defaults, not a fresh document. A standalone config that
	// wants nothing for kind 5 writes the whole document in strict mode.
	if cfg.Rules["5"] == nil || !cfg.Rules["5"].RequireAuth {
		t.Fatal("kind 5 is whitelisted, so its default rule stays")
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
	if err := os.WriteFile(path, []byte(`{"rules": {"4": {"max_size": 100}}, "nip11": {"name": "from file"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": path}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if cfg.Rules["4"].MaxSize.Bytes != 100 || cfg.NIP11.Name != "from file" {
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

func TestConfigStrictModeFromEnvironment(t *testing.T) {
	dir := t.TempDir()

	full, err := policies.DefaultConfig().JSON()
	if err != nil {
		t.Fatalf("failed to render: %v", err)
	}
	complete := filepath.Join(dir, "complete.json")
	if err := os.WriteFile(complete, full, 0o600); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	partial := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(partial, []byte(`{"rules": {"4": {"max_size": 512}}}`), 0o600); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// lenient is the default: a partial file is a patch
	cfg, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": partial}))
	if err != nil {
		t.Fatalf("a partial file must be accepted by default: %v", err)
	}
	if cfg.Rules["4"].MaxSize.Bytes != 512 || !cfg.Rules["4"].RequireAuth {
		t.Fatalf("the patch did not apply on top of the defaults: %+v", cfg.Rules["4"])
	}

	// strict refuses it, and does so before anything can be wired
	if _, err := policies.LoadConfig(envFunc(map[string]string{
		"BKIND_CONFIG":        partial,
		"BKIND_CONFIG_STRICT": "true",
	})); err == nil {
		t.Fatal("strict mode accepted a partial file")
	} else if !strings.Contains(err.Error(), `"kinds"`) {
		t.Fatalf("the error does not name the first missing section: %v", err)
	}

	// the complete file is accepted in strict mode and means exactly what the
	// defaults mean
	cfg, err = policies.LoadConfig(envFunc(map[string]string{
		"BKIND_CONFIG":        complete,
		"BKIND_CONFIG_STRICT": "true",
	}))
	if err != nil {
		t.Fatalf("strict mode rejected a complete file: %v", err)
	}
	want := policies.DefaultConfig()
	if err := want.Validate(); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("the complete file does not mean the defaults:\n got %+v\nwant %+v", cfg, want)
	}

	// strict applies to the inline document too
	if _, err := policies.LoadConfig(envFunc(map[string]string{
		"BKIND_CONFIG_JSON":   `{"rules": {"4": {"max_size": 512}}}`,
		"BKIND_CONFIG_STRICT": "true",
	})); err == nil {
		t.Fatal("strict mode accepted a partial inline document")
	}

	// and it is still a boolean
	if _, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG_STRICT": "yes please"})); err == nil {
		t.Fatal("a non-boolean BKIND_CONFIG_STRICT was accepted")
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
				c.Connections.RateLimits = []policies.RateLimit{{Scope: "npub", Limit: 1, Window: policies.Duration{time.Hour}}}
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

// A kind in the whitelist without a rule is served with the strictest defaults:
// authenticated writes, author-only reads. A rule that is present and zero is
// the opposite — an explicit "no restrictions".
func TestUnruledKindIsStrictest(t *testing.T) {
	cfg := policies.DefaultConfig()
	// SetKinds prunes the rules of the kinds the new whitelist drops; kind 1059
	// stays in the whitelist without a rule
	cfg.SetKinds([]uint16{4, 1059})

	relay, rules := wire(t, cfg)
	write := writePolicy(relay)

	// writes to the unruled kind need authentication
	evt := &nostr.Event{Kind: 1059, PubKey: aliceKey, Content: "x"}
	if reject, msg := write(context.Background(), evt); !reject || !strings.HasPrefix(msg, "auth-required:") {
		t.Fatalf("an unruled kind must still require auth on write: %v %q", reject, msg)
	}
	if reject, _ := write(aliceCtx(), evt); reject {
		t.Fatal("an authenticated write to an unruled kind must pass")
	}

	// reads of the unruled kind are author-only
	if _, msg := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{1059}, Authors: []string{bobKey}}); msg == "" {
		t.Fatal("a third party must not read an unruled kind")
	}
	if reject, _ := rules.ReadFilter(aliceCtx(), nostr.Filter{Kinds: []int{1059}, Authors: []string{aliceKey}}); reject {
		t.Fatal("the author must read their own unruled-kind events")
	}

	// a zero rule is wide open: the operator chose that
	cfg.Rules["1059"] = &policies.KindRule{}
	relay, rules = wire(t, cfg)
	write = writePolicy(relay)
	if reject, _ := write(context.Background(), evt); reject {
		t.Fatal("a zero rule means no write restrictions")
	}
	if reject, _ := rules.ReadFilter(context.Background(), nostr.Filter{Kinds: []int{1059}}); reject {
		t.Fatal("a zero rule means public reads")
	}
	if rules.PreventBroadcast(&bkind.WebSocket{}, evt) {
		t.Fatal("a zero rule means public delivery")
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
		Description:  "master account backup",
		Write:        policies.WriteGate{Allow: policies.AllowList{"*"}},
		Read:         policies.ReadGate{Allow: policies.AllowList{"*"}, Privileged: true},
		RequireAuth:  true,
		RequiredTags: []string{"d", "expiration", "client"},
		TagPatterns:  map[string]string{"d": "^vaultkey$"},
		TagLimits:    policies.TagLimits{MaxTags: 16, MaxNameChars: 64, MaxValueChars: 256},
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

func TestPrintedConfigRoundTripsThroughStrictMode(t *testing.T) {
	public := policies.DefaultConfig()
	public.SetKinds([]uint16{1})
	public.Rules = map[string]*policies.KindRule{
		"1": {
			Description:   "public notes",
			Write:         policies.WriteGate{Allow: policies.AllowList{"*"}},
			Read:          policies.ReadGate{Allow: policies.AllowList{"*"}},
			MaxSize:       policies.Size{Bytes: 8192},
			MaxExpiration: policies.Duration{24 * time.Hour},
			TagLimits:     policies.TagLimits{MaxTags: 8, MaxNameChars: 32, MaxValueChars: 128},
			RateLimits: []policies.RateLimit{
				{Scope: "npub", Limit: 10, Window: policies.Duration{time.Minute}},
			},
			TagPatterns: map[string]string{"d": "^note-[0-9]+$"},
			Errors:      map[string]string{"max_size": "blocked: too big ({size} > {limit})"},
		},
	}
	public.NIP11.ExtraNIPs = []int{50}
	public.Negentropy = true

	// the two ends of strict mode have to be inverses: what the relay prints, the
	// relay accepts, and it means the same thing. A field added to Config but not
	// to the printed document would fail here.
	for _, cfg := range []policies.Config{policies.DefaultConfig(), public} {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("bad fixture: %v", err)
		}

		document, err := cfg.JSON()
		if err != nil {
			t.Fatalf("failed to render: %v", err)
		}

		var restored policies.Config
		if restored, err = restored.WithStrictJSON(document); err != nil {
			t.Fatalf("the printed document is not accepted in strict mode: %v\n%s", err, document)
		}
		if err := restored.Validate(); err != nil {
			t.Fatalf("the printed document does not validate: %v", err)
		}
		if !reflect.DeepEqual(restored, cfg) {
			t.Fatalf("round trip changed the config:\n got %+v\nwant %+v", restored, cfg)
		}
	}
}

func TestStrictJSONRequiresEveryField(t *testing.T) {
	full, err := policies.DefaultConfig().JSON()
	if err != nil {
		t.Fatalf("failed to render: %v", err)
	}

	// removing any one field must be caught, and named in the error
	var document map[string]json.RawMessage
	if err := json.Unmarshal(full, &document); err != nil {
		t.Fatalf("failed to parse the rendered config: %v", err)
	}

	cloneDoc := func() map[string]json.RawMessage {
		clone := map[string]json.RawMessage{}
		for k, v := range document {
			clone[k] = v
		}
		return clone
	}
	mustFail := func(t *testing.T, name string, doc map[string]json.RawMessage) {
		t.Helper()
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var cfg policies.Config
		if _, err := cfg.WithStrictJSON(body); err == nil {
			t.Fatalf("strict mode accepted a document without %s", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Fatalf("the error does not name %s: %v", name, err)
		}
	}

	// every top-level key
	for _, key := range []string{"kinds", "rules", "filters", "reads", "connections", "count", "nip11", "negentropy"} {
		clone := cloneDoc()
		delete(clone, key)
		mustFail(t, key, clone)
	}

	// every field of every flat section
	for _, section := range []string{"kinds", "filters", "count", "nip11"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(document[section], &fields); err != nil {
			t.Fatal(err)
		}
		for name := range fields {
			reduced := map[string]json.RawMessage{}
			for k, v := range fields {
				reduced[k] = v
			}
			delete(reduced, name)
			body, err := json.Marshal(reduced)
			if err != nil {
				t.Fatal(err)
			}
			clone := cloneDoc()
			clone[section] = body
			t.Run(section+"."+name, func(t *testing.T) {
				mustFail(t, section+"."+name, clone)
			})
		}
	}

	// every field of a rule body, of its gates, of tag_limits and of a rate
	// limit entry
	var rules map[string]json.RawMessage
	if err := json.Unmarshal(document["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(rules["4"], &rule); err != nil {
		t.Fatal(err)
	}
	withRule := func(t *testing.T, name string, mutate func(map[string]json.RawMessage)) {
		t.Helper()
		body := map[string]json.RawMessage{}
		for k, v := range rule {
			body[k] = v
		}
		mutate(body)
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rulesClone := map[string]json.RawMessage{}
		for k, v := range rules {
			rulesClone[k] = v
		}
		rulesClone["4"] = encoded
		encodedRules, err := json.Marshal(rulesClone)
		if err != nil {
			t.Fatal(err)
		}
		clone := cloneDoc()
		clone["rules"] = encodedRules
		mustFail(t, name, clone)
	}

	for _, name := range []string{"description", "write", "read", "require_auth", "max_size", "max_expiration", "max_age_of_event", "max_age_event_in_future", "p_tag", "required_tags", "tag_patterns", "tag_limits", "rate_limits", "shape", "errors"} {
		field := name
		withRule(t, "rules.4."+field, func(body map[string]json.RawMessage) {
			delete(body, field)
		})
	}

	// the gates
	for gate, keys := range map[string][]string{"write": {"allow"}, "read": {"allow", "privileged"}} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rule[gate], &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range keys {
			gateName, fieldName := gate, name
			withRule(t, "rules.4."+gateName+"."+fieldName, func(body map[string]json.RawMessage) {
				reduced := map[string]json.RawMessage{}
				for k, v := range fields {
					reduced[k] = v
				}
				delete(reduced, fieldName)
				encoded, err := json.Marshal(reduced)
				if err != nil {
					t.Fatal(err)
				}
				body[gateName] = encoded
			})
		}
	}

	// tag_limits
	withRule(t, "rules.4.tag_limits.max_tags", func(body map[string]json.RawMessage) {
		delete(body, "tag_limits")
		body["tag_limits"] = []byte(`{"max_tag_name_chars": 64, "max_tag_value_chars": 256}`)
	})

	// a rate limit entry
	withRule(t, "rules.4.rate_limits[0].window", func(body map[string]json.RawMessage) {
		body["rate_limits"] = []byte(`[{"scope": "npub", "limit": 30}]`)
	})

	// the same reduced documents are fine in lenient mode: that is the difference
	clone := cloneDoc()
	var partialRules map[string]json.RawMessage
	if err := json.Unmarshal(clone["rules"], &partialRules); err != nil {
		t.Fatal(err)
	}
	partialRules["4"] = []byte(`{"max_size": 512}`)
	encoded, err := json.Marshal(partialRules)
	if err != nil {
		t.Fatal(err)
	}
	clone["rules"] = encoded
	body, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&policies.Config{}).WithJSON(body); err != nil {
		t.Fatalf("lenient mode rejected a partial document: %v", err)
	}

	// an empty document is the extreme case, and the message should say where to
	// get a complete one rather than "kinds.whitelist is empty"
	if _, err := (&policies.Config{}).WithStrictJSON([]byte(`{}`)); err == nil {
		t.Fatal("strict mode accepted an empty document")
	} else if !strings.Contains(err.Error(), "print-config") {
		t.Fatalf("the error does not point at -print-config: %v", err)
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
