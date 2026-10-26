package policies_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := policies.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default config must be valid: %v", err)
	}

	if got := cfg.Kinds.Sorted(); len(got) != 3 || got[0] != 4 || got[1] != 5 || got[2] != 62 {
		t.Fatalf("default kinds are %v, want [4 5 62]", got)
	}
	if !cfg.Auth.Required || !cfg.Expiration.Required || !cfg.Count.Reject {
		t.Fatalf("the default must stay authenticated, expiring and COUNT-free: %+v", cfg)
	}
	if cfg.Expiration.MaxDuration() != 75*time.Hour {
		t.Fatalf("default expiration max is %v", cfg.Expiration.MaxDuration())
	}
	if cfg.Content.Max != 4096 {
		t.Fatalf("default content max is %d", cfg.Content.Max)
	}
}

func TestConfigFromJSONMerges(t *testing.T) {
	cfg, err := policies.DefaultConfig().WithJSON([]byte(`{
		"kinds": {"allowed": [1059], "recipient_visible": [1059]},
		"content": {"max": 512},
		"rate_limits": []
	}`))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if got := cfg.Kinds.Sorted(); len(got) != 1 || got[0] != 1059 {
		t.Fatalf("kinds are %v, want [1059]", got)
	}
	if cfg.Content.Max != 512 {
		t.Fatalf("content max is %d, want 512", cfg.Content.Max)
	}
	// fields absent from the document keep their default
	if cfg.Tags.Max != 16 || cfg.NIP11.MaxLimit != 500 || !cfg.Auth.Required {
		t.Fatalf("untouched defaults were lost: %+v", cfg)
	}
	if len(cfg.RateLimits) != 0 {
		t.Fatalf("rate_limits should have been replaced by the empty list, got %d", len(cfg.RateLimits))
	}

	// the shape validator for a kind that is no longer served is gone too
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the merged config should validate: %v", err)
	}
	for _, kind := range cfg.Validation.ShapeKinds {
		t.Fatalf("kind %d still has a shape validator although it is not served", kind)
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	_, err := policies.DefaultConfig().WithJSON([]byte(`{"contnet": {"max": 1}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a typo must be an error, got %v", err)
	}
}

func TestConfigEnvOverrides(t *testing.T) {
	cfg, err := policies.LoadConfig(envFunc(map[string]string{
		"BKIND_KINDS":                   "4,1059",
		"BKIND_RECIPIENT_VISIBLE_KINDS": "4,1059",
		"BKIND_MAX_EXPIRATION":          "2h",
		"BKIND_MAX_CONTENT":             "2048",
		"BKIND_MAX_TAGS":                "8",
		"BKIND_MAX_TAG_NAME":            "32",
		"BKIND_MAX_TAG_VALUE":           "128",
		"BKIND_REQUIRED_TAGS":           "client,expiration",
		"BKIND_REQUIRE_EXPIRATION":      "true",
		"BKIND_REJECT_COUNT":            "false",
		"BKIND_NEGENTROPY":              "true",
		"BKIND_NAME":                    "test relay",
	}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if got := cfg.Kinds.Sorted(); len(got) != 2 || got[0] != 4 || got[1] != 1059 {
		t.Fatalf("kinds are %v", got)
	}
	if cfg.Expiration.MaxDuration() != 2*time.Hour || cfg.Content.Max != 2048 {
		t.Fatalf("durations/sizes not applied: %+v", cfg)
	}
	if cfg.Tags.Max != 8 || cfg.Tags.MaxNameLen != 32 || cfg.Tags.MaxValueLen != 128 {
		t.Fatalf("tag limits not applied: %+v", cfg.Tags)
	}
	if len(cfg.Tags.Required) != 2 || cfg.Tags.Required[1] != "expiration" {
		t.Fatalf("required tags are %v", cfg.Tags.Required)
	}
	if cfg.Count.Reject || !cfg.Negentropy || cfg.NIP11.Name != "test relay" {
		t.Fatalf("booleans/name not applied: %+v", cfg)
	}
	if got := cfg.Kinds.AuthorOnly; len(got) != 0 {
		t.Fatalf("kinds 5 and 62 are no longer served but stayed author-only: %v", got)
	}
}

func TestConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, []byte(`{"content": {"max": 100}, "nip11": {"name": "from file"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": path}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if cfg.Content.Max != 100 || cfg.NIP11.Name != "from file" {
		t.Fatalf("file values not applied: %+v", cfg)
	}

	// the environment still wins over the file
	cfg, err = policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": path, "BKIND_MAX_CONTENT": "7"}))
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if cfg.Content.Max != 7 {
		t.Fatalf("BKIND_MAX_CONTENT did not override the file: %d", cfg.Content.Max)
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
	if err := os.WriteFile(partial, []byte(`{"content":{"max":512}}`), 0o600); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// lenient is the default: a partial file is a patch
	cfg, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG": partial}))
	if err != nil {
		t.Fatalf("a partial file must be accepted by default: %v", err)
	}
	if cfg.Content.Max != 512 || !cfg.Auth.Required {
		t.Fatalf("the patch did not apply on top of the defaults: %+v", cfg)
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
		"BKIND_CONFIG_JSON":   `{"content":{"max":512}}`,
		"BKIND_CONFIG_STRICT": "true",
	})); err == nil {
		t.Fatal("strict mode accepted a partial inline document")
	}

	// and it is still a boolean
	if _, err := policies.LoadConfig(envFunc(map[string]string{"BKIND_CONFIG_STRICT": "yes please"})); err == nil {
		t.Fatal("a non-boolean BKIND_CONFIG_STRICT was accepted")
	}

	// environment overrides still apply on top of a strict file: strictness is about
	// the file being complete, not about freezing the process
	cfg, err = policies.LoadConfig(envFunc(map[string]string{
		"BKIND_CONFIG":        complete,
		"BKIND_CONFIG_STRICT": "true",
		"BKIND_MAX_CONTENT":   "1024",
	}))
	if err != nil {
		t.Fatalf("an override on a strict file failed: %v", err)
	}
	if cfg.Content.Max != 1024 {
		t.Fatalf("the override did not apply: content max is %d", cfg.Content.Max)
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
			mutate: func(c *policies.Config) { c.Kinds.Allowed = nil },
			reason: "serve nothing",
		},
		{
			name: "recipient kind outside the allowlist",
			mutate: func(c *policies.Config) {
				c.Kinds.Allowed = []uint16{4}
				c.Kinds.RecipientVisible = []uint16{4, 1059}
			},
			reason: "not in kinds.allowed",
		},
		{
			name: "a kind in both classes",
			mutate: func(c *policies.Config) {
				c.Kinds.AuthorOnly = append(c.Kinds.AuthorOnly, 4)
			},
			reason: "both",
		},
		{
			name: "ephemeral kind without allow_ephemeral",
			mutate: func(c *policies.Config) {
				c.Kinds.Allowed = []uint16{4, 20001}
			},
			reason: "ephemeral",
		},
		{
			name: "shape validator for an unserved kind",
			mutate: func(c *policies.Config) {
				c.Validation.ShapeKinds = []uint16{4, 5, 62, 1059}
			},
			reason: "not in kinds.allowed",
		},
		{
			name: "shape validator that does not exist",
			mutate: func(c *policies.Config) {
				c.Kinds.Allowed = append(c.Kinds.Allowed, 1)
				c.Validation.ShapeKinds = []uint16{1}
			},
			reason: "no registered shape validator",
		},
		{
			name:   "bad expiration",
			mutate: func(c *policies.Config) { c.Expiration.Max = "75" },
			reason: "not a positive duration",
		},
		{
			name: "bad rate limit scope",
			mutate: func(c *policies.Config) {
				c.RateLimits = []policies.RateLimit{{Scope: "read", Key: "ip", Tokens: 1, Interval: "1h", Max: 1}}
			},
			reason: "must be event, filter or connection",
		},
		{
			name: "connection limit per pubkey",
			mutate: func(c *policies.Config) {
				c.RateLimits = []policies.RateLimit{{Scope: "connection", Key: "authed", Tokens: 1, Interval: "1h", Max: 1}}
			},
			reason: "only support the ip key",
		},
		{
			name: "bad rate limit interval",
			mutate: func(c *policies.Config) {
				c.RateLimits = []policies.RateLimit{{Scope: "event", Key: "ip", Tokens: 1, Interval: "hour", Max: 1}}
			},
			reason: "not a positive duration",
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

func TestKindRulesRejectUnservedFilters(t *testing.T) {
	rules := policies.DefaultConfig().Kinds

	// a filter with no kinds means "every kind" and is expanded, not rejected
	f := nostr.Filter{}
	rules.OverwriteFilters()(context.Background(), &f)
	if len(f.Kinds) != 3 || f.LimitZero {
		t.Fatalf("empty kinds should be expanded to the allowlist, got %v", f.Kinds)
	}

	// an explicit kind outside the allowlist is left alone so the read policy can
	// explain itself instead of silently returning an empty EOSE
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

// Every gate has to answer the same question the same way, or a kind is accepted on
// write and invisible on read (or worse, the other way around).
func TestKindRulesGatesAgree(t *testing.T) {
	rules := policies.DefaultConfig().Kinds
	ctx := bkind.WithAuthenticatedPubKey(context.Background(), "alice")
	evt := func(kind int) *nostr.Event {
		return &nostr.Event{Kind: kind, PubKey: "alice", Tags: nostr.Tags{{"p", "bob"}}, Content: "ciphertext"}
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
			filter := nostr.Filter{Kinds: []int{tc.kind}, Authors: []string{"alice"}}
			readReject, _ := rules.ReadFilter(ctx, filter)
			countReject, _ := rules.RejectCount(ctx, filter)
			if readReject != countReject {
				t.Fatalf("kind %d: read and COUNT disagree", tc.kind)
			}
			if readReject == tc.served {
				t.Fatalf("kind %d: read gate served=%v but rejected=%v", tc.kind, tc.served, readReject)
			}

			// live delivery to the author
			prevented := rules.PreventBroadcast(&bkind.WebSocket{AuthedPublicKey: "alice"}, evt(tc.kind))
			if prevented == tc.visible {
				t.Fatalf("kind %d: broadcast guard prevented=%v for the author", tc.kind, prevented)
			}

			// a third party never gets someone else's event
			if !rules.PreventBroadcast(&bkind.WebSocket{AuthedPublicKey: "carol"}, evt(tc.kind)) {
				t.Fatalf("kind %d: a third party would receive the event", tc.kind)
			}
		})
	}
}

func TestConfigWireDerivesNIP11(t *testing.T) {
	relay := bkind.NewRelay()
	if err := policies.DefaultConfig().Wire(relay); err != nil {
		t.Fatalf("failed to wire: %v", err)
	}

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
		t.Fatalf("the limitation document is not derived from the auth setting: %+v", relay.Info.Limitation)
	}

	// a relay that serves COUNT and does not require auth says so
	cfg := policies.DefaultConfig()
	cfg.Count.Reject = false
	cfg.Auth.Required = false
	cfg.Kinds.Allowed = []uint16{1}
	cfg.Kinds.RecipientVisible = nil
	cfg.Kinds.AuthorOnly = nil
	cfg.Validation.ShapeKinds = nil
	cfg.Tags.Required = nil
	cfg.Expiration.Required = false

	relay = bkind.NewRelay()
	if err := cfg.Wire(relay); err != nil {
		t.Fatalf("failed to wire: %v", err)
	}
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
		t.Fatal("auth_required is still set after auth.required was disabled")
	}
}

// The example file must stay a faithful, copyable description of the defaults, or
// it teaches users a config the binary does not ship.
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
	// the two ends of strict mode have to be inverses: what the relay prints, the
	// relay accepts, and it means the same thing. A field added to Config but not to
	// the printed document would fail here.
	for _, cfg := range []policies.Config{
		policies.DefaultConfig(),
		func() policies.Config {
			c := policies.DefaultConfig()
			c.SetKinds([]uint16{1})
			c.Expiration.Required = false
			c.Tags.Required = nil
			c.RateLimits = nil
			c.NIP11.ExtraNIPs = []int{50}
			c.Negentropy = true
			return c
		}(),
	} {
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

	for _, section := range []string{"kinds", "auth", "nip11"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(document[section], &fields); err != nil {
			t.Fatalf("failed to parse %q: %v", section, err)
		}
		for name := range fields {
			trimmed := map[string]json.RawMessage{}
			for k, v := range document {
				trimmed[k] = v
			}
			reduced := map[string]json.RawMessage{}
			for k, v := range fields {
				if k != name {
					reduced[k] = v
				}
			}
			body, err := json.Marshal(reduced)
			if err != nil {
				t.Fatalf("failed to re-encode %q: %v", section, err)
			}
			trimmed[section] = body

			whole, err := json.Marshal(trimmed)
			if err != nil {
				t.Fatalf("failed to re-encode the document: %v", err)
			}

			if _, err := (&policies.Config{}).WithStrictJSON(whole); err == nil {
				t.Fatalf("strict mode accepted a document without %s.%s", section, name)
			} else if !strings.Contains(err.Error(), section+"."+name) {
				t.Fatalf("the error does not name %s.%s: %v", section, name, err)
			}

			// the same document is fine in lenient mode: that is the difference
			if _, err := (&policies.Config{}).WithJSON(whole); err != nil {
				t.Fatalf("lenient mode rejected a document without %s.%s: %v", section, name, err)
			}
		}
	}

	// a rate limit missing a field is a different shape
	var limits []map[string]json.RawMessage
	if err := json.Unmarshal(document["rate_limits"], &limits); err != nil {
		t.Fatalf("failed to parse rate_limits: %v", err)
	}
	limits[0]["max"] = nil
	delete(limits[0], "max")
	body, err := json.Marshal(limits)
	if err != nil {
		t.Fatalf("failed to re-encode rate_limits: %v", err)
	}
	document["rate_limits"] = body
	whole, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("failed to re-encode the document: %v", err)
	}
	if _, err := (&policies.Config{}).WithStrictJSON(whole); err == nil || !strings.Contains(err.Error(), "rate_limits[0].max") {
		t.Fatalf("strict mode did not name the missing rate limit field: %v", err)
	}

	// an empty document is the extreme case, and the message should say where to get
	// a complete one rather than "kinds.allowed is empty"
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
