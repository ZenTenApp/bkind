package policies_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ZenTenApp/bkind"
	"github.com/ZenTenApp/bkind/policies"
	"github.com/nbd-wtf/go-nostr"
)

// real keys, because the policies validate that a pubkey is a point on the curve
var (
	alice = newPubKey()
	bob   = newPubKey()
	carol = newPubKey()
)

func newPubKey() string {
	pk, err := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	if err != nil {
		panic(err)
	}
	return pk
}

func evt(kind int, tags nostr.Tags, content string) *nostr.Event {
	return &nostr.Event{
		ID:        strings.Repeat("f", 64),
		PubKey:    alice,
		CreatedAt: nostr.Now(),
		Kind:      kind,
		Tags:      tags,
		Content:   content,
	}
}

func TestRequireAuthedAuthor(t *testing.T) {
	ctx := context.Background()

	if reject, msg := policies.RequireAuthedAuthor(ctx, evt(4, nil, "x")); !reject || !strings.HasPrefix(msg, "auth-required:") {
		t.Fatalf("unauthenticated write should be rejected with a challenge, got %v %q", reject, msg)
	}

	if reject, _ := policies.RequireAuthedAuthor(bkind.WithAuthenticatedPubKey(ctx, bob), evt(4, nil, "x")); !reject {
		t.Fatal("a write on behalf of another key should be rejected")
	}

	if reject, msg := policies.RequireAuthedAuthor(bkind.WithAuthenticatedPubKey(ctx, alice), evt(4, nil, "x")); reject {
		t.Fatalf("an authenticated author should be accepted, got %q", msg)
	}

	// server-side deletions and expirations go through Relay.AddEvent without a
	// connection and must not be blocked by the write policies
	if reject, msg := policies.RequireAuthedAuthor(bkind.WithInternalCall(ctx), evt(4, nil, "x")); reject {
		t.Fatalf("internal calls should be accepted, got %q", msg)
	}
}

func TestRequireExpiration(t *testing.T) {
	policy := policies.RequireExpiration(75 * time.Hour)
	ctx := context.Background()
	in := func(d time.Duration) nostr.Tag {
		return nostr.Tag{"expiration", fmt.Sprint(int64(time.Now().Add(d).Unix()))}
	}

	tests := []struct {
		name   string
		tags   nostr.Tags
		reason string
	}{
		{"valid", nostr.Tags{in(time.Hour)}, ""},
		{"at the limit", nostr.Tags{in(74 * time.Hour)}, ""},
		{"missing", nostr.Tags{{"p", bob}}, `missing mandatory "expiration" tag`},
		{"duplicated", nostr.Tags{in(time.Hour), in(2 * time.Hour)}, `multiple "expiration" tags`},
		{"without a value", nostr.Tags{{"expiration"}}, "not a unix timestamp"},
		{"not a number", nostr.Tags{{"expiration", "tomorrow"}}, "not a unix timestamp"},
		{"already expired", nostr.Tags{in(-time.Minute)}, "already expired"},
		{"too far away", nostr.Tags{in(76 * time.Hour)}, "too far in the future"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := policy(ctx, evt(4, tc.tags, "x"))
			if tc.reason == "" {
				if reject {
					t.Fatalf("should have been accepted, got %q", msg)
				}
				return
			}
			if !reject || !strings.Contains(msg, tc.reason) {
				t.Fatalf("expected %q, got %v %q", tc.reason, reject, msg)
			}
		})
	}
}

func TestRequireTag(t *testing.T) {
	policy := policies.RequireTag("client")
	ctx := context.Background()

	tests := []struct {
		name   string
		tags   nostr.Tags
		reason string
	}{
		{"valid", nostr.Tags{{"client", "amethyst"}}, ""},
		{"missing", nostr.Tags{{"p", bob}}, `missing mandatory "client" tag`},
		{"empty value", nostr.Tags{{"client", ""}}, "must have a non-empty value"},
		{"no value", nostr.Tags{{"client"}}, "must have a non-empty value"},
		{"duplicated", nostr.Tags{{"client", "a"}, {"client", "b"}}, `multiple "client" tags`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := policy(ctx, evt(4, tc.tags, "x"))
			if tc.reason == "" {
				if reject {
					t.Fatalf("should have been accepted, got %q", msg)
				}
				return
			}
			if !reject || !strings.Contains(msg, tc.reason) {
				t.Fatalf("expected %q, got %v %q", tc.reason, reject, msg)
			}
		})
	}
}

func TestMaxContentLen(t *testing.T) {
	policy := policies.MaxContentLen(4096)
	ctx := context.Background()

	if reject, msg := policy(ctx, evt(4, nil, strings.Repeat("x", 4096))); reject {
		t.Fatalf("4096 bytes should fit, got %q", msg)
	}
	if reject, msg := policy(ctx, evt(4, nil, strings.Repeat("x", 4097))); !reject {
		t.Fatalf("4097 bytes should be rejected, got %q", msg)
	}
}

func TestTagShapeLimits(t *testing.T) {
	policy := policies.TagShapeLimits(16, 64, 256)
	ctx := context.Background()

	withTags := func(tags ...nostr.Tag) *nostr.Event { return evt(4, tags, "x") }

	if reject, msg := policy(ctx, withTags(nostr.Tag{"t", strings.Repeat("v", 256)})); reject {
		t.Fatalf("256 byte values should fit, got %q", msg)
	}
	if reject, msg := policy(ctx, withTags(nostr.Tag{"t", strings.Repeat("v", 257)})); !reject {
		t.Fatalf("257 byte values should be rejected, got %q", msg)
	}
	if reject, msg := policy(ctx, withTags(nostr.Tag{strings.Repeat("n", 64), "v"})); reject {
		t.Fatalf("64 byte names should fit, got %q", msg)
	}
	if reject, msg := policy(ctx, withTags(nostr.Tag{strings.Repeat("n", 65), "v"})); !reject {
		t.Fatalf("65 byte names should be rejected, got %q", msg)
	}
	if reject, msg := policy(ctx, withTags(nostr.Tag{})); !reject {
		t.Fatalf("an empty tag should be rejected, got %q", msg)
	}

	tags := make(nostr.Tags, 16)
	for i := range tags {
		tags[i] = nostr.Tag{"t", fmt.Sprint(i)}
	}
	if reject, msg := policy(ctx, withTags(tags...)); reject {
		t.Fatalf("16 tags should fit, got %q", msg)
	}
	if reject, msg := policy(ctx, withTags(append(tags, nostr.Tag{"t", "extra"})...)); !reject {
		t.Fatalf("17 tags should be rejected, got %q", msg)
	}
}

func TestValidateKind4Shape(t *testing.T) {
	ctx := context.Background()
	dm := func(tags nostr.Tags, content string) *nostr.Event {
		tags = append(nostr.Tags{{"p", bob}, {"expiration", "9999999999"}, {"client", "test"}}, tags...)
		return evt(4, tags, content)
	}

	tests := []struct {
		name   string
		evt    *nostr.Event
		reason string
	}{
		{"valid", dm(nil, "ciphertext"), ""},
		{"empty content", dm(nil, ""), "must have encrypted content"},
		{"wrong kind is not its business", evt(1, nil, ""), ""},
		{"no recipient", evt(4, nostr.Tags{{"client", "test"}}, "x"), `exactly one "p" tag`},
		{"two recipients", dm(nostr.Tags{{"p", carol}}, "x"), `exactly one "p" tag`},
		{"invalid recipient", evt(4, nostr.Tags{{"p", "nope"}}, "x"), "64-character hex pubkey"},
		{"self addressed", evt(4, nostr.Tags{{"p", alice}}, "x"), "addressed to its own author"},
		{"with an event reference", dm(nostr.Tags{{"e", strings.Repeat("a", 64)}}, "x"), `must not carry "e" tags`},
		{"with a parameterized reference", dm(nostr.Tags{{"a", "1:" + alice + ":x"}}, "x"), `must not carry "a" tags`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := policies.ValidateKind4Shape(ctx, tc.evt)
			if tc.reason == "" {
				if reject {
					t.Fatalf("should have been accepted, got %q", msg)
				}
				return
			}
			if !reject || !strings.Contains(msg, tc.reason) {
				t.Fatalf("expected %q, got %v %q", tc.reason, reject, msg)
			}
		})
	}
}

func TestValidateKind5Shape(t *testing.T) {
	ctx := context.Background()
	deletion := func(tags ...nostr.Tag) *nostr.Event {
		return evt(5, append(nostr.Tags{{"expiration", "9999999999"}, {"client", "test"}}, tags...), "")
	}
	eventID := nostr.Tag{"e", strings.Repeat("a", 64)}

	tests := []struct {
		name   string
		evt    *nostr.Event
		reason string
	}{
		{"valid", deletion(eventID), ""},
		{"several targets", deletion(eventID, nostr.Tag{"e", strings.Repeat("b", 64)}), ""},
		{"no target", deletion(), `at least one event with an "e" tag`},
		{"malformed target", deletion(nostr.Tag{"e", "abc"}), "64-character hex event id"},
		{"address reference", deletion(eventID, nostr.Tag{"a", "1:" + alice + ":x"}), `must not carry "a" tags`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := policies.ValidateKind5Shape(ctx, tc.evt)
			if tc.reason == "" {
				if reject {
					t.Fatalf("should have been accepted, got %q", msg)
				}
				return
			}
			if !reject || !strings.Contains(msg, tc.reason) {
				t.Fatalf("expected %q, got %v %q", tc.reason, reject, msg)
			}
		})
	}
}

func TestValidateKind62Shape(t *testing.T) {
	ctx := context.Background()
	vanish := func(tags ...nostr.Tag) *nostr.Event {
		return evt(62, append(nostr.Tags{{"expiration", "9999999999"}, {"client", "test"}}, tags...), "")
	}

	tests := []struct {
		name   string
		evt    *nostr.Event
		reason string
	}{
		{"without a relay tag", vanish(), ""},
		{"relay all", vanish(nostr.Tag{"relay", "all"}), ""},
		{"relay url", vanish(nostr.Tag{"relay", "wss://relay.example"}), ""},
		{"empty relay tag", vanish(nostr.Tag{"relay", ""}), `"relay" tag must have a value`},
		{"unrelated tag", vanish(nostr.Tag{"t", "spam"}), `must not carry "t" tags`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := policies.ValidateKind62Shape(ctx, tc.evt)
			if tc.reason == "" {
				if reject {
					t.Fatalf("should have been accepted, got %q", msg)
				}
				return
			}
			if !reject || !strings.Contains(msg, tc.reason) {
				t.Fatalf("expected %q, got %v %q", tc.reason, reject, msg)
			}
		})
	}
}

func TestDMReadPolicy(t *testing.T) {
	ctx := bkind.WithAuthenticatedPubKey(context.Background(), alice)

	tests := []struct {
		name   string
		filter nostr.Filter
		reason string
	}{
		{"own messages", nostr.Filter{Kinds: []int{4}, Authors: []string{alice}}, ""},
		{"own mailbox", nostr.Filter{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{alice}}}, ""},
		{"own deletions", nostr.Filter{Kinds: []int{5}, Authors: []string{alice}}, ""},
		{"own vanish requests", nostr.Filter{Kinds: []int{62}, Authors: []string{alice}}, ""},
		{"everything with an author pin", nostr.Filter{Authors: []string{alice}}, ""},
		{"everything", nostr.Filter{}, "pin"},
		{"every message", nostr.Filter{Kinds: []int{4}}, "pin"},
		{"every deletion", nostr.Filter{Kinds: []int{5}}, "only readable by their author"},
		{"someone else's messages", nostr.Filter{Kinds: []int{4}, Authors: []string{bob}}, "pin"},
		{"someone else's mailbox", nostr.Filter{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob}}}, "pin"},
		{"mixed authors", nostr.Filter{Kinds: []int{4}, Authors: []string{alice, bob}}, "pin"},
		{"deletions plus a mailbox pin", nostr.Filter{Kinds: []int{4, 5}, Tags: nostr.TagMap{"p": []string{alice}}}, "only readable by their author"},
		{"a kind this relay does not serve", nostr.Filter{Kinds: []int{1}, Authors: []string{alice}}, "not served"},
		{"a mix including one it does not serve", nostr.Filter{Kinds: []int{4, 7}, Authors: []string{alice}}, "not served"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := policies.DMReadPolicy(ctx, tc.filter)
			if tc.reason == "" {
				if reject {
					t.Fatalf("should have been accepted, got %q", msg)
				}
				return
			}
			if !reject || !strings.Contains(msg, tc.reason) {
				t.Fatalf("expected %q, got %v %q", tc.reason, reject, msg)
			}
		})
	}

	t.Run("unauthenticated", func(t *testing.T) {
		if reject, msg := policies.DMReadPolicy(context.Background(), nostr.Filter{Authors: []string{alice}}); !reject || !strings.HasPrefix(msg, "auth-required:") {
			t.Fatalf("expected a challenge, got %v %q", reject, msg)
		}
	})

	t.Run("counts follow the same rules", func(t *testing.T) {
		if reject, _ := policies.DMCountPolicy(ctx, nostr.Filter{Kinds: []int{4}}); !reject {
			t.Fatal("counting every message should be refused")
		}
		if reject, msg := policies.DMCountPolicy(ctx, nostr.Filter{Kinds: []int{4}, Authors: []string{alice}}); reject {
			t.Fatalf("counting own messages should be allowed, got %q", msg)
		}
	})
}

func TestDMBroadcastGuard(t *testing.T) {
	blocked := func(authed string, e *nostr.Event) bool {
		return policies.DMBroadcastGuard(&bkind.WebSocket{AuthedPublicKey: authed}, e)
	}

	dm := evt(4, nostr.Tags{{"p", bob}}, "ciphertext")
	if blocked(alice, dm) {
		t.Fatal("the author should receive their own message")
	}
	if blocked(bob, dm) {
		t.Fatal("the recipient should receive the message")
	}
	if !blocked(carol, dm) {
		t.Fatal("a third party must not receive the message")
	}
	if !blocked("", dm) {
		t.Fatal("an unauthenticated connection must not receive the message")
	}

	deletion := evt(5, nostr.Tags{{"e", strings.Repeat("a", 64)}}, "")
	if blocked(alice, deletion) {
		t.Fatal("the author should receive their own deletion")
	}
	if !blocked(bob, deletion) {
		t.Fatal("the recipient must not receive the deletion")
	}

	if !blocked(alice, evt(1, nil, "a note")) {
		t.Fatal("kinds outside the allowlist must never be broadcast")
	}
}

func TestFilterAuthedPubKeyRateLimiter(t *testing.T) {
	policy := policies.FilterAuthedPubKeyRateLimiter(1, time.Hour, 1)
	ctx := bkind.WithAuthenticatedPubKey(context.Background(), alice)

	if reject, msg := policy(ctx, nostr.Filter{}); reject {
		t.Fatalf("the first request should pass, got %q", msg)
	}
	if reject, msg := policy(ctx, nostr.Filter{}); !reject {
		t.Fatalf("the second request should be limited, got %q", msg)
	}

	// another user has their own budget
	if reject, msg := policy(bkind.WithAuthenticatedPubKey(context.Background(), bob), nostr.Filter{}); reject {
		t.Fatalf("another user should not be limited, got %q", msg)
	}

	// unauthenticated requests are left to the ip limiter
	if reject, msg := policy(context.Background(), nostr.Filter{}); reject {
		t.Fatalf("unauthenticated requests should pass, got %q", msg)
	}
}
