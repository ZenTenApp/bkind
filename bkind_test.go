package bkind_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZenTenApp/bkind"
	"github.com/ZenTenApp/bkind/policies"
	"github.com/fasthttp/websocket"
	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/nbd-wtf/go-nostr/nip42"
)

// testStore serializes access to slicestore, which reads its slice without a lock
// and therefore races with the deletions done by the expiration sweeper and by
// vanish requests. Those are real code paths here, so the test store has to be
// safe for them.
type testStore struct {
	mu sync.Mutex
	ss slicestore.SliceStore
}

func (s *testStore) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ss.Init()
}

func (s *testStore) SaveEvent(ctx context.Context, evt *nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ss.SaveEvent(ctx, evt)
}

func (s *testStore) DeleteEvent(ctx context.Context, evt *nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ss.DeleteEvent(ctx, evt)
}

func (s *testStore) CountEvents(ctx context.Context, filter nostr.Filter) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ss.CountEvents(ctx, filter)
}

func (s *testStore) QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, err := s.ss.QueryEvents(ctx, filter)
	if err != nil {
		return nil, err
	}

	// drain under the lock: slicestore walks its slice from a goroutine
	out := make(chan *nostr.Event, 64)
	for evt := range ch {
		out <- evt
	}
	close(out)
	return out, nil
}

// The relay wired here is examples/bkind/main.go: the reference config, wired by
// the same call. There is nothing to keep in sync by hand anymore.
func newBKindRelay(t *testing.T, serviceURL string) (*bkind.Relay, *testStore) {
	return newRelayWithConfig(t, serviceURL, func(c *policies.Config) {})
}

// newRelayWithConfig wires the reference relay and lets a test adjust the policy
// set before it is applied, which is how the config-driven behaviour is tested.
func newRelayWithConfig(t *testing.T, serviceURL string, mutate func(*policies.Config)) (*bkind.Relay, *testStore) {
	t.Helper()

	relay := bkind.NewRelay()
	relay.ServiceURL = serviceURL

	store := &testStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	relay.StoreEvent = append(relay.StoreEvent, store.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, store.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, store.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, store.DeleteEvent)

	cfg := policies.DefaultConfig()
	// the tests speak far faster than the production limits allow
	cfg.RateLimits = nil
	for _, rule := range cfg.Rules {
		rule.RateLimits = nil
	}
	cfg.ReadLimits = nil
	cfg.ConnectionLimits = nil
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Wire(relay); err != nil {
		t.Fatalf("failed to wire the relay: %v", err)
	}

	return relay, store
}

type testClient struct {
	t         *testing.T
	conn      *websocket.Conn
	sk        string
	pk        string
	relayURL  string
	challenge string
}

func dial(t *testing.T, serverURL string) *testClient {
	t.Helper()

	wsURL := "ws" + strings.TrimPrefix(serverURL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial %s: %v", wsURL, err)
	}
	t.Cleanup(func() { conn.Close() })

	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("failed to derive pubkey: %v", err)
	}

	return &testClient{t: t, conn: conn, sk: sk, pk: pk, relayURL: wsURL}
}

func (c *testClient) readEnvelope() nostr.Envelope {
	c.t.Helper()

	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		c.t.Fatalf("failed to read message: %v", err)
	}

	env, err := nostr.NewMessageParser().ParseMessage(string(msg))
	if err != nil {
		c.t.Fatalf("failed to parse %q: %v", string(msg), err)
	}
	return env
}

// publish sends an event and returns the relay's OK response, remembering any
// NIP-42 challenge the relay sent along the way.
func (c *testClient) publish(evt *nostr.Event) nostr.OKEnvelope {
	c.t.Helper()

	if err := c.conn.WriteJSON(nostr.EventEnvelope{Event: *evt}); err != nil {
		c.t.Fatalf("failed to write event: %v", err)
	}

	for {
		switch env := c.readEnvelope().(type) {
		case *nostr.AuthEnvelope:
			if env.Challenge != nil {
				c.challenge = *env.Challenge
			}
		case *nostr.OKEnvelope:
			if env.EventID == evt.ID {
				return *env
			}
		case *nostr.NoticeEnvelope:
			c.t.Fatalf("unexpected notice while publishing: %s", string(*env))
		}
	}
}

// authenticate signs the last challenge the relay offered. If no challenge has
// been seen yet, it provokes one with a self-consistent event: the relay answers
// writes from unauthenticated clients with "auth-required: " plus an AUTH message.
func (c *testClient) authenticate() {
	c.t.Helper()

	if c.challenge == "" {
		peerSK := nostr.GeneratePrivateKey()
		peerPK, err := nostr.GetPublicKey(peerSK)
		if err != nil {
			c.t.Fatalf("failed to derive pubkey: %v", err)
		}
		c.publish(dmEvent(c.t, c.sk, peerPK, "auth-probe"))
	}

	if c.challenge == "" {
		c.t.Fatal("no NIP-42 challenge was received")
	}

	authEvent := nip42.CreateUnsignedAuthEvent(c.challenge, c.pk, c.relayURL)
	if err := authEvent.Sign(c.sk); err != nil {
		c.t.Fatalf("failed to sign auth event: %v", err)
	}
	if err := c.conn.WriteJSON(nostr.AuthEnvelope{Event: authEvent}); err != nil {
		c.t.Fatalf("failed to write auth event: %v", err)
	}

	for {
		switch env := c.readEnvelope().(type) {
		case *nostr.OKEnvelope:
			if env.EventID != authEvent.ID {
				continue
			}
			if !env.OK {
				c.t.Fatalf("authentication failed: %s", env.Reason)
			}
			return
		case *nostr.AuthEnvelope:
			if env.Challenge != nil {
				c.challenge = *env.Challenge
			}
		}
	}
}

// publishAuthed authenticates on demand and retries once.
func (c *testClient) publishAuthed(evt *nostr.Event) nostr.OKEnvelope {
	c.t.Helper()

	res := c.publish(evt)
	if res.OK || !strings.HasPrefix(res.Reason, "auth-required:") {
		return res
	}

	c.authenticate()
	return c.publish(evt)
}

// query sends a REQ and collects events until EOSE. When the relay refuses the
// filter it returns the CLOSED reason instead.
func (c *testClient) query(filter nostr.Filter) (events []*nostr.Event, closed string) {
	c.t.Helper()

	subID := fmt.Sprintf("sub-%d", time.Now().UnixNano())
	if err := c.conn.WriteJSON(nostr.ReqEnvelope{SubscriptionID: subID, Filters: nostr.Filters{filter}}); err != nil {
		c.t.Fatalf("failed to write req: %v", err)
	}
	defer c.conn.WriteJSON(nostr.CloseEnvelope(subID))

	for {
		switch env := c.readEnvelope().(type) {
		case *nostr.EventEnvelope:
			events = append(events, cloneEvent(&env.Event))
		case *nostr.EOSEEnvelope:
			return events, ""
		case *nostr.ClosedEnvelope:
			return events, env.Reason
		case *nostr.AuthEnvelope:
			if env.Challenge != nil {
				c.challenge = *env.Challenge
			}
		case *nostr.NoticeEnvelope:
			return events, "notice: " + string(*env)
		}
	}
}

func (c *testClient) count(filter nostr.Filter) (int64, string) {
	c.t.Helper()

	subID := fmt.Sprintf("count-%d", time.Now().UnixNano())
	if err := c.conn.WriteJSON(nostr.CountEnvelope{SubscriptionID: subID, Filter: filter}); err != nil {
		c.t.Fatalf("failed to write count: %v", err)
	}

	for {
		switch env := c.readEnvelope().(type) {
		case *nostr.CountEnvelope:
			if env.Count == nil {
				return 0, "no count"
			}
			return *env.Count, ""
		case *nostr.ClosedEnvelope:
			return 0, env.Reason
		case *nostr.NoticeEnvelope:
			return 0, "notice: " + string(*env)
		}
	}
}

func cloneEvent(evt *nostr.Event) *nostr.Event {
	cp := *evt
	cp.Tags = make(nostr.Tags, len(evt.Tags))
	for i, tag := range evt.Tags {
		cp.Tags[i] = append(nostr.Tag{}, tag...)
	}
	return &cp
}

func expirationTag(d time.Duration) nostr.Tag {
	return nostr.Tag{"expiration", fmt.Sprint(int64(time.Now().Add(d).Unix()))}
}

func dmEvent(t *testing.T, sk, recipient, content string) *nostr.Event {
	t.Helper()

	evt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      4,
		Tags: nostr.Tags{
			{"p", recipient},
			expirationTag(time.Hour),
			{"client", "bkind-test"},
		},
		Content: content,
	}
	if err := evt.Sign(sk); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return evt
}

func TestBKindRequiresAuthAndAuthorship(t *testing.T) {
	relay, _ := newBKindRelay(t, "")
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	bob := dial(t, server.URL)

	// unauthenticated writes are refused with a challenge, not dropped
	unauthed := dmEvent(t, alice.sk, bob.pk, "ciphertext-1")
	res := alice.publish(unauthed)
	if res.OK || !strings.HasPrefix(res.Reason, "auth-required:") {
		t.Fatalf("expected auth-required, got ok=%v reason=%q", res.OK, res.Reason)
	}
	if alice.challenge == "" {
		t.Fatal("relay did not send a NIP-42 challenge")
	}

	alice.authenticate()

	if res := alice.publish(unauthed); !res.OK {
		t.Fatalf("expected the event to be accepted after auth, got %q", res.Reason)
	}

	// an authenticated client cannot publish on behalf of someone else
	bob.authenticate()
	forged := dmEvent(t, alice.sk, bob.pk, "ciphertext-2")
	if res := bob.publish(forged); res.OK || !strings.Contains(res.Reason, "authenticated key") {
		t.Fatalf("expected a blocked authorship error, got ok=%v reason=%q", res.OK, res.Reason)
	}
}

func TestBKindWriteRules(t *testing.T) {
	relay, _ := newBKindRelay(t, "")
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	alice.authenticate()
	bob := dial(t, server.URL)

	valid := func() *nostr.Event {
		return dmEvent(t, alice.sk, bob.pk, "ciphertext")
	}

	if res := alice.publishAuthed(valid()); !res.OK {
		t.Fatalf("baseline event was rejected: %q", res.Reason)
	}

	tests := []struct {
		name   string
		evt    func() *nostr.Event
		reason string
	}{
		{
			name: "wrong kind",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Kind = 1
				evt.Tags = nostr.Tags{expirationTag(time.Hour), {"client", "bkind-test"}}
				evt.Sign(alice.sk)
				return evt
			},
			reason: "not allowed",
		},
		{
			name: "oversized content",
			evt: func() *nostr.Event {
				return dmEvent(t, alice.sk, bob.pk, strings.Repeat("x", 4097))
			},
			reason: "content is too large",
		},
		{
			name: "missing expiration",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags = nostr.Tags{{"p", bob.pk}, {"client", "bkind-test"}}
				evt.Sign(alice.sk)
				return evt
			},
			reason: `missing mandatory "expiration" tag`,
		},
		{
			name: "expiration too far away",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags[1] = expirationTag(76 * time.Hour)
				evt.Sign(alice.sk)
				return evt
			},
			reason: "too far in the future",
		},
		{
			name: "expiration in the past",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags[1] = nostr.Tag{"expiration", fmt.Sprint(int64(time.Now().Add(-time.Minute).Unix()))}
				evt.Sign(alice.sk)
				return evt
			},
			reason: "already expired",
		},
		{
			name: "missing client tag",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags = nostr.Tags{{"p", bob.pk}, expirationTag(time.Hour)}
				evt.Sign(alice.sk)
				return evt
			},
			reason: `missing mandatory "client" tag`,
		},
		{
			name: "too many tags",
			evt: func() *nostr.Event {
				evt := valid()
				for i := 0; i < 14; i++ {
					evt.Tags = append(evt.Tags, nostr.Tag{"t", fmt.Sprint(i)})
				}
				evt.Sign(alice.sk)
				return evt
			},
			reason: "too many tags",
		},
		{
			name: "tag name too long",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags = append(evt.Tags, nostr.Tag{strings.Repeat("n", 65), "value"})
				evt.Sign(alice.sk)
				return evt
			},
			reason: "tag name is too long",
		},
		{
			name: "tag value too long",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags = append(evt.Tags, nostr.Tag{"t", strings.Repeat("v", 257)})
				evt.Sign(alice.sk)
				return evt
			},
			reason: "tag value is too long",
		},
		{
			name: "two recipients",
			evt: func() *nostr.Event {
				evt := valid()
				other := dial(t, server.URL)
				evt.Tags = append(evt.Tags, nostr.Tag{"p", other.pk})
				evt.Sign(alice.sk)
				return evt
			},
			reason: `exactly one "p" tag`,
		},
		{
			name: "references another event",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags = append(evt.Tags, nostr.Tag{"e", strings.Repeat("a", 64)})
				evt.Sign(alice.sk)
				return evt
			},
			reason: `must not carry "e" tags`,
		},
		{
			name: "addressed to itself",
			evt: func() *nostr.Event {
				evt := valid()
				evt.Tags[0] = nostr.Tag{"p", alice.pk}
				evt.Sign(alice.sk)
				return evt
			},
			reason: "cannot be addressed to their own author",
		},
		{
			name: "deletion without targets",
			evt: func() *nostr.Event {
				evt := &nostr.Event{
					CreatedAt: nostr.Now(),
					Kind:      5,
					Tags:      nostr.Tags{expirationTag(time.Hour), {"client", "bkind-test"}},
				}
				evt.Sign(alice.sk)
				return evt
			},
			reason: `at least one event with an "e" tag`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := alice.publishAuthed(tc.evt())
			if res.OK {
				t.Fatalf("expected the event to be rejected")
			}
			if !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("expected reason to contain %q, got %q", tc.reason, res.Reason)
			}
		})
	}
}

func TestBKindPrivacy(t *testing.T) {
	relay, _ := newBKindRelay(t, "")
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	alice.authenticate()
	bob := dial(t, server.URL)
	bob.authenticate()
	carol := dial(t, server.URL)
	carol.authenticate()

	dm := dmEvent(t, alice.sk, bob.pk, "for-bob-only")
	if res := alice.publishAuthed(dm); !res.OK {
		t.Fatalf("alice could not publish: %q", res.Reason)
	}

	t.Run("recipient can read", func(t *testing.T) {
		events, closed := bob.query(nostr.Filter{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob.pk}}})
		if closed != "" {
			t.Fatalf("bob was refused: %s", closed)
		}
		if len(events) != 1 || events[0].ID != dm.ID {
			t.Fatalf("bob expected the message, got %d events", len(events))
		}
	})

	t.Run("author can read their own sent messages", func(t *testing.T) {
		events, closed := alice.query(nostr.Filter{Kinds: []int{4}, Authors: []string{alice.pk}})
		if closed != "" {
			t.Fatalf("alice was refused: %s", closed)
		}
		if len(events) != 1 {
			t.Fatalf("alice expected her message, got %d events", len(events))
		}
	})

	t.Run("third party cannot enumerate", func(t *testing.T) {
		for _, filter := range []nostr.Filter{
			{Kinds: []int{4}},
			{Authors: []string{alice.pk}},
			{Kinds: []int{4}, Authors: []string{alice.pk, bob.pk}},
			{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob.pk}}},
			{Kinds: []int{5}, Authors: []string{alice.pk}},
			{},
		} {
			if events, closed := carol.query(filter); closed == "" {
				t.Fatalf("filter %v should have been refused, returned %d events", filter, len(events))
			}
		}
	})

	t.Run("third party querying their own mailbox is allowed but empty", func(t *testing.T) {
		events, closed := carol.query(nostr.Filter{Kinds: []int{4}, Authors: []string{carol.pk}})
		if closed != "" {
			t.Fatalf("carol was refused her own mailbox: %s", closed)
		}
		if len(events) != 0 {
			t.Fatalf("carol sees %d events that are not hers", len(events))
		}
	})

	t.Run("unauthenticated reads are refused", func(t *testing.T) {
		anon := dial(t, server.URL)
		if _, closed := anon.query(nostr.Filter{Kinds: []int{4}, Authors: []string{anon.pk}}); !strings.HasPrefix(closed, "auth-required:") {
			t.Fatalf("expected auth-required, got %q", closed)
		}
	})

	t.Run("counts are refused for other people's messages", func(t *testing.T) {
		if _, reason := carol.count(nostr.Filter{Kinds: []int{4}, Authors: []string{alice.pk}}); reason == "" {
			t.Fatal("expected the count to be refused")
		}
	})

	t.Run("live delivery reaches the recipient only", func(t *testing.T) {
		subID := "live"
		if err := bob.conn.WriteJSON(nostr.ReqEnvelope{
			SubscriptionID: subID,
			Filters:        nostr.Filters{{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob.pk}}}},
		}); err != nil {
			t.Fatalf("failed to subscribe: %v", err)
		}

		// wait for EOSE before publishing
		for {
			if _, ok := bob.readEnvelope().(*nostr.EOSEEnvelope); ok {
				break
			}
		}

		live := dmEvent(t, alice.sk, bob.pk, "live-message")
		if res := alice.publishAuthed(live); !res.OK {
			t.Fatalf("alice could not publish: %q", res.Reason)
		}

		switch env := bob.readEnvelope().(type) {
		case *nostr.EventEnvelope:
			if env.ID != live.ID {
				t.Fatalf("bob received the wrong event %s", env.ID)
			}
		default:
			t.Fatalf("bob received %T instead of the event", env)
		}
	})
}

func TestBKindDeletion(t *testing.T) {
	relay, _ := newBKindRelay(t, "")
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	alice.authenticate()
	bob := dial(t, server.URL)
	bob.authenticate()
	mallory := dial(t, server.URL)
	mallory.authenticate()

	dm := dmEvent(t, alice.sk, bob.pk, "delete-me")
	if res := alice.publishAuthed(dm); !res.OK {
		t.Fatalf("alice could not publish: %q", res.Reason)
	}

	t.Run("a foreign deletion is refused and changes nothing", func(t *testing.T) {
		forged := &nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      5,
			Tags: nostr.Tags{
				{"e", dm.ID},
				expirationTag(time.Hour),
				{"client", "bkind-test"},
			},
		}
		forged.Sign(mallory.sk)

		res := mallory.publishAuthed(forged)
		if res.OK || !strings.Contains(res.Reason, "no valid deletion targets") {
			t.Fatalf("expected the deletion to be refused, got ok=%v reason=%q", res.OK, res.Reason)
		}

		events, closed := bob.query(nostr.Filter{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob.pk}}})
		if closed != "" {
			t.Fatalf("bob was refused: %s", closed)
		}
		if len(events) != 1 {
			t.Fatalf("the message was deleted by a third party")
		}
	})

	t.Run("the author can delete their own message", func(t *testing.T) {
		deletion := &nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      5,
			Tags: nostr.Tags{
				{"e", dm.ID},
				expirationTag(time.Hour),
				{"client", "bkind-test"},
			},
		}
		deletion.Sign(alice.sk)

		if res := alice.publishAuthed(deletion); !res.OK {
			t.Fatalf("deletion was refused: %q", res.Reason)
		}

		events, closed := bob.query(nostr.Filter{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob.pk}}})
		if closed != "" {
			t.Fatalf("bob was refused: %s", closed)
		}
		if len(events) != 0 {
			t.Fatalf("the message is still readable after deletion")
		}
	})

	t.Run("the deleted message cannot be republished", func(t *testing.T) {
		res := alice.publishAuthed(dm)
		if res.OK || !strings.Contains(res.Reason, "has been deleted") {
			t.Fatalf("expected the republish to be refused, got ok=%v reason=%q", res.OK, res.Reason)
		}
	})
}

func TestBKindVanish(t *testing.T) {
	// the relay needs to know its own URL to accept a targeted vanish request
	relay, _ := newBKindRelay(t, "ws://placeholder")
	server := httptest.NewServer(relay)
	defer server.Close()
	relay.ServiceURL = "ws" + strings.TrimPrefix(server.URL, "http")

	alice := dial(t, server.URL)
	alice.authenticate()
	bob := dial(t, server.URL)
	bob.authenticate()

	first := dmEvent(t, alice.sk, bob.pk, "one")
	second := dmEvent(t, alice.sk, bob.pk, "two")
	for _, evt := range []*nostr.Event{first, second} {
		if res := alice.publishAuthed(evt); !res.OK {
			t.Fatalf("alice could not publish: %q", res.Reason)
		}
	}

	t.Run("a request for another relay is refused", func(t *testing.T) {
		vanish := &nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      62,
			Tags: nostr.Tags{
				{"relay", "wss://somewhere-else.example"},
				expirationTag(time.Hour),
				{"client", "bkind-test"},
			},
		}
		vanish.Sign(alice.sk)

		res := alice.publishAuthed(vanish)
		if res.OK || !strings.Contains(res.Reason, "another relay") {
			t.Fatalf("expected the request to be refused, got ok=%v reason=%q", res.OK, res.Reason)
		}
	})

	t.Run("a request for this relay erases the author", func(t *testing.T) {
		vanish := &nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      62,
			Tags: nostr.Tags{
				{"relay", relay.ServiceURL},
				expirationTag(time.Hour),
				{"client", "bkind-test"},
			},
		}
		vanish.Sign(alice.sk)
		relay.ServiceURL = "ws" + strings.TrimPrefix(server.URL, "http")

		if res := alice.publishAuthed(vanish); !res.OK {
			t.Fatalf("vanish request was refused: %q", res.Reason)
		}

		events, closed := bob.query(nostr.Filter{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{bob.pk}}})
		if closed != "" {
			t.Fatalf("bob was refused: %s", closed)
		}
		if len(events) != 0 {
			t.Fatalf("alice still has %d events after vanishing", len(events))
		}

		// anything dated before the request is refused from now on
		older := dmEvent(t, alice.sk, bob.pk, "stale")
		older.CreatedAt = vanish.CreatedAt - 10
		older.Sign(alice.sk)
		if res := alice.publishAuthed(older); res.OK || !strings.Contains(res.Reason, "vanish") {
			t.Fatalf("expected stale events to be refused, got ok=%v reason=%q", res.OK, res.Reason)
		}
	})
}

func TestBKindVanishNeedsADeletableStore(t *testing.T) {
	relay, _ := newBKindRelay(t, "")
	relay.DeleteEvent = nil
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	alice.authenticate()

	vanish := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      62,
		Tags:      nostr.Tags{expirationTag(time.Hour), {"client", "bkind-test"}},
	}
	vanish.Sign(alice.sk)

	res := alice.publishAuthed(vanish)
	if res.OK || !strings.Contains(res.Reason, "cannot honor") {
		t.Fatalf("expected the request to be refused, got ok=%v reason=%q", res.OK, res.Reason)
	}
}

func TestBKindNIP11(t *testing.T) {
	relay, _ := newBKindRelay(t, "")
	relay.Info.SupportedNIPs = []any{4, 9, 11, 40, 42, 62}
	relay.Info.Limitation = &nip11.RelayLimitationDocument{
		MaxContentLength: 4096,
		MaxEventTags:     16,
		AuthRequired:     true,
		RestrictedWrites: true,
	}
	server := httptest.NewServer(relay)
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/nostr+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to fetch NIP-11: %v", err)
	}
	defer res.Body.Close()

	var info struct {
		SupportedNIPs []any `json:"supported_nips"`
		Limitation    struct {
			AuthRequired     bool `json:"auth_required"`
			RestrictedWrites bool `json:"restricted_writes"`
		} `json:"limitation"`
	}
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		t.Fatalf("failed to decode NIP-11: %v", err)
	}

	if !info.Limitation.AuthRequired || !info.Limitation.RestrictedWrites {
		t.Fatalf("NIP-11 does not advertise authentication: %+v", info.Limitation)
	}
	// the store wires CountEvents, so the framework would advertise NIP-45 on its
	// own; this relay refuses every COUNT, so it must not
	for _, advertised := range info.SupportedNIPs {
		if advertised == float64(45) {
			t.Fatalf("NIP-11 advertises NIP-45 while every COUNT is refused: %v", info.SupportedNIPs)
		}
	}
	for _, nip := range []any{float64(4), float64(9), float64(42), float64(62)} {
		found := false
		for _, advertised := range info.SupportedNIPs {
			if advertised == nip {
				found = true
			}
		}
		if !found {
			t.Fatalf("NIP-11 is missing nip %v: %v", nip, info.SupportedNIPs)
		}
	}
}

// An already-expired event that is in the store when the relay starts must be
// deleted by the startup scan, not an hour later by the first periodic sweep.
func TestBKindExpirationSweepOnStartup(t *testing.T) {
	relay, store := newBKindRelay(t, "")
	relay.SetExpirationInterval(time.Hour)

	sk := nostr.GeneratePrivateKey()
	peer, err := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	if err != nil {
		t.Fatalf("failed to derive pubkey: %v", err)
	}

	stale := dmEvent(t, sk, peer, "written before the restart")
	stale.Tags[1] = nostr.Tag{"expiration", fmt.Sprint(int64(nostr.Now() - 60))}
	if err := stale.Sign(sk); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	if err := store.SaveEvent(context.Background(), stale); err != nil {
		t.Fatalf("failed to preload the event: %v", err)
	}

	// the sweeper starts on first use, so any request is enough to trigger it
	server := httptest.NewServer(relay)
	defer server.Close()
	res, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("failed to query the relay: %v", err)
	}
	res.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ch, err := store.QueryEvents(context.Background(), nostr.Filter{IDs: []string{stale.ID}})
		if err != nil {
			t.Fatalf("failed to query the store: %v", err)
		}
		if evt := <-ch; evt == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatal("the startup scan left an expired event in the store")
}

// The kind set is configuration, not code: adding a kind to the allowlist is enough
// for the relay to serve it end to end, and removing one makes it reject the REQ with
// a reason the client can act on instead of returning a silent empty EOSE.
func TestBKindKindsAreConfigurable(t *testing.T) {
	relay, _ := newRelayWithConfig(t, "", func(c *policies.Config) {
		c.Kinds.Whitelist = []uint16{4, 5, 62, 1}
		// a public note kind: a rule with no restrictions, which is a choice the
		// per-kind dialect makes explicit
		c.Rules["1"] = &policies.KindRule{
			Description: "public notes",
			RuleSettings: policies.RuleSettings{
				Write: policies.WriteGate{Allow: policies.AllowList{"*"}},
				Read:  policies.ReadGate{Allow: policies.AllowList{"*"}},
			},
		}
	})
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	alice.authenticate()

	note := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags: nostr.Tags{
			expirationTag(time.Hour),
			{"client", "bkind-test"},
		},
		Content: "a note, on a relay configured to serve it",
	}
	if err := note.Sign(alice.sk); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if res := alice.publishAuthed(note); !res.OK {
		t.Fatalf("the configured kind was refused: %q", res.Reason)
	}

	events, closed := alice.query(nostr.Filter{Kinds: []int{1}, Authors: []string{alice.pk}})
	if closed != "" {
		t.Fatalf("the author could not read their own note: %s", closed)
	}
	if len(events) != 1 || events[0].ID != note.ID {
		t.Fatalf("the configured kind is not served on read: %d events", len(events))
	}

	// a kind that stayed out of the allowlist is rejected, not silently dropped
	if _, closed := alice.query(nostr.Filter{Kinds: []int{7}, Authors: []string{alice.pk}}); !strings.Contains(closed, "not served") {
		t.Fatalf("a REQ for an unserved kind should be refused with a reason, got %q", closed)
	}
}

// A relay whose kinds come from a JSON document and environment variables ends up
// wired, not just parsed.
func TestBKindConfigFileWiresTheRelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, []byte(`{
		"kinds": {"whitelist": [4]},
		"rules": {
			"4": {
				"write": {"allow": "*"},
				"read": {"allow": "*", "privileged": true},
				"require_auth": true,
				"max_size": 64,
				"tag_limits": {"max_tags": 8, "max_tag_name_chars": 64, "max_tag_value_chars": 256},
				"required_tags": ["expiration", "client"],
				"p_tag": "hex",
				"shape": true
			}
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := policies.LoadConfig(func(key string) (string, bool) {
		if key == "BKIND_CONFIG" {
			return path, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("failed to load %s: %v", path, err)
	}

	relay := bkind.NewRelay()
	if err := cfg.Wire(relay); err != nil {
		t.Fatalf("failed to wire: %v", err)
	}
	server := httptest.NewServer(relay)
	defer server.Close()

	alice := dial(t, server.URL)
	alice.authenticate()

	// a DM to a peer, oversized by one byte: the size limit is what the client
	// should hear about, not the shape rules that follow it
	peer, err := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if res := alice.publishAuthed(dmEvent(t, alice.sk, peer, strings.Repeat("x", 65))); res.OK || !strings.Contains(res.Reason, "too large") {
		t.Fatalf("the JSON content limit is not enforced: ok=%v reason=%q", res.OK, res.Reason)
	}

	// kind 5 is no longer served
	if _, closed := alice.query(nostr.Filter{Kinds: []int{5}, Authors: []string{alice.pk}}); !strings.Contains(closed, "not served") {
		t.Fatalf("kind 5 is still served after the allowlist dropped it: %q", closed)
	}
}
