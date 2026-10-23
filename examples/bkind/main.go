// A relay that only serves NIP-04 direct messages: kind 4, plus the two utility
// kinds needed to make a message deletable (NIP-09) and to erase an identity
// (NIP-62). Everything is authenticated, everything expires, and a message is only
// ever readable by its author and its recipient.
//
// See docs/cookbook/dm-only-relay.md for the reasoning behind each policy,
// docs/cookbook/deploying.md for running it on a server, and
// docs/cookbook/docker.md for the container path.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fiatjaf/eventstore/badger"
	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/nbd-wtf/go-nostr/nip40"
)

// Limits of the relay. The defaults can be changed with the flags below; the
// deployment guide runs them from an environment file.
const (
	defaultMaxContentLen  = 4096
	defaultMaxTags        = 16
	defaultMaxTagNameLen  = 64
	defaultMaxTagValueLen = 256
	defaultMaxExpiration  = 75 * time.Hour
	defaultSweepInterval  = 5 * time.Minute

	// the websocket frame limit is only a backstop: the real limit is enforced on
	// the content by policies.MaxContentLen, so that a client gets a NAK instead of
	// a closed connection
	maxMessageBytes = 12 * 1024
)

type config struct {
	addr          string
	serviceURL    string
	dbPath        string // empty means an in-memory store, for local testing
	sweepInterval time.Duration
	maxContentLen int
	maxExpiration time.Duration
	maxTags       int
}

func main() {
	cfg := parseConfig()

	relay, closer, err := newRelay(cfg)
	if err != nil {
		log.Fatalf("failed to start the relay: %v", err)
	}
	defer closer()

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           relay,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("listening on %s, serving %s (kinds 4/5/62, content <= %d bytes, expiration <= %s)",
			cfg.addr, cfg.serviceURL, cfg.maxContentLen, cfg.maxExpiration)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")

	// give in-flight requests a moment, then close the store: a websocket accept
	// that lands after the store is closed loses the event, one that lands after a
	// hard kill can lose it too
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func parseConfig() config {
	addr := envOr("BKIND_ADDR", ":3334")
	serviceURL := envOr("BKIND_URL", "")
	dbPath := envOr("BKIND_DB", "")
	sweepInterval := envOr("BKIND_SWEEP_INTERVAL", defaultSweepInterval.String())
	maxExpiration := envOr("BKIND_MAX_EXPIRATION", defaultMaxExpiration.String())
	maxContentLen := envOr("BKIND_MAX_CONTENT", strconv.Itoa(defaultMaxContentLen))
	maxTags := envOr("BKIND_MAX_TAGS", strconv.Itoa(defaultMaxTags))

	flag.StringVar(&addr, "addr", addr, "address to listen on")
	flag.StringVar(&serviceURL, "url", serviceURL, "public URL of this relay (wss://...), used for NIP-42 and NIP-62")
	flag.StringVar(&dbPath, "db", dbPath, "path of the database directory (empty means in-memory, nothing is persisted)")
	flag.StringVar(&sweepInterval, "sweep-interval", sweepInterval, "how often expired events are deleted")
	flag.StringVar(&maxExpiration, "max-expiration", maxExpiration, "longest allowed NIP-40 expiration")
	flag.StringVar(&maxContentLen, "max-content", maxContentLen, "maximum content length in bytes")
	flag.StringVar(&maxTags, "max-tags", maxTags, "maximum number of tags")
	flag.Parse()

	cfg := config{
		addr:       addr,
		serviceURL: normalizeServiceURL(serviceURL),
		dbPath:     dbPath,
	}

	var err error
	if cfg.sweepInterval, err = time.ParseDuration(sweepInterval); err != nil || cfg.sweepInterval <= 0 {
		log.Fatalf("invalid -sweep-interval %q", sweepInterval)
	}
	if cfg.maxExpiration, err = time.ParseDuration(maxExpiration); err != nil || cfg.maxExpiration <= 0 {
		log.Fatalf("invalid -max-expiration %q", maxExpiration)
	}
	if cfg.maxContentLen, err = strconv.Atoi(maxContentLen); err != nil || cfg.maxContentLen <= 0 {
		log.Fatalf("invalid -max-content %q", maxContentLen)
	}
	if cfg.maxTags, err = strconv.Atoi(maxTags); err != nil || cfg.maxTags <= 0 {
		log.Fatalf("invalid -max-tags %q", maxTags)
	}

	return cfg
}

// newRelay wires the store and the policy set. It returns the relay plus a close
// function for the store.
func newRelay(cfg config) (*khatru.Relay, func(), error) {
	relay := khatru.NewRelay()
	relay.ServiceURL = cfg.serviceURL
	relay.MaxMessageSize = maxMessageBytes
	relay.SetExpirationInterval(cfg.sweepInterval)
	relay.Negentropy = false // set reconciliation would leak which event ids exist

	closer := func() {}
	store, err := openStore(cfg.dbPath)
	if err != nil {
		return nil, nil, err
	}
	closer = store.close

	relay.StoreEvent = append(relay.StoreEvent, store.saveEvent)
	relay.QueryEvents = append(relay.QueryEvents, dropExpired(store.queryEvents))
	relay.CountEvents = append(relay.CountEvents, store.countEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, store.deleteEvent)

	// ---------------------------------------------------------------- writes
	relay.RejectEvent = append(relay.RejectEvent,
		policies.RestrictToSpecifiedKinds(false, policies.DMKindAllowlist...),
		policies.RequireAuthedAuthor,
		policies.RequireExpiration(cfg.maxExpiration),
		policies.RequireTag("client"),
		policies.MaxContentLen(cfg.maxContentLen),
		policies.TagShapeLimits(cfg.maxTags, defaultMaxTagNameLen, defaultMaxTagValueLen),
		policies.ValidateKind4Shape,
		policies.ValidateKind5Shape,
		policies.ValidateKind62Shape,

		// per npub: refill every hour, then a daily ceiling
		policies.EventAuthedPubKeyRateLimiter(30, time.Hour, 60),
		policies.EventAuthedPubKeyRateLimiter(200, 24*time.Hour, 400),
		// per ip, for whatever arrives before it is authenticated
		policies.EventIPRateLimiter(60, time.Hour, 120),
		policies.EventIPRateLimiter(400, 24*time.Hour, 800),
	)

	// a filter without kinds means "every kind" to the store, so narrow it to the
	// kinds this relay actually serves before anything else looks at it
	relay.OverwriteFilter = append(relay.OverwriteFilter, func(ctx context.Context, filter *nostr.Filter) {
		if len(filter.Kinds) == 0 {
			filter.Kinds = []int{4, 5, 62}
			return
		}

		kinds := make([]int, 0, len(filter.Kinds))
		for _, kind := range filter.Kinds {
			switch uint16(kind) {
			case 4, 5, 62:
				kinds = append(kinds, kind)
			}
		}
		filter.Kinds = kinds
		if len(kinds) == 0 {
			filter.LimitZero = true // nothing to return, but stay subscribed
		}
	})

	// ----------------------------------------------------------------- reads
	relay.RejectFilter = append(relay.RejectFilter,
		policies.MustAuth,
		policies.DMReadPolicy,
		policies.NoEmptyFilters,
		policies.NoSearchQueries,

		policies.FilterAuthedPubKeyRateLimiter(60, time.Hour, 120),
		policies.FilterAuthedPubKeyRateLimiter(400, 24*time.Hour, 800),
		policies.FilterIPRateLimiter(120, time.Hour, 240),
		policies.FilterIPRateLimiter(800, 24*time.Hour, 1600),
	)

	// a COUNT over direct messages is a metadata leak even when no event is returned
	relay.RejectCountFilter = append(relay.RejectCountFilter,
		policies.MustAuth,
		policies.DMCountPolicy,
	)

	// live delivery does not re-run the filter policies, so a wide subscription
	// would otherwise receive kind 4 events for the life of the connection
	relay.PreventBroadcast = append(relay.PreventBroadcast, policies.DMBroadcastGuard)

	relay.RejectConnection = append(relay.RejectConnection,
		policies.ConnectionRateLimiter(120, time.Hour, 240),
	)

	// --------------------------------------------------------------- NIP-11
	relay.Info.Name = "B kind relay"
	relay.Info.Description = "kind 4 direct messages only. Authenticated, ephemeral (max 75h), size-limited."
	relay.Info.SupportedNIPs = []any{4, 9, 11, 40, 42, 62}
	relay.Info.Limitation = &nip11.RelayLimitationDocument{
		MaxMessageLength: maxMessageBytes,
		MaxEventTags:     cfg.maxTags,
		MaxContentLength: cfg.maxContentLen,
		MaxSubscriptions: 10,
		MaxFilters:       4,
		MaxLimit:         500,
		AuthRequired:     true,
		RestrictedWrites: true,
	}

	return relay, closer, nil
}

// store is the subset of an eventstore backend this relay uses, so the main file
// does not care whether it is talking to badger or to memory.
type store struct {
	saveEvent   func(context.Context, *nostr.Event) error
	queryEvents func(context.Context, nostr.Filter) (chan *nostr.Event, error)
	countEvents func(context.Context, nostr.Filter) (int64, error)
	deleteEvent func(context.Context, *nostr.Event) error
	close       func()
}

func openStore(path string) (store, error) {
	if path == "" {
		log.Println("no -db given: using an in-memory store, everything is lost on restart")
		ss := &slicestore.SliceStore{}
		if err := ss.Init(); err != nil {
			return store{}, err
		}
		return store{
			saveEvent:   ss.SaveEvent,
			queryEvents: ss.QueryEvents,
			countEvents: ss.CountEvents,
			deleteEvent: ss.DeleteEvent,
			close:       func() {},
		}, nil
	}

	db := &badger.BadgerBackend{
		Path: path,
		// keep the page size the NIP-11 document advertises
		MaxLimit: 500,
	}
	if err := db.Init(); err != nil {
		return store{}, fmt.Errorf("failed to open the database at %s: %w", path, err)
	}

	return store{
		saveEvent:   db.SaveEvent,
		queryEvents: db.QueryEvents,
		countEvents: db.CountEvents,
		deleteEvent: db.DeleteEvent,
		close:       func() { db.Close() },
	}, nil
}

// dropExpired hides events whose NIP-40 expiration has already passed but that the
// background sweep has not deleted yet, so the answer never depends on when the last
// sweep ran.
func dropExpired(
	query func(context.Context, nostr.Filter) (chan *nostr.Event, error),
) func(context.Context, nostr.Filter) (chan *nostr.Event, error) {
	return func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
		ch, err := query(ctx, filter)
		if err != nil || ch == nil {
			return ch, err
		}

		out := make(chan *nostr.Event)
		go func() {
			defer close(out)

			now := nostr.Now()
			for evt := range ch {
				if expiresAt := nip40.GetExpiration(evt.Tags); expiresAt != -1 && expiresAt <= now {
					continue
				}
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}()

		return out, nil
	}
}

// normalizeServiceURL checks the public URL this relay advertises and strips the
// trailing slash, so NIP-62 "relay" tags and NIP-42 "relay" tags compare equal.
func normalizeServiceURL(raw string) string {
	if raw == "" {
		return "" // fine for local testing; NIP-42 falls back to the request host
	}

	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("invalid -url %q: %v", raw, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		log.Fatalf("invalid -url %q: scheme must be ws or wss", raw)
	}
	if u.Host == "" {
		log.Fatalf("invalid -url %q: missing host", raw)
	}

	return strings.TrimSuffix(raw, "/")
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
