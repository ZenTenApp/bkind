// A relay that only serves NIP-04 direct messages: kind 4, plus the two utility
// kinds needed to make a message deletable (NIP-09) and to erase an identity
// (NIP-62). Everything is authenticated, everything expires, and a message is only
// ever readable by its author and its recipient.
//
// See docs/BKind.md for the reasoning behind each policy.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/nbd-wtf/go-nostr/nip40"
)

const (
	maxContentLen  = 4096
	maxTags        = 16
	maxTagNameLen  = 64
	maxTagValueLen = 256
	maxExpiration  = 75 * time.Hour

	// the websocket frame limit is only a backstop: the real limit is enforced on
	// the content by policies.MaxContentLen, so that a client gets a NAK instead of
	// a closed connection
	maxMessageBytes = 12 * 1024

	// how often expired events are swept from the store
	sweepInterval = 5 * time.Minute
)

func main() {
	addr := flag.String("addr", ":3334", "address to listen on")
	serviceURL := flag.String("url", "", "public URL of this relay (ws:// or wss://), used for NIP-42 and NIP-62")
	flag.Parse()

	relay := khatru.NewRelay()
	relay.ServiceURL = *serviceURL
	relay.MaxMessageSize = maxMessageBytes
	relay.SetExpirationInterval(sweepInterval)
	relay.Negentropy = false // set reconciliation would leak which event ids exist

	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}

	relay.StoreEvent = append(relay.StoreEvent, store.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, dropExpired(store.QueryEvents))
	relay.CountEvents = append(relay.CountEvents, store.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, store.DeleteEvent)

	// ---------------------------------------------------------------- writes
	relay.RejectEvent = append(relay.RejectEvent,
		policies.RestrictToSpecifiedKinds(false, policies.DMKindAllowlist...),
		policies.RequireAuthedAuthor,
		policies.RequireExpiration(maxExpiration),
		policies.RequireTag("client"),
		policies.MaxContentLen(maxContentLen),
		policies.TagShapeLimits(maxTags, maxTagNameLen, maxTagValueLen),
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
		MaxEventTags:     maxTags,
		MaxContentLength: maxContentLen,
		MaxSubscriptions: 10,
		MaxFilters:       4,
		MaxLimit:         500,
		AuthRequired:     true,
		RestrictedWrites: true,
	}

	log.Printf("listening on %s (kinds 4/5/62, content <= %d bytes, expiration <= %s)", *addr, maxContentLen, maxExpiration)
	if err := http.ListenAndServe(*addr, relay); err != nil {
		log.Fatal(err)
	}
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
