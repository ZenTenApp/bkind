package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ZenTenApp/bkind"
	"github.com/nbd-wtf/go-nostr"
)

// DMKindAllowlist is the set of kinds served by a relay that only exists to carry
// NIP-04 direct messages: Kind 4 itself, NIP-09 deletions and NIP-62 vanish
// requests, both of which are needed to make a DM deletable.
//
// It is documentation now: the DM* policies below read dmKindRules, and a relay built
// from a policies.Config reads that config, so mutating this variable changes nothing.
// Use Config.Kinds (or BKIND_KINDS) to change what is served.
var DMKindAllowlist = []uint16{4, 5, 62}

// dmKindRules is the gate set that goes with DMKindAllowlist. The DM* policies
// below are thin wrappers around these methods kept for callers that wired
// khatru by hand; a relay built from a policies.Config uses the Config directly
// (see Config.Wire), so the write gate, the read gate, COUNT, live delivery and
// NIP-11 all read the same value.
var dmKindRules = DefaultConfig().KindRules()

// DMReadPolicy is the read policy for a direct-message relay.
//
// Every kind it serves is private, so nothing here is a "public filter" case:
//
//   - Kind 4 is readable by its author and by its "p" recipient, so a filter must
//     pin either the authors or the "#p" tags to the authenticated pubkey;
//   - kinds 5 and 62 are readable by their author only, so a filter that can match
//     them must pin the authors to the authenticated pubkey.
//
// An empty kinds list means "every kind" and is treated as the strictest case. A
// filter asking for a kind outside the allowlist is rejected instead of being
// silently narrowed, so clients notice that they are talking to the wrong relay.
//
// This is KindRules.ReadFilter with the DM kind set; use KindRules directly to serve
// a different set.
func DMReadPolicy(ctx context.Context, filter nostr.Filter) (bool, string) {
	return dmKindRules.ReadFilter(ctx, filter)
}

// DMCountPolicy applies the same visibility rules to NIP-45 COUNT requests: a count
// over direct messages leaks metadata even when no event is returned.
func DMCountPolicy(ctx context.Context, filter nostr.Filter) (bool, string) {
	return dmKindRules.RejectCount(ctx, filter)
}

// DMBroadcastGuard is a PreventBroadcast hook for a direct-message relay.
//
// Live delivery does not go through the filter policies (a subscription's filter is
// stored at REQ time and matched with Filter.Matches), so without this a wide
// subscription would keep receiving Kind 4 events for the life of the connection,
// even though its REQ was rejected. It returns true to prevent the event from being
// written to that connection.
func DMBroadcastGuard(ws *bkind.WebSocket, evt *nostr.Event) bool {
	return dmKindRules.PreventBroadcast(ws, evt)
}

// RequireAuthedAuthor requires NIP-42 authentication for writes and that the
// authenticated key is the event's author.
//
// Server-side calls made through Relay.AddEvent have no connection and therefore no
// authenticated key; those are let through when they carry the internal-call marker
// that B Kind itself uses for deletions and expirations.
func RequireAuthedAuthor(ctx context.Context, evt *nostr.Event) (bool, string) {
	if bkind.IsInternalCall(ctx) {
		return false, ""
	}

	authed := bkind.GetAuthed(ctx)
	if authed == "" {
		return true, "auth-required: you must be authenticated to publish to this relay (NIP-42)"
	}
	if authed != evt.PubKey {
		return true, "blocked: you can only publish events signed by your authenticated key"
	}

	return false, ""
}

// RequireExpiration rejects events without a single valid "expiration" tag (NIP-40)
// that is in the future and no further away than max. It is the kind-rule check
// of the default configuration, exported for callers that wire by hand.
func RequireExpiration(max time.Duration) func(context.Context, *nostr.Event) (bool, string) {
	return expirationEventCheck(true, max)
}

// RequireTag rejects events that do not carry exactly one non-empty named tag.
func RequireTag(name string) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		count := 0
		for _, tag := range evt.Tags {
			if len(tag) == 0 || tag[0] != name {
				continue
			}
			count++
			if len(tag) < 2 || tag[1] == "" {
				return true, fmt.Sprintf("invalid: %q tag must have a non-empty value", name)
			}
		}

		switch {
		case count == 0:
			return true, fmt.Sprintf("invalid: missing mandatory %q tag", name)
		case count > 1:
			return true, fmt.Sprintf("invalid: multiple %q tags", name)
		}

		return false, ""
	}
}

// MaxContentLen rejects events whose content is longer than max bytes.
func MaxContentLen(max int) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		if len(evt.Content) > max {
			return true, fmt.Sprintf("invalid: content is too large (%d bytes, max %d)", len(evt.Content), max)
		}
		return false, ""
	}
}

// EventLen is the size in bytes of the event as a client sends it: the JSON of
// the event itself, id, signature and tags included, without the ["EVENT", ...]
// envelope. It is what max_event_size bounds; max_event_content_size bounds the
// content alone.
func EventLen(evt *nostr.Event) int {
	encoded, err := json.Marshal(evt)
	if err != nil {
		// an event that cannot be encoded carries no meaningful size; the id and
		// signature gates refuse it
		return 0
	}
	return len(encoded)
}

// MaxEventLen rejects events whose serialized form is longer than max bytes.
func MaxEventLen(max int) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		if size := EventLen(evt); size > max {
			return true, fmt.Sprintf("invalid: event is too large (%d bytes, max %d)", size, max)
		}
		return false, ""
	}
}

// TagShapeLimits rejects events with more than maxTags tags, tag names longer than
// maxNameLen or any tag value longer than maxValueLen. It looks at every tag and
// every position, unlike PreventLargeTags, which only checks single-letter names
// and the first value.
func TagShapeLimits(maxTags, maxNameLen, maxValueLen int) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		if len(evt.Tags) > maxTags {
			return true, fmt.Sprintf("invalid: too many tags (%d, max %d)", len(evt.Tags), maxTags)
		}

		for _, tag := range evt.Tags {
			if len(tag) == 0 {
				return true, "invalid: empty tag"
			}
			if len(tag[0]) > maxNameLen {
				return true, fmt.Sprintf("invalid: tag name is too long (%d bytes, max %d)", len(tag[0]), maxNameLen)
			}
			for _, value := range tag[1:] {
				if len(value) > maxValueLen {
					return true, fmt.Sprintf("invalid: tag value is too long (%d bytes, max %d)", len(value), maxValueLen)
				}
			}
		}

		return false, ""
	}
}
