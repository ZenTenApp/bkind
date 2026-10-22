package policies

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
)

// DMKindAllowlist is the set of kinds served by a relay that only exists to carry
// NIP-04 direct messages: kind 4 itself, NIP-09 deletions and NIP-62 vanish
// requests, both of which are needed to make a DM deletable.
var DMKindAllowlist = []uint16{4, 5, 62}

// DMReadPolicy is the read policy for a direct-message relay.
//
// Every kind it serves is private, so nothing here is a "public filter" case:
//
//   - kind 4 is readable by its author and by its "p" recipient, so a filter must
//     pin either the authors or the "#p" tags to the authenticated pubkey;
//   - kinds 5 and 62 are readable by their author only, so a filter that can match
//     them must pin the authors to the authenticated pubkey.
//
// An empty kinds list means "every kind" and is treated as the strictest case. A
// filter asking for a kind outside the allowlist is rejected instead of being
// silently narrowed, so clients notice that they are talking to the wrong relay.
func DMReadPolicy(ctx context.Context, filter nostr.Filter) (bool, string) {
	authed := khatru.GetAuthed(ctx)
	if authed == "" {
		return true, "auth-required: this relay only serves encrypted messages to authenticated users (NIP-42)"
	}

	var matchesDM, matchesAuthorOnly bool
	if len(filter.Kinds) == 0 {
		matchesDM = true
		matchesAuthorOnly = true
	}
	for _, kind := range filter.Kinds {
		switch uint16(kind) {
		case 4:
			matchesDM = true
		case 5, 62:
			matchesAuthorOnly = true
		default:
			return true, fmt.Sprintf("restricted: kind %d is not served by this relay", kind)
		}
	}

	sendersPinned := len(filter.Authors) > 0
	for _, author := range filter.Authors {
		if author != authed {
			sendersPinned = false
		}
	}
	receiversPinned := len(filter.Tags["p"]) > 0
	for _, receiver := range filter.Tags["p"] {
		if receiver != authed {
			receiversPinned = false
		}
	}

	if matchesAuthorOnly {
		// deletions and vanish requests are only meaningful to the key that made them
		if !sendersPinned {
			return true, "restricted: deletions and vanish requests are only readable by their author, pin \"authors\" to your own pubkey"
		}
		return false, ""
	}

	if matchesDM {
		if !sendersPinned && !receiversPinned {
			return true, "restricted: kind 4 events are only visible to their author and their recipient, pin \"authors\" or \"#p\" to your own pubkey"
		}
		return false, ""
	}

	return true, "restricted: this relay only serves kinds 4, 5 and 62"
}

// DMCountPolicy applies the same visibility rules to NIP-45 COUNT requests: a count
// over direct messages leaks metadata even when no event is returned.
func DMCountPolicy(ctx context.Context, filter nostr.Filter) (bool, string) {
	return DMReadPolicy(ctx, filter)
}

// DMBroadcastGuard is a PreventBroadcast hook for a direct-message relay.
//
// Live delivery does not go through the filter policies (a subscription's filter is
// stored at REQ time and matched with Filter.Matches), so without this a wide
// subscription would keep receiving kind 4 events for the life of the connection,
// even though its REQ was rejected. It returns true to prevent the event from being
// written to that connection.
func DMBroadcastGuard(ws *khatru.WebSocket, evt *nostr.Event) bool {
	authed := ws.AuthedPublicKey
	if authed == "" {
		return true
	}

	switch evt.Kind {
	case 4:
		if authed == evt.PubKey {
			return false
		}
		for _, tag := range evt.Tags {
			if len(tag) > 1 && tag[0] == "p" && tag[1] == authed {
				return false
			}
		}
		return true
	case 5, 62:
		return authed != evt.PubKey
	}

	return true
}

// RequireAuthedAuthor requires NIP-42 authentication for writes and that the
// authenticated key is the event's author.
//
// Server-side calls made through Relay.AddEvent have no connection and therefore no
// authenticated key; those are let through when they carry the internal-call marker
// that khatru itself uses for deletions and expirations.
func RequireAuthedAuthor(ctx context.Context, evt *nostr.Event) (bool, string) {
	if khatru.IsInternalCall(ctx) {
		return false, ""
	}

	authed := khatru.GetAuthed(ctx)
	if authed == "" {
		return true, "auth-required: you must be authenticated to publish to this relay (NIP-42)"
	}
	if authed != evt.PubKey {
		return true, "blocked: you can only publish events signed by your authenticated key"
	}

	return false, ""
}

// RequireExpiration rejects events without a single valid "expiration" tag (NIP-40)
// that is in the future and no further away than max.
func RequireExpiration(max time.Duration) func(context.Context, *nostr.Event) (bool, string) {
	maxSeconds := nostr.Timestamp(max.Seconds())

	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		var raw string
		var count int
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
		if nostr.Timestamp(expiresAt) > now+maxSeconds {
			return true, fmt.Sprintf("invalid: expiration is too far in the future (max %s)", max)
		}

		return false, ""
	}
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

// ValidateKind4Shape enforces the structure of a NIP-04 message: exactly one "p"
// tag naming a valid pubkey that is not the author, no event references and a
// non-empty (encrypted) content.
func ValidateKind4Shape(ctx context.Context, evt *nostr.Event) (bool, string) {
	if evt.Kind != 4 {
		return false, ""
	}

	recipients := 0
	for _, tag := range evt.Tags {
		if len(tag) == 0 {
			continue
		}

		switch tag[0] {
		case "p":
			if len(tag) < 2 || !nostr.IsValidPublicKey(tag[1]) {
				return true, `invalid: "p" tag must be a 64-character hex pubkey`
			}
			if tag[1] == evt.PubKey {
				return true, `invalid: a kind 4 event cannot be addressed to its own author`
			}
			recipients++
		case "e", "a", "d":
			return true, fmt.Sprintf("invalid: kind 4 events must not carry %q tags", tag[0])
		}
	}

	if recipients != 1 {
		return true, `invalid: kind 4 events must have exactly one "p" tag`
	}
	if evt.Content == "" {
		return true, "invalid: kind 4 events must have encrypted content"
	}

	return false, ""
}

// ValidateKind5Shape limits a NIP-09 deletion to the tags that make sense on this
// relay: event references plus the mandatory utility tags. It is what keeps "e"
// as the only reference type on a relay that has no addressable kinds.
func ValidateKind5Shape(ctx context.Context, evt *nostr.Event) (bool, string) {
	if evt.Kind != 5 {
		return false, ""
	}

	targets := 0
	for _, tag := range evt.Tags {
		if len(tag) == 0 {
			continue
		}

		switch tag[0] {
		case "e":
			if len(tag) < 2 || !nostr.IsValid32ByteHex(tag[1]) {
				return true, `invalid: "e" tag must be a 64-character hex event id`
			}
			targets++
		case "client", "expiration":
			// required utility tags
		default:
			return true, fmt.Sprintf("invalid: kind 5 events must not carry %q tags on this relay", tag[0])
		}
	}

	if targets == 0 {
		return true, `invalid: kind 5 events must reference at least one event with an "e" tag`
	}

	return false, ""
}

// ValidateKind62Shape limits a NIP-62 vanish request to the tags that make sense on
// this relay. The "relay" tag is validated at request time against the relay's own
// URL, so only its shape is checked here.
func ValidateKind62Shape(ctx context.Context, evt *nostr.Event) (bool, string) {
	if evt.Kind != 62 {
		return false, ""
	}

	for _, tag := range evt.Tags {
		if len(tag) == 0 {
			continue
		}

		switch tag[0] {
		case "relay":
			if len(tag) < 2 || tag[1] == "" {
				return true, `invalid: "relay" tag must have a value`
			}
		case "client", "expiration":
			// required utility tags
		default:
			return true, fmt.Sprintf("invalid: kind 62 events must not carry %q tags on this relay", tag[0])
		}
	}

	return false, ""
}
