package policies

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ZenTenApp/bkind"
	"github.com/nbd-wtf/go-nostr"
)

// KindRules is the kind allowlist of a relay, expressed as data instead of as a
// policy function with a literal in it. Every gate that has to know which kinds
// are served — the write policy, the filter overwrite, the read policy, the COUNT
// policy, live delivery and the NIP-11 document — is derived from one KindRules
// value, so they cannot disagree.
//
// A kind belongs to at most one visibility class:
//
//   - RecipientVisible: readable by its author and by the pubkey in its "p" tag
//     (Kind 4 and, for other relay shapes, Kind 1059 gift wraps and Kind 14 DMs);
//   - AuthorOnly: readable by its author only (Kind 5, Kind 62);
//   - neither: served, but rejected on read unless the filter pins the author,
//     which is the strictest class and the default for an unclassified kind.
type KindRules struct {
	// Allowed is the complete set of kinds the relay accepts and serves.
	Allowed []uint16 `json:"allowed"`
	// RecipientVisible is the subset readable by author and "p" recipient.
	RecipientVisible []uint16 `json:"recipient_visible"`
	// AuthorOnly is the subset readable by author only.
	AuthorOnly []uint16 `json:"author_only"`
	// AllowEphemeral lets every ephemeral kind through without listing it.
	AllowEphemeral bool `json:"allow_ephemeral"`
	// RejectUnservedFilters makes a REQ naming a kind outside Allowed fail with
	// "restricted: kind N is not served by this relay" instead of being silently
	// narrowed to the served kinds. A filter that lists no kinds at all is still
	// expanded to Allowed.
	RejectUnservedFilters bool `json:"reject_unserved_filters"`
}

// Validate checks that the set is internally consistent. It is what turns a typo in
// a config file into a startup error instead of a relay that accepts a kind it
// cannot serve.
func (k KindRules) Validate() error {
	if len(k.Allowed) == 0 {
		return fmt.Errorf("kinds.allowed is empty: the relay would serve nothing")
	}

	allowed := k.Sorted()
	for _, kind := range allowed {
		if kind == 0 {
			return fmt.Errorf("kinds.allowed contains kind 0, which is not a valid kind to serve")
		}
		if nostr.IsEphemeralKind(int(kind)) && !k.AllowEphemeral {
			return fmt.Errorf("kinds.allowed contains the ephemeral kind %d but allow_ephemeral is false: it would be accepted by the filter policy and rejected on write", kind)
		}
	}

	for _, kind := range k.RecipientVisible {
		if !slices.Contains(allowed, kind) {
			return fmt.Errorf("kinds.recipient_visible contains kind %d, which is not in kinds.allowed", kind)
		}
		if slices.Contains(k.AuthorOnly, kind) {
			return fmt.Errorf("kind %d is listed in both kinds.recipient_visible and kinds.author_only", kind)
		}
	}
	for _, kind := range k.AuthorOnly {
		if !slices.Contains(allowed, kind) {
			return fmt.Errorf("kinds.author_only contains kind %d, which is not in kinds.allowed", kind)
		}
	}

	return nil
}

// Sorted returns Allowed sorted and de-duplicated, which is what the write policy
// and the NIP-11 document need.
func (k KindRules) Sorted() []uint16 {
	out := append([]uint16(nil), k.Allowed...)
	slices.Sort(out)
	return slices.Compact(out)
}

// Has reports whether kind is served.
func (k KindRules) Has(kind uint16) bool {
	return slices.Contains(k.Allowed, kind)
}

// IsRecipientVisible reports whether kind is readable by its author and its "p".
func (k KindRules) IsRecipientVisible(kind uint16) bool {
	return slices.Contains(k.RecipientVisible, kind)
}

// IsAuthorOnly reports whether kind is readable by its author only.
func (k KindRules) IsAuthorOnly(kind uint16) bool {
	return slices.Contains(k.AuthorOnly, kind)
}

// list renders a kind set for a rejection message: "4, 5 and 62".
func (k KindRules) list() string {
	kinds := make([]string, 0, len(k.Allowed))
	for _, kind := range k.Sorted() {
		kinds = append(kinds, fmt.Sprintf("%d", kind))
	}

	switch len(kinds) {
	case 0:
		return "none"
	case 1:
		return kinds[0]
	default:
		return strings.Join(kinds[:len(kinds)-1], ", ") + " and " + kinds[len(kinds)-1]
	}
}

// RestrictKind is the write policy: anything outside Allowed, and any ephemeral kind
// unless AllowEphemeral, is rejected.
func (k KindRules) RestrictKind() func(context.Context, *nostr.Event) (bool, string) {
	// the allowlist is sorted in place by the policy, so hand it a copy: Allowed is
	// also what OverwriteFilters and the NIP-11 document read
	return RestrictToSpecifiedKinds(k.AllowEphemeral, append([]uint16(nil), k.Allowed...)...)
}

// OverwriteFilters bounds an incoming filter to the served kinds. It runs before the
// REQ is rejected, so it decides what the read policy and the store get to see:
//
//   - a filter with no kinds means "every kind" to the store and is expanded to
//     Allowed, because a subscription with no kinds has always been legal here;
//   - with RejectUnservedFilters set, an explicit kind list is left untouched so
//     ReadFilter can reject it with a reason the client can act on;
//   - otherwise it is intersected, and an empty result sets LimitZero so the
//     subscription stays open and returns nothing.
func (k KindRules) OverwriteFilters() func(context.Context, *nostr.Filter) {
	allowed := k.Sorted()

	return func(ctx context.Context, filter *nostr.Filter) {
		if len(filter.Kinds) == 0 {
			filter.Kinds = make([]int, 0, len(allowed))
			for _, kind := range allowed {
				filter.Kinds = append(filter.Kinds, int(kind))
			}
			return
		}

		if k.RejectUnservedFilters {
			return
		}

		kinds := make([]int, 0, len(filter.Kinds))
		for _, kind := range filter.Kinds {
			if k.Has(uint16(kind)) {
				kinds = append(kinds, kind)
			}
		}
		filter.Kinds = kinds
		if len(kinds) == 0 {
			filter.LimitZero = true // nothing to return, but stay subscribed
		}
	}
}

// ReadFilter is the read policy: deny by default, require auth, refuse a kind the
// relay does not serve rather than narrowing it, then require the filter to pin the
// authenticated pubkey in the place that makes the matching events visible.
func (k KindRules) ReadFilter(ctx context.Context, filter nostr.Filter) (bool, string) {
	authed := bkind.GetAuthed(ctx)
	if authed == "" {
		return true, "auth-required: this relay requires authentication (NIP-42)"
	}

	matchesRecipientVisible, matchesAuthorOnly := false, false
	if len(filter.Kinds) == 0 {
		matchesRecipientVisible, matchesAuthorOnly = true, true
	}
	for _, kind := range filter.Kinds {
		switch {
		case k.IsRecipientVisible(uint16(kind)):
			matchesRecipientVisible = true
		case k.IsAuthorOnly(uint16(kind)):
			matchesAuthorOnly = true
		case k.Has(uint16(kind)):
			// served, but not classified: author-only is the strictest reading
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

	recipientVisibleOnly := matchesRecipientVisible && !matchesAuthorOnly

	if recipientVisibleOnly && !sendersPinned && !receiversPinned {
		return true, "restricted: events of this kind are only visible to their author and their recipient, pin \"authors\" or \"#p\" to your own pubkey"
	}
	if !recipientVisibleOnly && !sendersPinned {
		return true, "restricted: events of this kind are only readable by their author, pin \"authors\" to your own pubkey"
	}

	return false, ""
}

// RejectCount applies the read rule to NIP-45 COUNT: a count over private events
// leaks metadata even when no event is returned.
func (k KindRules) RejectCount(ctx context.Context, filter nostr.Filter) (bool, string) {
	return k.ReadFilter(ctx, filter)
}

// PreventBroadcast is a PreventBroadcast hook: live delivery does not re-run the
// filter policies, so a subscription whose REQ was rejected would otherwise keep
// receiving matching events for the life of the connection. It returns true when the
// event must not be written to that connection.
func (k KindRules) PreventBroadcast(ws *bkind.WebSocket, evt *nostr.Event) bool {
	authed := ws.AuthedPublicKey
	if authed == "" {
		return true
	}

	switch {
	case k.IsRecipientVisible(uint16(evt.Kind)):
		if authed == evt.PubKey {
			return false
		}
		for _, tag := range evt.Tags {
			if len(tag) > 1 && tag[0] == "p" && tag[1] == authed {
				return false
			}
		}
		return true
	case k.IsAuthorOnly(uint16(evt.Kind)):
		return authed != evt.PubKey
	case k.Has(uint16(evt.Kind)):
		// served but not classified: author-only is the strictest reading
		return authed != evt.PubKey
	default:
		// not served at all: never deliver it, whoever is asking
		return true
	}
}

// KindShapeValidator is a per-kind structural validator, such as ValidateKind4Shape.
type KindShapeValidator func(context.Context, *nostr.Event) (bool, string)

// kindShapeValidators is the registry of shape validators the framework ships. A
// config names the kinds to validate; the functions themselves cannot live in JSON.
var kindShapeValidators = map[uint16]KindShapeValidator{
	4:  ValidateKind4Shape,
	5:  ValidateKind5Shape,
	62: ValidateKind62Shape,
}

// ShapeValidator returns the registered validator for kind, or nil.
func ShapeValidator(kind uint16) KindShapeValidator {
	return kindShapeValidators[kind]
}
