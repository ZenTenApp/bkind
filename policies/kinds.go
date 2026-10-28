package policies

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ZenTenApp/bkind"
	"github.com/nbd-wtf/go-nostr"
)

// visibility is who may see the events of a kind.
type visibility uint8

const (
	// visibilityPublic: anyone within the kind's reader list.
	visibilityPublic visibility = iota
	// visibilityAuthorOnly: the author, within the reader list.
	visibilityAuthorOnly
	// visibilityRecipient: the author and the pubkey in the event's "p" tag.
	visibilityRecipient
)

// kindAccess is the read side of one kind: its visibility class, whether NIP-42
// is required to read it, and the explicit reader list (nil: anyone).
type kindAccess struct {
	visibility visibility
	// requireAuth: reading this kind needs an authenticated connection.
	requireAuth bool
	// readers: nil means anyone; otherwise the only pubkeys allowed to read.
	readers []string
}

// KindRules is the derived gate set of a relay. Every gate that has to know
// which kinds are served — the write policy, the filter overwrite, the read
// policy, the COUNT policy, live delivery and the NIP-11 document — is derived
// from one KindRules value, so they cannot disagree.
//
// The value is built from the per-kind rules by Config.KindRules. A kind without
// an access entry (an ephemeral kind admitted by allow_ephemeral) gets the
// strictest access: readable by its author only, after authentication.
type KindRules struct {
	// Allowed is the complete set of kinds the relay accepts and serves.
	Allowed []uint16
	// AllowEphemeral lets every ephemeral kind through without listing it.
	AllowEphemeral bool
	// RejectUnservedFilters makes a REQ naming a kind outside Allowed fail with
	// "restricted: kind N is not served by this relay" instead of being silently
	// narrowed to the served kinds. A filter that lists no kinds at all is still
	// expanded to Allowed.
	RejectUnservedFilters bool

	// access holds the read rules of every kind in Allowed, by kind.
	access map[uint16]kindAccess
}

// newKindRules builds the gate set from the allowlist and the per-kind access
// rules. Kinds without an access entry (which must not happen for kinds in
// Allowed when built by Config.kindRules) read as the strictest class.
func newKindRules(allowed []uint16, allowEphemeral, rejectUnserved bool, access map[uint16]kindAccess) KindRules {
	return KindRules{
		Allowed:               allowed,
		AllowEphemeral:        allowEphemeral,
		RejectUnservedFilters: rejectUnserved,
		access:                access,
	}
}

// Validate checks the invariants the gate set itself can break: an empty
// allowlist would serve nothing, and an ephemeral kind listed without
// allow_ephemeral would be accepted by the filter policy and rejected on write.
func (k KindRules) Validate() error {
	if len(k.Allowed) == 0 {
		return fmt.Errorf("kinds.whitelist is empty: the relay would serve nothing")
	}

	for _, kind := range k.Allowed {
		if kind == 0 {
			return fmt.Errorf("kinds.whitelist contains kind 0, which is not a valid kind to serve")
		}
		if nostr.IsEphemeralKind(int(kind)) && !k.AllowEphemeral {
			return fmt.Errorf("kinds.whitelist contains the ephemeral kind %d but kinds.allow_ephemeral is false: it would be accepted by the filter policy and rejected on write", kind)
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

// List renders a kind set for a log line: "4, 5 and 62".
func (k KindRules) List() string {
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

// RestrictKind is the write gate: anything outside Allowed, and any ephemeral
// kind unless AllowEphemeral, is rejected.
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

// accessFor returns the read rules of a served kind. Config.KindRules fills an
// entry for every kind in Allowed, so a miss here means the kind was admitted by
// allow_ephemeral: it reads as the strictest class, since no rule was written for
// it.
func (k KindRules) accessFor(kind uint16) kindAccess {
	if acc, ok := k.access[kind]; ok {
		return acc
	}
	return kindAccess{visibility: visibilityAuthorOnly, requireAuth: true}
}

// ReadFilter is the read policy: refuse a kind the relay does not serve, then
// ask of the filter what the matched kinds require — authentication for kinds
// that need it, a pinned author (or "#p") for privileged kinds, membership in
// the reader list for kinds that have one. A filter of only public kinds is
// answered for anyone, which is what makes a mixed relay possible.
func (k KindRules) ReadFilter(ctx context.Context, filter nostr.Filter) (bool, string) {
	authed := bkind.GetAuthed(ctx)

	kinds := filter.Kinds
	if len(kinds) == 0 {
		for _, kind := range k.Sorted() {
			kinds = append(kinds, int(kind))
		}
	}

	needAuth, pinAuthors, pinEither := false, false, false
	for _, kind := range kinds {
		if !k.Has(uint16(kind)) {
			return true, fmt.Sprintf("restricted: kind %d is not served by this relay", kind)
		}

		acc := k.accessFor(uint16(kind))
		if acc.requireAuth || acc.visibility != visibilityPublic {
			needAuth = true
		}
		switch acc.visibility {
		case visibilityAuthorOnly:
			pinAuthors = true
		case visibilityRecipient:
			pinEither = true
		}
		if acc.readers != nil && !slices.Contains(acc.readers, authed) {
			return true, "restricted: your key is not allowed to read this kind on this relay"
		}
	}

	if needAuth && authed == "" {
		return true, "auth-required: this relay requires authentication (NIP-42)"
	}

	// public kinds only: nothing to pin
	if !pinAuthors && !pinEither {
		return false, ""
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

	if pinAuthors {
		if !sendersPinned {
			return true, "restricted: events of this kind are only readable by their author, pin \"authors\" to your own pubkey"
		}
		return false, ""
	}

	// only recipient-visible kinds matched: the author or the recipient may read
	if !sendersPinned && !receiversPinned {
		return true, "restricted: events of this kind are only visible to their author and their recipient, pin \"authors\" or \"#p\" to your own pubkey"
	}

	return false, ""
}

// RejectCount applies the read rule to NIP-45 COUNT: a count over private events
// leaks metadata even when no event is returned.
func (k KindRules) RejectCount(ctx context.Context, filter nostr.Filter) (bool, string) {
	return k.ReadFilter(ctx, filter)
}

// PreventBroadcast is a PreventBroadcast hook: live delivery does not re-run
// the filter policies, so a subscription whose REQ was rejected would otherwise
// keep receiving matching events for the life of the connection. It returns true
// when the event must not be written to that connection.
func (k KindRules) PreventBroadcast(ws *bkind.WebSocket, evt *nostr.Event) bool {
	if !k.Has(uint16(evt.Kind)) {
		// not served at all: never deliver it, whoever is asking
		return true
	}

	acc := k.accessFor(uint16(evt.Kind))
	authed := ws.AuthedPublicKey
	if (acc.requireAuth || acc.visibility != visibilityPublic) && authed == "" {
		return true
	}
	if acc.readers != nil && !slices.Contains(acc.readers, authed) {
		return true
	}

	switch acc.visibility {
	case visibilityPublic:
		return false
	case visibilityAuthorOnly:
		return authed != evt.PubKey
	case visibilityRecipient:
		if authed == evt.PubKey {
			return false
		}
		for _, tag := range evt.Tags {
			if len(tag) > 1 && tag[0] == "p" && tag[1] == authed {
				return false
			}
		}
		return true
	}

	return true
}

// KindShapeValidator is a per-kind structural validator, such as ValidateKind4Shape.
type KindShapeValidator func(context.Context, *nostr.Event) (bool, string)

// kindShapeValidators is the registry of shape validators the framework ships. A
// kind rule turns its validator on; the functions themselves cannot live in JSON.
var kindShapeValidators = map[uint16]KindShapeValidator{
	4:  ValidateKind4Shape,
	5:  ValidateKind5Shape,
	62: ValidateKind62Shape,
}

// ShapeValidator returns the registered validator for kind, or nil.
func ShapeValidator(kind uint16) KindShapeValidator {
	return kindShapeValidators[kind]
}
