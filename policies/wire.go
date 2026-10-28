package policies

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ZenTenApp/bkind"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
)

// KindRules derives the gate set every read path answers from. A kind's own rule
// decides its visibility class: privileged with a "hex" p rule is
// recipient-visible (author and "p"), privileged without one is author-only,
// unprivileged is public within the reader list. A kind the document gave no rule
// reads as the empty rule: nobody in the reader list, so nobody may query it.
func (c Config) KindRules() KindRules {
	access := make(map[uint16]kindAccess, len(c.Kinds.Whitelist))
	for _, kind := range c.Kinds.Whitelist {
		rule := c.Rule(kind)
		acc := kindAccess{visibility: visibilityPublic}
		switch {
		case rule.Read.Privileged && rule.PTag == "hex":
			acc.visibility = visibilityRecipient
		case rule.Read.Privileged:
			acc.visibility = visibilityAuthorOnly
		}
		// a privileged kind is only answerable to a known reader, so it always
		// needs NIP-42 — whatever the write side says about authentication
		acc.requireAuth = rule.RequireAuth || rule.Read.Privileged
		if !rule.Read.Allow.Anyone() {
			// non-nil even when empty: an empty reader list means nobody, which is
			// not the same value as "no list, anyone"
			acc.readers = append(AllowList{}, rule.Read.Allow...)
		}
		access[kind] = acc
	}
	return newKindRules(c.Kinds.Whitelist, c.Kinds.AllowEphemeral, c.Kinds.RejectUnservedFilters, access)
}

// writePolicy is the per-kind write gate: the checks of the event's own rule, in
// the order a client can act on.
func (c Config) writePolicy() func(context.Context, *nostr.Event) (bool, string) {
	byKind := make(map[uint16][]eventCheck, len(c.Kinds.Whitelist))
	for _, kind := range c.Kinds.Whitelist {
		byKind[kind] = c.Rule(kind).checks(kind)
	}

	return func(ctx context.Context, evt *nostr.Event) (bool, string) {
		// RestrictKind has already rejected unserved kinds, so a miss here is an
		// ephemeral kind admitted by allow_ephemeral: it runs the empty rule, which
		// lets nobody publish it
		checks, ok := byKind[uint16(evt.Kind)]
		if !ok {
			return false, ""
		}
		for _, check := range checks {
			if reject, msg := check(ctx, evt); reject {
				return true, msg
			}
		}
		return false, ""
	}
}

// Wire installs the whole policy set on a relay. Every gate that decides which
// kinds are served is derived from the same Config, so the write policy, the
// filter overwrite, the read policy, COUNT, live delivery and NIP-11 cannot
// disagree.
//
// It does not touch the store, the expiration sweeper or ServiceURL: those stay
// explicit in the wiring file.
func (c Config) Wire(relay *bkind.Relay) error {
	if err := c.Validate(); err != nil {
		return err
	}

	k := c.KindRules()

	relay.Negentropy = c.Negentropy

	// ---------------------------------------------------------------- writes
	relay.RejectEvent = append(relay.RejectEvent,
		k.RestrictKind(),
		c.writePolicy(),
	)

	// ----------------------------------------------------------------- reads
	relay.OverwriteFilter = append(relay.OverwriteFilter, k.OverwriteFilters())

	readPolicies := make([]func(context.Context, nostr.Filter) (bool, string), 0, 4)
	readPolicies = append(readPolicies, k.ReadFilter)
	if c.Filters.RejectEmpty {
		readPolicies = append(readPolicies, NoEmptyFilters)
	}
	if c.Filters.RejectSearch {
		readPolicies = append(readPolicies, NoSearchQueries)
	}
	for _, rl := range c.ReadLimits {
		switch rl.Scope {
		case "npub":
			readPolicies = append(readPolicies, FilterAuthedPubKeyRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit))
		case "ip":
			readPolicies = append(readPolicies, FilterIPRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit))
		}
	}
	relay.RejectFilter = append(relay.RejectFilter, readPolicies...)

	if c.Count.Reject {
		relay.RejectCountFilter = append(relay.RejectCountFilter, k.ReadFilter)
	}

	// live delivery does not re-run the filter policies
	relay.PreventBroadcast = append(relay.PreventBroadcast, k.PreventBroadcast)

	var rejectConnection []func(*http.Request) bool
	for _, rl := range c.ConnectionLimits {
		rejectConnection = append(rejectConnection, ConnectionRateLimiter(rl.Limit, rl.Window.Duration, rl.Limit))
	}
	relay.RejectConnection = append(relay.RejectConnection, rejectConnection...)

	// --------------------------------------------------------------- NIP-11
	return c.applyNIP11(relay, k)
}

// applyNIP11 derives the information document from the configuration.
func (c Config) applyNIP11(relay *bkind.Relay, k KindRules) error {
	relay.Info.Name = c.NIP11.Name
	relay.Info.Description = c.NIP11.Description
	if relay.Info.Description == "" {
		relay.Info.Description = c.defaultDescription(k)
	}

	anyExpiration, anyAuth, maxTags, maxContent := false, false, 0, 0
	for _, rule := range c.RulesByKind() {
		if slices.Contains(rule.RequiredTags, "expiration") || rule.MaxExpiration.Duration > 0 {
			anyExpiration = true
		}
		if rule.RequireAuth {
			anyAuth = true
		}
		if rule.TagLimits.MaxTags > maxTags {
			maxTags = rule.TagLimits.MaxTags
		}
		if rule.MaxEventContentSize.Bytes > maxContent {
			maxContent = rule.MaxEventContentSize.Bytes
		}
	}

	nips := map[int]bool{11: true}
	for _, kind := range k.Sorted() {
		switch kind {
		case 4:
			nips[4] = true // encrypted direct messages
		case 5:
			nips[9] = true // event deletion
		case 62:
			nips[62] = true // request to vanish
		}
	}
	if anyExpiration {
		nips[40] = true
	}
	if anyAuth {
		nips[42] = true
	}
	if !c.Count.Reject {
		nips[45] = true
	}
	if c.Negentropy {
		nips[77] = true
	}
	for _, nip := range c.NIP11.ExtraNIPs {
		nips[nip] = true
	}

	supported := make([]any, 0, len(nips))
	for nip := range nips {
		supported = append(supported, nip)
	}
	slices.SortFunc(supported, func(a, b any) int {
		return a.(int) - b.(int)
	})
	relay.Info.SupportedNIPs = supported

	// HandleNIP11 adds 9, 45 and 77 on its own when the store has DeleteEvent,
	// CountEvents or Negentropy wired. Those are facts about the wiring, not about
	// what this relay will actually answer — a COUNT is refused here — so the served
	// document keeps exactly the derived list.
	relay.OverwriteRelayInformation = append(relay.OverwriteRelayInformation,
		func(ctx context.Context, r *http.Request, info nip11.RelayInformationDocument) nip11.RelayInformationDocument {
			info.SupportedNIPs = supported
			return info
		})

	relay.Info.Limitation = &nip11.RelayLimitationDocument{
		MaxMessageLength: c.NIP11.MaxMessageLength,
		MaxEventTags:     maxTags,
		MaxContentLength: maxContent,
		MaxSubscriptions: c.NIP11.MaxSubscriptions,
		MaxFilters:       c.NIP11.MaxFilters,
		MaxLimit:         c.NIP11.MaxLimit,
		AuthRequired:     anyAuth,
		RestrictedWrites: anyAuth,
	}

	return nil
}

// defaultDescription is generated from the kind list, so the NIP-11 document
// cannot claim "Kind 4 only" after the whitelist changed.
func (c Config) defaultDescription(k KindRules) string {
	var parts []string
	for _, kind := range k.Sorted() {
		switch kind {
		case 4:
			parts = append(parts, "Kind 4 direct messages")
		case 5:
			parts = append(parts, "Kind 5 deletions")
		case 62:
			parts = append(parts, "Kind 62 vanish requests")
		default:
			parts = append(parts, fmt.Sprintf("Kind %d events", kind))
		}
	}
	return strings.Join(parts, ", ") + " only."
}
