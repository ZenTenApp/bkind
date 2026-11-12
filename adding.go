package bkind

import (
	"context"
	"errors"
	"fmt"

	"github.com/fiatjaf/eventstore"
	"github.com/nbd-wtf/go-nostr"
)

// checkEventAcceptable runs every write policy (RejectEvent) against an event.
//
// This is separate from handleNormal so that callers can run the policies before
// the kind-specific side effects: Kind 5 deletions and Kind 62 vanish requests act
// on the store and must never run for an event that would be rejected afterwards.
// Policies are only run once per event, otherwise stateful ones (the rate
// limiters) would count the same event twice.
//
// A rejection is recorded at debug level before it is returned. The reason also
// goes back to the client in its OK envelope, but that is the only other place it
// surfaces: without this line an operator cannot tell a relay rejecting every
// write from a relay nobody is writing to. Debug keeps a policy gate quiet by
// default, because a rejected event is the normal outcome of a rate limit, not an
// error worth a line on the info log.
func (rl *Relay) checkEventAcceptable(ctx context.Context, evt *nostr.Event) error {
	for _, reject := range rl.RejectEvent {
		if reject, msg := reject(ctx, evt); reject {
			reason := "blocked: no reason"
			if msg != "" {
				reason = nostr.NormalizeOKMessage(msg, "blocked")
			}

			rl.log().Debug("rejected event by write policy",
				"event", evt.ID,
				"kind", evt.Kind,
				"pubkey", evt.PubKey,
				"reason", reason)

			return errors.New(reason)
		}
	}
	return nil
}

// handleKindSpecificSideEffects applies the store mutations implied by an event
// kind before the event itself is stored: NIP-09 deletions and NIP-62 vanish
// requests. It must only be called after checkEventAcceptable.
func (rl *Relay) handleKindSpecificSideEffects(ctx context.Context, evt *nostr.Event) error {
	switch evt.Kind {
	case 5:
		return rl.handleDeleteRequest(ctx, evt)
	case 62:
		return rl.handleVanishRequest(ctx, evt)
	}
	return nil
}

// AddEvent sends an event through then normal add pipeline, as if it was received from a websocket.
func (rl *Relay) AddEvent(ctx context.Context, evt *nostr.Event) (skipBroadcast bool, writeError error) {
	rl.ensureExpirationManager()

	if evt == nil {
		return false, errors.New("error: event is nil")
	}

	if err := rl.checkEventAcceptable(ctx, evt); err != nil {
		return true, err
	}

	if err := rl.handleKindSpecificSideEffects(ctx, evt); err != nil {
		return true, err
	}

	if nostr.IsEphemeralKind(evt.Kind) {
		return false, rl.handleEphemeral(ctx, evt)
	} else {
		return rl.handleNormal(ctx, evt)
	}
}

func (rl *Relay) handleNormal(ctx context.Context, evt *nostr.Event) (skipBroadcast bool, writeError error) {
	// a stored NIP-62 request means the author asked us to erase them and stop
	// accepting their events: refuse anything they dated before that request.
	if err := rl.checkVanished(ctx, evt); err != nil {
		return true, err
	}

	// Check to see if the event has been deleted by ID. The query is scoped to the
	// event author: without that, anyone could permanently block any event id by
	// publishing a Kind 5 that merely references it.
	//
	// The tag name is the bare "e": go-nostr matches filter tag names verbatim
	// ("#e" is only the JSON spelling used on the wire).
	for _, query := range rl.QueryEvents {
		ch, err := query(ctx, nostr.Filter{
			Kinds:   []int{5},
			Authors: []string{evt.PubKey},
			Tags:    nostr.TagMap{"e": []string{evt.ID}},
		})
		if err != nil {
			continue
		}
		target := <-ch
		if target == nil {
			continue
		}

		return true, errors.New("blocked: this event has been deleted")
	}

	// will store
	// regular kinds are just saved directly
	if nostr.IsRegularKind(evt.Kind) {
		for _, store := range rl.StoreEvent {
			if err := store(ctx, evt); err != nil {
				switch err {
				case eventstore.ErrDupEvent:
					return true, nil
				default:
					return false, fmt.Errorf("%s", nostr.NormalizeOKMessage(err.Error(), "error"))
				}
			}
		}
	} else {
		// Check to see if the event has been deleted by address
		for _, query := range rl.QueryEvents {
			dTagValue := ""
			for _, tag := range evt.Tags {
				if len(tag) > 1 && tag[0] == "d" {
					dTagValue = tag[1]
					break
				}
			}

			address := fmt.Sprintf("%d:%s:%s", evt.Kind, evt.PubKey, dTagValue)
			ch, err := query(ctx, nostr.Filter{
				Kinds:   []int{5},
				Authors: []string{evt.PubKey},
				Since:   &evt.CreatedAt,
				Tags:    nostr.TagMap{"a": []string{address}},
			})
			if err != nil {
				continue
			}
			target := <-ch
			if target == nil {
				continue
			}

			return true, errors.New("blocked: this event has been deleted")
		}

		// otherwise it's a replaceable -- so we'll use the replacer functions if we have any
		if len(rl.ReplaceEvent) > 0 {
			for _, repl := range rl.ReplaceEvent {
				if err := repl(ctx, evt); err != nil {
					switch err {
					case eventstore.ErrDupEvent:
						return true, nil
					default:
						return false, fmt.Errorf("%s", nostr.NormalizeOKMessage(err.Error(), "error"))
					}
				}
			}
		} else {
			// otherwise do it the manual way
			filter := nostr.Filter{Limit: 1, Kinds: []int{evt.Kind}, Authors: []string{evt.PubKey}}
			if nostr.IsAddressableKind(evt.Kind) {
				// when addressable, add the "d" tag to the filter
				filter.Tags = nostr.TagMap{"d": []string{evt.Tags.GetD()}}
			}

			// now we fetch old events and delete them
			shouldStore := true
			for _, query := range rl.QueryEvents {
				ch, err := query(ctx, filter)
				if err != nil {
					continue
				}
				for previous := range ch {
					if isOlder(previous, evt) {
						for _, del := range rl.DeleteEvent {
							del(ctx, previous)
						}
					} else {
						// we found a more recent event, so we won't delete it and also will not store this new one
						shouldStore = false
					}
				}
			}

			// store
			if shouldStore {
				for _, store := range rl.StoreEvent {
					if saveErr := store(ctx, evt); saveErr != nil {
						switch saveErr {
						case eventstore.ErrDupEvent:
							return true, nil
						default:
							return false, fmt.Errorf("%s", nostr.NormalizeOKMessage(saveErr.Error(), "error"))
						}
					}
				}
			}
		}
	}

	for _, ons := range rl.OnEventSaved {
		ons(ctx, evt)
	}

	// track event expiration if applicable
	rl.expirationManager.trackEvent(evt)

	return false, nil
}
