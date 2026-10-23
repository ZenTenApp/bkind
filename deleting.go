package bkind

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// handleDeleteRequest applies a NIP-09 deletion event.
//
// Only targets authored by the deletion's own author are actionable. Targets that
// belong to someone else are skipped silently: answering with a reason like "you
// are not the author of this event" would turn the relay into an existence oracle
// for any event id in the store. When no target at all could be acted on, the
// deletion is rejected so that nothing is stored and no other relay can mistake a
// stored Kind 5 for evidence that the referenced event existed here.
func (rl *Relay) handleDeleteRequest(ctx context.Context, evt *nostr.Event) error {
	authorized := 0
	seen := make(map[string]struct{}, len(evt.Tags))

	for _, tag := range evt.Tags {
		if len(tag) < 2 {
			continue
		}

		var f nostr.Filter
		switch tag[0] {
		case "e":
			f = nostr.Filter{IDs: []string{tag[1]}}
		case "a":
			spl := strings.SplitN(tag[1], ":", 3)
			if len(spl) != 3 {
				continue
			}
			kind, err := strconv.Atoi(spl[0])
			if err != nil {
				continue
			}
			f = nostr.Filter{
				Kinds:   []int{kind},
				Authors: []string{spl[1]},
				Tags:    nostr.TagMap{"d": []string{spl[2]}},
				Until:   &evt.CreatedAt,
			}
		default:
			continue
		}

		key := f.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if rl.deleteEventAuthorized(ctx, evt, f) {
			authorized++
		}
	}

	if authorized == 0 {
		return errors.New("blocked: no valid deletion targets")
	}

	return nil
}

// deleteEventAuthorized deletes the first event matching the filter and returns
// true if the deletion was accepted. It never reveals whether the target exists.
func (rl *Relay) deleteEventAuthorized(ctx context.Context, evt *nostr.Event, f nostr.Filter) bool {
	ictx := WithInternalCall(ctx)

	for _, query := range rl.QueryEvents {
		ch, err := query(ictx, f)
		if err != nil {
			continue
		}

		target := <-ch
		if target == nil {
			continue
		}

		// the author can always delete their own events; apps may widen this with
		// OverwriteDeletionOutcome, but the default never accepts a foreign target
		acceptDeletion := target.PubKey == evt.PubKey
		if !acceptDeletion {
			for _, odo := range rl.OverwriteDeletionOutcome {
				acceptDeletion, _ = odo(ictx, target, evt)
			}
		}
		if !acceptDeletion {
			// silently skip: do not confirm to the sender that this id exists
			return false
		}

		for _, del := range rl.DeleteEvent {
			if err := del(ictx, target); err != nil {
				return false
			}
		}

		// if it was tracked to be expired that is not needed anymore
		rl.expirationManager.removeEvent(target.ID)
		return true
	}

	return false
}

// handleVanishRequest applies a NIP-62 request to vanish: every event authored by
// the request's pubkey is deleted and, because the request itself is stored, later
// events from that pubkey are refused by checkVanished.
func (rl *Relay) handleVanishRequest(ctx context.Context, evt *nostr.Event) error {
	// NIP-62 asks clients to send one request per relay; only honor requests that
	// are addressed to us (a missing relay tag means "the relay that receives it").
	if tag := evt.Tags.Find("relay"); len(tag) > 1 {
		target := strings.TrimSuffix(tag[1], "/")
		if target != "all" && target != "*" && !rl.relayURLMatches(target) {
			return errors.New("blocked: vanish request targets another relay")
		}
	}

	if len(rl.DeleteEvent) == 0 {
		return errors.New("error: this relay cannot honor a vanish request")
	}

	ictx := WithInternalCall(ctx)

	until := nostr.Now()
	for _, query := range rl.QueryEvents {
		err := forEachEventPage(ictx, query, nostr.Filter{
			Authors: []string{evt.PubKey},
			Until:   &until,
		}, func(batch []*nostr.Event) error {
			for _, target := range batch {
				if target.ID == evt.ID {
					continue
				}
				for _, del := range rl.DeleteEvent {
					if err := del(ictx, target); err != nil {
						return err
					}
				}
				rl.expirationManager.removeEvent(target.ID)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// relayURLMatches compares a NIP-62 "relay" tag against this relay's URL.
func (rl *Relay) relayURLMatches(target string) bool {
	if rl.ServiceURL == "" {
		return false
	}
	return strings.TrimSuffix(rl.ServiceURL, "/") == target
}

// checkVanished returns an error when the event author has a stored NIP-62 request
// to vanish that is newer than (or as old as) the event being stored.
func (rl *Relay) checkVanished(ctx context.Context, evt *nostr.Event) error {
	for _, query := range rl.QueryEvents {
		ch, err := query(ctx, nostr.Filter{
			Kinds:   []int{62},
			Authors: []string{evt.PubKey},
			Limit:   1,
		})
		if err != nil {
			continue
		}

		for vanished := range ch {
			if vanished.ID == evt.ID {
				continue
			}
			if vanished.CreatedAt > evt.CreatedAt ||
				(evt.Kind != 62 && vanished.CreatedAt == evt.CreatedAt) {
				return errors.New("blocked: author has requested to vanish from this relay")
			}
		}
	}

	return nil
}
