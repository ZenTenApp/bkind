package bkind

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

// queryPageSize is the page size used when the relay has to walk an unbounded set
// of events: large enough to be cheap, small enough to stay under the limits the
// stores apply to a single query.
const queryPageSize = 500

// forEachEventPage calls eachPage for every event matching filter, newest first,
// in pages of queryPageSize events.
//
// An empty filter is not the same as "no limit" across stores: some treat Limit 0
// as "return nothing", so an explicit page size is always set and the walk continues
// until a page comes back short. eachPage gets a materialized page, so it is free to
// delete or store events without pulling the iterator from under the store.
func forEachEventPage(
	ctx context.Context,
	query func(context.Context, nostr.Filter) (chan *nostr.Event, error),
	filter nostr.Filter,
	eachPage func(events []*nostr.Event) error,
) error {
	until := filter.Until

	for page := 0; page < 10000; page++ {
		current := filter
		current.Limit = queryPageSize
		if until != nil {
			current.Until = until
		}

		ch, err := query(ctx, current)
		if err != nil {
			return err
		}

		batch := make([]*nostr.Event, 0, queryPageSize)
		var oldest nostr.Timestamp
		for evt := range ch {
			if evt == nil {
				continue
			}
			batch = append(batch, evt)
			if oldest == 0 || evt.CreatedAt < oldest {
				oldest = evt.CreatedAt
			}
		}

		if len(batch) == 0 {
			return nil
		}
		if err := eachPage(batch); err != nil {
			return err
		}
		if len(batch) < queryPageSize || oldest == 0 {
			return nil
		}

		// the next page holds events strictly older than the ones just seen
		next := oldest - 1
		if until != nil && next >= *until {
			return nil
		}
		until = &next
	}

	return nil
}
