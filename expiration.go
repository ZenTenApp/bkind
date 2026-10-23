package bkind

import (
	"container/heap"
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip40"
)

type expiringEvent struct {
	id        string
	expiresAt nostr.Timestamp
}

type expiringEventHeap []expiringEvent

func (h expiringEventHeap) Len() int           { return len(h) }
func (h expiringEventHeap) Less(i, j int) bool { return h[i].expiresAt < h[j].expiresAt }
func (h expiringEventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *expiringEventHeap) Push(x interface{}) {
	*h = append(*h, x.(expiringEvent))
}

func (h *expiringEventHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type expirationManager struct {
	events   expiringEventHeap
	mu       sync.Mutex
	relay    *Relay
	interval atomic.Int64 // nanoseconds
}

func newExpirationManager(relay *Relay) *expirationManager {
	em := &expirationManager{
		events: make(expiringEventHeap, 0),
		relay:  relay,
	}
	em.interval.Store(int64(time.Hour))
	return em
}

// getInterval returns how often expired events are swept.
func (em *expirationManager) getInterval() time.Duration {
	if d := time.Duration(em.interval.Load()); d > 0 {
		return d
	}
	return time.Hour
}

func (em *expirationManager) start(ctx context.Context) {
	// scan and sweep before the first tick: otherwise, after a restart,
	// already-expired events stay readable for a whole interval
	em.initialScan(ctx)
	em.checkExpiredEvents(ctx)

	timer := time.NewTimer(em.getInterval())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			em.checkExpiredEvents(ctx)
			timer.Reset(em.getInterval())
		}
	}
}

func (em *expirationManager) initialScan(ctx context.Context) {
	em.mu.Lock()
	defer em.mu.Unlock()

	// query all events
	ctx = WithInternalCall(ctx)
	for _, query := range em.relay.QueryEvents {
		err := forEachEventPage(ctx, query, nostr.Filter{}, func(batch []*nostr.Event) error {
			for _, evt := range batch {
				if expiresAt := nip40.GetExpiration(evt.Tags); expiresAt != -1 {
					heap.Push(&em.events, expiringEvent{
						id:        evt.ID,
						expiresAt: expiresAt,
					})
				}
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	heap.Init(&em.events)
}

func (em *expirationManager) checkExpiredEvents(ctx context.Context) {
	em.mu.Lock()
	defer em.mu.Unlock()

	now := nostr.Now()

	// keep deleting events from the heap as long as they're expired
	for em.events.Len() > 0 {
		next := em.events[0]
		if now < next.expiresAt {
			break
		}

		heap.Pop(&em.events)

		ctx := WithInternalCall(ctx)
		for _, query := range em.relay.QueryEvents {
			ch, err := query(ctx, nostr.Filter{IDs: []string{next.id}})
			if err != nil {
				continue
			}

			if evt := <-ch; evt != nil {
				for _, del := range em.relay.DeleteEvent {
					del(ctx, evt)
				}
			}
			break
		}
	}
}

func (em *expirationManager) trackEvent(evt *nostr.Event) {
	if expiresAt := nip40.GetExpiration(evt.Tags); expiresAt != -1 {
		em.mu.Lock()
		heap.Push(&em.events, expiringEvent{
			id:        evt.ID,
			expiresAt: expiresAt,
		})
		em.mu.Unlock()
	}
}

func (em *expirationManager) removeEvent(id string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Find and remove the event from the heap
	for i := 0; i < len(em.events); i++ {
		if em.events[i].id == id {
			heap.Remove(&em.events, i)
			break
		}
	}
}
