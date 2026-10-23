package bkind

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

func (rl *Relay) handleEphemeral(ctx context.Context, evt *nostr.Event) error {
	for _, oee := range rl.OnEphemeralEvent {
		oee(ctx, evt)
	}

	return nil
}
