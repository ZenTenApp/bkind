package khatru

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

const (
	wsKey = iota
	subscriptionIdKey
	nip86HeaderAuthKey
	internalCallKey
	authedPubKeyKey
)

func RequestAuth(ctx context.Context) {
	ws := GetConnection(ctx)
	ws.authLock.Lock()
	if ws.Authed == nil {
		ws.Authed = make(chan struct{})
	}
	ws.authLock.Unlock()
	ws.WriteJSON(nostr.AuthEnvelope{Challenge: &ws.Challenge})
}

func GetConnection(ctx context.Context) *WebSocket {
	wsi := ctx.Value(wsKey)
	if wsi != nil {
		return wsi.(*WebSocket)
	}
	return nil
}

func GetAuthed(ctx context.Context) string {
	if conn := GetConnection(ctx); conn != nil && conn.AuthedPublicKey != "" {
		return conn.AuthedPublicKey
	}
	if pubkey, ok := ctx.Value(authedPubKeyKey).(string); ok && pubkey != "" {
		return pubkey
	}
	if nip86Auth := ctx.Value(nip86HeaderAuthKey); nip86Auth != nil {
		return nip86Auth.(string)
	}
	return ""
}

// WithAuthenticatedPubKey marks a context as authenticated as pubkey.
//
// Relays learn who is connected from the websocket (NIP-42), so this is for
// contexts that have no connection: server-side code that calls Relay.AddEvent on
// behalf of a user, and tests of policies that read the authenticated key.
func WithAuthenticatedPubKey(ctx context.Context, pubkey string) context.Context {
	return context.WithValue(ctx, authedPubKeyKey, pubkey)
}

// IsInternalCall returns true when a call to QueryEvents, for example, is being made because of a deletion
// or expiration request.
func IsInternalCall(ctx context.Context) bool {
	return ctx.Value(internalCallKey) != nil
}

// WithInternalCall marks a context as an internal call: the relay itself acting on
// the store (deletions, expirations) rather than a user. Policies that require
// authentication let internal calls through, see policies.RequireAuthedAuthor.
func WithInternalCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalCallKey, struct{}{})
}

func GetIP(ctx context.Context) string {
	conn := GetConnection(ctx)
	if conn == nil {
		return ""
	}

	return GetIPFromRequest(conn.Request)
}

func GetSubscriptionID(ctx context.Context) string {
	return ctx.Value(subscriptionIdKey).(string)
}
