---
outline: deep
---

# B Kind: a Kind-4-only DM relay

A relay that serves NIP-04 direct messages and the two utility kinds needed to
operate them, and nothing else. Everything is authenticated, everything expires,
and a message is only ever readable by its author and its recipient.

The wiring lives in `examples/bkind/main.go`; this
page records the specification, the khatru behaviour that had to change to meet
it, and the reasons behind each policy. For running it on a server, see
[deploying a relay](./deploying.md) or [deploying with Docker](./docker.md).

Status: implemented on branch `complex/bkind`.

## Requirements

| Requirement | Rule |
|---|---|
| Kinds | `{4, 5, 62}` only, no ephemeral (`kinds.whitelist` in the config) |
| Payload size | `len(content) <= 4096` bytes |
| Frame backstop | `MaxMessageSize ~= 12KB` (websocket read limit, not a check) |
| Expiration | mandatory, exactly one tag, `now < expiration <= now + 75h` |
| Client tag | mandatory, exactly one, non-empty value |
| Authentication | NIP-42 on writes and reads; write author must equal authed key |
| Privacy | Kind 4 visible to author and `p` recipient only |
| Tags | max 16 tags, tag name max 64 bytes, tag value max 256 bytes |
| Kind 4 shape | exactly one `p`, 64-char hex, not the author, no `e`/`a`/`d` |
| Kind 5 | `e` tags only, every target must be authored by the sender |
| Kind 62 | self-signed, relay-scoped; deletes all author events and blocks further |
| Rate limits | events and REQs, per npub and per ip, at 1h and 1d windows |
| NIP-11 | advertise `{4, 5, 9, 11, 40, 42, 62}`, `auth_required`, `restricted_writes` |

Housekeeping: `Negentropy = false` (set reconciliation leaks ID sets),
`ManagementAPI` left nil (no out-of-band write path), `policies.ApplySaneDefaults`
is **not** used (its 2-per-3-minutes event limit contradicts our numbers).

## Design decisions

1. **Content is capped at 4096 bytes**, not the serialized event. Tags and JSON
   overhead live inside the websocket frame limit only.
2. **Kinds `{4, 5, 62}`.** The set is `kinds.whitelist` in
   `policies.DefaultConfig`, not a literal in the wiring, and the write gate, the filter
   rewrite, reads, `COUNT`, live delivery and NIP-11 all derive from it — see
   [Configuring a relay](./configuration.md). Kind 5 lets a sender delete their own DM. Kind 62 is
   the "request to vanish" counterpart: purge the identity's whole footprint.
   No social kinds (0, 1, 3, 6, 7, 9735): they leak the social graph of a relay
   whose only purpose is private conversation. No NIP-17 seals or gift wraps
   either: gift wrap is signed by a throwaway key, so "authed key equals author"
   can never hold, and it would defeat the size and tag rules.
3. **Kind 5 and 62 are stored, but only when authorized.** Both are broadcast.
   Reading them is restricted to their author: a stored Kind 5 lists the IDs of
   the sender's messages, and a stored Kind 62 is a durable request. Storing kind
   62 is what makes "stop accepting events from this key" survive a restart.
4. **Deletion is author-only.** No `OverwriteDeletionOutcome`. A recipient cannot
   destroy the sender's copy; clients should delete locally.
5. **Tombstones are scoped by author** (see the censorship vector below).
6. **Kind 62 is implemented now**, not deferred.

## What changed in khatru

The requirements cannot be met by wiring policies in a `main.go` alone: several
code paths in khatru itself had to change. Each item below is a real bug for this
kind of relay, not a preference.

### The write gate now runs before kind-specific side effects

`handlers.go` used to run `handleDeleteRequest` before `handleNormal` applied
`RejectEvent`. An oversize, tag-less, unauthenticated or already-expired Kind 5
therefore performed its deletion and was only afterwards rejected with
`blocked: Kind 5 events are not allowed on this relay`.

The write policy loop is now `checkEventAcceptable(ctx, evt)`, called by both the
websocket handler and `Relay.AddEvent` before `handleKindSpecificSideEffects`,
which dispatches Kind 5 to `handleDeleteRequest` and Kind 62 to
`handleVanishRequest`. Policies run exactly once per event, so stateful ones (the
rate limiters) do not count the same event twice.

### Stored deletions are no longer a censorship vector

`adding.go` blocks a re-published event by querying stored Kind 5 events for
`e = evt.ID` without an author filter. Once Kind 5 is persisted, anyone could
permanently block any event ID on the relay with a Kind 5 that merely references
it, even though `deleting.go` correctly declines to delete events they do not
own.

Both halves are fixed:

1. Only authorized deletions are stored: `e` targets that the sender does not
   author are skipped, and the whole event is rejected when no target survives.
2. The deleted-by-ID query carries `Authors: []string{evt.PubKey}`, so even a
   stored Kind 5 cannot block someone else's event.

The same scoping applies to the replaceable-by-address tombstone query.

### Internal filter tag names do not take a `#`

Found while writing the tests above: `Filters.Tags` uses **bare** tag names
(`"e"`, `"p"`, `"d"`). The `#` is only the JSON spelling on the wire
(`Filter.UnmarshalJSON` strips it) and `Filter.Matches` compares the name
verbatim. The existing tombstone queries used `nostr.TagMap{"#e": ...}`, which
matches nothing on stores that filter with `Filter.Matches` — so a deleted event
could be re-published anyway. The internal queries now use `"e"` and `"a"`.

### Privacy had two live bypasses

`policies/nip04.go` returns early when the filter does not contain Kind 4, so a
filter with **empty `Kinds`** queried every kind and never triggered the auth
check.

`notifyListeners` matched the filter stored at subscription time and never
re-ran `RejectFilter`. That stored filter is the pre-`OverwriteFilter` copy, so a
wide live subscription kept receiving Kind-4 events regardless of the check done
at REQ time.

Fixed with a deny-by-default read policy that treats empty `Kinds` as "all kinds"
(`policies.DMReadPolicy`), the same rule wired into `RejectCountFilter` (a DM
count is a metadata leak), and `policies.DMBroadcastGuard` on `PreventBroadcast`
for live delivery. `notifyListeners` also takes a copy of the listener slice now:
it used to race with subscription removal (visible under `go test -race`).

### Deletion is no longer an existence oracle

`deleting.go` answered `blocked: you are not the author of this event` when a kind
5 targeted someone else's event, which confirms the existence of any ID in the
store.

Non-authored targets are now skipped silently and the event is accepted if at
least one target was actionable. When nothing could be acted on the whole deletion
is rejected with `blocked: no valid deletion targets` so that nothing is stored
and other relays cannot mistake a stored Kind 5 for evidence that the target
existed here. `OverwriteDeletionOutcome` can still widen acceptance for someone
else's event; it is not consulted for the author's own targets.

`handleDeleteRequest` keeps support for `a` references because it is shared with
other relays; on this one `ValidateKind5Shape` rejects `a` tags outright, since
the allowlist has no addressable kind.

### Expiration now survives restarts

`expiration.go` only swept: `initialScan` did not run until the first tick, so
after a restart expired DMs stayed readable for an hour, and the interval was
hardcoded to one hour.

Now the sweeper starts on first use (`Relay.ensureExpirationManager`, called from
`ServeHTTP` and `AddEvent`, so the scan always sees a fully wired relay), it
scans **and** sweeps before the first tick, and the interval is configurable with
`Relay.SetExpirationInterval`. The example additionally wraps `QueryEvents` with
`dropExpired`, so an answer never depends on when the last sweep ran.

Paging got a shared helper, `forEachEventPage`: an empty filter is not "no limit"
across stores (some treat `Limit: 0` as "return nothing"), so the walk uses an
explicit page size and continues until a short page. It also hands each page over
materialized, so deleting while paginating cannot pull the iterator from under the
store.

### Server-side writes have proper escape hatches

`AddEvent` now goes through the write policies, which means it trips
`RequireAuthedAuthor` (there is no connection, so no authenticated key). Two small
exported helpers make that usable instead of forcing callers to reach into the
package:

- `bkind.WithInternalCall(ctx)` — the relay acting on the store itself
  (deletions, expirations). Policies that require authentication let it through.
- `bkind.WithAuthenticatedPubKey(ctx, pubkey)` — act on behalf of a user, and
  what the policy tests use.

`GetAuthed` now also consults the context value, so both work outside a
websocket.

### Remaining gaps, deliberately not fixed

- `relay.MaxMessageSize` (512KB default) is a websocket read limit: exceeding it
  closes the connection with 1009 instead of returning a NAK. The example lowers
  it to 12KB as a backstop; the real limit is the content check.
- `GetIPFromRequest` takes the first public `X-Forwarded-For` entry, so per-IP
  limits are spoofable unless a proxy overwrites the header.
- `go test -race ./...` fails on `relay_test.go` because `slicestore` reads its
  slice without a lock while writes happen. That predates this branch (the same
  tests race on `9f99b98`); the new tests use a locking wrapper instead.

## The policy set

`policies/kinds.go`:

- `KindRules` — the allowlist plus the two visibility classes. Every gate is a method on
  it: `RestrictKind` (write), `OverwriteFilters` (filter rewrite), `ReadFilter` (read),
  `RejectCount` (`COUNT`) and `PreventBroadcast` (live delivery).
- `ReadFilter` — deny by default; require auth; a kind outside the allowlist is
  rejected rather than narrowed, so a client notices it is on the wrong relay;
  empty `Kinds` counts as "every kind", the strictest case; a recipient-visible kind
  needs `authors` or `p` pinned to the authed key; an author-only kind needs
  `authors == [authed]`.
- `RejectCount` — the same rule for `RejectCountFilter`.
- `PreventBroadcast` — recipient-visible to its author or its `p`, author-only to its
  author, a kind that is not served never.
- `ShapeValidator` — the per-kind structural validator registry (`4`, `5`, `62`).

`policies/dm.go` keeps `DMKindAllowlist`, `DMReadPolicy`, `DMCountPolicy` and
`DMBroadcastGuard` as thin wrappers over the DM `KindRules` for code that wired khatru
by hand.
- `RequireAuthedAuthor` — `auth-required:` when unauthenticated (which is what
  triggers the NIP-42 challenge), `blocked:` when the authed key is not the
  author, silent pass for internal calls.
- `RequireExpiration(max)` — exactly one tag, integer, `now < expiration <= now+max`.
- `RequireTag(name)` — exactly one, non-empty.
- `MaxContentLen(n)`.
- `TagShapeLimits(maxTags, maxNameLen, maxValueLen)` — every tag, every element,
  unlike `PreventLargeTags`, which only looks at single-letter names and `tag[1]`.
- `ValidateKind4Shape`, `ValidateKind5Shape`, `ValidateKind62Shape`.

`policies/ratelimits.go` gained `FilterAuthedPubKeyRateLimiter`: `startRateLimitSystem`
is unexported, so a per-npub REQ limit could not be built outside the package.

## Wiring

`examples/bkind/main.go` no longer lists policies. It loads a `policies.Config`
(defaults, then `BKIND_CONFIG`, then `BKIND_KINDS`, then flags) and calls one
function:

```go
if err := cfg.Wire(relay); err != nil { ... }
```

`Wire` installs, in this order:

`RejectEvent`:

```go
k.RestrictKind(),            // the whitelist
c.writePolicy(),             // the checks of the event's own effective rule —
// the top-level defaults with the kind's rule laid over them — in this order:
//   write.allow, require_auth, max_age_of_event, max_age_event_in_future,
//   max_expiration + required_tags, tag_patterns, max_size, tag_limits,
//   p_tag, the shape validator, the kind's write rate limits
```

`OverwriteFilter` is `k.OverwriteFilters()`; `RejectFilter` is `k.ReadFilter` (which
carries the per-kind auth and visibility requirements), `NoEmptyFilters`,
`NoSearchQueries` plus the read limiters; `RejectCountFilter` is `k.ReadFilter`;
`PreventBroadcast` is `k.PreventBroadcast`; `RejectConnection` is the connection
limiters. The NIP-11 document is derived from the same config, including
`supported_nips`.

The store, `ServiceURL`, `MaxMessageSize`, the expiration sweep interval and the HTTP
server stay explicit in `main.go` — they are structure, not policy.

## Tests

- `bkind_test.go` wires the reference config (`policies.DefaultConfig()`, rate limits
  off) and drives it over a real
  websocket: the NIP-42 challenge round trip, authorship binding, the whole
  `RejectEvent` table (kind, content size, expiration, client tag, tag shape,
  Kind 4 structure), the read matrix (author, recipient, third party,
  unauthenticated), live delivery to the recipient only, deletion by author vs
  third party (including the re-publish attempt), the vanish request (foreign
  relay tag, erasure, refusing older events, missing `DeleteEvent`), NIP-11, and
  the startup expiration sweep.
- `policies/dm_test.go` covers each policy directly, including the boundary
  values: 4096 vs 4097 bytes of content, 16 vs 17 tags, 64 vs 65 byte tag names,
  256 vs 257 byte tag values, exactly 75h vs 76h of expiration.

Run everything with:

```sh
gofmt -l . && go build ./... && go vet ./... && go test ./...
```

The example reads its process settings from `BKIND_*` environment variables and flags
(`-url`, `-addr`, `-db`, `-sweep-interval`, `-kinds`, `-name`, `-description`), and its
policy set from a JSON document named by `BKIND_CONFIG` (or `BKIND_CONFIG_JSON`).
[Configuring a relay](./configuration.md) is the reference for the document.

## Accepted consequences

- **Kind 5 and 62 read as author-only**, unlike Kind 4 which is author-or-recipient.
- **Deletion is not durable past expiration.** A Kind 5 self-prunes after at most
  75 hours; after the sweep the sender, who still holds the original, can
  re-publish it. Deletion is author-only, so this is not a new trust problem. If
  "delete means gone" is required, a Kind 5's expiration must be at least that of
  its targets.
- **Kind 62 blocks re-publication for the life of the stored Kind 62**, that is,
  up to 75 hours after it was sent.
- **Expiration is enforced from the sweep and the read wrapper**, so a client that
  reads through a different query path (for example `COUNT` on its own events) may
  briefly see an event the sweep has not removed yet.
- **Per-IP limits are only as good as the proxy in front of the relay.**
- **NIP-11 also advertises 45** (COUNT), because B Kind adds it whenever
  `CountEvents` is wired. That is correct: clients can count their own messages,
  and `DMCountPolicy` refuses everything else.
- **The store defaults to in-memory.** Without `-db` the example uses
  `slicestore`, so nothing survives a restart. Give it a directory to use badger;
  see [deploying a relay](./deploying.md) or [deploying with Docker](./docker.md).
