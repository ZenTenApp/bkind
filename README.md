# B Kind

[![Run Tests](https://github.com/ZenTenApp/bkind/actions/workflows/test.yml/badge.svg)](https://github.com/ZenTenApp/bkind/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ZenTenApp/bkind.svg)](https://pkg.go.dev/github.com/ZenTenApp/bkind)
[![Go Report Card](https://goreportcard.com/badge/github.com/ZenTenApp/bkind)](https://goreportcard.com/report/github.com/ZenTenApp/bkind)

B Kind is a Go library for writing Nostr relays with code instead of
configuration — and a reference relay built with it that carries NIP-04 direct
messages and nothing else.

It is the continuation of khatru v0.19.1. khatru is archived; this fork carries
the framework plus the DM relay and the policy set.

- custom event and filter acceptance policies, in plain Go
- custom `AUTH` handlers and first-class NIP-42 enforcement
- pluggable storage, including every [eventstore](https://github.com/fiatjaf/eventstore) backend
- custom HTTP handlers and pages next to the websocket endpoint
- ready-made policies for NIP-40 expiration and rate limits

## The reference relay: what it enforces

`examples/bkind` is the relay this project exists for: private messages, and
nothing else. Every rule below is a policy in [`policies/`](./policies) wired up
in [`examples/bkind/main.go`](./examples/bkind/main.go).

| Requirement | Rule | Where it lives |
|---|---|---|
| **Only Kind 4** | Kind 4 only, plus the two utility kinds needed to operate it: Kind 5 (NIP-09 delete) and Kind 62 (NIP-62 vanish request). No ephemeral kinds, no social kinds. The set is the key list of the config document, not a literal, and one value drives the write gate, the filter rewrite, reads, `COUNT`, live delivery and NIP-11. | `policies/default.json` |
| **Privileged** | A Kind 4 is readable only by its author and its `p` recipient: every filter must pin `authors` or `#p` to the authenticated pubkey. Kind 5 and 62 are readable by their author only. The same check runs on live delivery, so a wide subscription cannot leak events after its `REQ` was rejected. `COUNT` is refused for the same reason. | `read.privileged` per kind, derived into `KindRules.ReadFilter`, `KindRules.PreventBroadcast`, `KindRules.RejectCount` (the `DM*` functions are wrappers over the default kind set) |
| **Mandatory expiration, max 75h** | Exactly one `expiration` tag, a unix timestamp, in the future and no further than 75 hours away. Expired events are filtered out of queries even before the background sweep deletes them. | `required_tags: ["expiration", …]` + `max_expiration: "75h"` per kind |
| **Max content 4 KB, event 64 KB** | `len(content) <= 4096` bytes, and the serialized event at most 64 KB. The content limit is on the payload, not the serialized event; the 12 KB websocket frame limit is only a backstop. | `max_event_content_size` and `max_event_size` per kind (`MaxContentLen` and `MaxEventLen` under them) |
| **Mandatory tags** | Exactly one non-empty `client` tag, and the mandatory `expiration` tag above. | `required_tags` per kind (`RequireTag` under it) |
| **Authenticated** | NIP-42 on writes and reads. The author of an event must equal the authenticated key. Rejections use the `auth-required:` prefix so clients know to authenticate and retry. | `require_auth` per kind (`RequireAuthedAuthor` under it) |
| **Rate limits: 1h, 1d, per npub, per ip** | Writes: 30/hour and 200/day per npub; 60/hour and 400/day per IP, per kind. Reads: 60/hour and 400/day per npub; 120/hour and 800/day per IP. Connections: 120/hour per IP. | `rate_limits` (per kind, defaulted at the top level), `read_limits`, `connection_limits` |
| **Tag restrictions** | At most 16 tags; tag names at most 64 bytes; every tag value at most 256 bytes. Checked on every tag and every position, unlike `PreventLargeTags`. | `tag_limits` per kind (`TagShapeLimits` under it) |

On top of the requirements, what a kind demands comes from its rule alone: there
is no structural validator layered on top, so a Kind 4 is whatever its
`required_tags`, `tag_patterns` and `tag_limits` say it is. Reply references
(`e` tags, which NIP-04 allows) and a message addressed to its own author are
both storable now — if a relay wants them gone, it says so in the rule instead of
relying on a hidden check.

### Deliberate deviations from the original spec

The relay began as "Kind 4 only". Five decisions changed or sharpened that:

1. **Kinds 5 and 62 are allowed.** With only Kind 4, a message could never be
   deleted and an identity could never be erased. Both extra kinds are
   constrained: a Kind 5 may only carry `e` references (plus `client` and
   `expiration`) and may only target the sender's own events; Kind 62 is
   self-signed and relay-scoped. Neither is readable by anyone but its author.
2. **`COUNT` is rejected, not filtered.** A count over direct messages leaks
   metadata even when no event is returned, so `DMCountPolicy` applies the same
   visibility rule as reads.
3. **Negentropy is off.** Set reconciliation would leak which event IDs exist on
   the relay.
4. **`policies.ApplySaneDefaults` is not used here.** Its 2-events-per-3-minutes
   limit contradicts the rate limits above; the library default remains
   available for relays that want it.
5. **The size limit is on `content`.** Tags and JSON overhead are bounded only
   by the websocket frame limit, so an oversized *event* is never accepted just
   because its content is small.

## Quick start

```bash
go get github.com/ZenTenApp/bkind
```

```go
package main

import (
	"context"
	"net/http"

	"github.com/ZenTenApp/bkind"
	"github.com/ZenTenApp/bkind/policies"
	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	relay := bkind.NewRelay()

	// bring your own storage: here, in-memory; swap in sqlite3, postgres, lmdb, badger...
	store := &slicestore.SliceStore{}
	store.Init()
	relay.StoreEvent = append(relay.StoreEvent, store.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, store.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, store.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, store.DeleteEvent)

	// built-in policies: base64 media, rate limits, no complex filters
	policies.ApplySaneDefaults(relay)

	// or write your own, as a plain function
	relay.RejectEvent = append(relay.RejectEvent,
		func(ctx context.Context, event *nostr.Event) (bool, string) {
			if event.Kind == 1 && len(event.Content) > 280 {
				return true, "invalid: notes are limited to 280 characters here"
			}
			return false, ""
		},
	)

	relay.Info.Name = "B Kind"
	relay.Info.Description = "a relay built with B Kind"

	http.ListenAndServe(":3334", relay)
}
```

The full runnable version of this file, with a custom read policy, is
[`examples/readme-demo`](./examples/readme-demo). The storage examples for each
backend are in [`examples/`](./examples).

## Run the reference relay

```bash
go run ./examples/bkind                 # in-memory store, ws://localhost:3334
BKIND_DB=./data go run ./examples/bkind # badger on disk, survives restarts
```

It is the relay described above: authenticated Kind 4 messages, max 75 hours of
retention, 4 KB of content, mandatory `expiration` and `client` tags, and the
rate limits in the table. The whole policy set is one document —
`policies/default.json`, embedded in the binary — and every per-kind setting
lives in that kind's own rule: no top-level defaults, no inheritance. The relay
loads the embedded document, then a JSON file, then `BKIND_KINDS`, then flags:

```bash
BKIND_CONFIG=/etc/bkind/bkind.json go run ./examples/bkind   # a file
BKIND_KINDS=4,5,62 go run ./examples/bkind                   # variables

# your own copy of the whole document, to edit and keep in version control
go run ./examples/bkind -print-config > bkind.json
BKIND_CONFIG=bkind.json go run ./examples/bkind
```

| Env | Flag | Default | Meaning |
|---|---|---|---|
| `BKIND_CONFIG` | — | *(empty)* | path to a JSON policy file; see [Configuring a relay](./docs/cookbook/configuration.md) and `examples/bkind/*.example.json` |
| `BKIND_CONFIG_JSON` | — | *(empty)* | the same document inline |
| `BKIND_ADDR` | `-addr` | `:3334` | listen address |
| `BKIND_URL` | `-url` | *(empty)* | public `ws(s)://` URL; must match what clients connect to, used by NIP-42 and NIP-62 |
| `BKIND_DB` | `-db` | *(empty)* | database directory; empty means in-memory and nothing is persisted |
| `BKIND_SWEEP_INTERVAL` | `-sweep-interval` | `5m` | how often expired events are deleted |
| `BKIND_KINDS` | `-kinds` | `4,5,62` | comma-separated kinds the relay serves; drops the rules of kinds it leaves out |
| `BKIND_NAME` | `-name` | `B Kind` | relay name in NIP-11 |
| `BKIND_DESCRIPTION` | `-description` | *(derived)* | description in NIP-11; empty derives it from the kind list |

Per-kind limits, tag rules, gates, write rate limits and error templates live in
the JSON document (or `BKIND_CONFIG_JSON`), keyed by kind; the relay-wide
settings — read and connection limits, filters, `COUNT`, NIP-11 — are defaults in
`policies.DefaultSettings()`, moved by flags. Every field is documented in
[Configuring a relay](./docs/cookbook/configuration.md), and
`bkind -print-config` prints the resolved document (the kinds, in full).

The NIP-11 document it serves:

```json
{
  "name": "B Kind",
  "description": "Kind 4 direct messages, Kind 5 deletions, Kind 62 vanish requests only.",
  "supported_nips": [4, 9, 11, 40, 42, 62],
  "limitation": {
    "max_message_length": 12288,
    "max_event_tags": 16,
    "max_content_length": 4096,
    "max_subscriptions": 10,
    "max_filters": 4,
    "max_limit": 500,
    "auth_required": true,
    "restricted_writes": true
  }
}
```

The document is derived from the config: `supported_nips` gains `45` only when
`COUNT` is answered, and the description is generated from the served kinds, so
neither can claim a feature this relay does not have.
`max_event_tags` and `max_content_length` are the maxima across the kind rules.

## Documentation

- [Why B Kind](./docs/why.md) — what the framework is for, and what people build with it
- [Getting started](./docs/getting-started/index.md) — install, store, policies, routers
- [The DM relay spec](./docs/cookbook/dm-only-relay.md) — every rule above, and the khatru behaviour that had to change to meet it
- [Configuring a relay](./docs/cookbook/configuration.md) — the policy file, the environment variables, and how to serve a different kind set
- [Deploying on Ubuntu](./docs/cookbook/deploying.md) and [with Docker](./docs/cookbook/docker.md)
- [Naming rules](./NAMING.md) — what is called `B Kind`, `bkind`, `BKIND_*`, and what must never be renamed
- API reference: [pkg.go.dev/github.com/ZenTenApp/bkind](https://pkg.go.dev/github.com/ZenTenApp/bkind)

## Migrating from khatru

The module path and package changed; the API did not:

```bash
go get github.com/ZenTenApp/bkind
```

```diff
-import "github.com/fiatjaf/khatru"
+import "github.com/ZenTenApp/bkind"
```

Every identifier moves with it — `khatru.NewRelay()` becomes `bkind.NewRelay()`,
`khatru.GetAuthed(ctx)` becomes `bkind.GetAuthed(ctx)`, and the test package
becomes `bkind_test`. If you import the policies, point that at
`github.com/ZenTenApp/bkind/policies` too.

Behaviour that changed, all of it to make a private relay actually private:

- write policies now run **before** Kind 5/62 side effects, so a rejected
  deletion no longer deletes anything
- stored Kind 5 events are scoped by author, so they cannot be used to block
  someone else's event IDs
- Kind 5 and Kind 62 handling now respects NIP-09 and NIP-62, and expired
  events are swept on the configured interval rather than on a hardcoded one

The reasoning for each is in [`docs/cookbook/dm-only-relay.md`](./docs/cookbook/dm-only-relay.md).

## Status

Pre-`v1.0.0`. The framework API is the khatru API, so it is stable in practice;
the relay's defaults may still change before the first tagged release. Issues and
patches are welcome.

## Provenance and license

B Kind continues khatru v0.19.1, by fiatjaf and the khatru contributors. khatru
is archived; its announced successor no longer resolves. The full git history is
preserved, so `git blame` still points at the original authors.

Public domain, under the [Unlicense](./LICENSE). There is nothing to sign and
nothing to attribute — the credit in this section is a courtesy, not an
obligation.
