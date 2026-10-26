---
outline: deep
---

# Configuring a relay

The reference relay in `examples/bkind` keeps its policy set in
`policies.Config` (`policies/config.go`) — kinds, visibility, limits, rate limits and
the NIP-11 document — and loads it from the environment. Nothing in the policy set is a
literal in `main.go`, so a different relay shape is a config file, not a patch.

## Precedence

Each layer overrides the one before it:

1. `policies.DefaultConfig()` — the Kind-4 DM relay.
2. `BKIND_CONFIG=/etc/bkind/bkind.json` — a JSON file.
3. `BKIND_CONFIG_JSON='{"content":{"max":2048}}'` — inline JSON, for containers and
   systemd `Environment=` lines that cannot mount a file.
4. `BKIND_*` scalar variables (below) — the ones worth setting on a command line.
5. Flags — `-kinds`, `-max-content`, … .

The result is validated before the listener starts; an invalid configuration is a
startup error, never a relay that accepts events it cannot serve.

JSON is parsed strictly: an unknown field is an error, so `{"contnet": ...}` fails
instead of silently doing nothing. Absent fields keep their default, which means a file
only has to name what it changes.

## Partial or explicit?

Two ways to use the file, and the difference is a switch, not a rewrite:

- **Partial** (the default). The file is a patch on the defaults. `{"content":{"max":512}}`
  changes one thing and inherits everything else. Good for an experiment, and good for a
  relay that wants to track the defaults as they evolve.
- **Explicit** (`BKIND_CONFIG_STRICT=true`). Every field must be present. Absent fields
  are a startup error naming the field, and there is no "inherits whatever the binary
  happened to default to". Good for a config kept in version control and reviewed, and
  the only mode where reading the file tells you what the relay does.

Neither mode is "safer" in the abstract: strict is about knowing, not about being right.
The reason to want it is that a defaulted field is invisible — `auth.required` flipping
from `true` to `false` two releases later is a config change nobody reviewed.

Start an explicit file from the relay's own output, so it cannot be missing a field:

```sh
bkind -print-config > /etc/bkind/bkind.json
```

`-print-config` prints the **effective** configuration — defaults, then file, then
environment, then flags — in the canonical form, one field per line, with the lists and
rate limits on single lines. It exits without opening the store or the listener, so it is
safe on a production host:

```sh
sudo -u bkind env $(cat /etc/bkind/bkind.env | xargs) \
  /usr/local/bin/bkind -print-config > /tmp/bkind.json
```

Then pin it:

```sh
BKIND_CONFIG=/etc/bkind/bkind.json
BKIND_CONFIG_STRICT=true
```

`examples/bkind/bkind.example.json` in the repository is exactly this output for the
default configuration — a test compares it byte for byte with `DefaultConfig().JSON()`,
so the file in the repo and the binary's defaults cannot drift apart. Feeding it back
with strict mode on reproduces the defaults exactly; that round trip is a test too.

Three things strict mode deliberately does **not** do:

- it does not freeze the environment. `BKIND_*` variables still override a strict file,
  because the switch is about the file being complete, not about the process being
  read-only. If you want one source of truth, set no `BKIND_*` policy variables and pass
  no policy flags;
- it does not cover the process settings (`-addr`, `-url`, `-db`, `-sweep-interval`).
  Those are not policy — see [the boundary](#what-is-still-not-configurable);
- it does not make an incomplete file mean "use the zero value". A missing field is an
  error, never a silent `false`.

## Kinds and visibility

Every gate that decides what the relay serves is derived from `kinds`:

| Gate | Hook | Derived from |
|---|---|---|
| Write | `RejectEvent` | `kinds.allowed` (plus `allow_ephemeral`) |
| Filter rewrite | `OverwriteFilter` | `kinds.allowed`, `reject_unserved_filters` |
| Read | `RejectFilter` | `kinds.allowed` + the two visibility classes |
| `COUNT` | `RejectCountFilter` | the same rule as reads |
| Live delivery | `PreventBroadcast` | the same three-way switch |
| NIP-11 | `HandleNIP11` | `supported_nips`, description and limits |

A kind is in exactly one visibility class:

- `recipient_visible` — readable by its author **and** by the pubkey in its `p` tag
  (Kind 4; Kind 1059 gift wraps on a NIP-17 relay). A filter must pin `authors` or `#p`
  to the authenticated key.
- `author_only` — readable by its author only (Kind 5 deletions, Kind 62 vanish
  requests). A filter must pin `authors` to the authenticated key.
- neither — served, but read like `author_only`. That is the strict default for a kind
  you have not classified yet.

A kind outside `allowed` is never written, never read, never delivered, and is not
advertised.

`reject_unserved_filters` (default `true`) decides what a `REQ` for an unserved kind
gets:

- `true` — `CLOSED` with `restricted: kind 7 is not served by this relay`, so a client
  notices it is talking to the wrong relay;
- `false` — the kind is silently dropped from the filter, and a filter with nothing left
  returns an empty `EOSE` (the subscription stays open, `LimitZero`).

Either way, a `REQ` that names no kinds at all is expanded to `kinds.allowed`, so
"everything I am allowed to see" keeps working.

## The file

```json
{
  "kinds": {
    "allowed": [4, 5, 62],
    "recipient_visible": [4],
    "author_only": [5, 62],
    "allow_ephemeral": false,
    "reject_unserved_filters": true
  },
  "expiration": {"required": true, "max": "75h"},
  "tags": {"required": ["client"], "max": 16, "max_name_len": 64, "max_value_len": 256},
  "content": {"max": 4096},
  "auth": {"required": true},
  "count": {"reject": true},
  "validation": {"shape_kinds": [4, 5, 62]},
  "filters": {"reject_empty": true, "reject_search": true},
  "rate_limits": [
    {"scope": "event", "key": "authed", "tokens": 30, "interval": "1h", "max": 60},
    {"scope": "event", "key": "ip", "tokens": 60, "interval": "1h", "max": 120},
    {"scope": "filter", "key": "authed", "tokens": 60, "interval": "1h", "max": 120},
    {"scope": "filter", "key": "ip", "tokens": 120, "interval": "1h", "max": 240},
    {"scope": "connection", "key": "ip", "tokens": 120, "interval": "1h", "max": 240}
  ],
  "nip11": {
    "name": "B Kind",
    "description": "",
    "max_message_length": 12288,
    "max_subscriptions": 10,
    "max_filters": 4,
    "max_limit": 500,
    "extra_nips": []
  },
  "negentropy": false
}
```

That is the whole set, and it is what `bkind -print-config` prints. Copy it whole and
delete what you do not want to change (partial mode), or keep it whole and set
`BKIND_CONFIG_STRICT=true` (explicit mode).

### Fields

| Field | Default | Meaning |
|---|---|---|
| `kinds.allowed` | `[4,5,62]` | the complete set of kinds served |
| `kinds.recipient_visible` | `[4]` | subset readable by author **and** `p` recipient |
| `kinds.author_only` | `[5,62]` | subset readable by author only |
| `kinds.allow_ephemeral` | `false` | accept ephemeral kinds (20000–29999) without listing them |
| `kinds.reject_unserved_filters` | `true` | reject a `REQ` for an unserved kind instead of narrowing it |
| `expiration.required` | `true` | NIP-40 `expiration` tag is mandatory, exactly one |
| `expiration.max` | `75h` | how far in the future the expiration may point |
| `tags.required` | `["client"]` | tags that must appear exactly once with a non-empty value |
| `tags.max` | `16` | maximum tags per event |
| `tags.max_name_len` | `64` | maximum tag name length, bytes |
| `tags.max_value_len` | `256` | maximum tag value length, bytes |
| `content.max` | `4096` | maximum `content` length, bytes |
| `auth.required` | `true` | NIP-42 on reads and writes, author must equal the authed key |
| `count.reject` | `true` | refuse NIP-45 `COUNT` (metadata leak) |
| `validation.shape_kinds` | `[4,5,62]` | per-kind structural validators to run, from the registry in `policies/kinds.go` |
| `filters.reject_empty` | `true` | refuse a filter with no kind, id, author or tag |
| `filters.reject_search` | `true` | refuse `search` queries |
| `rate_limits[].scope` | — | `event`, `filter` or `connection` |
| `rate_limits[].key` | — | `ip`, `authed` or `pubkey` (`connection` supports `ip` only) |
| `rate_limits[].tokens` | — | tokens refilled per interval |
| `rate_limits[].interval` | — | refill window, a Go duration (`1h`, `24h`) |
| `rate_limits[].max` | — | bucket size |
| `nip11.name` | `"B Kind"` | relay name |
| `nip11.description` | derived | empty means "generated from `kinds.allowed`" |
| `nip11.max_message_length` | `12288` | websocket frame backstop |
| `nip11.max_subscriptions` | `10` | advertised limit |
| `nip11.max_filters` | `4` | advertised limit |
| `nip11.max_limit` | `500` | advertised limit |
| `nip11.extra_nips` | `[]` | NIPs to add to the derived `supported_nips` |
| `negentropy` | `false` | NIP-77 set reconciliation (leaks which event ids exist) |

`rate_limits` replaces the whole list when given: a half-merged list of token buckets
would be a trap. `[]` means no rate limits at all.

`shape_kinds` names kinds; the validators themselves are Go functions in
`policies/kinds.go`, because a JSON document cannot carry code. Naming a kind with no
registered validator is a startup error, not a silent skip.

### Environment and flags

| Env | Flag | Default | Meaning |
|---|---|---|---|
| `BKIND_CONFIG` | — | empty | path to the JSON file above |
| `BKIND_CONFIG_JSON` | — | empty | the same JSON inline |
| `BKIND_CONFIG_STRICT` | — | `false` | require every field in the file; see [Partial or explicit?](#partial-or-explicit) |
| `BKIND_KINDS` | `-kinds` | `4,5,62` | comma-separated allowlist; prunes stale classes |
| `BKIND_RECIPIENT_VISIBLE_KINDS` | — | `4` | comma-separated |
| `BKIND_AUTHOR_ONLY_KINDS` | — | `5,62` | comma-separated |
| `BKIND_SHAPE_KINDS` | — | `4,5,62` | comma-separated |
| `BKIND_ALLOW_EPHEMERAL` | `-allow-ephemeral` | `false` | |
| `BKIND_REJECT_UNSERVED_FILTERS` | — | `true` | |
| `BKIND_REQUIRE_EXPIRATION` | `-require-expiration` | `true` | |
| `BKIND_MAX_EXPIRATION` | `-max-expiration` | `75h` | |
| `BKIND_REQUIRED_TAGS` | `-required-tags` | `client` | comma-separated, empty for none |
| `BKIND_MAX_TAGS` | `-max-tags` | `16` | |
| `BKIND_MAX_TAG_NAME` | `-max-tag-name` | `64` | |
| `BKIND_MAX_TAG_VALUE` | `-max-tag-value` | `256` | |
| `BKIND_MAX_CONTENT` | `-max-content` | `4096` | |
| `BKIND_REQUIRE_AUTH` | `-require-auth` | `true` | |
| `BKIND_REJECT_COUNT` | `-reject-count` | `true` | |
| `BKIND_REJECT_EMPTY_FILTERS` | — | `true` | |
| `BKIND_REJECT_SEARCH` | — | `true` | |
| `BKIND_MAX_MESSAGE_LENGTH` | — | `12288` | |
| `BKIND_MAX_SUBSCRIPTIONS` | — | `10` | |
| `BKIND_MAX_FILTERS` | — | `4` | |
| `BKIND_MAX_LIMIT` | — | `500` | |
| `BKIND_NAME` | `-name` | `B Kind` | |
| `BKIND_DESCRIPTION` | `-description` | derived | |
| `BKIND_NEGENTROPY` | `-negentropy` | `false` | |
| — | `-print-config` | off | print the effective policy set as JSON and exit |
| `BKIND_ADDR` | `-addr` | `:3334` | listen address |
| `BKIND_URL` | `-url` | empty | public `ws(s)://` URL, used by NIP-42 and NIP-62 |
| `BKIND_DB` | `-db` | empty | store directory; empty means in-memory |
| `BKIND_SWEEP_INTERVAL` | `-sweep-interval` | `5m` | expired-event sweep |

## NIP-11 is derived, not written

`supported_nips` is computed from the config, so it cannot claim a feature the relay
does not have: `11` always, `4` if Kind 4 is served, `9` if Kind 5 is, `62` if Kind 62
is, `40` if expirations are required, `42` if auth is required, `45` only when `COUNT`
is answered (`count.reject: false`). The description, when left empty, is generated from
the kind list, and `auth_required`/`restricted_writes` follow `auth.required`.
`extra_nips` is the deliberate escape hatch.

## Examples

### The reference DM relay

The default. Nothing to write:

```sh
go run ./examples/bkind
```

### A public note relay

One kind, no auth, no expiration, no shape validation:

```json
{
  "kinds": {"allowed": [1], "recipient_visible": [], "author_only": []},
  "expiration": {"required": false},
  "tags": {"required": []},
  "auth": {"required": false},
  "count": {"reject": false},
  "validation": {"shape_kinds": []},
  "rate_limits": [
    {"scope": "event", "key": "ip", "tokens": 60, "interval": "1h", "max": 120}
  ],
  "nip11": {"name": "notes"}
}
```

NIP-11 then advertises `[11, 45]` and `auth_required: false` without a code change.

### Kind 4 plus NIP-17 gift wraps

```json
{
  "kinds": {
    "allowed": [4, 5, 62, 1059],
    "recipient_visible": [4, 1059],
    "author_only": [5, 62]
  }
}
```

Reads and live delivery follow: a `1059` reaches its author and its `p`, and a filter
must pin one of them. Two things do not come from the config:

1. a gift wrap is signed by a throwaway key, so `auth.required: true` (author must equal
   the authed key) only works if the client authenticates as that throwaway key — a
   relay serving real NIP-17 traffic sets `auth.required: false` or relaxes the check in
   `policies.RequireAuthedAuthor`;
2. gift wraps are short-lived and not encrypted at the relay's level, so the size and
   tag rules are yours to set: `content.max` and `tags.required` above are inherited
   from the DM defaults unless you change them.

## What is still not configurable

The config covers the policy set, not the relay's structure — which is also why strict
mode does not try to make one file describe the whole process. Still Go or process
settings:

- storage backends and the expiration sweeper (`relay.StoreEvent`, `SetExpirationInterval`);
- `ServiceURL`, the HTTP server and the sweep interval — flags and `BKIND_*`, not the
  policy file (`examples/bkind/main.go`);
- the websocket frame limit and the store page size are *advertised* from the config
  (`nip11.max_message_length`, `nip11.max_limit`) but the values themselves are wiring;
- the shape validators themselves, `policies/kinds.go`;
- `RequireAuthedAuthor` is on or off; the rule "author equals the authed key" cannot be
  replaced by "author is any key" from a file. A relay that needs that writes its own
  `RejectEvent` policy instead.

## Tests

`policies/config_test.go` covers the defaults, strict mode (every field required, the
error naming the field, the round trip from `-print-config` back through
`WithStrictJSON`), the JSON merge (including
`kinds.allowed` pruning the classes and validators of the kinds it drops), unknown
fields, every `BKIND_*` override, the file-plus-environment precedence, the validation
errors, the reject-vs-narrow switch, NIP-11 derivation, and keeps
`bkind.example.json` byte-for-byte equal to `DefaultConfig().JSON()`.
`policies/config_strict_test.go` reflects over `Config` to keep the hand-written strict
schema from falling behind the struct.
`TestKindRulesGatesAgree` asserts that write, read, `COUNT` and live delivery answer the
same question the same way for every kind; `TestBKindKindsAreConfigurable` proves a kind
added by config is served end to end over a real websocket.
