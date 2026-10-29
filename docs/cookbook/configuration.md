---
outline: deep
---

# Configuring a relay

The reference relay keeps its policy set in a document, `policies/default.json`,
embedded into the binary at build time: running `bkind` with no configuration at
all is running that file. The document is **one rule per kind and nothing else** —
the top-level keys are kind numbers. Every per-kind setting lives in the kind's
own rule, and a rule is complete: there is no defaults block, no inheritance and
no patch-a-field layer. `-print-config` prints the effective document.

```json
{
  "4": {
    "description": "NIP-04 direct messages",
    "write": {"allow": "*"},
    "read": {"allow": "*", "privileged": true},
    "require_auth": true,
    "max_event_size": 65536,
    "max_event_content_size": 4096,
    "max_expiration": "75h",
    "max_age_of_event": "0s",
    "max_age_event_in_future": "0s",
    "required_tags": ["p", "expiration", "client"],
    "tag_patterns": {"p": "^[0-9a-f]{64}$"},
    "tag_limits": {"max_tags": 16, "max_tag_name_chars": 64, "max_tag_value_chars": 256},
    "rate_limits": [
      {"scope": "npub", "limit": 30, "window": "1h"},
      {"scope": "ip", "limit": 60, "window": "1h"}
    ],
    "errors": {}
  },
  "5":  {"description": "NIP-09 deletion requests", "...": "spelled out like kind 4, no p tag demanded"},
  "62": {"description": "NIP-62 vanish requests", "...": "spelled out like kind 4, no p tag demanded"}
}
```

The two utility kinds are abbreviated above; the real file spells them out. That
is the whole set, and it is exactly what `bkind -print-config` prints for an
unconfigured relay (`examples/bkind/bkind.example.json`, compared byte for byte
by a test).

The example documents that ship with the relay, each loaded, validated and
rendered by a test:

| File | Shape |
|---|---|
| `bkind.example.json` | the reference DM relay; the output of `-print-config` |
| `bkind.nip17.example.json` | kinds 4 + 1059, one rule each, per-kind age windows |
| `bkind.dm-verbose.example.json` | the same kinds spelled in full, with their own write limits and rejection wording |
| `bkind.appdata.example.json` | addressable backup kinds (5, 37801, 37802) told apart by a `d` pattern |
| `bkind.appdata-verbose.example.json` | the same, in full, with a one-tag budget per kind |
| `bkind.minimal.example.json` | the smallest document that validates: one kind, one description |

`examples/bkind/invalid/` holds documents a relay must **refuse** at startup, one
fault each, so every failure message can be tried by hand:

| File | Fault |
|---|---|
| `unknown-field.json` | a misspelled setting inside a rule (`contnet`) |
| `not-a-kind-number.json` | a top-level key that is not a kind number (`dm`) |
| `bad-size.json` | `4.max_event_size: "4KK"` |
| `bad-duration.json` | `4.max_expiration: "P3W"` (weeks are not a span a relay can act on) |
| `bad-regex.json` | `tag_patterns.d: "["` |
| `empty-document.json` | `{}` — a relay that would serve nothing |
| `gate-conflict.json` | `4.read.allow: ["*", <pubkey>]` |
| `tag-budget-impossible.json` | `max_tags: 2` while `p`, `expiration` and `client` are mandatory |

```sh
BKIND_CONFIG=examples/bkind/invalid/tag-budget-impossible.json bkind -print-config
# invalid configuration: rules[4]: tag_limits.max_tags is 2 but
#   "expiration", "client" and "p" must be present, so no event could be accepted
```

`TestInvalidExamplesFail` runs every file there, insists on the reason rather
than just the failure, and fails if a fixture has no expectation listed.

## Precedence

Each layer overrides the one before it:

1. `policies/default.json` — the document embedded in the binary, so a relay with
   no configuration at all still has one.
2. `BKIND_CONFIG=/etc/bkind/bkind.json` — a JSON file.
3. `BKIND_CONFIG_JSON='{"4":{"max_event_content_size":2048}}'` — inline JSON, for
   containers and systemd `Environment=` lines that cannot mount a file.
4. `BKIND_KINDS=4,1059` — which kinds are served, which also drops the rules of
   the kinds it leaves out.
5. Flags — `-kinds`, `-name`, `-description`.

The result is validated before the listener starts; an invalid configuration is
a startup error, never a relay that accepts events it cannot serve.

JSON is parsed strictly: an unknown field anywhere — in a rule, in a gate, in a
rate limit — is an error, so `{"4": {"contnet": ...}}` fails instead of silently
doing nothing. A top-level key that is not a kind number is an error too, so a
document cannot carry sections besides kinds.

## The document is the served set

The keys are the relay: a kind is served exactly when the document has a rule for
it, and a rule is one kind's whole policy.

- **A document replaces the whole kind set.** A layer does not patch the one
  before it kind by kind: `BKIND_CONFIG` naming kinds 4 and 1059 serves those two
  and nothing else, so a file is self-contained and readable on its own.
- **A rule is replaced, never patched.** `{"4": {"max_event_content_size": 512}}`
  gives kind 4 exactly one setting: no write gate, no tags, no limits. To change
  one setting of a kind, copy its whole rule and change the line.
- **Nothing is deleted.** A kind without a rule is simply not served, so `null`
  is refused: there is no rule to delete. Drop the kind from the document (or use
  `BKIND_KINDS`) instead.

Start a file from the binary's own output, so it cannot be missing a kind you
meant to keep:

```sh
bkind -print-config > /etc/bkind/bkind.json
BKIND_CONFIG=/etc/bkind/bkind.json
```

`-print-config` prints the **effective** document — embedded document, then file,
then environment, then flags — and exits without opening the store or the
listener. `examples/bkind/bkind.example.json` is exactly this output for an
unconfigured relay; a test compares it byte for byte, and feeding it back
reproduces the same configuration.

What *is* checked at startup: the document is not empty, kind 0 is not served,
every rule has a description, and the relay-wide settings are positive (a zero
frame limit or zero subscription budget is a refusal, not a default).

## Where the relay-wide settings live

Filters, read and connection limits, `COUNT`, the NIP-11 document and NIP-77
negentropy are not properties of one kind, so they are not in the document. They
live in `policies.Settings`, defaulted by `policies.DefaultSettings()` and carried
on `policies.Config`:

| Setting | Default |
|---|---|
| `Filters.RejectEmpty`, `Filters.RejectSearch` | `true`, `true` |
| `ReadLimits` | 60/1h and 400/1d per `npub`, 120/1h and 800/1d per `ip` |
| `ConnectionLimits` | 120/1h per `ip` |
| `Count.Reject` | `true` (NIP-45 refused) |
| `NIP11.*` | name `B Kind`, 12KB frames, 10 subscriptions, 4 filters, 500 limit |
| `Negentropy` | `false` |
| `RejectUnservedFilters` | `true` |

The command line and the environment reach the ones worth a flag: `-name` /
`BKIND_NAME`, `-description` / `BKIND_DESCRIPTION`, and `-kinds` / `BKIND_KINDS`
for the served set. The rest are set in code — the reference wiring passes the
max frame length and the store page size from `Settings.NIP11` — because they are
facts about the deployment, not about a kind.

## A rule is one kind's whole policy

There is no inheritance and no layering inside a document:

> **`rules` are the whole answer**

Every setting a rule leaves out is its zero value, and every zero means
**inactive** — never "somebody else's number":

| Zero | Means |
|---|---|
| `max_event_size`, `max_event_content_size`, `max_expiration`, `max_age_of_event`, `max_age_event_in_future` | no limit, no cap |
| `tag_limits` all zero | no tag-budget check |
| `tag_patterns`, `required_tags`, `rate_limits` empty | none |
| `errors` empty | the built-in wording |
| `require_auth`, `read.privileged` `false` | off |
| **`write.allow` / `read.allow` empty** | **nobody** — `"*"` is the word for anyone |

The empty allow list is the one worth reading twice: `[]` means nobody, and only
the literal `"*"` means anyone. It is what the printed document shows, and `[]`
has to mean what it looks like.

Every rule needs a description: a kind that says nothing about itself is not a
kind this relay knows how to serve.

The structural validator of a kind is not a setting at all. It runs whenever one
is registered for that kind (`policies/kinds.go`), so a relay cannot serve a kind
it does not know how to check, and a document cannot switch the check off. The
validators are Go functions because a document cannot carry code; the cost is
that a kind with no registered validator is served with no structural check.

`errors` is a per-kind table too, so one kind can reword its rejections without
touching another kind's.

### The per-kind settings

These are the names inside a rule, which is the only place a per-kind setting
appears.

| Field | Zero value | Meaning |
|---|---|---|
| `description` | **required** | one sentence saying what the kind is; not sent anywhere, but a rule without it is a startup error |
| `write.allow` | nobody | `"*"` for anyone, or a list of the only pubkeys that may publish this kind |
| `read.allow` | nobody | `"*"` for anyone, or a list of the only pubkeys that may query this kind |
| `read.privileged` | public | author-only (or author + `p` recipient) reads; see below |
| `require_auth` | off | NIP-42 on writes: the author must be the authenticated key |
| `max_event_size` | unlimited | limit on the serialized event — id, signature, tags and content — in bytes: `65536` or `"64KB"` |
| `max_event_content_size` | unlimited | limit on the content alone, in bytes: `4096` or `"4KB"`; this is NIP-11's `max_content_length` |
| `max_expiration` | no cap | how far a NIP-40 `expiration` tag may point |
| `max_age_of_event` | no limit | reject events created_at older than this |
| `max_age_event_in_future` | no limit | reject events created_at further ahead (clock-skew allowance) |
| `required_tags` | none | tags that must appear exactly once, non-empty; `"expiration"` here makes NIP-40 mandatory, and `"p"` here is what makes a privileged kind recipient-visible |
| `tag_patterns` | none | tag name → regular expression every value of that tag must match; `{"p": "^[0-9a-f]{64}$"}` is how a `p` tag is held to a pubkey |
| `tag_limits` | none | `max_tags`, `max_tag_name_chars`, `max_tag_value_chars`. A `max_tags` smaller than the tags the rule demands (`required_tags`) is a startup error — it would reject every event |
| `rate_limits` | none | write limits for this kind: `{scope, limit, window}` |
| `errors` | built-ins | rejection message templates, see below |

Durations accept three notations, everywhere: a bare number is seconds
(`3600`), a Go duration is `"75h"`, `"1h30m"`, a day count is `"2d"`, and
ISO-8601 is `"P3D"`, `"PT75H"`. Sizes are bytes: `4096` or `"4KB"` (1024-based).
A bad pattern, duration or size is a startup error naming the field.

`max_event_content_size` and `max_event_size` bound two different things, and
both are checked: the first is the payload a client chooses (`content`), the
second is the event as it goes on the wire — id, signature and every tag
included. A client can stay well inside the content limit and still send a fat
tag list, so a relay that cares about storage sets both. `max_event_size`
counts the event object, not the `["EVENT", …]` envelope; the frame limit is
`nip11.max_message_length`, which is relay-wide.

The reference relay ships 4KB of content and a 64KB event budget, the latter
comfortably above the 12KB frame limit so that the payload limits are the ones a
client actually meets.

### Visibility: how `read` derives the classes

`read.privileged` decides *whether* a kind is private, and `required_tags`
decides *who* may see it: an event that must carry a `p` tag has a recipient, and
that is the whole answer. Every gate — the read policy, `COUNT`, live delivery and
the NIP-11 document — is derived from the same answer:

| `read.privileged` | requires a `p` tag | who may read |
|---|---|---|
| `true` | yes | the author **and** the `p` recipient; a filter must pin `authors` or `#p` to the authenticated key |
| `true` | no | the author only; a filter must pin `authors` |
| `false` | — | anyone within `read.allow` — the public kind |

There is no separate switch for "recipient-visible": addressing an event *is*
requiring its `p` tag, and a rule that demands one (with a pattern such as
`{"p": "^[0-9a-f]{64}$"}` so the value is a pubkey) gets the recipient class for
free. The "not your own pubkey" part of the DM rule is the Kind 4 structural
validator's job, since only a validator can compare a tag value to the author.

`read.allow` narrows whichever class the kind is in: a list means only those
pubkeys may query it, and live delivery agrees with the read policy.

Reads are cross-kind (a filter can span kinds), so read rate limits are
relay-wide (`Settings.ReadLimits`), and connection limits have their own key
(`Settings.ConnectionLimits`, per ip). Write limits — `rate_limits` — live on the
kind they bound, because that is the only place they can be.
Every limit is one token bucket: `limit` events per `window` per `scope`
(`npub` = the author's key, `ip` = the remote address); the bucket size is the
limit itself.

### One spelling

Every setting has exactly one name, and the document has exactly one shape: the
top level is kind numbers, and a rule names `max_event_size`,
`max_event_content_size`, `max_expiration`, `required_tags`, `tag_patterns` and
`read.privileged`.

Earlier versions wrapped the kinds in a `kinds`/`rules` pair, and before that put
kind numbers beside a `kind` section with short field names. Both are **gone**,
and the names are refused rather than silently renamed. Configs written that way
need one edit:

| Was | Now |
|---|---|
| `{"kinds": {"whitelist": [4]}, "rules": {"4": {...}}}` | `{"4": {...}}` |
| `"kind": {...}` / `"kinds": {...}` (a section) | no sections: the top level is kinds |
| `"filters"`, `"read_limits"`, `"connection_limits"`, `"count"`, `"nip11"`, `"negentropy"` | `policies.Settings` (flags / Go defaults) |
| `size_limit` | `max_event_size` / `max_event_content_size` |
| `max_expiry_duration` | `max_expiration` |
| `must_have_tags` | `required_tags` |
| `identifier_regex` | `tag_patterns.d` |
| `privileged` | `read.privileged` |

### Rejection messages

`errors` overrides the wording of the rejections, with placeholders. The keys
are stable; the built-in wording may change between versions, the keys do not.

| Key | Rejects | Placeholders |
|---|---|---|
| `write_denied` | a key outside `write.allow` | — |
| `auth_required` | unauthenticated or wrong-key publish | — |
| `too_old` | older than `max_age_of_event` | `{limit}` |
| `in_future` | further ahead than `max_age_event_in_future` | `{limit}` |
| `expiration` | a bad, past or too-far NIP-40 tag | `{limit}` |
| `missing_tag` | a missing or duplicated required tag | `{tag}` |
| `tag_pattern` | a tag value that misses its pattern | `{tag}`, `{pattern}`, `{value}` |
| `max_event_size` | an event whose serialized form is too long | `{size}`, `{limit}` |
| `max_event_content_size` | oversized content | `{size}`, `{limit}` |
| `tag_limits` | too many tags, or a name/value too long | — |
| `rate_limited` | the write limits of the kind | — |

`{detail}` is always available and carries the built-in message, so a template
can wrap the specific reason instead of replacing it with a generic one:
`"tag_limits": "{detail}"` keeps "invalid: too many tags (33, max 32)" while
`"missing_tag": "invalid: missing required tag: {tag}"` replaces that rejection
with the operator's wording.

```json
"errors": {
  "max_event_size": "blocked: event exceeds size limit ({size} > {limit})",
  "max_event_content_size": "blocked: content exceeds size limit ({size} > {limit})",
  "missing_tag": "invalid: missing required tag: {tag}"
}
```

Messages keep their NIP-01 prefixes (`auth-required:`, `blocked:`, `invalid:`,
`rate-limited:`, `restricted:`) — that is the client's contract.

## NIP-11 is derived, not written

`supported_nips` is computed from the document, so it cannot claim a feature the
relay does not have: `11` always, `4` if Kind 4 is served, `9` for Kind 5, `62`
for Kind 62, `40` if any kind requires or caps an expiration, `42` if any kind
requires auth, `45` only when `COUNT` is answered. The limitation document's
`max_event_tags` and `max_content_length` are the maxima across the rules
(`max_content_length` comes from each rule's `max_event_content_size`), and
`max_message_length` stays the relay-wide frame limit — the per-kind event
budget has no NIP-11 field of its own, so it is not advertised, only enforced.
`auth_required` and `restricted_writes` follow the rules' `require_auth`. The
description, when left empty, is generated from the served kinds.

## Examples

### The reference DM relay

The default. Nothing to write:

```sh
go run ./examples/bkind
```

### A public note relay

A public kind is a rule with nothing restrictive in it, spelled out:

```json
{
  "1": {
    "description": "public notes",
    "write": {"allow": "*"},
    "read": {"allow": "*"},
    "max_event_content_size": "8KB",
    "rate_limits": [{"scope": "ip", "limit": 60, "window": "1h"}]
  }
}
```

### Kind 4 plus NIP-17 gift wraps

`examples/bkind/bkind.nip17.example.json` spells one rule per kind. A new kind
copies nothing, so its rule says what it needs on its own:

```json
{
  "4":    {"description": "NIP-04 direct messages", "...": "as in the reference relay"},
  "1059": {
    "description": "gift wraps",
    "write": {"allow": "*"},
    "read": {"allow": "*", "privileged": true},
    "max_event_content_size": "64KB",
    "max_expiration": "P3D",
    "required_tags": ["p", "expiration"],
    "tag_patterns": {"p": "^[0-9a-f]{64}$"}
  }
}
```

A `1059` reaches its author and its `p` because its rule is privileged *and*
demands a `p` tag, and a filter must pin one of them. A gift wrap is signed by a
throwaway key, so the rule leaves `require_auth` at its zero, which is off.

### A rule, and what it leaves out

```json
{
  "4": {
    "description": "Nostr DM events",
    "write": {"allow": "*"},
    "read": {"allow": "*", "privileged": true},
    "max_event_content_size": 4096,
    "max_age_of_event": 3600,
    "max_age_event_in_future": 60,
    "max_expiration": "P3D",
    "required_tags": ["p", "expiration", "client"]
  }
}
```

That document serves kind 4 and nothing else: kinds 5 and 62 are gone with the
old document, and 1059 is not mentioned, so it is not served. In kind 4,
`require_auth` is off because the rule does not say it, and `tag_limits` is
unchecked for the same reason — a setting a rule omits is inactive.

## What is still not configurable

The document covers the per-kind policy set, not the relay's structure. Still Go
or process settings:

- the relay-wide settings above (`policies.Settings`) are Go defaults plus flags,
  not document fields;
- storage backends and the expiration sweeper (`relay.StoreEvent`,
  `SetExpirationInterval`);
- `ServiceURL`, the HTTP server and the sweep interval — flags and `BKIND_*`,
  not the policy file (`examples/bkind/main.go`);
- the structural validators themselves, `policies/kinds.go` — they are code,
  because a JSON document cannot carry code, and they always run for the kinds
  that have one. Serving a kind with no registered validator is possible, and
  means serving it without a structural check;
- `require_auth` is on or off per kind; the rule "author equals the authenticated
  key" cannot be replaced by "author is any key" from a file. A relay that
  needs that writes its own `RejectEvent` policy instead.

## Tests

`policies/config_test.go` covers the document layer
(`TestConfigDocumentReplacesWhatItNames`: a document is the whole kind set, and a
rule is a whole rule), that
rules do not inherit (`TestRulesDoNotInherit`: two kinds with unrelated policies,
both honoured by the relay), the description requirement, that the structural
validator is not a setting (`TestShapeIsNotASetting`: `shape` is an unknown field
and the registered validator runs anyway), every duration and size notation, the
one-spelling rule (old names refused, top-level sections refused), the validation
errors, allow lists on both sides (including `[]` meaning nobody), the age
window, tag patterns, error templates, per-kind differences (one kind demands an
expiration, another does not), the two size limits
(`TestEventSizeAndContentSizeAreSeparate`: a fat tag under the content limit is
refused for the event size, a long payload for the content size), NIP-11
derivation, the round trip from `-print-config` back through `WithJSON`, and byte
equality between `bkind.example.json` and the embedded `policies/default.json`.
`TestKindRulesGatesAgree` asserts that write, read, `COUNT` and live delivery
answer the same question the same way for every kind;
`TestBKindKindsAreConfigurable` proves a kind added by config is served end to end
over a real websocket, and `TestEphemeralKindNeedsOnlyARule` that a rule is the
only permission an ephemeral kind needs.
