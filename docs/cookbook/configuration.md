---
outline: deep
---

# Configuring a relay

The reference relay keeps its policy set in a document, `policies/default.json`,
embedded into the binary at build time: running `bkind` with no configuration at
all is running that file. Every per-kind setting lives in the kind's own rule
under `rules`, and a rule is complete — there is no top-level defaults block, no
inheritance and no patch-a-field layer. `-print-config` prints the effective
document.

```json
{
  "kinds": {"whitelist": [4, 5, 62]},
  "rules": {
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
      "p_tag": "hex",
      "required_tags": ["expiration", "client"],
      "tag_patterns": {},
      "tag_limits": {"max_tags": 16, "max_tag_name_chars": 64, "max_tag_value_chars": 256},
      "rate_limits": [
        {"scope": "npub", "limit": 30, "window": "1h"},
        {"scope": "ip", "limit": 60, "window": "1h"}
      ],
      "errors": {},
      "shape": true
    },
    "5":  {"description": "NIP-09 deletion requests", "...": "spelled out like kind 4, p_tag empty"},
    "62": {"description": "NIP-62 vanish requests", "...": "spelled out like kind 4, p_tag empty"}
  },
  "filters": {"reject_empty": true, "reject_search": true},
  "read_limits": [{"scope": "npub", "limit": 60, "window": "1h"}],
  "connection_limits": [{"scope": "ip", "limit": 120, "window": "1h"}],
  "count": {"reject": true},
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
| `bkind.minimal.example.json` | the smallest document that validates: a whitelist and the four NIP-11 ceilings, everything else taken from the embedded document |

`examples/bkind/invalid/` holds documents a relay must **refuse** at startup, one
fault each, so every failure message can be tried by hand:

| File | Fault |
|---|---|
| `unknown-field.json` | a misspelled section (`contnet`) |
| `bad-size.json` | `rules.4.max_event_size: "4KK"` |
| `bad-duration.json` | `rules.4.max_expiration: "P3W"` (weeks are not a span a relay can act on) |
| `bad-regex.json` | `tag_patterns.d: "["` |
| `unserved-rule.json` | a rule for kind 7 when the whitelist is `[4]` |
| `ephemeral-kind.json` | kind 20001 whitelisted without `allow_ephemeral` |
| `missing-shape-validator.json` | `shape: true` on 1059, which has none |
| `bad-scope.json` | a `connection_limits` entry keyed by `npub` |
| `unknown-error-key.json` | an `errors` key that is not a rejection |
| `gate-conflict.json` | `rules.4.read.allow: ["*", <pubkey>]` |
| `empty-whitelist.json` | a relay that would serve nothing |
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
3. `BKIND_CONFIG_JSON='{"rules":{"4":{"max_event_content_size":2048}}}'` — inline
   JSON, for containers and systemd `Environment=` lines that cannot mount a file.
4. `BKIND_KINDS=4,1059` — the whitelist, which also drops the rules of the
   kinds it leaves out.
5. Flags — `-kinds`, `-name`, `-description`.

The result is validated before the listener starts; an invalid configuration is
a startup error, never a relay that accepts events it cannot serve.

JSON is parsed strictly: an unknown field anywhere — top level, in a rule, in a
gate, in a rate limit — is an error, so `{"contnet": ...}` fails instead of
silently doing nothing. A section the document does not name keeps its previous
value, so a file only has to name what it changes — except a rule, which is
always replaced whole rather than patched (see below).

## Where the policy lives

The policy set is one document, and there are no policy values in Go to move:
`policies/default.json` is the reference relay's policy, a file you can read,
diff and copy, and the binary's only opinion is where to read it from.

Loading is layering of documents, and only that. A document replaces the sections
it names and the rules it names, and leaves everything else alone. Two
consequences are deliberate:

- **A rule is replaced, never patched.** `{"rules": {"4":
  {"max_event_content_size": 512}}}` gives kind 4 exactly one setting: no write
  gate, no tags, no limits. To change one setting of a kind, copy its whole rule
  and change the line.
- **`null` deletes.** `{"rules": {"4": null}}` removes kind 4's rule; the kind
  stays whitelisted and is served with the empty rule — nobody may publish it and
  nobody may read it. Silence means "leave it alone"; `null` means "make it say
  nothing".

Start a file from the binary's own output, so it cannot be missing a section:

```sh
bkind -print-config > /etc/bkind/bkind.json
BKIND_CONFIG=/etc/bkind/bkind.json
```

`-print-config` prints the **effective** configuration — embedded document, then
file, then environment, then flags — and exits without opening the store or the
listener. `examples/bkind/bkind.example.json` in the repository is exactly this
output for an unconfigured relay; a test compares it byte for byte, and feeding it
back reproduces the same configuration.

There is no strict mode and no "explicit vs partial" switch: a document is never
wrong for saying less, it just leaves more at zero. What *is* checked at startup
is that the whitelist is not empty and that the four NIP-11 ceilings are
positive. A relay that serves nothing or cannot describe itself is not a relay,
and zero is a refusal rather than a default.

## A rule is one kind's whole policy

A kind is served exactly when it is in `kinds.whitelist`, and its rule is what the
relay does with it. There is no inheritance and no layering inside a document:

> **`rules[<kind>]` is the whole answer**

Every setting a rule leaves out is the Go zero value, and every zero has a
meaning — never "somebody else's number":

| Zero | Means |
|---|---|
| `max_event_size`, `max_event_content_size`, `max_expiration`, `max_age_of_event`, `max_age_event_in_future` | no limit, no cap |
| `tag_limits` all zero | no tag-budget check |
| `tag_patterns`, `required_tags`, `rate_limits`, `errors` empty | none |
| `p_tag` `""` | no `p` rule |
| `require_auth`, `read.privileged`, `shape` `false` | off |
| **`write.allow` / `read.allow` empty** | **nobody** — `"*"` is the word for anyone |

The empty allow list is the one worth reading twice: `[]` means nobody, and only
the literal `"*"` means anyone. It is what the printed document shows, and `[]`
has to mean what it looks like.

A whitelisted kind with no rule at all is served with the empty rule: nobody may
publish it and nobody may read it. That is the safe reading of "the document said
nothing", and it is a state the relay starts in rather than a hole it falls into.

`shape` runs a validator registered for one specific kind (`policies/kinds.go`).
A document cannot carry code, only the switch for it, so the switch is per rule
and there is nowhere else for it to live.

`errors` is a per-kind table too, so one kind can reword its rejections without
touching another kind's.

Replacing the whitelist (in the file or with `BKIND_KINDS`/`-kinds`) drops the
rules of the kinds it leaves out, so narrowing what is served cannot fail on a
stale rule. A rule the *document itself* names for an unserved kind is a
different thing — a contradiction — and is a startup error.

### The per-kind settings

These are the names inside a rule, which is the only place a per-kind setting
appears.

| Field | Zero value | Meaning |
|---|---|---|
| `description` | `""` | operator documentation; not sent anywhere — a rule only, it has no default |
| `write.allow` | nobody | `"*"` for anyone, or a list of the only pubkeys that may publish this kind |
| `read.allow` | nobody | `"*"` for anyone, or a list of the only pubkeys that may query this kind |
| `read.privileged` | public | author-only (or author + `p` recipient) reads; see below |
| `require_auth` | off | NIP-42 on writes: the author must be the authenticated key |
| `max_event_size` | unlimited | limit on the serialized event — id, signature, tags and content — in bytes: `65536` or `"64KB"` |
| `max_event_content_size` | unlimited | limit on the content alone, in bytes: `4096` or `"4KB"`; this is NIP-11's `max_content_length` |
| `max_expiration` | no cap | how far a NIP-40 `expiration` tag may point |
| `max_age_of_event` | no limit | reject events created_at older than this |
| `max_age_event_in_future` | no limit | reject events created_at further ahead (clock-skew allowance) |
| `p_tag` | none | `"hex"`: exactly one `p` tag, a valid pubkey, not the author |
| `required_tags` | none | tags that must appear exactly once, non-empty; `"expiration"` here makes NIP-40 mandatory |
| `tag_patterns` | none | tag name → regular expression every value of that tag must match |
| `tag_limits` | none | `max_tags`, `max_tag_name_chars`, `max_tag_value_chars`. A `max_tags` smaller than the tags the rule demands (`required_tags` plus `p_tag`) is a startup error — it would reject every event |
| `rate_limits` | none | write limits for this kind: `{scope, limit, window}` |
| `shape` | off | run the registered structural validator for this kind (registry in `policies/kinds.go`); it is per rule, because a validator belongs to one kind |
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

Both are ordinary defaults: they sit in the top-level block, `-print-config`
shows them, and `0` turns either one off. The reference relay ships 4KB of
content and a 64KB event budget, the latter comfortably above the 12KB frame
limit so that the payload limits are the ones a client actually meets.

### Visibility: how `read` derives the classes

`read.privileged` plus `p_tag` decide who may see the events of the kind, and
every gate — the read policy, `COUNT`, live delivery and the NIP-11 document —
is derived from the same answer:

| `read.privileged` | `p_tag` | who may read |
|---|---|---|
| `true` | `"hex"` | the author **and** the `p` recipient; a filter must pin `authors` or `#p` to the authenticated key |
| `true` | — | the author only; a filter must pin `authors` |
| `false` | — | anyone within `read.allow` — the public kind |

`read.allow` narrows whichever class the kind is in: a list means only those
pubkeys may query it, and live delivery agrees with the read policy.

Reads are cross-kind (a filter can span kinds), so read rate limits are
relay-wide (`read_limits`), and connection limits have their own key
(`connection_limits`, per ip). Write limits — `rate_limits` — live on the kind
they bound, which is why the same field name appears at the top level: as the
default write limits.
Every limit is one token bucket: `limit` events per `window` per `scope`
(`npub` = the author's key, `ip` = the remote address); the bucket size is the
limit itself.

### One spelling

Every setting has exactly one name, and the document has exactly one shape:
the kinds section is `kinds`, per-kind overrides live under `rules` keyed by
kind number, and a rule names `max_event_size`, `max_event_content_size`,
`max_expiration`, `required_tags`,
`tag_patterns` and `read.privileged`. Strict mode checks the same names, so a
document that passes the lenient decoder is one strict mode can read too.

Earlier versions also accepted a summary dialect — `kind` for the section,
kind numbers at the top level, and the short field names. It is **gone**, and
the names are refused as unknown fields rather than silently renamed. Configs
written that way need one edit:

| Was | Now |
|---|---|
| `"kind": {...}` (top level) | `"kinds": {...}` |
| `"4": {...}` (a kind at the top level) | `"rules": {"4": {...}}` |
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
| `p_tag` | a `p` tag that is not one valid pubkey ≠ author | — |
| `tag_pattern` | a tag value that misses its pattern | `{tag}`, `{pattern}`, `{value}` |
| `max_event_size` | an event whose serialized form is too long | `{size}`, `{limit}` |
| `max_size` | oversized content | `{size}`, `{limit}` |
| `tag_limits` | too many tags, or a name/value too long | — |
| `rate_limited` | the write limits of the kind | — |
| `shape` | the structural validator | — |

`{detail}` is always available and carries the built-in message, so a template
can wrap the specific reason instead of replacing it with a generic one:
`"tag_limits": "{detail}"` keeps "invalid: too many tags (33, max 32)" while
`"missing_tag": "invalid: missing required tag: {tag}"` replaces that rejection
with the operator's wording.

```json
"errors": {
  "max_event_size": "blocked: event exceeds size limit ({size} > {limit})",
  "max_size": "blocked: content exceeds size limit ({size} > {limit})",
  "missing_tag": "invalid: missing required tag: {tag}"
}
```

Messages keep their NIP-01 prefixes (`auth-required:`, `blocked:`, `invalid:`,
`rate-limited:`, `restricted:`) — that is the client's contract.

## The rest of the document

| Section | Meaning |
|---|---|
| `kinds.whitelist` | what the relay serves at all |
| `kinds.allow_ephemeral` | let ephemeral kinds (20000–29999) through without listing each |
| `kinds.reject_unserved_filters` | reject a `REQ` for an unserved kind instead of narrowing it (default `true`) |
| `filters.reject_empty` | refuse a filter with no kind, id, author or tag |
| `filters.reject_search` | refuse `search` queries |
| `read_limits` | REQ limits, `npub` or `ip` — relay-wide, because one REQ spans kinds |
| `connection_limits` | connect limits, `ip` only |
| `count.reject` | refuse NIP-45 `COUNT` (metadata leak); `false` serves it and advertises NIP-45 |
| `nip11.*` | name, description and the advertised limits; `supported_nips` is derived, `extra_nips` appends |
| `negentropy` | NIP-77 set reconciliation (leaks which event ids exist) |

## NIP-11 is derived, not written

`supported_nips` is computed from the config, so it cannot claim a feature the
relay does not have: `11` always, `4` if Kind 4 is served, `9` for Kind 5, `62`
for Kind 62, `40` if any kind requires or caps an expiration, `42` if any kind
requires auth, `45` only when `COUNT` is answered. The limitation document's
`max_event_tags` and `max_content_length` are the maxima across the rules
(`max_content_length` comes from each rule's `max_event_content_size`), and
`max_message_length` stays the relay-wide frame limit — the per-kind event
budget has no NIP-11 field of its own, so it is not advertised, only enforced.
`auth_required` and `restricted_writes` follow the rules' `require_auth`. The
description, when left empty, is generated from the whitelist.

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
  "kinds": {"whitelist": [1]},
  "rules": {
    "1": {
      "description": "public notes",
      "write": {"allow": "*"},
      "read": {"allow": "*"},
      "max_event_content_size": "8KB",
      "rate_limits": [{"scope": "ip", "limit": 60, "window": "1h"}]
    }
  },
  "count": {"reject": false}
}
```

### Kind 4 plus NIP-17 gift wraps

`examples/bkind/bkind.nip17.example.json` spells one rule per kind. A new kind
copies nothing, so its rule says what it needs on its own:

```json
{
  "kinds": {"whitelist": [4, 5, 62, 1059]},
  "rules": {
    "1059": {
      "description": "gift wraps",
      "write": {"allow": "*"},
      "read": {"allow": "*", "privileged": true},
      "max_event_content_size": "64KB",
      "max_expiration": "P3D",
      "p_tag": "hex",
      "required_tags": ["expiration"]
    }
  }
}
```

A `1059` reaches its author and its `p` because its rule says `read.privileged`
and `p_tag: "hex"`, and a filter must pin one of them. A gift wrap is signed by a
throwaway key, so the rule leaves `require_auth` at its zero, which is off.

The checked-in example takes the other route — it spells `require_auth: true` —
and differs from the reference relay only in what a DM relay over both kinds
needs:

```sh
BKIND_CONFIG=examples/bkind/bkind.nip17.example.json go run ./examples/bkind
bkind -print-config   # with that BKIND_CONFIG set: shows the effective rules
```

### A rule, and what it leaves out

A rule is one kind's whole policy, so what it does not name is off:

```json
{
  "kinds": {"whitelist": [4, 1059]},
  "rules": {
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
}
```

That document replaces the whitelist and kind 4's rule. Kinds 5 and 62 lose their
rules with the whitelist, and kind 1059 is whitelisted with no rule at all — so
nobody may publish it and nobody may read it until a rule is added. In kind 4,
`require_auth` is off because the rule does not say it, and `tag_limits` is
unchecked for the same reason.
## What is still not configurable

The config covers the policy set, not the relay's structure. Still Go or
process settings:

- storage backends and the expiration sweeper (`relay.StoreEvent`,
  `SetExpirationInterval`);
- `ServiceURL`, the HTTP server and the sweep interval — flags and `BKIND_*`,
  not the policy file (`examples/bkind/main.go`);
- the shape validators themselves, `policies/kinds.go` — a rule turns its
  kind's validator on or off, but the checks are code, because a JSON document
  cannot carry code. Naming `shape: true` for a kind with no registered
  validator is a startup error;
- `require_auth` is on or off per kind; the rule "author equals the authenticated
  key" cannot be replaced by "author is any key" from a file. A relay that
  needs that writes its own `RejectEvent` policy instead.

## Tests

`policies/config_test.go` covers the document layer (`TestConfigDocumentReplaces
WhatItNames`: a named section and a named rule replace what came before, unnamed
ones stay, and a whitelist change prunes), that rules do not inherit
(`TestRulesDoNotInherit`: two kinds with unrelated policies, both honoured by the
relay), the empty rule (`TestUnruledKindIsTheEmptyRule`: an unruled kind lets
nobody publish or read, and giving it a rule opens it), every duration and size
notation, the one-spelling rule (every old summary name refused as an unknown
field), the validation errors, allow lists on both sides (including `[]` meaning
nobody), the age window, tag patterns, error templates, per-kind differences (one
kind demands an expiration, another does not), the two size limits
(`TestEventSizeAndContentSizeAreSeparate`: a fat tag under the content limit is
refused for the event size, a long payload for the content size), NIP-11
derivation, the round trip from `-print-config` back through `WithJSON`, and byte
equality between `bkind.example.json` and the embedded `policies/default.json`.
`TestKindRulesGatesAgree` asserts that write, read, `COUNT` and live delivery
answer the same question the same way for every kind;
`TestBKindKindsAreConfigurable` proves a kind added by config is served end to end
over a real websocket.