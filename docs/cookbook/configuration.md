---
outline: deep
---

# Configuring a relay

The reference relay in `examples/bkind` keeps its policy set in
`policies.Config` (`policies/config.go`). The per-kind settings — gates, limits,
tag rules, write rate limits — appear twice in the document: once at the **top
level**, where they are the defaults every kind starts from, and once inside
**`rules`**, where a kind overrides what it needs. A different relay shape is a
config file, not a patch.

```json
{
  "kinds": {"whitelist": [4, 5, 62]},

  "write": {"allow": "*"},
  "read": {"allow": "*", "privileged": true},
  "require_auth": true,
  "max_size": "4KB",
  "max_expiration": "75h",
  "required_tags": ["expiration", "client"],
  "p_tag": "hex",
  "tag_limits": {"max_tags": 16, "max_tag_name_chars": 64, "max_tag_value_chars": 256},
  "rate_limits": [
    {"scope": "npub", "limit": 30, "window": "1h"},
    {"scope": "ip", "limit": 60, "window": "1h"}
  ],

  "rules": {
    "4":    {"description": "NIP-04 direct messages", "shape": true},
    "5":    {"description": "NIP-09 deletion requests", "p_tag": "", "shape": true},
    "62":   {"description": "NIP-62 vanish requests", "p_tag": "", "shape": true}
  },

  "filters": {"reject_empty": true, "reject_search": true},
  "read_limits": [{"scope": "npub", "limit": 60, "window": "1h"}],
  "connection_limits": [{"scope": "ip", "limit": 120, "window": "1h"}],
  "count": {"reject": true},
  "nip11": {"name": "B Kind"},
  "negentropy": false
}
```

That is the whole set, and it is exactly what `bkind -print-config` prints for
the default configuration (`examples/bkind/bkind.example.json`, compared byte for
byte by a test).

Three example documents ship with the relay, and a test loads, validates and
renders every one of them:

| File | Shape |
|---|---|
| `bkind.example.json` | the reference DM relay; the output of `-print-config` |
| `bkind.nip17.example.json` | kinds 4 + 1059 in the summary spelling, per-kind age windows |
| `bkind.dm-verbose.example.json` | the same kinds spelled in full, with their own write limits and rejection wording |
| `bkind.appdata.example.json` | addressable backup kinds (5, 37801, 37802) told apart by a `d` pattern |
| `bkind.appdata-verbose.example.json` | the same, in full, with a one-tag budget per kind |

`examples/bkind/invalid/` holds documents a relay must **refuse** at startup, one
fault each, so every failure message can be tried by hand:

| File | Fault |
|---|---|
| `unknown-field.json` | a misspelled section (`contnet`) |
| `bad-size.json` | `max_size: "4KK"` |
| `bad-duration.json` | `max_expiration: "P3W"` (weeks are not a span a relay can act on) |
| `bad-regex.json` | `tag_patterns.d: "["` |
| `alias-conflict.json` | `size_limit` and `max_size` in one rule |
| `unserved-rule.json` | a rule for kind 7 when the whitelist is `[4]` |
| `ephemeral-kind.json` | kind 20001 whitelisted without `allow_ephemeral` |
| `missing-shape-validator.json` | `shape: true` on 1059, which has none |
| `duplicate-kind.json` | kind 4 at the top level *and* under `rules` |
| `bad-scope.json` | a `connection_limits` entry keyed by `npub` |
| `unknown-error-key.json` | an `errors` key that is not a rejection |
| `gate-conflict.json` | `read.allow: ["*", <pubkey>]` |
| `empty-whitelist.json` | a relay that would serve nothing |
| `tag-budget-impossible.json` | `max_tags: 1` while `p`, `expiration` and `client` are mandatory |

```sh
BKIND_CONFIG=examples/bkind/invalid/tag-budget-impossible.json bkind -print-config
# invalid configuration: rules[4] resolved over the defaults: tag_limits.max_tags
#   is 1 but "expiration", "client" and "p" must be present, so no event could be accepted
```

`TestInvalidExamplesFail` runs every file there, insists on the reason rather
than just the failure, and fails if a fixture has no expectation listed.

`examples/bkind/strict-incomplete.example.json` is the mirror image: one setting,
perfectly valid as a patch, refused only because strict mode wants an explicit
configuration. `TestStrictModeRefusesAPatch` covers both directions, including
freezing the resolved document and feeding that back.

## Precedence

Each layer overrides the one before it:

1. `policies.DefaultConfig()` — the Kind-4 DM relay.
2. `BKIND_CONFIG=/etc/bkind/bkind.json` — a JSON file.
3. `BKIND_CONFIG_JSON='{"rules":{"4":{"max_size":2048}}}'` — inline JSON, for
   containers and systemd `Environment=` lines that cannot mount a file.
4. `BKIND_KINDS=4,1059` — the whitelist, which also drops the rules of the
   kinds it leaves out.
5. Flags — `-kinds`, `-name`, `-description`.

The result is validated before the listener starts; an invalid configuration is
a startup error, never a relay that accepts events it cannot serve.

JSON is parsed strictly: an unknown field anywhere — top level, in a rule, in a
gate, in a rate limit — is an error, so `{"contnet": ...}` fails instead of
silently doing nothing. Absent fields keep their previous value, which means a
file only has to name what it changes.

## Partial or explicit?

Two ways to use the file, and the difference is a switch, not a rewrite:

- **Partial** (the default). The file is a patch on the reference config.
  `{"max_size":"512B"}` changes one default, for every kind that does not
  override it; `{"rules":{"4":{"max_size":512}}}` changes one kind only.
- **Explicit** (`BKIND_CONFIG_STRICT=true`). Every top-level field must be
  present — the defaults, the sections, and the entries of the rate-limit lists.
  Absent fields are a startup error naming the field, and there is no "inherits
  whatever the binary happened to default to". A rule body stays sparse: that is
  what "everything else is inherited" means, and the defaults are now in the same
  file, in front of you.

Start an explicit file from the relay's own output, so it cannot be missing a
field:

```sh
bkind -print-config > /etc/bkind/bkind.json
BKIND_CONFIG=/etc/bkind/bkind.json
BKIND_CONFIG_STRICT=true
```

`-print-config` prints the **effective** configuration — defaults, then file,
then environment, then flags — and exits without opening the store or the
listener. `examples/bkind/bkind.example.json` in the repository is exactly this
output for the default configuration; a test compares it byte for byte, and
feeding it back through strict mode reproduces the defaults exactly.

Strict mode does not freeze the process: `BKIND_KINDS` still applies on top of a
strict file, because the switch is about the file being complete. Process
settings (`-addr`, `-url`, `-db`, `-sweep-interval`) are not policy and are not
covered.

## The defaults, and what a rule adds

A kind is served exactly when it is in `kinds.whitelist`. What the relay does
with it is resolved in one direction only:

> **top-level defaults ← the kind's rule**

Every setting a rule names replaces the default; every setting it does not name
keeps the default. So:

- **A kind with a rule** overrides what it needs and inherits the rest.
- **A kind in the whitelist without a rule** gets exactly the defaults. That is
  what makes a new kind cheap to add: whitelist it, and it is already governed.
- **A rule for a kind outside the whitelist** is a startup error, not a silent
  skip: the document contradicts itself.

The one thing a rule cannot inherit is `shape`. It runs a validator registered
for one specific kind (`policies/kinds.go`), so it is rule-local by nature: a
newly whitelisted kind would inherit a flag it could never honour. Set `"shape":
true` on the kinds that have one.

`errors` is the other half-inherited setting: the tables merge key by key, so a
kind can reword one rejection without repeating the rest.

An **explicit zero is a choice**: `"max_size": 0` in a rule means "unlimited"
even when the default is `4KB`, and `"required_tags": []` means "none" even when
the default demands tags. In a document, "I named it" and "I did not" are
different things; a `KindRule` built in Go is the exception, because Go has no
way to leave a field unset — a struct literal is fully explicit.

Replacing the whitelist (in the file or with `BKIND_KINDS`/`-kinds`) prunes the
rules of the kinds it drops, so narrowing what is served cannot leave a stale
rule behind.

### The per-kind settings

These names are the same at the top level (as defaults) and inside a rule (as
overrides).

| Field | Zero value | Meaning |
|---|---|---|
| `description` | `""` | operator documentation; not sent anywhere — a rule only, it has no default |
| `write.allow` | anyone | `"*"` or a list of the only pubkeys that may publish this kind |
| `read.allow` | anyone | `"*"` or a list of the only pubkeys that may query this kind |
| `read.privileged` | public | author-only (or author + `p` recipient) reads; see below |
| `require_auth` | off | NIP-42 on writes: the author must be the authenticated key |
| `max_size` | unlimited | content limit in bytes: `4096` or `"4KB"` |
| `max_expiration` | no cap | how far a NIP-40 `expiration` tag may point |
| `max_age_of_event` | no limit | reject events created_at older than this |
| `max_age_event_in_future` | no limit | reject events created_at further ahead (clock-skew allowance) |
| `p_tag` | none | `"hex"`: exactly one `p` tag, a valid pubkey, not the author |
| `required_tags` | none | tags that must appear exactly once, non-empty; `"expiration"` here makes NIP-40 mandatory |
| `tag_patterns` | none | tag name → regular expression every value of that tag must match |
| `tag_limits` | none | `max_tags`, `max_tag_name_chars`, `max_tag_value_chars`. A `max_tags` smaller than the tags the rule demands (`required_tags` plus `p_tag`) is a startup error — it would reject every event |
| `rate_limits` | none | write limits for this kind: `{scope, limit, window}` |
| `shape` | off | run the registered structural validator for this kind (registry in `policies/kinds.go`); a rule only, never inherited |
| `errors` | built-ins | rejection message templates, see below |

Durations accept three notations, everywhere: a bare number is seconds
(`3600`), a Go duration is `"75h"`, `"1h30m"`, a day count is `"2d"`, and
ISO-8601 is `"P3D"`, `"PT75H"`. Sizes are bytes: `4096` or `"4KB"` (1024-based).
A bad pattern, duration or size is a startup error naming the field.

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

### The two spellings

The dialect accepts a summary spelling alongside the full one — the same
config, written the way a policy table is:

| Alias | Canonical |
|---|---|
| `kind` (top level) | `kinds` |
| kind keys at the top level (`{"4": {...}}`) | entries of `rules` |
| `size_limit` | `max_size` |
| `max_expiry_duration` | `max_expiration` |
| `must_have_tags` | `required_tags` |
| `identifier_regex` | `tag_patterns.d` |
| `privileged` | `read.privileged` |

Both spellings can be mixed; an alias and its canonical name in the same rule
body is an error ("they are the same setting"). Strict mode demands the
canonical names.

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
  "max_size": "blocked: event exceeds size limit ({size} > {limit})",
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
`max_event_tags` and `max_content_length` are the maxima across the rules,
`auth_required` and `restricted_writes` follow the rules' `require_auth`. The
description, when left empty, is generated from the whitelist.

## Examples

### The reference DM relay

The default. Nothing to write:

```sh
go run ./examples/bkind
```

### A public note relay

Defaults that suit a public kind, and no rules at all — the kind inherits them:

```json
{
  "kinds": {"whitelist": [1]},
  "read": {"allow": "*"},
  "require_auth": false,
  "max_size": "8KB",
  "max_expiration": 0,
  "p_tag": "",
  "required_tags": [],
  "rate_limits": [{"scope": "ip", "limit": 60, "window": "1h"}],
  "count": {"reject": false}
}
```

### Kind 4 plus NIP-17 gift wraps

`examples/bkind/bkind.nip17.example.json` is this shape in full, in the summary
spelling. The DM defaults stay, and the new kind names only what differs:

```json
{
  "kinds": {"whitelist": [4, 5, 62, 1059]},
  "rules": {
    "1059": {"description": "gift wraps", "max_size": "64KB", "max_expiration": "P3D", "require_auth": false}
  }
}
```

A `1059` reaches its author and its `p` (inherited: `read.privileged` and
`p_tag: "hex"`), and a filter must pin one of them. A gift wrap is signed by a
throwaway key, so `require_auth: false` turns off the inherited NIP-42 check for
that kind alone.

The checked-in example takes the other route — it keeps the inherited
`require_auth` — and differs from the defaults only in what a DM relay over both
kinds needs:

```sh
BKIND_CONFIG=examples/bkind/bkind.nip17.example.json go run ./examples/bkind
bkind -print-config   # with that BKIND_CONFIG set: shows the resolved rules
```

### The summary spelling

The same kind rule as a policy table:

```json
{
  "kind": {"whitelist": [4, 1059]},
  "rules": {
    "4": {
      "description": "Nostr DM events",
      "privileged": true,
      "size_limit": 4096,
      "max_age_of_event": 3600,
      "max_age_event_in_future": 60,
      "max_expiry_duration": "P3D",
      "must_have_tags": ["p", "expiration", "client"]
    }
  }
}
```

The top-level fields were left out of that document, so this is a patch: they
keep the reference relay's values, and kind 1059 — whitelisted with no rule at
all — is served with them too (authenticated writes, privileged reads).

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

`policies/config_test.go` covers the defaults, the inheritance (`TestDefaultsApply
ToSparseRules`: an unnamed setting comes from the defaults, a named one wins, an
explicit zero turns off, and the relay honours the result), `shape` never being
inherited, the per-kind merge (an existing rule patched, pruning on whitelist
change), both spellings and their conflicts, every duration and size notation,
strict mode (every top-level field required, the error naming the field, sparse
rule bodies accepted, misspellings inside them refused, and the round trip from
`-print-config` back through `WithStrictJSON`), the validation errors,
allow lists on both sides, the age window, tag patterns, error templates,
per-kind differences (one kind demands an expiration, another does not), NIP-11
derivation, and keeps `bkind.example.json` byte-for-byte equal to
`DefaultConfig().JSON()`. `policies/config_strict_test.go` reflects over
`Config` and `KindRule` to keep the hand-written strict schema from falling
behind the structs. `TestKindRulesGatesAgree` asserts that write, read, `COUNT`
and live delivery answer the same question the same way for every kind;
`TestBKindKindsAreConfigurable` proves a kind added by config is served end to
end over a real websocket.
