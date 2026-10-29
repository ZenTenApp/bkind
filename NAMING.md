# Naming

Canonical forms, so the code, the docs and the release scripts do not drift. Read
this before renaming anything.

The project is **B Kind** — cognate with "be kind". It is never "Kind B".

## The four buckets

Every label belongs to exactly one of these. They move at different speeds: the
first two can change, the last two must not.

### 1. Display — `B Kind`

Titles, prose, NIP-11 identity. Always two words, both capitalised: `B Kind`.
Never `Bkind`, `B-Kind`, `Bkind`, `b kind`, `Kind B`.

| Where | Value |
|---|---|
| NIP-11 `name` | `B Kind` |
| Docs site `title`, hero `name` | `B Kind` |
| Page and section titles | `B Kind` |
| Prose | `B Kind` |

The name carries no qualifier. "B Kind" is understood as "be kind"; it does not
need `— kind 4 DM relay` appended to disambiguate it. What the relay serves belongs
in the NIP-11 `description` and in the docs subtitle, not in the name.

### 2. Namespace — `bkind`

One token, all lowercase, no separators. Used wherever a machine or a human types
it as an identifier.

| Where | Value |
|---|---|
| Module path tail | `github.com/<owner>/bkind` |
| Go package | `bkind` — `bkind.NewRelay()`, `bkind.GetAuthed(ctx)` |
| Repo name | `bkind` (must equal the module tail) |
| Binary | `bkind` |
| Container image | `ghcr.io/<owner>/bkind`, tags `vX.Y.Z` and `latest` |
| Compose project (`name:`) | `bkind` |
| Docs URL slugs | lowercase, hyphenated, frozen once published |

Never put an uppercase letter in a module path: Go's proxy escapes it
(`BKind` → `!b!k ind`-style escape), and it is not a valid import path.

### 3. Affix — `BKIND_`, `[bkind]`, `bkind.service`

Frozen now. These are sticky because they outlive a deploy: renaming them later
orphans an operator's config, logs, unit file or volume.

| Surface | Value | Why frozen |
|---|---|---|
| Env vars | `BKIND_ADDR`, `BKIND_URL`, `BKIND_DB`, `BKIND_SWEEP_INTERVAL`, `BKIND_CONFIG`, `BKIND_CONFIG_JSON`, `BKIND_KINDS`, `BKIND_NAME`, `BKIND_DESCRIPTION` | an operator's `.env` and systemd `EnvironmentFile` |
| Log prefix | `[bkind]` | what people grep in journals |
| systemd unit | `bkind.service` | `systemctl` name in every runbook |
| Config dir | `/etc/bkind/` | |
| State dir | `/var/lib/bkind/` | `StateDirectory=bkind` |
| Compose volume | `bkind-data` → `bkind_bkind-data` | renaming the project orphans existing stores |
| CLI flags | `-addr -url -db -sweep-interval -kinds -max-expiration -require-expiration -required-tags -max-content -max-tags -max-tag-name -max-tag-value -require-auth -reject-count -negentropy -name -description -print-config -version` | deliberately unprefixed; no brand in flag names |

### 4. Provenance — not ours

`khatru`, the upstream author, the contributors. Appears **only** in statements
about history, always lowercase, never as our name.

```markdown
B Kind continues khatru v0.19.1. khatru is archived; this fork carries the
framework plus the DM relay and the policy set.
```

| Where | Rule |
|---|---|
| `NOTICE`, `CREDITS` | names the upstream author and contributors |
| `CHANGELOG.md` | `v1.0.0 — B Kind, continuation of khatru v0.19.1` |
| `docs/history/` | verbatim snapshots, including the old name |
| Everything else | `khatru` must not appear; use `B Kind` |
| `LICENSE` | Unlicense, unchanged — public-domain code cannot be relicensed |

## Prose rules

- **`Kind N`**, capital K, space before the number: `Kind 4`, `Kind 5`, `Kind 62`.
  Compound adjectives may hyphenate: `a Kind-4-only relay`.
- Never `kind 4` in prose, never `Kind4` in prose. `Kind4` is acceptable inside a Go
  identifier (`ValidateKind4Shape`), because that is code, not prose.
- `NIP-NN` keeps its hyphen and capitals: `NIP-42`, `NIP-40`, `NIP-62`.
- Nostr wire vocabulary stays lowercase: `kind` as a field name, `event`, `filter`,
  and tag names `p`, `e`, `a`, `expiration`, `client` — e.g. `"kind": 4`.
- "Authenticated", "expiration", "vanish request" are lowercase unless starting a
  sentence.

## Do not rename

These look like branding and are not. Changing them breaks clients or lies about
the protocol:

| Item | Why |
|---|---|
| Close-reason prefixes: `invalid:`, `blocked:`, `restricted:`, `rate-limited:`, `auth-required:`, `error:` | NIP-01 standard, matched by clients |
| `kind`, `event`, `filter`, and tag names | NIP-01 wire vocabulary |
| NIP numbers | normative |
| `khatru29` in `docs/core/routing.md` | a third-party package, not us |
| The Unlicense text in `LICENSE` | public domain; credit belongs in `NOTICE` |
| Any `khatru` path in a `go.mod` that we do not own | not our namespace |

## Where the labels actually live

| Label | Location |
|---|---|
| NIP-11 `name` / `description` | `policies.Settings.NIP11`, defaulted in Go, set by `-name` / `-description`; the description is derived from the kind list when empty |
| NIP-11 `software` / `version` defaults | `relay.go`, `NewRelay()` — currently the upstream URL and `"n/a"`; the product overrides these later |
| Log prefix default | `relay.go` (`[khatru-relay]` until the module rename), overridden by the product |
| Env var names | `policies.LoadConfig` / `ApplyEnv` (`policies/config.go`), plus `envOr(...)` in `examples/bkind/main.go` for the process settings |
| Unit, dirs, volume | `docs/cookbook/deploying.md`, `examples/bkind/docker-compose.yml` |
| Prose | `docs/`, `README.md` |
| Rewrite tool | `scripts/rename-khatru.sh` |

## Frozen vs still open

Frozen (do not change without a migration note): bucket 3, and the docs slugs
(`/cookbook/dm-only-relay`, `/cookbook/deploying`, `/cookbook/docker`). Nothing
external links to them yet, so this is the cheap moment to change them — they are
descriptive and stay as they are unless renamed deliberately in one pass.

Still open, decide before `v1.0.0`:

1. `docs/logo.png` is the khatru wordmark; B Kind needs its own asset or none
   (VitePress falls back to the site title).
2. Git identity of the release commit and whether `v1.0.0` is a signed tag —
   whoever signs it is making the provenance claim.
3. A project npub for release announcements, and optionally a domain to point
   `software` and the badges at.
4. Repo description text — say what it is (`a Nostr relay framework and a kind
   4 relay`), because `bkind` collides with unrelated projects in search.
