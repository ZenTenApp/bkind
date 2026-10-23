# Taking over B Kind (continuation of khatru)

Status: **plan only.** Nothing renamed, nothing published. Branch `complex/bkind`
at `6c14683`; base `9f99b98` is the archived upstream tip.

Supersedes the earlier `RENAME-PLAN.md`, whose central assumption — "khatru keeps
its name as the framework, the rename waits until porting fixes upstream is no
longer needed" — is falsified by what follows.

## 1. Verified state of the world

| Claim | Evidence |
|---|---|
| Upstream is archived | `api.github.com/repos/fiatjaf/khatru` → `archived: true`, `pushed_at` 2025-09-22, 137 stars, 35 forks, 5 open issues, Unlicense |
| We are level with it | `master` = `9f99b98` = our base; `v0.19.1` + one README-notice commit. Zero merge debt |
| The announced successor is **un-installable** | `go get fiatjaf.com/nostr/khatru` fails: `?go-get=1` for `/nostr` reports a git remote on `relay.ngit.dev`, for `/nostr/khatru` one on `basspistol.org`; Go rejects the disagreement. `proxy.golang.org/.../@latest` → `404 no matching versions` |
| It only *looks* alive | `pkg.go.dev/fiatjaf.com/nostr/khatru` still returns 200 from cache, with no versions |
| Nobody else continued it | The recently-pushed forks compare `identical` or `behind`; none carries a commit past `9f99b98` |
| Existing users are not few | 45 packages import `github.com/fiatjaf/khatru` (42 the root package) |
| Legally free | Unlicense: public domain, no notice, no relicensing constraint |

So there is no living upstream, no successor to defer to, and no competing
continuation to join. Either the project continues under a new name, or it stops
at `v0.19.1`. That is the whole argument for a takeover, and it is now a
verifiable one rather than a judgement call.

## 2. Ability is not authority

This sandbox's `origin` is `github.com/fiatjaf/khatru` and
`origin/complex/bkind` is already at `6c14683`, so pushes succeed through the
gateway's credential. That credential is delegated for this task; it is not
ownership of the repository, and the Unlicense gives rights over *code*, not over
someone's namespace.

Rules for the takeover:

- Do **not** push a rename, or a "maintained fork lives here" commit, to
  `fiatjaf/khatru`'s `master`.
- Do **not** delete, retag or force-push anything there.
- The archived repo cannot accept issues or PRs, so **outreach has to be a
  message** (nostr DM to the author's npub, or email) — one short, polite note that
  the announced successor no longer resolves and that a continuation exists at
  `<new URL>`. Send it once, with the evidence in section 1.

**Ask for a transfer first.** It is one message, and it is the difference between
a continuation and a hard fork: if `fiatjaf/khatru` moves to the new owner, all 45
importers keep working and the module path never changes. If the answer is no or
none arrives within a couple of weeks, the fork path below stands on its own.

## 3. What B Kind becomes

One module, one name, product and framework together:

| Surface | Form |
|---|---|
| Prose, NIP-11 `name` | `B Kind` — never `Bkind`, `B-Kind`, `BKind`, `Kind B` |
| Module | `github.com/<owner>/bkind` |
| Go package | `bkind`, so `bkind.NewRelay()`, `bkind.GetAuthed(ctx)` |
| Binary / image / compose project | `bkind` |
| Env vars, log prefix, unit, dirs | `BKIND_*`, `[bkind]`, `bkind.service`, `/var/lib/bkind` |
| Version | `v1.0.0` (new module path restarts semver; see §6) |

The full label set — including what must *not* be renamed, and why — is in
[`NAMING.md`](./NAMING.md). Only the module path, package clause and repo name move
in Phase 2; the affix bucket (`BKIND_*`, `[bkind]`, `bkind.service`, the compose
project name) is frozen now because renaming it later orphans operator config and
storage volumes.

No two-repo split. Our framework-level fixes (`adding.go`, `deleting.go`,
`expiration.go`, `utils.go`) would otherwise need upstreaming to a dead repo, and
the DM relay depends on them.

If the transfer in §2 happens instead, only the *product* surfaces change: the
module keeps its path, and the rename reduces to the NIP-11/log identity work.

## 4. Phases

### Phase 0 — preserve and credit (no external dependency, do first)

- `NOTICE` / `CREDITS`: public domain, upstream author and contributors (from
  `git shortlog -sne`), and a one-line statement of what B Kind adds.
- Keep the full git history. **No squash, no fresh-init repo**: history is the
  provenance, and it keeps `git blame` meaningful for upstream code.
- Snapshot what the archive will take with it: the 5 open issues (below), and the
  docs text that only exists in that repo. They go into `docs/history/`.
- Keep `LICENSE` as the Unlicense. Adding a second licence on top of public-domain
  code is not possible; `NOTICE` is the right place for credit.

The 5 orphaned issues worth adopting after the rename:

| # | Title | Why it matters |
|---|---|---|
| 65 | Allow gift wrap (Kind 1059) deletion by recipient (NIP-59) | overlaps our Kind-5 work |
| 64 | Add NIP-59 gift wrap access restriction | same area as our `DMReadPolicy` |
| 62 | Link | report of a broken/incorrect link in docs |
| 52 | bug: silent rejection of certain replaceable events | real bug, unaddressed |
| 22 | Question: relay synchronization? | FAQ material |

### Phase 1 — the new home

- Create the repo, then push **all** branches and tags (`git push --mirror` into an
  empty remote preserves tags and the default branch).
- `git remote rename origin upstream`, `git remote add origin <new home>`; keep
  `upstream` for the record. Do not fetch from it expecting new commits.
- README: replace the maintenance banner with a continuation banner — what B Kind
  is, that it is the continuation of khatru `v0.19.1`, that khatru is archived and
  its announced successor no longer resolves, what is new (write gate ordering,
  Kind 5/62 handling, DM policy set, expiration restart), and how to migrate.
- Docs site: `title`, `description`, hero `name`/`tagline`, `editLink.pattern`, the
  `Source` nav link, and `logo.png` (verify it is not a khatru wordmark).
- Badges: CI, Go Reference, Go Report Card all point at the new path.

### Phase 2 — mechanical rename (script ready, measured)

`scripts/rename-khatru.sh <new module path>` does the whole rename, verifies it,
and lists what a human still has to look at. Measured on the current tree:

```
39 go files, 17 markdown files
57 files changed, 176 insertions(+), 176 deletions(-)
go build ./... && go vet ./... && go test ./...   -> pass
```

Three findings from writing it, worth knowing before running anything by hand:

1. **Renaming the import path alone does not compile.** Every importer's qualified
   identifiers (`khatru.NewRelay`, `khatru.GetAuthed`, `khatru.Relay`) must be
   rewritten too, or you get `undefined: khatru`. The script does paths first, then
   `\bkhatru\.` → `bkind.`, then the `package` clauses (including `khatru_test`).
2. **`gofmt -w` is mandatory**, not cosmetic: shortening the import path re-sorts
   and re-groups import blocks across all 39 files.
3. **9 `khatru` strings legitimately survive**: the `[khatru-relay]` log prefix and
   `Info.Software` are handled by the script, but `/tmp/khatru-*` paths in the
   examples, a code comment in `policies/dm.go`, and `khatru29` in
   `docs/core/routing.md` (a third-party package) are left alone on purpose.

Run it with `--check` first; it is idempotent and refuses to run on a dirty tree or
an already-renamed module.

### Phase 3 — release `v1.0.0`

Gated, in this order, because Go's proxy is append-only in practice:

1. Fresh-consumer check in an empty module: `go get github.com/<owner>/bkind@main`,
   build a trivial relay, confirm it compiles and that `go doc bkind.Relay` renders.
2. Then tag `v1.0.0`, push the tag, and only then let pkg.go.dev index it.
3. `CHANGELOG.md`: `v1.0.0 — B Kind, continuation of khatru v0.19.1` with the rename
   note, the API-diff summary, and the migration snippet.
4. Once a version is fetched by the proxy it cannot be withdrawn. Never tag from a
   dirty tree, never move a published tag.

### Phase 4 — become the maintainer, not just the fork

- CI: `go test ./...` (as today) **plus** `go test -race` for the packages that pass
  under `-race`, and `gofmt -l` + `go vet`. Note the pre-existing `slicestore` read
  race in `relay_test.go` (documented in `docs/cookbook/dm-only-relay.md`); fix or
  quarantine it first, otherwise a `-race` gate is red on day one.
- `SECURITY.md`: how to report, expected response, and the fact that this fork
  carries unmerged fixes to privacy-relevant code paths.
- Issue/PR templates, and a deprecation policy for `khatru`-era API names.
- Adopt the 5 issues above; re-triage them against the fork.
- Migration doc for the 45 importers (§5) plus a link from the archived-era docs.

## 5. Migration for the 45 importers

Because the module path changes, every importer edits code anyway — so the package
rename rides along for free rather than costing a second migration later.

```sh
go mod edit -droprequire=github.com/fiatjaf/khatru
go get github.com/<owner>/bkind@v1.0.0
grep -rl 'github.com/fiatjaf/khatru' --include=*.go . \
  | xargs sed -i 's|github.com/fiatjaf/khatru|github.com/<owner>/bkind|g'
grep -rl 'khatru\.' --include=*.go . | xargs sed -i 's|\bkhatru\.|bkind.|g'
gofmt -w .
```

No compatibility shim will be published at any `khatru` path: the namespace is not
ours, and a shim that shadowed `github.com/fiatjaf/khatru` would be squatting. If
someone needs to test the fork without editing code,
`go mod edit -replace=github.com/fiatjaf/khatru=github.com/<owner>/bkind@v1.0.0`
works locally — but a `khatru`-importing program still needs the package rename for
the `khatru.` identifiers to resolve, which is precisely why the codemod exists.

## 6. Versioning stance

`v1.0.0`, not `v0.20.0`. The module path changes, so semver continuity is broken
regardless; `v1.0.0` says "the API is the one we will keep", which is the promise a
continuation owes its importers. Compatibility-wise the rename is source-breaking
but behaviour-preserving, so the changelog leads with the codemod, not with
deprecations.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Reads as taking over someone's project | §2: ask first, credit loudly, keep history, never push to their repo |
| 45 importers break | codemod + changelog + migration doc; `-replace` recipe for a trial run |
| `bkind` collides (26 GitHub repos, a `BKinD` research line) | NIP-11 `name: B Kind` with a description that says what it serves, descriptive repo description, owned domain if ever possible |
| Proxy caches a bad `v1.0.0` forever | §3 gate: fresh-consumer `go get` before tagging |
| Bus factor: I am the only maintainer | document release steps in `docs/`, keep tags reproducible, state the licence allows forks |
| The unmerged privacy/deletion fixes stay unmerged upstream | acceptable: upstream is archived and its successor is un-installable; document the fixes in the changelog |

## 8. Decisions needed

1. **Where does it live?** Owner and repo for `github.com/<owner>/bkind`. Blocking:
   Phases 1–3 all need it, and the module path must resolve before tagging.
2. **Ask for the transfer?** Recommended (one message, §2). If it lands, the module
   path stays `github.com/fiatjaf/khatru` and Phase 2 shrinks to identity strings.
3. **`v1.0.0` or `v0.20.0`?** Recommendation: `v1.0.0` (§6).

Settled elsewhere: `NAMING.md` fixes the label set, the `Kind N` prose form, and the
"khatru only in provenance" rule. The product's NIP-11 `name` is now literally
`B Kind`, with no qualifier appended — what it serves is said in `description`.

## 9. Ready to start without answers

- `scripts/rename-khatru.sh` — written, tested on a scratch worktree, idempotent,
  `--check` mode included. Reusable for downstream forks and for the docs site.
- Phase 0 artifacts: `NOTICE`/`CREDITS`, `docs/history/` snapshot of the 5 issues,
  README continuation banner.

These touch no external system and are reversible, so they can land before the
repo question is settled.
