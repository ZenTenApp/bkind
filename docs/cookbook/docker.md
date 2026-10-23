---
outline: deep
---

# Deploying with Docker

A runbook for putting the [Kind-4 DM relay](./dm-only-relay.md) on a fresh Ubuntu
server with the files in `examples/bkind/`: a `scratch` image, a compose file, and
an optional Caddy service that terminates TLS.

```
client ──wss──> caddy (443) ──ws──> bkind (127.0.0.1:3334) ──> bkind-data volume
```

Nothing needs to be installed on the host except Docker: no Go toolchain, no
systemd unit, no certificates to renew by hand. If you would rather run the binary
directly, the [Ubuntu guide](./deploying.md) covers that path.

## 0. Before you start

- Ubuntu 22.04 or 24.04, root or `sudo`.
- A DNS record for the relay's hostname (both `A` and `AAAA` if the box has IPv6)
  pointing at the server. Caddy proves control of the name over port 80, so the
  record has to resolve **before** the stack starts. A stale `AAAA` record on a
  host without working IPv6 looks exactly like a certificate failure.
- The source, on the server or on your laptop for copying. The image is built from
  the module root, so the whole repository is needed, not just `examples/bkind`.
  If the DM relay example is not on `master` yet, check out the branch that has it:

  ```sh
  git clone -b complex/bkind https://github.com/fiatjaf/khatru /opt/bkind-src
  ls /opt/bkind-src/examples/bkind
  ```

  If the branch lives in your fork, clone that and keep the same layout.

## 1. Base system

```sh
sudo apt update && sudo apt -y upgrade
sudo apt -y install ca-certificates curl git ufw jq
```

One small vCPU, 1 GB of memory and a couple of GB of free disk is plenty for a
personal relay. The build stage downloads the Go image and the module graph once;
after that only the 15 MB runtime image and the store grow.

## 2. Docker

Distribution packages (`docker.io`) are usually too old for compose profiles and
`stop_grace_period`, so use Docker's repository:

```sh
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

sudo apt update
sudo apt -y install docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

Check that both are new enough — the compose file uses `name:`, profiles and
`stop_grace_period`:

```sh
docker --version && docker compose version
```

Either prefix the commands below with `sudo`, or join the group and start a new
shell (`sudo usermod -aG docker "$USER"`). The group is effectively root, so
`sudo` is the safer habit on a single-purpose box.

## 3. Firewall

```sh
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp     # ACME http-01 challenge
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Do not open 3334. Compose publishes the relay on loopback only, so the only way in
is through Caddy.

## 4. Configure

```sh
cd /opt/bkind-src/examples/bkind
cp .env.example .env
```

Edit `.env`. For the TLS profile set **both** lines:

```sh
BKIND_URL=wss://dm.example.com
BKIND_DOMAIN=dm.example.com
```

`BKIND_URL` must be byte-for-byte the URL clients connect to: NIP-42 auth events
carry it in a `relay` tag and NIP-62 vanish requests are matched against it. The
compose default is `ws://127.0.0.1:3334`, and leaving that in place is the single
most common way to get "writes are refused with `auth-required` even though I
passed `--auth`".

`BKIND_DOMAIN` is only read by the `caddy` service, and it must be the hostname in
`BKIND_URL`. Compose refuses to start the profile if it is unset. The file is
already gitignored; `chmod 600 .env` if you like.

Everything else (`BKIND_SWEEP_INTERVAL`, `BKIND_MAX_EXPIRATION`,
`BKIND_MAX_CONTENT`, `BKIND_MAX_TAGS`) has a sane default baked into the image. See
the [configuration table](./deploying.md#_4-configuration) for what each one means.

## 5. Start

```sh
cd /opt/bkind-src/examples/bkind
sudo docker compose --profile tls up -d --build
sudo docker compose ps
sudo docker compose logs -f caddy
```

The first build compiles the relay in the `golang:1.24-alpine` stage and produces a
static binary, so the runtime image is `scratch`: no shell, no libc, nothing to
patch. Wait for `certificate obtained successfully` in the Caddy log, then `^C`.

Without TLS — behind an nginx you already run, or on a private network — drop the
profile:

```sh
sudo docker compose up -d --build      # relay on 127.0.0.1:3334 only
```

## 6. Verify

The NIP-11 document should advertise the DM kind set and the same limits the
policies enforce:

```sh
curl -sS -H 'Accept: application/nostr+json' https://dm.example.com \
  | jq '{nips: .supported_nips, lim: .limitation}'
```

```json
{
  "nips": [4, 9, 11, 40, 42, 62, 45],
  "lim": {
    "max_message_length": 12288,
    "max_event_tags": 16,
    "max_content_length": 4096,
    "auth_required": true,
    "restricted_writes": true
  }
}
```

`45` is there because khatru adds it whenever `CountEvents` is wired; the relay only
lets clients count their own messages.

Then the actual behaviour, with [`nak`](https://github.com/fiatjaf/nak)
(`go install github.com/fiatjaf/nak@latest`):

```sh
export RELAY=wss://dm.example.com
ALICE=$(nak key generate); APUB=$(nak key public "$ALICE")
BOB=$(nak key generate);   BPUB=$(nak key public "$BOB")
EXP=$(( $(date +%s) + 3600 ))

# 1. refused without NIP-42 auth
nak event -k 4 -c 'ciphertext' -t p="$BPUB" -t expiration="$EXP" -t client=test \
  --sec "$ALICE" "$RELAY"
# -> auth-required: you must be authenticated to publish to this relay (NIP-42)

# 2. accepted with --auth
nak event -k 4 -c 'ciphertext' -t p="$BPUB" -t expiration="$EXP" -t client=test \
  --sec "$ALICE" --auth "$RELAY"

# 3. the recipient reads their own mailbox
nak req -k 4 -t p="$BPUB" --sec "$BOB" --auth "$RELAY"

# 4. an outsider is refused
nak req -k 4 -a "$APUB" --sec "$(nak key generate)" --auth "$RELAY"
# -> CLOSED: restricted: Kind 4 events are only visible to their author and their
#    recipient, pin "authors" or "#p" to your own pubkey
```

## 7. Prove it persists

```sh
sudo docker compose restart bkind
nak req -k 4 -t p="$BPUB" --sec "$BOB" --auth "$RELAY"
```

An empty result means the store is not being written. Check the volume:

```sh
sudo docker volume ls | grep bkind_bkind-data
sudo docker compose logs bkind | grep -i badger
```

The volume is named `<project>_<volume>`, and the project name comes from `name:`
in the compose file, so it is `bkind_bkind-data` even if the directory is called
something else.

## 8. Day two

```sh
cd /opt/bkind-src/examples/bkind

sudo docker compose logs -f bkind         # rotated at 10MB x 3 by the compose file
sudo docker compose up -d --build         # upgrade in place, volume is reused
sudo docker compose restart bkind         # settings reload from .env
sudo docker compose stop bkind            # drains for up to 15s, then closes the store
```

**Backups.** Badger holds a `LOCK` inside the volume, so stop the relay first:

```sh
sudo docker compose stop bkind
sudo docker run --rm \
  -v bkind_bkind-data:/data:ro -v /var/backups:/backup alpine \
  tar -C /data -czf /backup/bkind-$(date +%F).tar.gz .
sudo docker compose start bkind
```

Every event expires within 75 hours, so a backup only ever holds recent messages;
its real value is the vanish blocklist and a quick recovery path. Copy it off the
box with `scp`.

**Upgrading the image.** Pull and rebuild; the store is on a volume, so the
container is disposable:

```sh
git -C /opt/bkind-src pull
sudo docker compose up -d --build
```

## Things that will bite

| Symptom | Cause |
|---|---|
| Every write refused with `auth-required`, even with `--auth` | `BKIND_URL` does not match the URL clients use (scheme, host, or a leftover trailing slash) |
| `BKIND_DOMAIN` error on `up` | the `tls` profile is active and the variable is unset |
| Caddy logs ACME failures | DNS not resolving yet, or a stale `AAAA`; fix DNS and `docker compose restart caddy` |
| `failed to open the database ... lock` | a second container on the same volume; never `--scale bkind=2` |
| Client closes with websocket code 1009 | the frame exceeded `max_message_length` (12KB); Kind 4 content is capped at 4KB, so this is usually something that is not a DM |
| `docker compose` cannot find `.env` or `./Caddyfile` | run it from `examples/bkind`; relative paths resolve against the compose file's directory |
| Events gone after a restart | relay started without `BKIND_DB=/data`, or the volume was removed (`docker compose down -v` deletes it) |
| `docker compose exec bkind sh` fails | expected: the runtime image is `scratch` and has no shell. Read the logs instead |
| Rate limits reset on every deploy | expected: token buckets are in memory, per process |

## Why this stack is shaped this way

- **One process, one volume.** Badger guards its directory with a `LOCK` file and
  the rate limiters keep their counters in memory, so replicas would fail to start
  or limit independently. Scale up, not out.
- **Loopback publishing.** TLS, HTTP/1.1 websocket upgrades and slow-client
  timeouts all live in the proxy, where they belong. The relay never opens an
  outbound connection.
- **`X-Forwarded-For` is overwritten, not appended.** khatru trusts the first
  public address in that header, so appending a client-supplied value would let
  anyone spoof the per-ip rate limits. This is why the bundled `Caddyfile` uses
  `header_up X-Forwarded-For {remote_host}`; if you replace Caddy, keep that
  property.
- **`read_only: true`.** The container writes nothing outside `/data` and a 16 MB
  tmpfs on `/tmp`. If you add a feature that needs another path, mount it
  explicitly.
- **No healthcheck.** The runtime image cannot run one, so probe NIP-11 from the
  host instead (step 6).
