---
outline: deep
---

# Deploying a relay on Ubuntu

A relay is a long-running websocket server, so the pieces are the usual ones: a
systemd unit, a TLS-terminating reverse proxy, and a persistent event store. This
page uses the [Kind-4 DM relay](./dm-only-relay.md) as the example workload, but
the service/proxy setup applies to any khatru relay.

The end state:

```
client ──wss──> Caddy (443, TLS) ──ws──> bkind (127.0.0.1:3334) ──> badger (/var/lib/bkind)
```

The relay itself never talks to the internet: it binds to loopback, so certificate
handling, HTTP/1.1 websocket upgrades and slow-client timeouts all stay in one
place. If you would rather not install Go on the server, the same stack is
available as a container image and a compose file — see
[Docker](./docker.md).

## 1. Prerequisites

- Ubuntu 22.04 or 24.04, with `sudo`.
- A DNS record (`A` and/or `AAAA`) pointing at the server, for example
  `dm.example.com`. Certificates are issued over HTTP, so the record must resolve
  before the proxy starts.
- Go 1.24 or newer (`go.mod` requires 1.24.1). Ubuntu's packaged Go is older on
  24.04, so install the official tarball.

```sh
# check what you have first
go version 2>/dev/null || echo "no go"

GO_VERSION=1.24.6
curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
# compare with the checksum published on https://go.dev/dl/
sha256sum "go${GO_VERSION}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
go version
```

On ARM servers use `linux-arm64` in both the filename and the checksum line.

## 2. Build the relay

```sh
git clone https://github.com/fiatjaf/khatru
cd khatru
git checkout complex/bkind     # until this branch is merged

# a static binary with no libc surprises
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/bkind ./examples/bkind
sudo install -m 0755 -o root -g root /tmp/bkind /usr/local/bin/bkind
bkind -h
```

Cross-compiling on your laptop instead of on the server works the same way:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o bkind ./examples/bkind
scp bkind root@dm.example.com:/tmp/bkind
```

`CGO_ENABLED=0` matters: `examples/bkind` uses the badger backend, which is pure
Go. The sqlite and lmdb backends in `eventstore` need cgo and system libraries.

## 3. User and directories

The relay runs unprivileged and owns nothing but its database directory.

```sh
sudo useradd --system --home-dir /var/lib/bkind --shell /usr/sbin/nologin bkind
sudo install -d -o bkind -g bkind -m 0700 /var/lib/bkind
sudo install -d -o root -g root -m 0750 /etc/bkind
```

A DM relay only stores ciphertext, but the database directory is still private:
event metadata (who talks to whom, when) is readable from it.

## 4. Configuration

The binary reads its settings from flags, and every flag defaults to an
environment variable. On a server, use an environment file: systemd reads it,
`bkind` picks the `BKIND_*` values up, and no secrets or URLs end up in the unit
file (or in `ps`).

`/etc/bkind/bkind.env`:

```sh
# public URL of the relay, without a trailing slash.
# This must be the exact URL clients connect to: NIP-42 auth events carry it in a
# "relay" tag, and NIP-62 vanish requests are matched against it.
BKIND_URL=wss://dm.example.com

# listen on loopback only; the proxy terminates TLS
BKIND_ADDR=127.0.0.1:3334

# persistent store (badger). Leave empty for an in-memory store: fine for a test,
# but every message is lost on restart.
BKIND_DB=/var/lib/bkind

# how often expired events are swept out of the store
BKIND_SWEEP_INTERVAL=5m

# write rules (must match what your NIP-11 document promises)
BKIND_MAX_EXPIRATION=75h
BKIND_MAX_CONTENT=4096
BKIND_MAX_TAGS=16
```

```sh
sudo install -o root -g root -m 0640 /dev/null /etc/bkind/bkind.env
sudo editor /etc/bkind/bkind.env
```

| Setting | Flag | Default | Meaning |
|---|---|---|---|
| `BKIND_URL` | `-url` | empty | public `ws://`/`wss://` URL used for NIP-42 and NIP-62 |
| `BKIND_ADDR` | `-addr` | `:3334` | listen address |
| `BKIND_DB` | `-db` | empty | store directory; empty means in-memory |
| `BKIND_SWEEP_INTERVAL` | `-sweep-interval` | `5m` | expired-event sweep period |
| `BKIND_MAX_EXPIRATION` | `-max-expiration` | `75h` | longest accepted NIP-40 expiration |
| `BKIND_MAX_CONTENT` | `-max-content` | `4096` | max content bytes |
| `BKIND_MAX_TAGS` | `-max-tags` | `16` | max tags per event |

Flags win over environment variables, so `bkind -db /tmp/x` overrides the file.

Rate limits are not flags: they are a handful of constants in
`examples/bkind/main.go` (`EventAuthedPubKeyRateLimiter`, `EventIPRateLimiter`,
`FilterAuthedPubKeyRateLimiter`, `FilterIPRateLimiter`, `ConnectionRateLimiter`).
Tune them there and rebuild. The defaults assume a small personal relay: 30
events/hour and 200/day per npub, 200/hour and 800/day per ip for reads.

## 5. systemd unit

`/etc/systemd/system/bkind.service`:

```ini
[Unit]
Description=B Kind relay (Kind 4 direct messages)
Documentation=https://github.com/fiatjaf/khatru/blob/master/docs/cookbook/dm-only-relay.md
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=bkind
Group=bkind
EnvironmentFile=/etc/bkind/bkind.env
ExecStart=/usr/local/bin/bkind
Restart=always
RestartSec=2

# the database directory: systemd creates it and makes it the only writable path
StateDirectory=bkind
StateDirectoryMode=0700
UMask=0077

# a relay holds many sockets: one per client, one per subscription
LimitNOFILE=65535

# hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# leave some room for the store, but do not let a leak take the box down
MemoryMax=1G
TasksMax=4096

[Install]
WantedBy=multi-user.target
```

Notes on the hardening, because a relay that fails to start is worse than one
that is slightly less locked down:

- `StateDirectory=bkind` creates `/var/lib/bkind` and makes it writable even
  under `ProtectSystem=strict`. If you point `BKIND_DB` somewhere else, either set
  `ReadWritePaths=` to that path or drop `ProtectSystem=strict`.
- Badger memory-maps its files. `MemoryDenyWriteExecute=true` is fine for a Go
  binary (no JIT), but `MemoryMax=1G` is a real limit: raise it for a busy relay.
- If the service dies immediately with `status=218/CAPABILITIES` or an `EPERM`
  syscall error, drop `SystemCallFilter=` first, then `MemoryDenyWriteExecute=`.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bkind
sudo systemctl status bkind --no-pager
sudo journalctl -u bkind -f
```

At this point the relay answers on loopback; it is not publicly reachable yet.

## 6. Containers

The files in `examples/bkind/` also build a `scratch` image and a compose stack,
with the same TLS front end included. That path needs no Go toolchain and no
systemd unit; it is written up separately:

- `examples/bkind/Dockerfile` — two stages, `CGO_ENABLED=0`, ~15MB runtime with
  no shell or libc.
- `examples/bkind/docker-compose.yml` — the relay plus an optional Caddy profile.
- `examples/bkind/Caddyfile` — the TLS front end that profile mounts.
- `examples/bkind/.env.example` — copy to `.env`.

See **[Deploying with Docker](./docker.md)** for the from-a-bare-server runbook
and the container-specific gotchas (volume ownership, no shell in the image, never
scaling).

## 7. TLS proxy

### Caddy (recommended, certificates are automatic)

```sh
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

`/etc/caddy/Caddyfile`:

```caddyfile
dm.example.com {
	reverse_proxy 127.0.0.1:3334 {
		# overwrite rather than append: a client-supplied X-Forwarded-For must not
		# reach the relay, otherwise per-ip rate limits are trivially spoofed
		header_up X-Forwarded-For {remote_host}
		header_up X-Forwarded-Proto {scheme}
	}
}
```

```sh
sudo systemctl reload caddy
sudo journalctl -u caddy -n 50 --no-pager
```

Caddy upgrades websockets on its own; no extra directives are needed.

### nginx (if you already run it)

```nginx
server {
    listen 443 ssl http2;
    server_name dm.example.com;

    ssl_certificate     /etc/letsencrypt/live/dm.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dm.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3334;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;

        # $remote_addr, not $proxy_add_x_forwarded_for: the relay trusts the first
        # public address in the header
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # websockets are idle between messages; do not cut them at 60s
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

Get certificates with `sudo certbot --nginx -d dm.example.com` if not already
wired up.

## 8. Firewall

```sh
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp     # ACME http-01
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Port 3334 stays closed; it is bound to loopback.

## 9. Verify

NIP-11 document:

```sh
curl -sS -H 'Accept: application/nostr+json' https://dm.example.com | jq .
```

Expect `supported_nips` to contain `4, 9, 40, 42, 62` (and `45`: khatru adds it
whenever `CountEvents` is wired), plus:

```json
"limitation": {
  "max_message_length": 12288,
  "max_event_tags": 16,
  "max_content_length": 4096,
  "auth_required": true,
  "restricted_writes": true
}
```

End-to-end with [`nak`](https://github.com/fiatjaf/nak) (`go install
github.com/fiatjaf/nak@latest`):

```sh
export RELAY=wss://dm.example.com

ALICE=$(nak key generate); APUB=$(nak key public "$ALICE")
BOB=$(nak key generate);   BPUB=$(nak key public "$BOB")
EXP=$(( $(date +%s) + 3600 ))

# 1. unauthenticated write is refused with a NIP-42 challenge
nak event -k 4 -c 'ciphertext' -t p="$BPUB" -t expiration="$EXP" -t client=test \
  --sec "$ALICE" "$RELAY"
# -> failed: auth-required: you must be authenticated to publish to this relay (NIP-42)

# 2. same event with --auth succeeds
nak event -k 4 -c 'ciphertext' -t p="$BPUB" -t expiration="$EXP" -t client=test \
  --sec "$ALICE" --auth "$RELAY"
# -> success.

# 3. the author reads it back
nak req -k 4 -a "$APUB" --sec "$ALICE" --auth "$RELAY"

# 4. the recipient reads it from their own mailbox
nak req -k 4 -t p="$BPUB" --sec "$BOB" --auth "$RELAY"

# 5. a third party is refused
CAROL=$(nak key generate)
nak req -k 4 -a "$APUB" --sec "$CAROL" --auth "$RELAY"
# -> CLOSED: restricted: Kind 4 events are only visible to their author and
#    their recipient, pin "authors" or "#p" to your own pubkey
```

A mismatch between `BKIND_URL` and the URL clients use shows up in step 2: the
AUTH event's `relay` tag will not match and the write stays refused. Fix the
variable, `systemctl restart bkind`.

Persistence check: publish an event, `sudo systemctl restart bkind`, read it
again. If it is gone, `BKIND_DB` is unset or not writable.

## 10. Operations

**Logs.** Everything goes to the journal, including badger's INFO lines.

```sh
journalctl -u bkind -f
journalctl -u bkind --since '1 hour ago' | grep -i error
```

Cap the journal in `/etc/systemd/journald.conf` (`SystemMaxUse=500M`) if the box
is small, then `sudo systemctl restart systemd-journald`.

**Upgrading.**

```sh
sudo systemctl stop bkind
sudo install -m 0755 /tmp/bkind.new /usr/local/bin/bkind
sudo systemctl start bkind
```

Badger tolerates a clean stop and also recovers from a crash, but stopping first
avoids replaying a partially written value log.

**Backups.** The store is a directory, so a cold copy is enough:

```sh
sudo systemctl stop bkind
sudo tar -C /var/lib -czf /root/bkind-$(date +%F).tar.gz bkind
sudo systemctl start bkind
```

Two caveats specific to this relay: only one process can open a badger directory
(it holds a `LOCK` file), and every event expires within 75 hours, so a backup
older than that holds mostly expired messages. Backups are for the stream of
recent messages and for the vanish blocklist, not an archive.

**Disk.** A message costs roughly its content plus ~1KB of indexes, and nothing
lives longer than 75 hours, so steady-state usage is bounded by traffic: a
thousand 1KB messages per day is a few tens of megabytes. Give it 10GB and forget
about it, but do watch it if `BKIND_MAX_EXPIRATION` is raised.

**Scaling.** This setup is one process on one box. Badger's directory lock rules
out running two replicas on the same volume, and the rate limiters keep their
counters in memory, so a second instance would enforce limits independently.
Scale up, not out.

## 11. Troubleshooting

| Symptom | Cause |
|---|---|
| `auth-required` forever, even with `--auth` | `BKIND_URL` does not match the URL the client uses (scheme, host, trailing path) |
| Client sees `restricted: Kind 4 events are only visible...` | the client's filter does not pin `authors` or `#p` to its own pubkey |
| Connection closes with code 1009 | the frame exceeded `MaxMessageSize` (12KB); content is capped at 4KB, so this is usually a client sending something else |
| `failed to open the database ... lock` | another `bkind` process already has the directory open |
| Service starts then exits `status=1` | run `/usr/local/bin/bkind` by hand with the same environment file to see the error |
| Events disappear after restart | `BKIND_DB` empty or unwritable; check `StateDirectory=`/`ReadWritePaths=` |
| NIP-62 vanish request is refused | `DeleteEvent` not wired (it is, in the example) or the `relay` tag names a different URL than `BKIND_URL` |
| `permission denied` on `/var/lib/bkind` | `User=` does not match the owner of the directory |
| Rate limits reset after every deploy | expected: the token buckets are in memory |
