#!/usr/bin/env bash
#
# Interactive, idempotent deployment of a B Kind relay on Ubuntu, following
# docs/cookbook/deploying.md.
#
#   sudo bash deploy-ubuntu.sh              # normal run, asks about every step
#   sudo bash deploy-ubuntu.sh --yes        # accept every default, no prompts
#   sudo bash deploy-ubuntu.sh --dry-run    # print what would change, change nothing
#   sudo bash deploy-ubuntu.sh --verify     # only run the checks (section 9)
#
# Pre-answer any prompt (combine freely):
#   --binary PATH          install a prebuilt binary instead of building
#   --source DIR           build from an existing source tree
#   --git URL              clone (or update) a repository
#   --domain HOST          derive BKIND_URL as wss://HOST
#   --url WS_URL           the exact public URL clients use
#   --addr HOST:PORT       listen address (default 127.0.0.1:3334)
#   --db DIR               database directory (default /var/lib/bkind)
#   --kinds LIST           kinds to serve (default 4,5,62; can only narrow)
#   --name NAME            NIP-11 name
#   --description TEXT     NIP-11 description (empty = derived)
#   --proxy nginx|caddy|none   TLS terminator (default: nginx)
#   --email ADDRESS        Let's Encrypt registration email
#
# Example, fully non-interactive:
#   sudo bash deploy-ubuntu.sh --yes --binary /tmp/bkind \
#     --domain dm.example.com --proxy nginx --email you@example.com
#
# Safe to re-run. It never deletes the database, never overwrites your pinned
# policy file without a backup, and skips anything already in place.
#
# What it does NOT do:
#   - provision DNS (section 1 expects the A/AAAA record to already resolve)
#   - set up a private git clone for you: if the repo needs credentials, clone it
#     yourself or hand the script a prebuilt binary
#   - run `nak` end-to-end tests unless you opt in at the end

set -euo pipefail

readonly SCRIPT_VERSION="1.0"
readonly DEFAULT_GO_VERSION="1.24.6"
readonly MIN_GO_VERSION="1.24.1"
readonly DEFAULT_REPO="https://github.com/ZenTenApp/bkind"
readonly BIN_PATH="/usr/local/bin/bkind"
readonly ENV_FILE="/etc/bkind/bkind.env"
readonly POLICY_FILE="/etc/bkind/bkind.json"
readonly UNIT_FILE="/etc/systemd/system/bkind.service"
readonly STATE_DIR="/var/lib/bkind"
readonly DEPLOY_LOG="/var/log/bkind-deploy.log"

ASSUME_YES=0
DRY_RUN=0
VERIFY_ONLY=0
ORIG_ARGS=()

# values that can be supplied up front; anything left empty is asked for
OPT_BINARY=""
OPT_SOURCE=""
OPT_GIT=""
OPT_DOMAIN=""
OPT_URL=""
OPT_ADDR=""
OPT_DB=""
OPT_KINDS=""
OPT_NAME=""
OPT_DESC=""
OPT_PROXY=""
OPT_EMAIL=""

# ---------------------------------------------------------------- output ----

if [[ -t 1 ]]; then
	readonly C_RESET=$'\033[0m' C_BOLD=$'\033[1m' C_RED=$'\033[31m'
	readonly C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m' C_BLUE=$'\033[34m'
	readonly C_DIM=$'\033[2m'
else
	readonly C_RESET='' C_BOLD='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_DIM=''
fi

say() { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$C_BOLD$C_BLUE" "$*" "$C_RESET"; }
info() { printf '    %s\n' "$*"; }
dim() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
ok() { printf '    %s✔%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '    %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err() { printf '    %s✘%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die() {
	err "$*"
	exit 1
}

log_line() {
	# best effort; never fail the deploy because the log is unwritable
	printf '%s %s\n' "$(date -Is)" "$*" >>"$DEPLOY_LOG" 2>/dev/null || true
}

# ----------------------------------------------------------------- input ----

# Prompts read from the terminal, not stdin, so `curl … | bash` still works.
# A container or a detached session may have no controlling terminal; opening
# /dev/tty fails there, so fall back to stdin and let have_tty() decide.
if ! { exec 3</dev/tty; } 2>/dev/null; then
	exec 3<&0
fi

# interactive only when both ends are terminals: a piped `curl | bash` has a
# readable stdin but nothing to answer with
have_tty() { [[ -t 0 && -t 3 ]]; }

ask() {
	# ask <prompt> [default] -> echoes the answer
	local prompt="$1" default="${2-}" ans
	if [[ $ASSUME_YES == 1 ]]; then
		# --yes means "take the default", including an empty one
		printf '%s' "$default"
		return 0
	fi
	have_tty || die "no terminal for input; re-run with --yes"
	if [[ -n $default ]]; then
		printf '%s [%s]: ' "$prompt" "$default" >&2
	else
		printf '%s: ' "$prompt" >&2
	fi
	IFS= read -r ans <&3 || ans=""
	printf '%s' "${ans:-$default}"
}

confirm() {
	# confirm <prompt> [y|n] -> exit 0 for yes
	local prompt="$1" default="${2:-y}" ans
	if [[ $ASSUME_YES == 1 ]]; then
		# --yes takes the safe default, which is not always "yes": a destructive
		# or irreversible prompt defaults to n and stays a no
		if [[ $default == y ]]; then
			dim "$prompt -> yes (--yes)"
			return 0
		fi
		dim "$prompt -> no (--yes, safe default)"
		return 1
	fi
	have_tty || die "no terminal for input; re-run with --yes"
	if [[ $default == y ]]; then
		printf '    %s [Y/n]: ' "$prompt" >&2
	else
		printf '    %s [y/N]: ' "$prompt" >&2
	fi
	IFS= read -r ans <&3 || ans=""
	ans="${ans:-$default}"
	[[ $ans =~ ^[Yy] ]]
}

choose() {
	# choose <prompt> <option1> <option2> ... -> echoes the chosen option
	local prompt="$1"
	shift
	local -a opts=("$@")
	local i ans

	if [[ $ASSUME_YES == 1 ]]; then
		printf '%s' "${opts[0]}"
		return 0
	fi
	have_tty || die "no terminal for input; re-run with --yes"

	printf '    %s\n' "$prompt" >&2
	for i in "${!opts[@]}"; do
		printf '      %d) %s\n' "$((i + 1))" "${opts[$i]}" >&2
	done
	while true; do
		printf '    choice [1]: ' >&2
		IFS= read -r ans <&3 || ans=""
		ans="${ans:-1}"
		if [[ $ans =~ ^[0-9]+$ ]] && ((ans >= 1 && ans <= ${#opts[@]})); then
			printf '%s' "${opts[$((ans - 1))]}"
			return 0
		fi
		printf '    please enter 1-%d\n' "${#opts[@]}" >&2
	done
}

# --------------------------------------------------------------- actions ----

run() {
	# run <cmd...> — a mutating command, honours --dry-run
	if [[ $DRY_RUN == 1 ]]; then
		dim "would run: $*"
		return 0
	fi
	log_line "run: $*"
	"$@"
}

run_sh() {
	# run_sh <shell string> — same, for pipelines
	if [[ $DRY_RUN == 1 ]]; then
		dim "would run: $1"
		return 0
	fi
	log_line "run: $1"
	bash -c "$1"
}

backup_file() {
	# backup_file <path> — copy beside it with a timestamp, keep 3 newest
	local path="$1" dir base stamp
	[[ -e $path ]] || return 0
	dir=$(dirname "$path")
	base=$(basename "$path")
	stamp=$(date +%Y%m%d-%H%M%S)
	run cp -a "$path" "$dir/$base.bak-$stamp"
	# prune old backups of this file, keeping the newest three
	if [[ $DRY_RUN == 0 ]]; then
		ls -1t "$dir/$base".bak-* 2>/dev/null | tail -n +4 | xargs -r rm -f
	fi
	ok "backed up $path -> $dir/$base.bak-$stamp"
}

version_ge() {
	# version_ge <a> <b> — true when a >= b, using sort -V
	[[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1) == "$2" ]]
}

go_version_installed() {
	command -v go >/dev/null 2>&1 || return 1
	local v
	v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//') || return 1
	[[ -n $v ]] || return 1
	printf '%s' "$v"
}

# --------------------------------------------------------------- preflight ---

preflight() {
	step "Preflight"

	if [[ $EUID -ne 0 ]]; then
		if command -v sudo >/dev/null 2>&1; then
			info "re-running under sudo…"
			# re-exec with the original arguments, not the ones main() consumed
			exec sudo --preserve-env=ASSUME_YES bash "$0" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
		fi
		die "run as root (sudo bash $0)"
	fi

	if [[ -r /etc/os-release ]]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		info "OS: ${PRETTY_NAME:-unknown}"
		if [[ ${ID:-} != ubuntu ]]; then
			warn "this script targets Ubuntu; ${ID:-unknown} may need different package names"
			confirm "Continue anyway?" y || exit 0
		fi
	fi

	case "$(uname -m)" in
	x86_64 | amd64) GOARCH_NAME="amd64" ;;
	aarch64 | arm64) GOARCH_NAME="arm64" ;;
	*) die "unsupported architecture $(uname -m) for the Go tarball; install Go manually" ;;
	esac
	info "Architecture: $(uname -m) (go $GOARCH_NAME)"

	command -v systemctl >/dev/null 2>&1 || die "systemd is required"
	command -v curl >/dev/null 2>&1 || die "curl is required"

	# the log file must exist before log_line can append
	: >>"$DEPLOY_LOG" 2>/dev/null || true

	ok "preflight passed (script $SCRIPT_VERSION)"
}

# -------------------------------------------------------------------- go ----

step_go() {
	step "2. Go toolchain (>= $MIN_GO_VERSION)"

	if [[ -z $SRC_DIR ]]; then
		ok "not building from source, so Go is not needed"
		return 0
	fi

	local current
	if current=$(go_version_installed); then
		if version_ge "$current" "$MIN_GO_VERSION"; then
			ok "Go $current already installed, nothing to do"
			return 0
		fi
		warn "Go $current is older than $MIN_GO_VERSION"
	else
		info "Go is not installed"
	fi

	confirm "Install Go to /usr/local/go?" y || {
		warn "skipping; the build step will need a working Go $MIN_GO_VERSION+"
		return 0
	}

	local ver
	ver=$(ask "Go version to install" "$DEFAULT_GO_VERSION")
	[[ $ver =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "not a Go version: $ver"

	local file="go${ver}.linux-${GOARCH_NAME}.tar.gz"
	local url="https://go.dev/dl/${file}"
	local tmp
	tmp=$(mktemp -d)

	info "downloading $url"
	curl -fsSL -o "$tmp/$file" "$url" || die "download failed: $url"

	# verify against the checksum Google publishes next to the tarball
	local want got
	want=$(curl -fsSL "https://dl.google.com/go/${file}.sha256" 2>/dev/null | tr -d '[:space:]') || true
	got=$(sha256sum "$tmp/$file" | awk '{print $1}')
	if [[ -n $want ]]; then
		[[ $want == "$got" ]] || die "checksum mismatch: expected $want, got $got"
		ok "sha256 verified"
	else
		warn "could not fetch the published checksum; got sha256 $got"
		confirm "Continue with this tarball?" n || die "aborted on unverified tarball"
	fi

	run rm -rf /usr/local/go
	run tar -C /usr/local -xzf "$tmp/$file"
	run ln -sf /usr/local/go/bin/go /usr/local/bin/go
	rm -rf "$tmp"

	ok "Go $(go_version_installed) installed"
}

# ---------------------------------------------------------------- source ----

# Sets: SRC_DIR (source tree, empty if using a prebuilt binary), PREBUILT_BIN
SRC_DIR=""
PREBUILT_BIN=""

clone_or_update() {
	local url="$1" dir
	dir=$(ask "Clone into" "/opt/bkind-src")
	if [[ -d $dir/.git ]]; then
		ok "already cloned at $dir"
		if confirm "Update it (git fetch + reset --hard origin/HEAD)?" y; then
			run_sh "git -C '$dir' fetch --all --prune && git -C '$dir' reset --hard '@{upstream}'"
		fi
	else
		run git clone --depth 1 "$url" "$dir" ||
			die "clone failed. This repository is private: configure an SSH key or a token, or use --binary/--source."
	fi
	SRC_DIR="$dir"
}

step_source() {
	step "1. Source or binary"

	# explicit choices win, so a re-run can be fully non-interactive
	if [[ -n $OPT_BINARY ]]; then
		[[ -x $OPT_BINARY ]] || die "$OPT_BINARY is not an executable"
		PREBUILT_BIN="$OPT_BINARY"
		ok "using prebuilt binary $OPT_BINARY"
		return 0
	fi
	if [[ -n $OPT_SOURCE ]]; then
		[[ -f $OPT_SOURCE/go.mod ]] || die "$OPT_SOURCE/go.mod not found"
		SRC_DIR="$OPT_SOURCE"
		ok "using source tree $OPT_SOURCE"
		return 0
	fi
	if [[ -n $OPT_GIT ]]; then
		clone_or_update "$OPT_GIT"
		return 0
	fi

	# --yes must never clone a repository implicitly
	if [[ $ASSUME_YES == 1 ]]; then
		if [[ -x $BIN_PATH ]]; then
			ok "keeping the binary already installed at $BIN_PATH"
			return 0
		fi
		die "--yes needs --binary PATH, --source DIR, --git URL, or an existing $BIN_PATH"
	fi

	local mode
	mode=$(choose "How should the relay binary be obtained on this server?" \
		"git clone (needs access to the repository)" \
		"existing source directory on this machine" \
		"prebuilt binary I will copy here" \
		"keep the binary already installed")

	case "$mode" in
	"git clone"*)
		local url
		url=$(ask "Repository URL" "$DEFAULT_REPO")
		clone_or_update "$url"
		;;
	"existing source"*)
		SRC_DIR=$(ask "Path to the bkind source tree" "/opt/bkind-src")
		[[ -f $SRC_DIR/go.mod ]] || die "$SRC_DIR/go.mod not found"
		;;
	"prebuilt binary"*)
		PREBUILT_BIN=$(ask "Path to the binary on this server" "/tmp/bkind")
		[[ -x $PREBUILT_BIN ]] || die "$PREBUILT_BIN is not an executable"
		;;
	"keep the binary"*)
		[[ -x $BIN_PATH ]] || die "no binary at $BIN_PATH to keep"
		ok "keeping $BIN_PATH"
		;;
	esac
}

# ----------------------------------------------------------------- build ----

step_build() {
	step "3. Build and install the binary"

	if [[ -n $PREBUILT_BIN ]]; then
		if [[ -f $BIN_PATH ]] && cmp -s "$PREBUILT_BIN" "$BIN_PATH"; then
			ok "$BIN_PATH already matches $PREBUILT_BIN"
			return 0
		fi
		backup_file "$BIN_PATH"
		run install -m 0755 -o root -g root "$PREBUILT_BIN" "$BIN_PATH"
		ok "installed $BIN_PATH from $PREBUILT_BIN"
		return 0
	fi

	if [[ -z $SRC_DIR ]]; then
		if [[ -x $BIN_PATH ]]; then
			ok "keeping existing $BIN_PATH"
			return 0
		fi
		die "nothing to build and no binary installed"
	fi

	confirm "Build a static binary from $SRC_DIR?" y || return 0

	local tmp
	tmp=$(mktemp -d)
	# build as root: GOCACHE lives in /root, the module cache is fetched once
	run_sh "cd '$SRC_DIR' && CGO_ENABLED=0 GOCACHE=/root/.cache/go-build go build -trimpath -ldflags='-s -w' -o '$tmp/bkind' ./examples/bkind"
	[[ $DRY_RUN == 1 ]] && { rm -rf "$tmp"; return 0; }
	[[ -x $tmp/bkind ]] || die "build produced no binary"

	if [[ -f $BIN_PATH ]] && cmp -s "$tmp/bkind" "$BIN_PATH"; then
		ok "build is identical to the installed binary; nothing to replace"
		rm -rf "$tmp"
		return 0
	fi

	backup_file "$BIN_PATH"
	run install -m 0755 -o root -g root "$tmp/bkind" "$BIN_PATH"
	rm -rf "$tmp"

	ok "built and installed $BIN_PATH ($(du -h "$BIN_PATH" | cut -f1))"
}

# ------------------------------------------------------------------ user ----

step_user() {
	step "4. Service user and directories"

	if id bkind >/dev/null 2>&1; then
		ok "user bkind already exists"
	else
		if confirm "Create the unprivileged system user 'bkind'?" y; then
			run useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin bkind
		fi
	fi

	# StateDirectory= would create this too; doing it here keeps permissions explicit
	run install -d -o bkind -g bkind -m 0700 "$STATE_DIR"
	# root:bkind 0750 so the service user can read the policy file inside (the
	# deploying doc uses root:root 0750, which the relay cannot traverse)
	run install -d -o root -g bkind -m 0750 /etc/bkind

	ok "$STATE_DIR (bkind:bkind 0700), /etc/bkind (root:bkind 0750)"
}

# ------------------------------------------------------------------- env ----

# Load an existing env file into associative arrays, preserving comments out.
declare -A ENV_CURRENT=()
load_env_file() {
	[[ -f $ENV_FILE ]] || return 0
	local line key val
	while IFS= read -r line || [[ -n $line ]]; do
		[[ $line =~ ^[[:space:]]*# ]] && continue
		[[ $line =~ ^[[:space:]]*$ ]] && continue
		if [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
			key=${BASH_REMATCH[1]}
			val=${BASH_REMATCH[2]}
			# strip one layer of matching quotes
			val=${val#\"}
			val=${val%\"}
			val=${val#\'}
			val=${val%\'}
			ENV_CURRENT[$key]=$val
		fi
	done <"$ENV_FILE"
}

write_env_file() {
	local tmp
	tmp=$(mktemp)
	cat >"$tmp" <<EOF
# B Kind relay environment — generated by deploy-ubuntu.sh
#
# The public URL clients connect to. NIP-42 auth events carry it in a "relay" tag
# and NIP-62 vanish requests are matched against it, so it must be exact.
BKIND_URL=${BKIND_URL}
BKIND_ADDR=${BKIND_ADDR}
BKIND_DB=${BKIND_DB}
BKIND_SWEEP_INTERVAL=${BKIND_SWEEP_INTERVAL}
BKIND_KINDS=${BKIND_KINDS}
# quoted: these two are free text and may contain spaces or '#'
BKIND_NAME="${BKIND_NAME}"
BKIND_DESCRIPTION="${BKIND_DESCRIPTION}"
EOF
	if [[ -n ${BKIND_CONFIG:-} ]]; then
		printf 'BKIND_CONFIG=%s\n' "$BKIND_CONFIG" >>"$tmp"
	fi
	if [[ -f $ENV_FILE ]] && cmp -s "$tmp" "$ENV_FILE"; then
		ok "$ENV_FILE already up to date"
		rm -f "$tmp"
		return 0
	fi
	backup_file "$ENV_FILE"
	run install -o root -g bkind -m 0640 "$tmp" "$ENV_FILE"
	rm -f "$tmp"
}

step_env() {
	step "5. Environment file ($ENV_FILE)"
	load_env_file

	local existing_note=""
	[[ ${#ENV_CURRENT[@]} -gt 0 ]] && existing_note=" (current values shown as defaults)"

	info "Press Enter to keep a value.$existing_note"

	# precedence for each default: explicit flag > existing env file > built-in
	local def_url def_addr def_db def_sweep def_kinds def_name
	if [[ -n $OPT_URL ]]; then
		def_url=$OPT_URL
	elif [[ -n $OPT_DOMAIN ]]; then
		def_url="wss://$OPT_DOMAIN"
	else
		def_url=${ENV_CURRENT[BKIND_URL]:-wss://dm.example.com}
	fi
	def_addr=${OPT_ADDR:-${ENV_CURRENT[BKIND_ADDR]:-127.0.0.1:3334}}
	def_db=${OPT_DB:-${ENV_CURRENT[BKIND_DB]:-$STATE_DIR}}
	def_sweep=${ENV_CURRENT[BKIND_SWEEP_INTERVAL]:-5m}
	def_kinds=${OPT_KINDS:-${ENV_CURRENT[BKIND_KINDS]:-4,5,62}}
	def_name=${OPT_NAME:-${ENV_CURRENT[BKIND_NAME]:-B Kind}}

	BKIND_URL=$(ask "Public relay URL (ws:// or wss://)" "$def_url")
	[[ $BKIND_URL =~ ^wss?://[^/[:space:]]+ ]] || die "BKIND_URL must start with ws:// or wss:// and have a host"
	BKIND_URL=${BKIND_URL%/} # NIP-42/62 compare this exactly

	BKIND_ADDR=$(ask "Listen address" "$def_addr")
	BKIND_DB=$(ask "Database directory" "$def_db")
	BKIND_SWEEP_INTERVAL=$(ask "Expired-event sweep interval" "$def_sweep")
	BKIND_KINDS=$(ask "Kinds served (comma-separated)" "$def_kinds")
	BKIND_NAME=$(ask "Relay name (NIP-11)" "$def_name")
	BKIND_DESCRIPTION=$(ask "Relay description (empty = derived from kinds)" "${OPT_DESC:-${ENV_CURRENT[BKIND_DESCRIPTION]:-}}")
	BKIND_CONFIG=${ENV_CURRENT[BKIND_CONFIG]:-}

	# BKIND_KINDS can only narrow the document, never add a kind to it
	local doc_kinds="4,5,62"
	if [[ -f $POLICY_FILE ]] && command -v python3 >/dev/null 2>&1; then
		doc_kinds=$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))))' "$POLICY_FILE" 2>/dev/null || echo "4,5,62")
	fi
	local missing=""
	local k
	IFS=, read -ra want <<<"$BKIND_KINDS"
	IFS=, read -ra have <<<"$doc_kinds"
	for k in "${want[@]}"; do
		[[ " ${have[*]} " == *" $k "* ]] || missing+="$k "
	done
	if [[ -n $missing ]]; then
		warn "kind(s) ${missing}are not in the policy document ($POLICY_FILE)."
		warn "BKIND_KINDS only removes kinds; to serve a new one, add its rule to the JSON."
		confirm "Continue (those kinds will NOT be served)?" n || die "edit the policy document first"
	fi

	if [[ $BKIND_DB != "$STATE_DIR" ]]; then
		warn "BKIND_DB is $BKIND_DB, not $STATE_DIR."
		warn "The systemd unit only makes $STATE_DIR writable under ProtectSystem=strict."
	fi

	write_env_file
}

# ---------------------------------------------------------------- policy ----

step_policy() {
	step "6. Kind policy document ($POLICY_FILE)"

	if [[ -f $POLICY_FILE ]]; then
		ok "policy file exists; treating it as the source of truth"
		BKIND_CONFIG="$POLICY_FILE"
		if confirm "Regenerate it from the binary's defaults instead? (your edits are backed up)" n; then
			generate_policy
		fi
	else
		BKIND_CONFIG="$POLICY_FILE"
		generate_policy
	fi

	# make sure the env file points at it
	if ! grep -q '^BKIND_CONFIG=' "$ENV_FILE" 2>/dev/null; then
		run_sh "printf 'BKIND_CONFIG=%s\n' '$BKIND_CONFIG' >> '$ENV_FILE'"
		ok "added BKIND_CONFIG to $ENV_FILE"
	fi

	# the file is read by the service user, so it must be group-readable by bkind
	run chown root:bkind "$POLICY_FILE"
	run chmod 0640 "$POLICY_FILE"
	ok "$POLICY_FILE (root:bkind 0640)"

	# validate before we ever start the service
	if [[ $DRY_RUN == 0 && -x $BIN_PATH ]]; then
		if env -u BKIND_CONFIG -u BKIND_CONFIG_JSON BKIND_CONFIG="$POLICY_FILE" \
			BKIND_KINDS="$BKIND_KINDS" BKIND_NAME="$BKIND_NAME" \
			BKIND_DESCRIPTION="$BKIND_DESCRIPTION" "$BIN_PATH" -print-config >/dev/null; then
			ok "configuration validates"
		else
			die "the policy document failed validation (see the message above)"
		fi
	fi
}

generate_policy() {
	[[ -x $BIN_PATH ]] || die "no binary at $BIN_PATH to render the configuration"

	local tmp
	tmp=$(mktemp)
	# render the effective document without the file we are about to replace
	if ! env -u BKIND_CONFIG -u BKIND_CONFIG_JSON \
		BKIND_KINDS="$BKIND_KINDS" BKIND_NAME="$BKIND_NAME" \
		BKIND_DESCRIPTION="$BKIND_DESCRIPTION" \
		"$BIN_PATH" -print-config >"$tmp" 2>/dev/null; then
		rm -f "$tmp"
		die "failed to render the default configuration"
	fi
	# sanity: must be non-empty JSON with at least one kind (the binary's own
	# validator is the real check; this catches an empty render)
	if [[ ! -s $tmp ]]; then
		rm -f "$tmp"
		die "rendered configuration is empty"
	fi
	if command -v python3 >/dev/null 2>&1; then
		if ! python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if d else 1)' "$tmp" 2>/dev/null; then
			rm -f "$tmp"
			die "rendered configuration is not a non-empty JSON document"
		fi
	fi
	if [[ -f $POLICY_FILE ]] && cmp -s "$tmp" "$POLICY_FILE"; then
		ok "$POLICY_FILE already matches the rendered policy"
		rm -f "$tmp"
		return 0
	fi
	backup_file "$POLICY_FILE"
	run install -o root -g bkind -m 0640 "$tmp" "$POLICY_FILE"
	rm -f "$tmp"
	ok "generated $POLICY_FILE from the binary defaults"
}

# ------------------------------------------------------------------ unit ----

step_unit() {
	step "7. systemd unit ($UNIT_FILE)"

	local unit
	unit=$(cat <<'EOF'
[Unit]
Description=B Kind relay (Kind 4 direct messages)
Documentation=https://github.com/ZenTenApp/bkind/blob/master/docs/cookbook/dm-only-relay.md
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
EOF
)

	if [[ -f $UNIT_FILE ]] && [[ $(cat "$UNIT_FILE") == "$unit" ]]; then
		ok "unit already up to date"
	else
		backup_file "$UNIT_FILE"
		run_sh "cat > '$UNIT_FILE' <<'UNITEOF'
$unit
UNITEOF"
		ok "wrote $UNIT_FILE"
	fi

	if ! grep -q '^ReadWritePaths=' "$UNIT_FILE" 2>/dev/null && [[ -n ${BKIND_DB:-} && $BKIND_DB != "$STATE_DIR" ]]; then
		warn "BKIND_DB=$BKIND_DB is outside StateDirectory; adding ReadWritePaths="
		run_sh "printf 'ReadWritePaths=%s\n' '$BKIND_DB' >> '$UNIT_FILE'"
	fi

	run systemctl daemon-reload
	ok "systemd reloaded"
}

# ----------------------------------------------------------------- proxy ----

DOMAIN=""

derive_domain() {
	local url="${BKIND_URL:-}"
	DOMAIN=${url#*://}
	DOMAIN=${DOMAIN%%/*}
	DOMAIN=${DOMAIN%%:*}
}

# The proxy connects to the relay; 0.0.0.0/[::]/:port all mean "loopback" here.
upstream_addr() {
	local addr="${BKIND_ADDR:-127.0.0.1:3334}"
	case "$addr" in
	:*) printf '127.0.0.1%s' "$addr" ;;
	0.0.0.0:*) printf '127.0.0.1:%s' "${addr#0.0.0.0:}" ;;
	"[::]:"*) printf '127.0.0.1:%s' "${addr#"[::]:"}" ;;
	*) printf '%s' "$addr" ;;
	esac
}

# HTTP-only: valid on a fresh box, before any certificate exists. Used first so
# certbot can complete its HTTP-01 challenge; nginx -t would fail with a
# `listen 443 ssl` block whose certificate files do not exist yet.
nginx_http_block() {
	cat <<EOF
# Managed by deploy-ubuntu.sh
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://$(upstream_addr);
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;

        # \$remote_addr, not \$proxy_add_x_forwarded_for: the relay trusts the first
        # public address in the header
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # websockets are idle between messages; do not cut them at 60s
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
}

nginx_tls_block() {
	cat <<EOF
# Managed by deploy-ubuntu.sh
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location / {
        proxy_pass http://$(upstream_addr);
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;

        # \$remote_addr, not \$proxy_add_x_forwarded_for: the relay trusts the first
        # public address in the header
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # websockets are idle between messages; do not cut them at 60s
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
}

write_nginx_site() {
	local content="$1"
	local site="/etc/nginx/sites-available/bkind.conf"
	local tmp
	# nginx may have been installed without these (or by a package variant)
	run install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled
	tmp=$(mktemp)
	printf '%s\n' "$content" >"$tmp"

	if [[ -f $site ]] && cmp -s "$tmp" "$site"; then
		ok "nginx site already up to date"
		rm -f "$tmp"
	else
		backup_file "$site"
		run install -m 0644 -o root -g root "$tmp" "$site"
		rm -f "$tmp"
		ok "wrote $site"
	fi

	run ln -sf "$site" /etc/nginx/sites-enabled/bkind.conf
	run nginx -t || die "nginx configuration test failed"
	run systemctl enable nginx >/dev/null 2>&1 || true
	run systemctl reload nginx 2>/dev/null || run systemctl restart nginx
}

step_proxy() {
	step "8. TLS reverse proxy"
	derive_domain
	[[ -n $DOMAIN ]] || die "could not derive a domain from BKIND_URL"

	local choice
	if [[ -n $OPT_PROXY ]]; then
		case "$OPT_PROXY" in
		nginx) choice="nginx (with certbot for certificates)" ;;
		caddy) choice="Caddy (automatic certificates)" ;;
		none) choice="Neither: I terminate TLS elsewhere" ;;
		*) die "--proxy must be nginx, caddy or none" ;;
		esac
	else
		choice=$(choose "How should TLS be terminated for $DOMAIN?" \
			"nginx (with certbot for certificates)" \
			"Caddy (automatic certificates)" \
			"Neither: I terminate TLS elsewhere")
	fi

	case "$choice" in
	Caddy*)
		if command -v caddy >/dev/null 2>&1; then
			ok "caddy already installed"
		else
			confirm "Install Caddy from the official repository?" y || return 0
			run apt-get update -qq
			run apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
			run_sh "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"
			run_sh "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list"
			run apt-get update -qq
			run apt-get install -y caddy
		fi

		local caddyfile="/etc/caddy/Caddyfile"
		local desired
		desired=$(
			cat <<EOF
$DOMAIN {
	reverse_proxy 127.0.0.1:3334 {
		# overwrite rather than append: a client-supplied X-Forwarded-For must not
		# reach the relay, otherwise per-ip rate limits are trivially spoofed
		header_up X-Forwarded-For {remote_host}
		header_up X-Forwarded-Proto {scheme}
	}
}
EOF
		)

		if [[ -f $caddyfile ]] && [[ $(cat "$caddyfile") == "$desired" ]]; then
			ok "Caddyfile already up to date"
		else
			if [[ -f $caddyfile ]] && [[ -s $caddyfile ]]; then
				warn "an existing $caddyfile will be replaced"
				confirm "Continue?" n || return 0
			fi
			backup_file "$caddyfile"
			run_sh "cat > '$caddyfile' <<'CADDYEOF'
$desired
CADDYEOF"
			ok "wrote $caddyfile"
		fi

		run systemctl enable --now caddy
		run systemctl reload caddy || run systemctl restart caddy
		ok "caddy reloaded"
		;;
	nginx*)
		if ! command -v nginx >/dev/null 2>&1; then
			confirm "Install nginx?" y || return 0
			run apt-get update -qq
			run apt-get install -y nginx
		fi

		local cert_dir="/etc/letsencrypt/live/$DOMAIN"

		if [[ -f $cert_dir/fullchain.pem ]]; then
			write_nginx_site "$(nginx_tls_block)"
			ok "nginx configured for $DOMAIN over TLS"
		else
			# an HTTP-only site is valid with no certificate yet; a `listen 443 ssl`
			# block referencing missing certificate files fails `nginx -t`
			write_nginx_site "$(nginx_http_block)"

			if confirm "Obtain a TLS certificate with certbot now?" y; then
				if ! command -v certbot >/dev/null 2>&1; then
					run apt-get install -y certbot python3-certbot-nginx
				fi
				local email
				email=$(ask "Email for Let's Encrypt (empty = register without one)" "$OPT_EMAIL")
				if [[ -n $email ]]; then
					run certbot --nginx -d "$DOMAIN" --non-interactive \
						--agree-tos -m "$email" ||
						warn "certbot failed; DNS or port 80 may not be ready yet"
				else
					run certbot --nginx -d "$DOMAIN" --non-interactive \
						--agree-tos --register-unsafely-without-email ||
						warn "certbot failed; DNS or port 80 may not be ready yet"
				fi
			fi

			if [[ -f $cert_dir/fullchain.pem ]]; then
				write_nginx_site "$(nginx_tls_block)"
				ok "nginx configured for $DOMAIN over TLS"
			else
				warn "no certificate at $cert_dir; nginx is serving plain HTTP on port 80"
				warn "run: certbot --nginx -d $DOMAIN   and then re-run this script"
			fi
		fi
		;;
	*)
		warn "skipping; make sure $DOMAIN proxies to 127.0.0.1:3334 with websocket upgrade"
		;;
	esac
}

# -------------------------------------------------------------- firewall ----

step_firewall() {
	step "9. Firewall (ufw)"

	if ! command -v ufw >/dev/null 2>&1; then
		warn "ufw is not installed; skipping"
		return 0
	fi

	# detect the SSH port first: enabling ufw without allowing it would lock us out
	local ssh_port=22
	if [[ -r /etc/ssh/sshd_config ]]; then
		local p
		p=$(awk '/^[[:space:]]*Port[[:space:]]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
		[[ -n $p ]] && ssh_port=$p
	fi

	# "Status: active" exactly — a substring test also matches "inactive"
	if ! ufw status 2>/dev/null | grep -q '^Status: active$'; then
		info "ufw is inactive"
		confirm "Enable ufw and allow SSH ($ssh_port/tcp), 80/tcp, 443/tcp?" y || return 0
		run ufw allow "$ssh_port/tcp"
		run ufw allow 80/tcp
		run ufw allow 443/tcp
		run ufw --force enable
	else
		ok "ufw is active"
		local rule
		for rule in "$ssh_port/tcp" "80/tcp" "443/tcp"; do
			if ufw status 2>/dev/null | grep -q "$rule"; then
				ok "rule present: $rule"
			else
				confirm "Allow $rule?" y || continue
				run ufw allow "$rule"
			fi
		done
	fi
	run ufw status verbose || true
}

# ----------------------------------------------------------------- start ----

step_start() {
	step "10. Start the service"

	run systemctl enable bkind

	if systemctl is-active --quiet bkind; then
		if confirm "Relay is running. Restart it to pick up the new configuration?" y; then
			run systemctl restart bkind
		fi
	else
		run systemctl start bkind
	fi

	# give it a moment, then report the truth rather than assuming success
	if [[ $DRY_RUN == 1 ]]; then
		dim "would wait for the unit and check its state"
		return 0
	fi
	sleep 2
	if systemctl is-active --quiet bkind; then
		ok "bkind is active"
	else
		err "bkind failed to start; last log lines:"
		journalctl -u bkind -n 30 --no-pager || true
		warn "if this is a sandboxing error (status=218/CAPABILITIES or EPERM), drop"
		warn "SystemCallFilter= first, then MemoryDenyWriteExecute= from $UNIT_FILE"
		return 1
	fi
}

# ---------------------------------------------------------------- verify ----

step_verify() {
	step "11. Verify"

	local addr="${BKIND_ADDR:-127.0.0.1:3334}"
	# 127.0.0.1:3334 -> http://127.0.0.1:3334
	local local_url="http://${addr}"
	[[ $addr == 0.0.0.0:* ]] && local_url="http://127.0.0.1:${addr##*:}"

	local doc
	if doc=$(curl -fsS -m 5 -H 'Accept: application/nostr+json' "$local_url/" 2>/dev/null); then
		ok "relay answers on $local_url"
		printf '%s' "$doc" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("      name:", d.get("name"))
print("      supported_nips:", d.get("supported_nips"))
lim=d.get("limitation") or {}
for k in ("max_message_length","max_content_length","max_event_tags","auth_required","restricted_writes"):
    if k in lim: print(f"      {k}:", lim[k])
' 2>/dev/null || printf '%s\n' "$doc"
	else
		err "no NIP-11 document from $local_url — check: journalctl -u bkind -n 50"
		return 1
	fi

	# public reachability, if TLS was configured
	if [[ -n ${DOMAIN:-} ]] && command -v curl >/dev/null 2>&1; then
		if curl -fsS -m 10 -H 'Accept: application/nostr+json' "https://$DOMAIN/" >/dev/null 2>&1; then
			ok "public endpoint https://$DOMAIN answers"
		else
			warn "https://$DOMAIN is not reachable yet (DNS, certificate, or proxy)"
			warn "certificates can take a minute; re-check with:"
			warn "  curl -sS -H 'Accept: application/nostr+json' https://$DOMAIN | jq ."
		fi
	fi

	# persistence reminder rather than an automated test: it needs a real client
	dim "Persistence: publish an event, restart, read it again — see docs §9."
}

step_nak() {
	step "12. End-to-end tests with nak (optional)"
	confirm "Install nak and run the section-9 checks?" n || return 0
	command -v nak >/dev/null 2>&1 || {
		warn "nak needs a Go toolchain: go install github.com/fiatjaf/nak@latest"
		return 0
	}
	warn "run the script in docs/cookbook/deploying.md §9 by hand; it needs your keys"
}

# ------------------------------------------------------------------ main ----

usage() {
	# print the header comment block (everything between the shebang and the
	# first non-comment line)
	awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
	exit 0
}

main() {
	ORIG_ARGS=("$@")
	while (($#)); do
		case "$1" in
		-y | --yes) ASSUME_YES=1 ;;
		--dry-run) DRY_RUN=1 ;;
		--verify) VERIFY_ONLY=1 ;;
		--binary) OPT_BINARY="${2-}"; shift ;;
		--source) OPT_SOURCE="${2-}"; shift ;;
		--git) OPT_GIT="${2-}"; shift ;;
		--domain) OPT_DOMAIN="${2-}"; shift ;;
		--url) OPT_URL="${2-}"; shift ;;
		--addr) OPT_ADDR="${2-}"; shift ;;
		--db) OPT_DB="${2-}"; shift ;;
		--kinds) OPT_KINDS="${2-}"; shift ;;
		--name) OPT_NAME="${2-}"; shift ;;
		--description) OPT_DESC="${2-}"; shift ;;
		--proxy) OPT_PROXY="${2-}"; shift ;;
		--email) OPT_EMAIL="${2-}"; shift ;;
		-h | --help) usage ;;
		*) die "unknown argument: $1 (see --help)" ;;
		esac
		shift
	done
	export ASSUME_YES

	preflight

	if [[ $VERIFY_ONLY == 1 ]]; then
		step_verify
		return
	fi

	step_source
	step_go
	step_build
	step_user
	step_env
	step_policy
	step_unit
	step_proxy
	step_firewall
	step_start
	step_verify
	step_nak

	say ""
	say "${C_GREEN}${C_BOLD}Deployment complete.${C_RESET}"
	say "  config:   $ENV_FILE"
	say "  policy:   $POLICY_FILE"
	say "  store:    ${BKIND_DB:-$STATE_DIR}"
	say "  logs:     journalctl -u bkind -f"
	say "  re-run:   sudo bash $0   (safe; skips what is already in place)"
}

# set BKIND_DEPLOY_LIB=1 to source the functions without running the deployment
if [[ -z ${BKIND_DEPLOY_LIB:-} ]]; then
	main "$@"
fi
