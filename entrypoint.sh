#!/bin/sh
# entrypoint.sh — brings up one WireGuard interface per *.conf file found in
# CONFIG_DIR, then execs the Go proxy binary.
#
# Required Docker flags:
#   --cap-add NET_ADMIN
#
# Environment variables (all optional):
#   CONFIG_DIR     — directory to scan for *.conf files (default: /etc/wireguard/configs)
#   MANIFEST_PATH  — path to write the interface manifest JSON for the proxy (default: /run/wg-proxy/manifest.json)

set -e

CONFIG_DIR="${CONFIG_DIR:-/etc/wireguard/configs}"
MANIFEST_PATH="${MANIFEST_PATH:-/run/wg-proxy/manifest.json}"
MANIFEST_DIR="$(dirname "$MANIFEST_PATH")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[entrypoint] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

# Extract a key=value from a wg-quick .conf file (case-insensitive key, strips spaces).
# Usage: get_field <file> <section> <key>
# Returns the value, or empty string if not found.
get_field() {
    local file="$1" section="$2" key="$3"
    awk -v sect="$section" -v key="$key" '
        /^\[/ { in_section = (tolower($0) == "[" tolower(sect) "]") }
        in_section && /^[[:space:]]*/ {
            if (match(tolower($0), "^[[:space:]]*" tolower(key) "[[:space:]]*=")) {
                sub(/^[^=]*=[[:space:]]*/, "")
                print; exit
            }
        }
    ' "$file"
}

# Write a cleaned copy of a .conf file with wg-quick-only directives removed
# so that `wg setconf` can parse it.
strip_wg_quick_keys() {
    local src="$1" dst="$2"
    grep -v -iE '^\s*(Address|DNS|Table|MTU|PostUp|PostDown|PreDown|PreUp|SaveConfig)\s*=' "$src" > "$dst"
}

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------

command -v wg    >/dev/null 2>&1 || die "'wg' not found — is wireguard-tools installed?"
command -v ip    >/dev/null 2>&1 || die "'ip' not found — is iproute2 installed?"

if [ ! -d "$CONFIG_DIR" ]; then
    die "CONFIG_DIR '$CONFIG_DIR' does not exist. Mount your WireGuard configs there."
fi

# ---------------------------------------------------------------------------
# Discover config files
# ---------------------------------------------------------------------------

CONFIGS=$(find "$CONFIG_DIR" -maxdepth 1 -name '*.conf' | sort)
if [ -z "$CONFIGS" ]; then
    die "No *.conf files found in '$CONFIG_DIR'."
fi

CONFIG_COUNT=$(echo "$CONFIGS" | wc -l | tr -d ' ')
log "Found $CONFIG_COUNT config file(s) in $CONFIG_DIR"

# ---------------------------------------------------------------------------
# Setup: one WireGuard interface per config, custom policy routing per tunnel
# ---------------------------------------------------------------------------

mkdir -p "$MANIFEST_DIR"
TMPCONF="$(mktemp)"

# Start building the JSON manifest list for the proxy.
printf '[' > "$MANIFEST_PATH"
FIRST=1
INDEX=0

for CONF in $CONFIGS; do
    IFACE="wg${INDEX}"

    log "Setting up $IFACE from $CONF"

    # Parse the Address field from [Interface].
    ADDRESS="$(get_field "$CONF" Interface Address)"
    if [ -z "$ADDRESS" ]; then
        log "WARNING: No Address= found in $CONF — $IFACE will have no IP assigned"
    fi

    # Strip wg-quick-only directives before passing to wg setconf.
    strip_wg_quick_keys "$CONF" "$TMPCONF"

    # Create the WireGuard interface (kernel module).
    ip link add "$IFACE" type wireguard 2>/dev/null || {
        log "Interface $IFACE already exists — removing and recreating"
        ip link del "$IFACE"
        ip link add "$IFACE" type wireguard
    }

    # Load keys and peers.
    wg setconf "$IFACE" "$TMPCONF"

    # Assign IP address.
    if [ -n "$ADDRESS" ]; then
        ip address add "$ADDRESS" dev "$IFACE"
    fi

    # Bring the interface up.
    ip link set "$IFACE" up

    # NOTE: No ip rule / ip route entries are needed.
    #
    # The proxy uses SO_BINDTODEVICE to force each client connection's traffic
    # out through a specific WireGuard interface. The kernel bypasses the normal
    # routing table for SO_BINDTODEVICE sockets and sends packets directly
    # through the bound interface.
    #
    # WireGuard's own encrypted UDP (sent to the peer's endpoint IP) uses a
    # separate socket inside the kernel module that is NOT bound to the tunnel
    # interface. It uses the main routing table → container default gateway
    # (eth0) → internet → peer. This works correctly without any policy routing.
    #
    # Policy routing (ip rule + ip route) is only required when you want ALL
    # unbound traffic to flow through the tunnel, which is not this use case.
    # Adding policy routing for multiple full-tunnel interfaces in the same
    # network namespace would cause routing loops (wg0's encrypted UDP would
    # match wg1's policy rule and be sent back through wg1).

    log "$IFACE is up (address: ${ADDRESS:-none})"

    # Append to JSON manifest.
    # Strip the /prefix-len for the display address but keep the original.
    if [ "$FIRST" = "1" ]; then
        FIRST=0
    else
        printf ',' >> "$MANIFEST_PATH"
    fi
    printf '{"interface":"%s","address":"%s"}' "$IFACE" "$ADDRESS" >> "$MANIFEST_PATH"

    INDEX=$((INDEX + 1))
done

rm -f "$TMPCONF"

printf ']' >> "$MANIFEST_PATH"

log "Manifest written to $MANIFEST_PATH"
log "WireGuard setup complete. Starting proxy…"

# ---------------------------------------------------------------------------
# Exec the proxy (replaces this shell so signals propagate correctly)
# ---------------------------------------------------------------------------

exec /app/proxy
