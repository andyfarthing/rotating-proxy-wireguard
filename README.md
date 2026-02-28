# multi-wireguard-proxy

An HTTP/HTTPS proxy that routes outbound connections through a pool of WireGuard tunnels. Each connection is assigned an exclusive tunnel for its lifetime, with tunnels distributed in round-robin order. When all tunnels are busy, new connections wait up to a configurable timeout before receiving a 503.

## How it works

1. On startup, the entrypoint script reads all `.conf` files from `configs/`, brings up a WireGuard interface for each, and configures per-tunnel policy routing so that outbound traffic is bound to the correct interface.

2. The Go proxy listens for HTTP and HTTPS (`CONNECT`) requests and leases a tunnel slot to each connection from the pool.

3. Connections are forwarded through the leased tunnel. When the connection closes, the tunnel is returned to the pool.

## Requirements

- Docker with `NET_ADMIN` capability (required for WireGuard)
- One or more WireGuard `.conf` files from your VPN provider

## Configuration

Place your WireGuard `.conf` files in the `configs/` directory. See `configs/example-WG.conf.example` for the expected format. Each file becomes one tunnel in the pool.

## Usage

```sh
docker compose up --build
```

The proxy is available at `http://localhost:8080`. Configure your HTTP client or tool to use this as its proxy.

The web UI is available at `http://localhost:8088` and shows per-tunnel status and statistics.

## Environment variables

| Variable         | Default                       | Description                                             |
| ---------------- | ----------------------------- | ------------------------------------------------------- |
| `PROXY_PORT`     | `8080`                        | Port the proxy listens on                               |
| `WEB_UI_PORT`    | `8088`                        | Port the web UI listens on (`0` to disable)             |
| `LEASE_TIMEOUT`  | `30s`                         | How long to wait for a free tunnel before returning 503 |
| `DIAL_TIMEOUT`   | `30s`                         | Timeout for dialling upstream through the tunnel        |
| `STATS_INTERVAL` | `5s`                          | How often to poll WireGuard stats for the web UI        |
| `LOG_LEVEL`      | `info`                        | Log verbosity: `debug`, `info`, `warn`, `error`         |
| `CONFIG_DIR`     | `/etc/wireguard/configs`      | Directory scanned for `.conf` files                     |
| `MANIFEST_PATH`  | `/run/wg-proxy/manifest.json` | Path for the interface manifest written at startup      |

## Running tests

```sh
cd tests
python -m pytest
```

Tests require the proxy to be running. See `tests/requirements.txt` for dependencies.
