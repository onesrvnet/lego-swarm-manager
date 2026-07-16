# lego-swarm-manager

A tiny [lego](https://go-acme.github.io/lego/) container that discovers domains from your **Traefik** router labels on a **Docker Swarm**, then issues and renews **Let's Encrypt** certificates for them — and writes a Traefik dynamic TLS config so Traefik serves those certs. ACME is fully external to Traefik; `certd` is the single ACME writer.

## How it works

On each cycle (`INTERVAL` seconds) the `certd.sh` entrypoint:

1. **Discovers domains** — inspects every Swarm service and extracts hostnames from `traefik.http.routers.*.rule` labels (`Host(\`...\`)`).
2. **Issues / renews certs** via lego:
   - Domains under a zone listed in `DNS_ZONES` use **DNS-01** (required for wildcards).
   - Everything else falls back to **HTTP-01** via lego's internal challenge server (Traefik must route `/.well-known/acme-challenge/` to this container on `HTTP_CHALLENGE_PORT`).
   - Renewals are no-ops until within `RENEW_DAYS` of expiry.
   - **HTTP-01 reachability preflight** (`PREFLIGHT=1`, default): before issuing/renewing an HTTP-01 domain, certd makes the same request Let's Encrypt will — an HTTP GET to `http://<domain>/.well-known/acme-challenge/…`. If nothing answers over HTTP the challenge can't succeed, so the domain is skipped and no failed-validation quota (5 per hostname per hour) is spent. DNS-01 domains aren't probed (they validate via a TXT record, not host reachability), and healthy certs are skipped entirely.
3. **Generates** `traefik-tls.yml` (a dynamic TLS config) atomically, which Traefik watches via its file provider.

Certs and lego state live on a shared volume (e.g. CephFS) so any manager node can read them. Run **exactly one** `certd` replica — it is the single ACME writer.

## Image

Published to GHCR on every GitHub release:

```
ghcr.io/onesrvnet/lego-swarm-manager:latest
ghcr.io/onesrvnet/lego-swarm-manager:<release-tag>
```

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `ACME_EMAIL` | yes | — | Account email for Let's Encrypt. |
| `DNS_PROVIDER` | yes | — | lego DNS provider name (e.g. `cloudflare`, `hetzner`). |
| `DNS_ZONES` | — | — | Comma-separated zones whose (sub)domains use DNS-01. Everything else uses HTTP-01. |
| `STATIC_DOMAINS` | — | — | Comma-separated domains/wildcards to always issue (e.g. `*.example.com,*.example.eu`). Wildcards require DNS-01. |
| `HTTP_CHALLENGE_PORT` | — | `8402` | Port for lego's internal HTTP-01 server. |
| `EXCLUDE_REGEX` | — | — | Regex of domains to skip (e.g. `\.local$`). |
| `INTERVAL` | — | `300` | Seconds between cycles. |
| `RENEW_DAYS` | — | `30` | Renew when within this many days of expiry. |
| `CERT_DIR` | — | `/letsencrypt` | Shared volume for lego state and generated config. |
| `ACME_SERVER` | — | LE production | Set to the LE staging directory URL to test first. |
| `PREFLIGHT` | — | `1` | HTTP GET the domain before an HTTP-01 issue/renew; skip if unreachable. Set `0` to disable. |
| `HTTP_PROBE_TIMEOUT` | — | `5` | Seconds for the HTTP-01 reachability probe. |

Provider credentials are passed as env vars per the [lego provider docs](https://go-acme.github.io/lego/dns/) (e.g. `CLOUDFLARE_DNS_API_TOKEN_FILE`).

## Usage

See [`docker-compose.example.yaml`](docker-compose.example.yaml) for a complete HA Traefik + certd Swarm stack.

```bash
docker stack deploy -c docker-compose.example.yaml ingress
```

Services opt in with the usual Traefik labels — no `certresolver` needed:

```yaml
deploy:
  labels:
    - traefik.enable=true
    - traefik.http.routers.myapp.rule=Host(`app.example.com`)
    - traefik.http.routers.myapp.entrypoints=websecure
    - traefik.http.routers.myapp.tls=true
    - traefik.http.services.myapp.loadbalancer.server.port=8080
```

## Building locally

```bash
docker build -t lego-swarm-manager .
```

The lego version is pinned via the `LEGO_VERSION` build arg (linux/amd64 only).

## License

[Apache-2.0](LICENSE)
