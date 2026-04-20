
# ZTNA Network Testing Tools

Web-based network diagnostic toolset that exposes common tools (ping, nslookup, traceroute, mtr (TCP), and OpenSSL TLS connect) via a simple web UI and an API endpoint.

## Features

- Web UI for running common network diagnostics
- Role-based access control with user accounts and permissions
- Administrative panel for user and permission management
- Password reset via email link
- Admin password reset from Docker host CLI
- In-app “Reset Password” option (menu) for authenticated users
- Streaming command output to the browser
- API endpoint for programmatic use: `/api/net-tool` (requires login)
- Optional header bearer token auth for API requests
- Admin authentication audit log (read-only), searchable, CSV export
- Container-friendly (Dockerfile + docker-compose included)
- SQLite database persisted in a mounted volume (data/ztna-tools.db)

## Prerequisites

Install the following tools before starting:

- Git
- Docker Engine
- Docker Compose (Docker CLI plugin)

Example package install on Ubuntu:

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-plugin
sudo systemctl enable --now docker
```

## Installation Guide

1. Clone the repository and enter the project directory:

```bash
git clone https://github.com/pbeyl/WebDiagTools.git
cd WebDiagTools
```

2. Create your environment file:

```bash
cp .env.example .env
```

3. Edit `.env` and set these values:

- `JWT_SECRET`: set a strong secret (example: `openssl rand -base64 32`)
- `APP_HOST`: hostname only, for example `tools.example.com`

`APP_HOST` should match the DNS A record of the target host.

## Run with Docker (Recommended)

From the project root, start the stack:

```bash
docker compose up -d
```

To build the WebDiagTools image locally with Docker Compose, ensure the `webdiagtools` service in `docker-compose.yaml` uses the `build:` block and does not use the `image:` line.

- Uncomment these lines for local builds:
	- `build:`
	- `context: .`
	- `network: host`
- Comment this line out for local builds:
	- `#image: pbeyl/webdiagtools:latest`

Then build and start locally:

```bash
docker compose up --build -d
```

After the containers are running:

1. Open `https://${APP_HOST}` in your browser.
2. Sign in with the default admin credentials:
   - Username: `admin`
   - Password: `admin`

Note: The default TLS certificate is self-signed by Caddy. Your browser may show a certificate warning until you trust it.

## Admin Password Reset From Docker Host CLI

Admins can reset a user password from the Docker host CLI.

Run:

```bash
docker compose exec net-tools-app npm run admin:reset-password -- --username alice
```

## API Usage

The application exposes a POST endpoint at `/api/net-tool` which accepts JSON payloads. Example fields:

- `tool` (string): one of `ping`, `nslookup`, `traceroute`, `mtr`, `openssl_sconnect`
- `host` (string): hostname or IP address
- `dnsServer` (optional string): DNS server for `nslookup`
- `port` (optional number): port for `mtr` (TCP) and `openssl_sconnect` (default: 443)
- `protocol` (optional string): `tcp` or `udp` (validated server-side)
- `debug` (optional boolean): enable more verbose output for certain tools

Authentication options for API calls:

- Session cookie (after `/api/auth/login`)
- Bearer token in header: `Authorization: Bearer <token>`
- Optional trusted-header user identification (admin-configured)

Users can self-manage bearer tokens from the app user menu (`My Profile / API Token`) where they can:

- Update their own email address
- Generate a new bearer token with a selected validity period
- Extend existing bearer token expiry
- Rotate (replace) token value

Important: bearer token values are shown only once at generation time and are never displayed again in the UI.

## Header-Based User Identification (Trusted Proxy)

The admin page includes a **Header Authentication** tab that can map a trusted request header to an existing local username.

### What it does

- Uses a configurable username header (default: `X-Authenticated-User`)
- Looks up the header value as a local app username
- Grants access as that user only when the request `remote_ip` is in the configured allow-list

### Admin configuration

In **Settings → Header Authentication**:

1. Enable or disable header authentication.
2. Set the header name that carries the username (default `X-Authenticated-User`).
3. Configure allowed `remote_ip` values, one per line.
	 - Each line can be a single IP (example: `192.168.1.10`) or CIDR (example: `10.0.0.0/8`).
	 - Default value is `0.0.0.0/0`.

### Request expectations

When this feature is enabled and the configured username header is present, the server expects:

- A username header (for example `X-Authenticated-User: alice`)
- A `remote_ip`-style header representing the original source IP
	- Supported names: `remote_ip`, `remote-ip`, `x-remote-ip`, `x-forwarded-for` (first IP is used)

If the username does not match an active local user, or if `remote_ip` is outside the allow-list, authentication is denied.

### Security warning

Misconfiguration can allow unauthorized access. Only enable this when:

- The app is behind a trusted reverse proxy or identity gateway
- Direct access to the app is blocked (so clients cannot forge auth headers)
- The proxy strips inbound spoofed headers and injects verified identity headers
- Allowed `remote_ip` ranges are as strict as possible

Example curl request (streaming output):

```bash
curl -N -X POST http://localhost:8080/api/net-tool \
	-H "Content-Type: application/json" \
	-d '{"tool":"ping","host":"8.8.8.8"}'
```

Example curl request with bearer token:

```bash
curl -N -X POST http://localhost:8080/api/net-tool \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer YOUR_TOKEN_VALUE" \
	-d '{"tool":"ping","host":"8.8.8.8"}'
```

Example: TLS handshake and show certificates:

```bash
curl -N -X POST http://localhost:8080/api/net-tool \
	-H "Content-Type: application/json" \
	-d '{"tool":"openssl_sconnect","host":"example.com","port":443,"debug":true}'
```

The server streams subprocess `stdout` and `stderr` directly back in the response.

## Environment Variables (Security Controls)

The following optional variables can be set in `.env` to tune runtime protections:

- `NET_TOOL_REQUEST_TIMEOUT_MS` (default: `15000`)
	- Maximum runtime per `/api/net-tool` request before subprocesses are terminated.
- `NET_TOOL_MAX_OUTPUT_BYTES` (default: `262144`)
	- Maximum total response output size per `/api/net-tool` request.
- `API_RATE_LIMIT_MAX_REQUESTS` (default: `4`)
	- Maximum number of `/api/*` requests allowed per rate-limit window.
- `API_RATE_LIMIT_WINDOW_MS` (default: `1000`)
	- Duration of the rate-limit window in milliseconds.

Rate-limit identities are determined in this order:

1. Header-auth username (when trusted header auth is enabled)
2. Bearer token (hashed for keying)
3. Cookie-auth user (`userId` from JWT)
4. Source IP fallback

## Authentication Audit Log

Admins can access **Settings → Auth Audit Log** to review authentication activity.

- Captures authentication successes and failures for `password`, `token`, and `header` auth types
- Stores timestamp, auth type, username, role, source IP, request method/path, failure reason, and relevant request header metadata
- Supports front-end filtering via the search field
- Supports CSV export from the page using the export button
- Retains records for up to 90 days (3 months) via automatic cleanup

Storage design: authentication audit entries are persisted in SQLite (`auth_audit_logs` table) with indexes on timestamp, auth type, and username for efficient filtering.

## Security Notes

- This application executes system network tools on behalf of HTTP clients. Do not expose it to untrusted networks or the public internet without additional access controls (authentication, IP allow-lists, rate-limiting).
- The server performs basic input sanitization and tool whitelisting, but running arbitrary commands from user-supplied input remains risky. Use in controlled environments only.

## Files of Interest

- `server.js` — Express server and tool execution logic (API implementation)
- `dashboard.html` — Front-end UI
- `Dockerfile` — Container image definition
- `docker-compose.yaml` — Compose file for container runs

## Contributing

Fixes, improvements, and documentation updates are welcome. Please open issues or PRs.

