
# ZTNA Network Testing Tools

Web-based network diagnostic toolset that exposes common tools (ping, nslookup, traceroute, mtr (TCP), and OpenSSL TLS connect) via a simple web UI and an API endpoint.

## Features

- Web UI for running common network diagnostics
- Role-based access control with user accounts and permissions
- Administrative panel for user and permission management
- Password reset via email link
- In-app “Reset Password” option (menu) for authenticated users
- Streaming command output to the browser
- API endpoint for programmatic use: `/api/net-tool` (requires login)
- Optional header bearer token auth for API requests
- Container-friendly (Dockerfile + docker-compose included)
- SQLite database persisted in a mounted volume (data/ztna-tools.db)

## Prerequisites

Before running the app, ensure one of the following environments is available.

- Docker (recommended) or Node.js 18+ and npm/yarn to run locally
- On Linux hosts (or containers) the following system packages are required for full functionality:
	- `iputils-ping` (provides `ping`)
	- `traceroute` (provides `traceroute`)
	- `dnsutils` (provides `nslookup` / `dig`)
	- `mtr` (provides `mtr`)
	- `openssl` (provides `openssl s_client`)

Note: Running network tools such as `ping`, `traceroute`, and `mtr` from inside a container often requires elevated network capabilities. The container examples below grant `NET_RAW` and `NET_ADMIN` capabilities; you can also use `network_mode: host` on Linux.

## Ubuntu (20.04 / 22.04 / 24.04) — Installation Guide

Follow these steps to prepare an Ubuntu machine to run the app locally or build the Docker image.

1) Update packages and install system requirements (for host-based runs):

```bash
sudo apt update
sudo apt install -y iputils-ping traceroute dnsutils mtr openssl curl ca-certificates
```

2) (Optional but recommended) Install Node.js 18+ via NodeSource (for running locally without Docker):

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs build-essential
node -v
npm -v
```

3) Install Docker (if you plan to run via Docker):

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER  # optional: allows running docker without sudo (re-login required)
```

With these prerequisites satisfied you can either run the project using Docker (recommended) or run it locally with Node.

## Run with Docker (recommended)

The repository includes a `Dockerfile` and `docker-compose.yaml` for an easy build + run.

Build and run with Docker Compose (with Caddy reverse proxy and self-signed TLS):

```bash
# From the project root (where docker-compose.yaml lives)
docker compose up --build -d
# or with classic docker-compose
docker-compose up --build -d
```

By default, Caddy will:

- Terminate HTTPS with a self-signed certificate issued by its internal CA.
- Serve the app on the hostname from `APP_HOST` (which must match the host part of `APP_URL`).
- Reverse proxy requests to the application container on port `8080`.

Once running, open your browser to your configured URL, for example: `https://tools.example.com`. Because the certificate is self-signed, you will need to trust it in your browser/OS.

If you need raw network capabilities (ICMP, traceroute, mtr) the compose file already requests `NET_RAW` and `NET_ADMIN` capabilities; for a Linux host you may alternatively use the provided linux variant which uses `network_mode: host`:

```bash
# linux-specific compose override (uses host networking)
docker compose -f docker-compose.yaml -f docker-compose.linux.yaml up --build -d
```

Or build and run the container manually (example with capabilities, without Caddy/TLS):

```bash
docker build -t net-tools .
docker run --rm -it -p 8080:8080 --cap-add=NET_RAW --cap-add=NET_ADMIN --name net-tools net-tools
```

Open your browser to: http://localhost:8080

## Run Locally (without Docker)

1. Install Node.js 18+ and the system packages listed in "Prerequisites".
2. From the project root:

```bash
npm install
npm start
```

The server listens on port `8080` by default. Visit http://localhost:8080

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

## Security Notes

- This application executes system network tools on behalf of HTTP clients. Do not expose it to untrusted networks or the public internet without additional access controls (authentication, IP allow-lists, rate-limiting).
- The server performs basic input sanitization and tool whitelisting, but running arbitrary commands from user-supplied input remains risky. Use in controlled environments only.

## Files of Interest

- `server.js` — Express server and tool execution logic (API implementation)
- `dashboard.html` — Front-end UI
- `Dockerfile` — Container image definition
- `docker-compose.yaml` and `docker-compos.linux.yaml` — Compose files for container runs

## Contributing

Fixes, improvements, and documentation updates are welcome. Please open issues or PRs.

