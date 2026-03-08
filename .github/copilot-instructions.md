# Copilot / AI agent instructions for WebDiagTools

This repository is a small web app that exposes common network diagnostic tools via a web UI and a streaming API. Use these notes to make focused, safe code changes and to run/debug the app quickly.

- Purpose: Web-based network diagnostic toolkit (ping, nslookup, traceroute, mtr, openssl s_client) with role-based access and streaming output.
- Entry points:
  - `server.js` — Express server and API (`/api/net-tool`, `/api/auth/*`). Primary place to change server logic and tool execution.
  - `static/js/dashboard.js` — Frontend UI logic, permission-to-tool mapping, and client-side streaming reader.
  - `views/*.ejs` — Server-rendered pages (login, dashboard, admin).

- Key runtime behaviors to respect:
  - The server streams subprocess stdout/stderr to the HTTP response. Clients (browser `fetch` reader) rely on streamed chunks to update the UI progressively.
  - The server executes OS-level network tools — avoid introducing any new user-driven shell execution. Work within the whitelisted `tool` values and server-side validation.
  - Role/permission model is used to hide tools in the UI. Example permission names from `static/js/dashboard.js`:
    - `administration` (full admin access)
    - `tool_ping`, `tool_nslookup`, `tool_nslookup_bulk`, `tool_traceroute`, `tool_mtr`, `tool_openssl`, `tool_curl`

- Developer workflows (commands used in this repo):
  - Docker (recommended):
    - Typical commands:
      - Build + run (default, with Caddy TLS reverse proxy):
        `docker compose up --build -d`
      - Linux variant (uses host networking for raw network tools):
        `docker compose -f docker-compose.yaml -f docker-compose.linux.yaml up --build -d`
      - Direct container run (example, grants elevated network capabilities):
        `docker build -t net-tools . && docker run --rm -it -p 8080:8080 --cap-add=NET_RAW --cap-add=NET_ADMIN --name net-tools net-tools`
    - Notes about compose and volumes:
      - `data/` is mounted into the container to persist the SQLite DB (`data/ztna-tools.db`).
      - The default compose brings up a Caddy container that terminates TLS and reverse-proxies to the app on `:8080`.
  - Streaming API examples (useful for integration tests):
    - Example using the `APP_URL` env value (ensure this matches your `.env`):
      ```bash
      export APP_URL=https://tools.example.local
      curl -N -X POST "$APP_URL/api/net-tool" -H "Content-Type: application/json" -d '{"tool":"ping","host":"8.8.8.8"}'
      ```
    - Authentication note: the API requires an authenticated session cookie. Use the login endpoint to obtain a cookie jar, then pass it with `-b`. Make sure the host in your curl command matches `APP_URL` in `.env` (scheme + host).
      - Login and save cookie jar (example):
        ```bash
        export APP_URL=https://tools.example.local
        curl -c cookies.txt -s -X POST "$APP_URL/api/auth/login" \
          -H "Content-Type: application/json" \
          -d '{"username":"admin","password":"changeme"}'
        ```
      - Use the saved cookie to call the streaming API:
        ```bash
        curl -b cookies.txt -N -X POST "$APP_URL/api/net-tool" \
          -H "Content-Type: application/json" \
          -d '{"tool":"ping","host":"8.8.8.8"}'
        ```
      - HTTPS / Caddy notes: when the app is fronted by Caddy with TLS, the session cookie may be set with the `Secure` flag. Use the HTTPS host that matches `APP_HOST`/`APP_URL` and, if testing a self-signed Caddy certificate, include `--insecure` or trust the CA locally.

- Important environment / infra notes:
  - The app expects local OS packages for the network tools: `iputils-ping`, `traceroute`, `dnsutils`, `mtr`, `openssl`.
  - The compose file may add `--cap-add=NET_RAW --cap-add=NET_ADMIN` or use `network_mode: host` for Linux.
  - Caddy and TLS behaviour:
    - The repository ships a `Caddyfile` and the default `docker-compose.yaml` runs a Caddy container as a reverse proxy.
    - Caddy issues a self-signed certificate (internal CA) in the default setup — you will need to trust it in your browser/OS for local testing.
    - Caddy reverse-proxies requests to the application container on port `8080`. The app expects `APP_HOST` / `APP_URL` to be configured to match the host used by Caddy.
    - If you change routing or the proxy port, update `server.js` or `Dockerfile` environment expectations accordingly.
  - SQLite DB file lives under `data/` (persisted volume): `data/ztna-tools.db`.

- Conventions and patterns specific to this project:
  - Keep changes small and focused near `server.js` when adjusting tool execution or streaming behavior; the front-end assumes a streaming text payload and a simple newline-delimited stream.
  - Permission strings are authoritative for UI visibility. Update both server-side auth logic and `static/js/dashboard.js` mapping when adding/removing tool permissions.
  - Password reset flow: the client honors a `user.forcePasswordChange` flag and forces the modal open (`static/js/dashboard.js`). If you change user fields or API responses, update the client expectation accordingly.

- Files to check when making changes:
  - `server.js` — API implementation and tool whitelist/validation.
  - `auth.js` — authentication helpers and session handling.
  - `db.js` — DB access pattern (SQLite usage).
  - `static/js/dashboard.js` — permission mapping, tool UI, and streaming client code.
  - `static/js/*` - javascript files for UI logic and API calls (dashboard, admin, auth)
  - `views/*` — templates for UI elements and modals (reset-password, admin)
  - `views/partials/header.ejs` - contains common header elements and modal dialogs 
  
- Safety and testing guidance for PRs:
  - Do not expose new endpoints that allow arbitrary command execution.
  - When changing streaming behavior, test with `curl -N` and the browser UI to ensure no regressions in progressive output.
  - For Docker-related changes, test docker compose successfully runs the application.

If anything here is incomplete or you'd like guidance to be more specific to a file or workflow, tell me which area to expand. I'll iterate quickly.
