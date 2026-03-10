# Copilot / AI agent instructions for WebDiagTools

## Big picture
- `server.js` is the application core: Express routes, auth APIs, admin APIs, and network-tool execution (`/api/net-tool`).
- `auth.js` owns authentication middleware order: header auth → bearer token → cookie JWT.
- `db.js` initializes and migrates SQLite schema (`data/ztna-tools.db`) and seeds default roles/permissions.
- UI is server-rendered EJS (`views/*.ejs`) with behavior in `static/js/dashboard.js` and `static/js/admin.js`.

## Runtime/data flow that matters
- `/api/net-tool` validates input, maps whitelisted `tool` values to `spawn(command, args)`, and streams stdout/stderr to the response.
- `nslookup_bulk` is intentionally sequential and chunked; keep this behavior for progressive output.
- Tool access is permission-driven: server checks `tool_${tool}` (or `administration`), UI filters tool options by permission map.
- Auth audit events are logged for password/bearer/header flows; admin UI reads `/api/admin/auth-audit-logs`.

## Security constraints (project-specific)
- Never introduce shell interpolation or user-provided command strings; keep execution in fixed command + argument arrays.
- Keep `/api/net-tool` tool whitelist in sync with UI values in `static/js/dashboard.js` (`ping`, `nslookup`, `nslookup_bulk`, `traceroute`, `mtr`, `openssl_sconnect`, `curl`).
- Header auth trusts proxy headers only when enabled in DB settings (`app_settings`) and `remote_ip` passes allow-list CIDR/IP checks.
- Caddy forwards `remote_ip` (`Caddyfile` header_up); changes here affect header-auth behavior.

## Developer workflows
- Local Node run: `npm install && npm start` (app on `:8080` by default).
- Tailwind assets: `npm run build:tailwind` (prod) or `npm run watch:tailwind` (dev).
- Docker default (with Caddy TLS): `docker compose up --build -d`.
- Linux host-network variant: `docker compose -f docker-compose.yaml -f docker-compose.linux.yaml up --build -d`.
- Manual streaming check (with auth cookie): login via `/api/auth/login`, then `curl -b cookies.txt -N -X POST "$APP_URL/api/net-tool" ...`.

## Integration points and dependencies
- System tools required at runtime (`Dockerfile`): `ping`, `traceroute`, `nslookup/dig`, `mtr`, `openssl`, `curl`.
- Reverse proxy/TLS is expected in default compose via `caddy`; self-signed cert (`tls internal`) may require trust or `--insecure` in curl.
- Persistent state is SQLite in mounted `data/` volume; avoid assuming stateless containers.

## Change patterns to follow
- When adding/removing a tool permission, update all three: DB seed permissions in `db.js`, server permission/whitelist logic in `server.js`, and UI permission map in `static/js/dashboard.js`.
- If auth response shape changes (`/api/auth/me`), update both dashboard/admin clients; they depend on `user.forcePasswordChange` and `permissions` array.
- For auth/header changes, verify both middleware behavior (`auth.js`) and admin settings UX (`static/js/admin.js` + admin routes in `server.js`).
- For streaming/tool changes, validate with `curl -N` and browser UI to confirm progressive chunk rendering.
