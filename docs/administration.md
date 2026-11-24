# Administration guide

Version 1.4.1. A self-hosted release candidate.

A self-hosted web administration interface for one remotely managed Cloudflare Tunnel. It runs the official `cloudflared` connector automatically as a supervised local process, with a Python standard-library backend and a dependency-free HTML/CSS/JS interface. No SSH keys, Docker socket, host shell access or per-service connector are needed.

## Install on Alpine Linux / Proxmox LXC

Create an unprivileged Alpine LXC with a stable LAN address, 1 CPU, 256–512 MB RAM and at least 1 GB disk. Enable SSH or use the Proxmox console. Transfer and unpack the release archive, then run as root from the extracted `tunnel-manager` directory:

```sh
sh install-alpine.sh
```

The installer downloads the official cloudflared binary if absent, installs Python, creates an unprivileged service account and enables an OpenRC service. Set `CLOUDFLARED_RELEASE` to a reviewed release tag to pin the download. The installer prints the dashboard address and random administrator password. Keep the dashboard on a trusted management network; the native HTTP listener uses port 8080.

For an existing native installation, run from the extracted release directory:

```sh
sh update-alpine.sh
```

This backs up the existing application files in `/root`, replaces the frontend/backend and restarts the service. It checks the local health endpoint and restores the previous application files if startup fails. It does not change `/var/lib/tunnel-manager`, the API token, tunnel ID, routes or administrator password. Expect a short interruption while the connector reconnects. Full backups of `/var/lib/tunnel-manager` and `/etc/conf.d/tunnel-manager` should be kept separately, securely and outside Git.

## Install on Linux (Docker Engine + Compose v2)

1. Buy or use an existing domain; add it to Cloudflare and complete the nameserver change. The domain must show Active. Ensure your Docker host can reach the LAN destinations and Cloudflare on outbound TCP 443 and TCP/UDP 7844. If using Cloudflare Access, create a Zero Trust organization and enable a suitable login method (e.g. One-time PIN).
2. Extract the ZIP on the Docker host, e.g. `/opt/tunnel-manager`. From a terminal in that directory:

   ```sh
   sh install.sh
   ```

   Enter this Docker host's LAN IP (e.g. `192.168.0.20`, not the Jellyfin IP). The script creates `.env` with a random admin password, builds the image and starts it. Save the password. If Docker requires elevated privileges on your system, run the script with `sudo sh install.sh` or use an authorized Docker account.
3. Open `http://192.168.0.20:8080` (replace with the IP you entered) and sign in. The dashboard is intentionally LAN-only by default; do not forward its port or publish it through a tunnel. HTTP is unencrypted, so use a trusted management network; for remote administration use a VPN or a trusted HTTPS reverse proxy and set `SECURE_COOKIE=1` in `.env`. Keep `.env` private. The service binds to the chosen LAN address, not all interfaces. A host firewall is still recommended; Docker-published ports may bypass some firewall configurations.

### Cloudflare API token (one-time)

Go to <https://dash.cloudflare.com/profile/api-tokens> → Create Token → Custom token. Select the account and only the domain(s) you want the app to manage.

| Scope | Permission | Level | Used for |
|---|---|---|---|
| Account | Cloudflare Tunnel | Edit | Create/read/configure tunnel; retrieve connector token |
| Zone | Zone | Read | Discover domain IDs and account |
| Zone | DNS | Edit | Create/remove proxied CNAME records |
| Account | Access: Apps and Policies | Edit | Protected hostnames and allowlist policies |
| Account | Access: Organizations, Identity Providers, and Groups | Read | Discover Zero Trust team name for JWT validation |
| Account | Cloudflare One Networks | Edit | Private IP routes (optional; Tunnel Edit may also cover these) |

Cloudflare may label Edit as Write. If your dashboard splits the Access permissions, select Apps Write and Policies Write or their combined equivalent. Zero Trust Read also works for reading the organization. Avoid the Global API Key. Token permissions are account/zone-scoped, not individual-route scoped. Protected publishing fails if required permissions are missing; it does not silently downgrade to public.

Paste the token into the app, choose your account and create a dedicated tunnel (recommended). Alternatively, attach to an existing remotely managed tunnel. Existing hostname rules appear read-only and are preserved when the app writes its own rules; do not manage the same tunnel concurrently in multiple dashboards. The app creates its connector, obtains its token and starts it; it should show Online once connected. Your existing tunnel's connectors may continue running as replicas, provided they can reach the same origins.

## Add a web service

Public routes → Add route:

- Application name: OpenMediaVault
- Subdomain: omv
- Domain: yourdomain.com
- Protocol: HTTP
- Local IP: 192.168.0.30
- Port: 80 (use your actual OMV web port)
- Access: Email allowlist; enter your authorized email(s).

Click Test connection, then Create route. The app creates a Cloudflare Access application and exclusive allow policy, checks the policy, sets cloudflared JWT validation using the app's audience, writes the tunnel ingress rule, and creates the proxied CNAME. The connector picks up remote configuration automatically. Open `https://omv.yourdomain.com` from a different network to verify the login challenge and application login. DNS/edge TLS issuance may take time. The destination does not need a public IP or port forwarding. Use strong application passwords too. For sensitive admin interfaces, private VPN access is preferable to any public hostname.

The UI accepts RFC1918 IPv4 HTTP/HTTPS origins with an explicit port. For HTTPS with a valid certificate on a different hostname, enter its name in Origin TLS options. Self-signed certificates aren't accepted by default; use a trusted certificate or a private route. Test connection checks HTTP reachability, not application functionality. Check HTTPS only reports the returned status; it does not prove access enforcement or end-to-end functionality.

Pause retains DNS/Access and returns a 404 by default, or the configured global fallback; delete removes managed DNS, ingress and Access. Editing changes the name, origin and TLS name. To change hostname or email policy, create a replacement route or delete and recreate the existing one. If external changes or partial API failures occur, inspect the Cloudflare dashboard before retrying. No multi-resource API transaction exists. Imported hostname rules are not adopted or deleted. Do not configure wildcard catch-all routes that could expose your origins independently of this manager. The local UI is not a continuous Access-policy auditor.

### Paused-route fallback

In Public routes → Pause settings (or Settings → Paused routes), enable the fallback and select Custom HTML, Redirect to URL, or Alternate local origin. It applies to all managed paused routes, including ones already paused. It is off by default. Resuming uses the saved original origin; changing the global fallback never rewrites DNS records or active routes.

- Custom HTML: edit or upload a standalone UTF-8 HTML file up to 32 KiB. The separate loopback listener serves HTTP 503 with no-store headers and a sandbox Content Security Policy. Inline CSS and embedded data images work; JavaScript, forms, remote assets and frames are blocked. Existing CDN rules or service workers can still interfere. No administrator endpoints are exposed by this listener.
- Redirect: a fixed HTTP(S) hostname or IP URL (bare hostname defaults to HTTPS). GET/HEAD receive a temporary HTTP 302; request paths, query strings and bodies are not forwarded. Visitors need network access to the destination; private IPs generally work only on the LAN/VPN.
- Alternate local origin: a private IPv4 HTTP(S) URL with an explicit port. The original hostname stays in the browser. Use a dedicated, trusted fallback server: original requests, cookies and headers may be forwarded to it. HTTPS certificates must validate normally. Direct loops to managed destinations are rejected; indirect DNS/HTTP loops outside the manager cannot be ruled out.

Existing Access applications and their email allowlists remain intact; the connector retains JWT validation on protected fallback routes. Disabling fallback restores HTTP 404 for paused routes. DNS is deliberately left untouched, avoiding DNS propagation delays; this is an ingress/redirect feature, not a DNS A/CNAME switch. Redirect and HTML modes require the locally managed connector on the same host/container as the application, with its loopback port 8081 available. Other connectors attached to the same tunnel must not receive these routes unless they run an equivalent listener with synchronized state. The updater does not expose port 8081 externally.

Pause/resume and global fallback updates are serialized, check DNS and rule ownership, and write a pending transaction before sending a single tunnel configuration update. The new settings are committed only after a read-back matches the intended ingress. The local fallback listener can serve the pending custom page when Cloudflare has already switched traffic to it. If the API is unreachable or the remote state conflicts, the UI displays an unconfirmed-update warning and blocks further mutations until the state is reconciled. The UI automatically polls for confirmation and disables further writes while an update is pending. No update is resent automatically. After 120 seconds, an administrator may explicitly clear an unconfirmed update only if the remote ingress still matches the previous state; a delayed remote write remains possible. Cloudflare has no conditional ingress PUT here, so simultaneous edits from another manager/dashboard are unsupported and may race. Never delete the pending journal without comparing actual Cloudflare configuration and your backups. After using fallback, turn it off and confirm all changes before downgrading to v1.3.

The dashboard defaults to light mode, including after upgrading from v1.3. A user-selected dark theme is saved in that browser.


## Private network routes

Private network routes are optional and independent of public hostnames. Configure Cloudflare One Client enrollment, split tunnels and Gateway rules in your Zero Trust account before adding private routes. A `/32` advertises all ports on a host; restrict access with Gateway policies and host firewall rules. Client enrollment is manual. See [Cloudflare private network documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/).

For public hostnames, select the desired access mode. There are no service-name-based restrictions. Check that your use complies with your provider's terms, including video delivery, and use application authentication for public services.

## Operate, update, and recover

```sh
docker compose ps
docker compose logs -f --tail=100
docker compose down
docker compose up -d
```

The connector is supervised and restarts after failure or machine reboot. The image uses the official cloudflared `latest` image at build time to get current fixes; for reproducible deployment pin a reviewed release or digest in the Dockerfile. To update: `docker compose build --pull && docker compose up -d`. Port 8080 can be changed in `.env` if in use. To change the local administrator password, edit `.env` to a new random password (16+ characters) and run `docker compose up -d --force-recreate`. Sessions expire after 12 hours or restart. The UI logs are in-memory only.

The app stores state, API token and connector token in the `manager-data` named volume with restricted file permissions. These are secrets, not encrypted at rest by the app. Restrict Docker/host access. Settings → Export JSON downloads managed routes and ingress (no bearer or connector tokens); it is a reference/export, not an automatic restore mechanism. Full backup includes the volume and `.env`, kept securely. Example from the project directory:

```sh
docker compose stop
umask 077
docker compose run --rm --no-deps -T --entrypoint tar tunnel-manager -czf - -C /data . > manager-data.tar.gz
docker compose up -d
```

For disaster recovery, restore into the same project with its original `.env`, only if the Cloudflare resources still exist and credentials are valid. Stop the service before restoring. To restore (overwrites matching files in the volume):

```sh
docker compose stop
docker compose run --rm --no-deps -T --entrypoint tar tunnel-manager -xzf - -C /data < manager-data.tar.gz
docker compose up -d
```

Do not use `docker compose down -v` unless you intend to erase local ownership metadata and credentials. To uninstall permanently, delete managed routes and private routes in the UI, stop the container, then remove the tunnel in Cloudflare if no other connectors/routes depend on it. Deleting a container does not delete DNS, Access apps or tunnel resources.

## Deployment notes

One installation manages one account and tunnel, with multiple zones. Existing external routes are read-only. The application has not undergone an independent security audit; verify live access controls before publishing sensitive services.

Official references:
- <https://developers.cloudflare.com/tunnel/get-started/>
- <https://developers.cloudflare.com/tunnel/reference/origin-parameters/>
- <https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/create/>
- <https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/>
- <https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/>
