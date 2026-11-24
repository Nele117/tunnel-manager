#!/bin/sh
set -eu
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo 'Run as root.'; exit 1; }
[ ! -e /etc/init.d/tunnel-manager ] && [ ! -e /var/lib/tunnel-manager/state.json ] || { echo 'Existing installation detected. Use update-alpine.sh.'; exit 1; }
apk add --no-cache python3 curl ca-certificates
if ! command -v cloudflared >/dev/null 2>&1 && [ ! -x /usr/local/bin/cloudflared ]; then
  case "$(uname -m)" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) echo 'Unsupported architecture'; exit 1;; esac
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  if [ -n "${CLOUDFLARED_RELEASE:-}" ]; then release="download/$CLOUDFLARED_RELEASE"; else release="latest/download"; fi
  curl -fsSL --retry 3 "https://github.com/cloudflare/cloudflared/releases/$release/cloudflared-linux-$arch" -o "$tmp"
  install -m 755 "$tmp" /usr/local/bin/cloudflared
fi
mkdir -p /opt/tunnel-manager/static /var/lib/tunnel-manager
install -m 644 app.py /opt/tunnel-manager/app.py
install -m 644 static/index.html /opt/tunnel-manager/static/index.html
id tunnelmgr >/dev/null 2>&1 || { addgroup -S tunnelmgr; adduser -S -D -H -G tunnelmgr -s /sbin/nologin tunnelmgr; }
chown tunnelmgr:tunnelmgr /var/lib/tunnel-manager
chmod 700 /var/lib/tunnel-manager
touch /var/log/tunnel-manager.log
chown tunnelmgr:tunnelmgr /var/log/tunnel-manager.log
PASS=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
ADDR=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')
[ -n "$ADDR" ]
cat > /etc/init.d/tunnel-manager <<'EOF'
#!/sbin/openrc-run
name="Tunnel Manager"
command="/usr/bin/python3"
command_args="/opt/tunnel-manager/app.py"
command_user="tunnelmgr:tunnelmgr"
directory="/opt/tunnel-manager"
supervisor="supervise-daemon"
pidfile="/run/tunnel-manager-supervisor.pid"
respawn_delay=5
respawn_max=0
export DATA_DIR=/var/lib/tunnel-manager
export PYTHONUNBUFFERED=1
export ADMIN_PASSWORD MANAGER_HOST_IP
output_log=/var/log/tunnel-manager.log
error_log=/var/log/tunnel-manager.log
depend() { need net; }
EOF
chmod 755 /etc/init.d/tunnel-manager
umask 077
printf 'ADMIN_PASSWORD=%s\nMANAGER_HOST_IP=%s\n' "$PASS" "$ADDR" > /etc/conf.d/tunnel-manager
rc-update add tunnel-manager default
rc-service tunnel-manager start
printf 'Dashboard: http://%s:8080\nPassword: %s\n' "$ADDR" "$PASS"
