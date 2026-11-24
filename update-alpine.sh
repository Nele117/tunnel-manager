#!/bin/sh
set -eu
cd "$(dirname "$0")"
DEST=/opt/tunnel-manager
[ "$(id -u)" = 0 ] || { echo 'Run as root.'; exit 1; }
[ -f "$DEST/app.py" ] && [ -f /etc/init.d/tunnel-manager ] || { echo 'Existing installation not found.'; exit 1; }
python3 -m py_compile app.py
umask 077
BACKUP=$(mktemp -d /root/tunnel-manager-backup.XXXXXX)
cp -p "$DEST/app.py" "$BACKUP/app.py"
cp -p "$DEST/static/index.html" "$BACKUP/index.html"
cp -p /etc/init.d/tunnel-manager "$BACKUP/service"
rollback() {
  echo 'Update failed; restoring previous application files.'
  cp -p "$BACKUP/app.py" "$DEST/app.py"
  cp -p "$BACKUP/index.html" "$DEST/static/index.html"
  cp -p "$BACKUP/service" /etc/init.d/tunnel-manager
  rc-service tunnel-manager restart || true
}
rc-service tunnel-manager stop || exit 1
if ! (install -m 644 app.py "$DEST/app.py" && install -m 644 static/index.html "$DEST/static/index.html" && sed -i '/^export PATH=/d' /etc/init.d/tunnel-manager && rc-service tunnel-manager start); then
  rollback; exit 1
fi
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "Updated to v1.4.1. Backup: $BACKUP"
    exit 0
  fi
  sleep 2
done
rollback
exit 1
