#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo 'Install Docker Engine and the Compose plugin first.'; exit 1; }
docker compose version >/dev/null
if [ ! -f .env ]; then
  printf 'Enter the LAN IP of THIS server (example: 192.168.0.20): '
  read -r ip
  case "$ip" in 10.*|192.168.*|172.*) ;; *) echo 'Enter a private LAN IPv4 address.'; exit 1;; esac
  printf '%s\n' "$ip" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1; if($1==172&&($2<16||$2>31)) exit 1}' || { echo 'Invalid private IP.'; exit 1; }
  pass=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  umask 077
  printf 'BIND_IP=%s\nMANAGER_PORT=8080\nADMIN_PASSWORD=%s\nSECURE_COOKIE=0\n' "$ip" "$pass" > .env
  printf '\nDashboard: http://%s:8080\nAdministrator password: %s\nSave this password. It is also stored in .env.\n\n' "$ip" "$pass"
else
  echo 'Using existing .env; credentials unchanged.'
fi
docker compose up -d --build
echo 'Open the dashboard address printed above (or check BIND_IP and MANAGER_PORT in .env).'
