#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: sudo $0 <HOST_IP> [LOGSTASH_CN=logstash.local] [REMOTE_PORT=2514]"
  exit 1
fi

HOST_IP="$1"
CN="${2:-logstash.local}"
PORT="${3:-2514}"

# Pre-req: copy the host cert first:
#   scp <host>:/path/to/elk-siem/logstash/certs/logstash.crt /tmp/logstash.crt

if [ ! -f /tmp/logstash.crt ]; then
  echo "ERROR: /tmp/logstash.crt not found. scp it from host and retry."
  exit 2
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog rsyslog-relp

install -o root -g root -m 0644 /tmp/logstash.crt /etc/rsyslog.d/ca.crt

mkdir -p /var/log/rtdst
touch /var/log/rtdst/events.ndjson
chown syslog:adm /var/log/rtdst/events.ndjson
chmod 0644 /var/log/rtdst/events.ndjson

cat >/etc/rsyslog.d/30-rtdst.conf <<EOF
module(load="imfile")
module(load="omrelp")
module(load="gtls")

\$MaxMessageSize 64k
\$EscapeControlCharactersOnReceive off

template(name="jsononly" type="string" string="%msg%\\n")

ruleset(name="send2siem") {
  queue.type="LinkedList"
  queue.size="10000"
  queue.dequeueBatchSize="1000"
  queue.maxdiskspace="1g"
  queue.filename="rtdst_relp"
  queue.saveonshutdown="on"
  queue.discardMark="9500"
  queue.highWatermark="8000"

  action(
    type="omrelp"
    target="${HOST_IP}"
    port="${PORT}"
    tls="on"
    tls.caCert="/etc/rsyslog.d/ca.crt"
    tls.permittedPeer="${CN}"
    template="jsononly"
    action.resumeRetryCount="-1"
    action.resumeInterval="10"
    ratelimit.interval="0"
  )
}

input(
  type="imfile"
  File="/var/log/rtdst/events.ndjson"
  Tag="rtdst:"
  ruleset="send2siem"
  addMetadata="on"
  readMode="2"
)
EOF

cat >/etc/logrotate.d/rtdst <<'EOF'
/var/log/rtdst/*.ndjson {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
EOF

systemctl restart rsyslog
sleep 1
systemctl --no-pager --full status rsyslog || true

# Smoke test
echo '{"@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","host":{"hostname":"'"$(hostname)"'"},"rtds":{"event_type":"PING","event_id":1}}' >> /var/log/rtdst/events.ndjson
echo "[victim-setup] Wrote a PING line to /var/log/rtdst/events.ndjson"
echo "[victim-setup] If Logstash is reachable at ${HOST_IP}:${PORT}, it should appear in Kibana (index: rtdst-syscalls*)."