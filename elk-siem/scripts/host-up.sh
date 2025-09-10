#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

LOGSTASH_SSL_CN=${LOGSTASH_SSL_CN:-logstash.local}
ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme}

mkdir -p logstash/certs
if [ ! -f logstash/certs/logstash.key ] || [ ! -f logstash/certs/logstash.crt ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout logstash/certs/logstash.key -out logstash/certs/logstash.crt \
    -subj "/CN=${LOGSTASH_SSL_CN}"
  echo "[host-up] Generated self-signed cert (CN=${LOGSTASH_SSL_CN})"
fi

docker compose up -d

echo "[host-up] Waiting for Elasticsearch..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200 >/dev/null; do
  sleep 2
done

./scripts/host-setup-ilm.sh
echo "[host-up] Done. Kibana: http://localhost:5601  (elastic/${ELASTIC_PASSWORD})"
echo "[host-up] Cert to copy to victim: $(pwd)/logstash/certs/logstash.crt"