#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

ES_URL=${ES_URL:-http://localhost:9200}
ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme}

echo "[host-setup-ilm] Applying ILM policy..."
curl -s -u "elastic:${ELASTIC_PASSWORD}" -X PUT \
  "${ES_URL}/_ilm/policy/rtdst-ilm" \
  -H 'Content-Type: application/json' \
  --data-binary @scripts/ilm.json >/dev/null
echo "[host-setup-ilm] ILM policy applied."

echo "[host-setup-ilm] Applying index template..."
curl -s -u "elastic:${ELASTIC_PASSWORD}" -X PUT \
  "${ES_URL}/_index_template/rtdst-template" \
  -H 'Content-Type: application/json' \
  --data-binary @scripts/index-template.json >/dev/null
echo "[host-setup-ilm] Index template applied."