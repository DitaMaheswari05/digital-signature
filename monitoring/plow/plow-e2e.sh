
PROXY_URL="${PROXY_URL:-http://proxy:8080}"
TARGET_PATH="${TARGET_PATH:-/api/data}"
REQUESTS="${REQUESTS:-10000}"
CONCURRENCY="${CONCURRENCY:-50}"
DURATION="${DURATION:-}"

FULL_URL="$PROXY_URL$TARGET_PATH"

echo "============================================"
echo "  Plow Load Test â€” END-TO-END"
echo "  Target      : $FULL_URL"
echo "  Requests    : $REQUESTS"
echo "  Concurrency : $CONCURRENCY"
echo "  Chain       : Plow->Proxy->WAF->WafSvc->WebApp"
echo "============================================"
echo ""

echo "[Phase 1] GET requests (handshake only, no CMS body)..."
plow "$FULL_URL" \
  -c "$CONCURRENCY" \
  -n 1000 \
  -m GET \
  -H "X-Load-Test: plow-e2e-phase1"

echo ""
echo "[Phase 2] POST requests (full CMS encrypt + sign flow)..."

BODY='{"message":"end-to-end load test payload","source":"plow-e2e","size":"medium","data":{"key1":"value1","key2":"value2","key3":"value3"}}'

if [ -n "$DURATION" ]; then
  plow "$FULL_URL" \
    -c "$CONCURRENCY" \
    -d "$DURATION" \
    -m POST \
    -H "Content-Type: application/json" \
    -H "X-Load-Test: plow-e2e-phase2" \
    -b "$BODY"
else
  plow "$FULL_URL" \
    -c "$CONCURRENCY" \
    -n "$REQUESTS" \
    -m POST \
    -H "Content-Type: application/json" \
    -H "X-Load-Test: plow-e2e-phase2" \
    -b "$BODY"
fi

echo ""
echo "[Phase 3] High concurrency burst (100 concurrent, 500 requests)..."
plow "$FULL_URL" \
  -c 100 \
  -n 500 \
  -m POST \
  -H "Content-Type: application/json" \
  -H "X-Load-Test: plow-e2e-phase3-burst" \
  -b "$BODY"

echo ""
echo "============================================"
echo "  Load test selesai. Cek Grafana dashboard:"
echo "  http://localhost:3000"
echo "============================================"
