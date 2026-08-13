
PROXY_URL="${PROXY_URL:-http://proxy:8080}"
REQUESTS="${REQUESTS:-5000}"
CONCURRENCY="${CONCURRENCY:-20}"
DURATION="${DURATION:-}"

echo "============================================"
echo "  Plow Load Test â€” PROXY DIRECT"
echo "  Target      : $PROXY_URL"
echo "  Requests    : $REQUESTS"
echo "  Concurrency : $CONCURRENCY"
echo "============================================"

ARGS="-c $CONCURRENCY -m POST \
  -H 'Content-Type: application/json' \
  -b '{\"message\":\"plow load test\",\"source\":\"plow-proxy\",\"ts\":\"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\"}'"

if [ -n "$DURATION" ]; then
  ARGS="$ARGS -d $DURATION"
else
  ARGS="$ARGS -n $REQUESTS"
fi

echo "Running: plow $PROXY_URL $ARGS"
echo ""

eval plow "$PROXY_URL" $ARGS
