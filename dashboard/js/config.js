const CONFIG = Object.freeze({
  PROXY_URL:      'http://localhost:8080',
  GRAFANA_URL:    'http://localhost:3000',
  PROMETHEUS_URL: 'http://localhost:8080',
  LOKI_URL:       'http://localhost:8080',
  HEALTH: {
    PROXY:      'http://localhost:8080/healthz',
    PROMETHEUS: 'http://localhost:8080/api/metrics?query=up',
  },
  GRAFANA_DASHBOARD_UID: 'mtls-proxy-monitoring',
  GRAFANA_PANELS: {
    overview: null,        
    latency:  2,           
    security: 4,           
    logs:     'logs',      
  },
  GRAFANA_USER: 'admin',
  GRAFANA_PASS: 'admin',
  PROM_QUERIES: {
    rps:         'sum(rate(flask_http_request_total[1m]))',
    blocked:     'sum(cms_verification_total{result="failed"}) or vector(0)',
    latency_p95: 'histogram_quantile(0.95, sum(rate(cms_verification_duration_seconds_bucket[5m])) by (le))',
    mtls_ok:     'sum(flask_http_request_total)',
  },
  PROM_POLL_INTERVAL_MS: 10000,
  ANIM: {
    PACKET_STEP_DURATION: 600,   
    PACKET_PAUSE:         300,   
    STEP_NARRATION_DELAY: 200,   
    LOADTEST_INTERVAL:    120,   
    LOADTEST_COUNT:       50,    
  },
});