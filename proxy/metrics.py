import os
from prometheus_client import Counter, Histogram
from prometheus_flask_exporter.multiprocess import GunicornPrometheusMetrics
PROXY_CMS_VERIFICATION_TOTAL = Counter(
    "cms_verification_total",
    "Total CMS response verification results in Proxy",
    labelnames=["result"],
)

PROXY_CMS_VERIFICATION_DURATION = Histogram(
    "cms_verification_duration_seconds",
    "CMS response verification duration in seconds (Proxy)",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)


def setup_proxy_metrics(app) -> GunicornPrometheusMetrics:
    multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR", "/tmp/multiproc")
    os.makedirs(multiproc_dir, exist_ok=True)
    metrics = GunicornPrometheusMetrics(app)
    metrics.register_endpoint("/metrics")
    metrics.info("proxy_info", "mTLS Proxy service info", version="1.0")
    return metrics


def record_proxy_cms_result(success: bool, duration_seconds: float) -> None:
    label = "success" if success else "failed"
    PROXY_CMS_VERIFICATION_TOTAL.labels(result=label).inc()
    PROXY_CMS_VERIFICATION_DURATION.observe(duration_seconds)