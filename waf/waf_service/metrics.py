import time
from prometheus_client import Counter, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

CMS_VERIFICATION_TOTAL = Counter(
    "cms_verification_total",
    "Total CMS signature verification attempts, labelled by result",
    labelnames=["result"],
)

CMS_VERIFICATION_DURATION = Histogram(
    "cms_verification_duration_seconds",
    "End-to-end CMS verification duration in seconds",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

CMS_SIGNATURE_VERIFICATION = Histogram(
    "cms_signature_verification_seconds",
    "RSA-PSS signature verification duration in seconds",
    buckets=[0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
)

CMS_CANONICALIZATION = Histogram(
    "cms_canonicalization_seconds",
    "Canonical headers construction duration in seconds",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025],
)

MTLS_HANDSHAKE_TOTAL = Counter(
    "mtls_handshake_total",
    "Total mTLS handshake results at Layer 1",
    labelnames=["result"],
)

HEADER_VERIFICATION_TOTAL = Counter(
    "header_verification_total",
    "Total header digest verification results at Layer 3b",
    labelnames=["result"],
)

REPLAY_ATTACK_TOTAL = Counter(
    "replay_attack_total",
    "Total replay attacks detected (signing-time outside 300s window)",
)

CERT_MISMATCH_TOTAL = Counter(
    "cert_mismatch_total",
    "Total certificate mismatch rejections (CMS signer != mTLS cert)",
)


def setup_waf_metrics(app) -> Instrumentator:
    instrumentator = Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=True,
        should_respect_env_var=False,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/metrics"],
    )
    instrumentator.instrument(app).expose(app, endpoint="/metrics")
    return instrumentator


def record_mtls_result(success: bool) -> None:
    label = "success" if success else "failed"
    MTLS_HANDSHAKE_TOTAL.labels(result=label).inc()


def record_cms_result(result: str) -> None:
    CMS_VERIFICATION_TOTAL.labels(result=result).inc()
    

def record_header_result(result: str) -> None:
    HEADER_VERIFICATION_TOTAL.labels(result=result).inc()
    

def record_replay_attack() -> None:
    REPLAY_ATTACK_TOTAL.inc()
    

def record_cert_mismatch() -> None:
    CERT_MISMATCH_TOTAL.inc()
    

class CMSVerifyTimer:
    _SCOPE_MAP = {
        "full": CMS_VERIFICATION_DURATION,
        "signature": CMS_SIGNATURE_VERIFICATION,
        "canonicalization": CMS_CANONICALIZATION,
    }
    
    def __init__(self, scope: str) -> None:
        if scope not in self._SCOPE_MAP:
            raise ValueError(
                f"Unknown CMSVerifyTimer scope '{scope}'. "
                f"Valid values: {list(self._SCOPE_MAP)}"
            )
        self._histogram = self._SCOPE_MAP[scope]
        self._start: float = 0.0
        
    def __enter__(self) -> "CMSVerifyTimer":
        self._start = time.perf_counter()
        return self
    
    def __exit__(self, *_) -> None:
        elapsed = time.perf_counter() - self._start
        self._histogram.observe(elapsed)