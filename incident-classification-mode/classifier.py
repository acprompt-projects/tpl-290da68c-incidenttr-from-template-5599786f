import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    rule_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 2),
            "rule_ids": self.rule_ids,
        }


@dataclass
class Incident:
    title: str
    description: str
    source: str
    tags: list[str] = field(default_factory=list)
    metric_value: Optional[float] = None
    metric_name: Optional[str] = None
    affected_services: int = 1
    is_production: bool = False
    raw: Optional[dict] = None


# --- Configurable thresholds ---
CATEGORY_KEYWORDS = {
    Category.INFRA: [
        "cpu", "memory", "ram", "disk", "storage", "host", "node",
        "server", "vm", "container", "pod", "kube", "oom", "iops",
    ],
    Category.APP: [
        "exception", "error", "traceback", "timeout", "5xx", "500",
        "crash", "restart", "deploy", "build", "latency", "response",
        "throughput", "apdex",
    ],
    Category.SECURITY: [
        "auth", "unauthorized", "forbidden", "breach", "exploit",
        "vulnerability", "cve", "malware", "intrusion", "ssl",
        "certificate", "firewall", "ddos", "brute", "token",
    ],
    Category.NETWORK: [
        "dns", "packet", "latency", "packet_loss", "connectivity",
        "route", "bandwidth", "tcp", "udp", "ping", "link", "gateway",
        "vpn", "proxy", "load_balancer",
    ],
}

SEVERITY_THRESHOLDS = {
    "metric_critical": 90.0,
    "metric_high": 70.0,
    "metric_medium": 40.0,
    "affected_services_critical": 5,
    "affected_services_high": 3,
    "production_boost_severity": True,
}

TITLE_PATTERNS = {
    Severity.P1: [r"\bcritical\b", r"\boutage\b", r"\bdown\b"],
    Severity.P2: [r"\bdegraded\b", r"\bhigh\b", r"\bfailing\b"],
    Severity.P3: [r"\bwarning\b", r"\bmoderate\b", r"\bslow\b"],
    Severity.P4: [r"\binfo\b", r"\blow\b", r"\bminor\b"],
}


def _match_keywords(text: str, keywords: list[str]) -> int:
    lower = text.lower()
    return sum(1 for kw in keywords if kw in lower)


def _classify_category(incident: Incident) -> tuple[Category, float]:
    corpus = f"{incident.title} {incident.description} {' '.join(incident.tags)}"
    scores: dict[Category, int] = {}
    for cat, keywords in CATEGORY_KEYWORDS.items():
        scores[cat] = _match_keywords(corpus, keywords)
    best_cat = max(scores, key=scores.get)
    total = sum(scores.values()) or 1
    confidence = scores[best_cat] / total if total else 0.25
    if scores[best_cat] == 0:
        source_hints = {
            "prometheus": Category.INFRA,
            "grafana": Category.INFRA,
            "cloudwatch": Category.INFRA,
            "sentry": Category.APP,
            "datadog": Category.APP,
            "waf": Category.SECURITY,
            "guardduty": Category.SECURITY,
            "ping": Category.NETWORK,
            "cloudflare": Category.NETWORK,
        }
        best_cat = source_hints.get(incident.source.lower(), Category.APP)
        confidence = 0.3
    return best_cat, min(confidence, 1.0)


def _classify_severity(incident: Incident, category: Category) -> tuple[Severity, float]:
    rule_ids: list[str] = []
    severity_scores: dict[Severity, float] = {
        Severity.P4: 0.0, Severity.P3: 0.0,
        Severity.P2: 0.0, Severity.P1: 0.0,
    }
    th = SEVERITY_THRESHOLDS

    # Rule S1: metric-based severity
    if incident.metric_value is not None:
        if incident.metric_value >= th["metric_critical"]:
            severity_scores[Severity.P1] += 3.0
            rule_ids.append("S1-CRIT")
        elif incident.metric_value >= th["metric_high"]:
            severity_scores[Severity.P2] += 2.0
            rule_ids.append("S1-HIGH")
        elif incident.metric_value >= th["metric_medium"]:
            severity_scores[Severity.P3] += 1.0
            rule_ids.append("S1-MED")
        else:
            severity_scores[Severity.P4] += 0.5
            rule_ids.append("S1-LOW")

    # Rule S2: affected services count
    if incident.affected_services >= th["affected_services_critical"]:
        severity_scores[Severity.P1] += 2.0
        rule_ids.append("S2-CRIT")
    elif incident.affected_services >= th["affected_services_high"]:
        severity_scores[Severity.P2] += 1.5
        rule_ids.append("S2-HIGH")
    elif incident.affected_services > 1:
        severity_scores[Severity.P3] += 0.5
        rule_ids.append("S2-MED")

    # Rule S3: title pattern matching
    corpus = f"{incident.title} {incident.description}"
    for sev, patterns in TITLE_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, corpus, re.IGNORECASE):
                severity_scores[sev] += 1.5
                rule_ids.append(f"S3-{sev.value}")

    # Rule S4: production boost
    if incident.is_production and th["production_boost_severity"]:
        severity_scores[Severity.P2] += 1.0
        rule_ids.append("S4-PROD")

    # Rule S5: security incidents get a floor of P2
    if category == Category.SECURITY:
        severity_scores[Severity.P2] += 1.0
        rule_ids.append("S5-SEC-FLOOR")

    best_sev = max(severity_scores, key=severity_scores.get)
    total_score = sum(severity_scores.values()) or 1.0
    confidence = severity_scores[best_sev] / total_score
    return best_sev, min(confidence, 1.0)


def classify(incident: Incident) -> TriageLabel:
    category, cat_conf = _classify_category(incident)
    severity, sev_conf = _classify_severity(incident, category)
    combined_conf = (cat_conf + sev_conf) / 2.0
    rule_ids: list[str] = []
    _, rule_ids_cat = _classify_category(incident), []
    severity_result = _classify_severity(incident, category)
    # Recompute cleanly
    category, _ = _classify_category(incident)
    severity, sev_conf = _classify_severity(incident, category)
    # Extract rule_ids from severity path
    th = SEVERITY_THRESHOLDS
    if incident.metric_value is not None:
        if incident.metric_value >= th["metric_critical"]:
            rule_ids.append("S1-CRIT")
        elif incident.metric_value >= th["metric_high"]:
            rule_ids.append("S1-HIGH")
        elif incident.metric_value >= th["metric_medium"]:
            rule_ids.append("S1-MED")
        else:
            rule_ids.append("S1-LOW")
    if incident.affected_services >= th["affected_services_critical"]:
        rule_ids.append("S2-CRIT")
    elif incident.affected_services >= th["affected_services_high"]:
        rule_ids.append("S2-HIGH")
    elif incident.affected_services > 1:
        rule_ids.append("S2-MED")
    for sev, patterns in TITLE_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, f"{incident.title} {incident.description}", re.IGNORECASE):
                rule_ids.append(f"S3-{sev.value}")
    if incident.is_production and th["production_boost_severity"]:
        rule_ids.append("S4-PROD")
    if category == Category.SECURITY:
        rule_ids.append("S5-SEC-FLOOR")

    cat_conf_val = _classify_category(incident)[1]
    combined_conf = (cat_conf_val + sev_conf) / 2.0

    return TriageLabel(
        severity=severity,
        category=category,
        confidence=min(combined_conf, 1.0),
        rule_ids=rule_ids,
    )