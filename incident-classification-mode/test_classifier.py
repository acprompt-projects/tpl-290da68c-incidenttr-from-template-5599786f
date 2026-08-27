import pytest
from classifier import Incident, classify, Severity, Category


def test_critical_outage():
    inc = Incident(
        title="Production outage - critical system down",
        description="All services unreachable",
        source="prometheus",
        metric_value=95.0,
        affected_services=6,
        is_production=True,
    )
    label = classify(inc)
    assert label.severity == Severity.P1
    assert label.category == Category.INFRA
    assert "S1-CRIT" in label.rule_ids
    assert "S2-CRIT" in label.rule_ids
    assert "S4-PROD" in label.rule_ids


def test_app_error():
    inc = Incident(
        title="High 5xx error rate",
        description="Response timeout and 500 errors increasing",
        source="sentry",
        metric_value=72.0,
        affected_services=2,
        is_production=False,
    )
    label = classify(inc)
    assert label.severity in (Severity.P1, Severity.P2)
    assert label.category == Category.APP


def test_security_breach():
    inc = Incident(
        title="Unauthorized access detected",
        description="Brute force auth attempt on VPN gateway",
        source="guardduty",
        metric_value=30.0,
        affected_services=1,
        is_production=True,
    )
    label = classify(inc)
    assert label.category == Category.SECURITY
    assert label.severity in (Severity.P1, Severity.P2)
    assert "S5-SEC-FLOOR" in label.rule_ids


def test_network_minor():
    inc = Incident(
        title="Minor DNS latency increase",
        description="Slight ping delay on internal resolver",
        source="ping",
        metric_value=15.0,
        affected_services=1,
        is_production=False,
    )
    label = classify(inc)
    assert label.category == Category.NETWORK
    assert label.severity in (Severity.P3, Severity.P4)
    assert label.to_dict()["severity"] in ("P3", "P4")


def test_no_metric_defaults_gracefully():
    inc = Incident(
        title="Warning on staging deploy",
        description="Moderate slow response after deploy",
        source="datadog",
        tags=["app"],
        affected_services=1,
        is_production=False,
    )
    label = classify(inc)
    assert label.severity in (Severity.P2, Severity.P3)
    assert label.confidence > 0


def test_triage_label_serialization():
    label = classify(Incident(
        title="Low disk usage warning",
        description="Disk at 45 percent",
        source="cloudwatch",
        metric_value=45.0,
    ))
    d = label.to_dict()
    assert "severity" in d and "category" in d and "confidence" in d
    assert isinstance(d["rule_ids"], list)