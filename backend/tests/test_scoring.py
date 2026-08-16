"""Attention scoring tests."""
from __future__ import annotations

from app.models import Asset, AssetType, Observation, Severity
from app.services.scoring import score_asset


def _asset(type=AssetType.URL, name="https://example.com/", props=None):
    return Asset(scan_id="s", type=type, name=name, properties=props or {})


def test_api_endpoint_scores_higher_than_static_url():
    api = _asset(AssetType.API, "https://example.com/api/users")
    url = _asset(AssetType.URL, "https://example.com/about")
    assert score_asset(api) > score_asset(url)


def test_missing_security_headers_increase_score():
    base = _asset(props={"status_code": 200, "scheme": "https",
                         "missing_security_headers": []})
    missing = _asset(props={"status_code": 200, "scheme": "https",
                            "missing_security_headers": [
                                "content-security-policy", "x-frame-options",
                                "strict-transport-security", "x-content-type-options"]})
    assert score_asset(missing) > score_asset(base)


def test_plaintext_http_increases_score():
    secure = _asset(props={"status_code": 200, "scheme": "https"})
    plain = _asset(props={"status_code": 200, "scheme": "http"})
    assert score_asset(plain) > score_asset(secure)


def test_expired_certificate_scores_high():
    cert = _asset(AssetType.CERTIFICATE, "example.com cert",
                  props={"expired": True})
    # CERT type weight (15) + expired bonus (35) = 50
    assert score_asset(cert) >= 50


def test_js_with_secret_scores_high():
    js = _asset(AssetType.JAVASCRIPT, "app.js",
                props={"secret_count": 1, "endpoint_count": 3})
    assert score_asset(js) >= 60


def test_admin_keyword_boost():
    normal = _asset(AssetType.SUBDOMAIN, "www.example.com")
    admin = _asset(AssetType.SUBDOMAIN, "admin.example.com")
    assert score_asset(admin) > score_asset(normal)


def test_severity_observations_boost():
    a = _asset()
    obs = [Observation(title="x", severity=Severity.HIGH, scan_id="s")]
    assert score_asset(a, obs) > score_asset(a)


def test_score_clamped_to_100():
    a = _asset(AssetType.API, "admin.example.com/api/secret",
               props={"status_code": 500, "scheme": "http",
                      "missing_security_headers": ["a", "b", "c", "d", "e", "f"]})
    obs = [Observation(title="x", severity=Severity.HIGH, scan_id="s") for _ in range(5)]
    assert score_asset(a, obs) <= 100
