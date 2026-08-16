"""Technology fingerprinting tests."""
from __future__ import annotations

from app.recon.http_client import FetchResult
from app.recon.tech import fingerprint


def _fetch(headers=None, text=""):
    return FetchResult(
        url="https://example.com/", status_code=200, headers=headers or {},
        text=text, content=text.encode(), elapsed_ms=10.0, final_url="https://example.com/",
    )


def test_detect_nginx_and_php():
    f = _fetch(headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.12",
                        "Set-Cookie": "PHPSESSID=abc123; path=/"})
    matches = {m.name for m in fingerprint(f)}
    assert "Nginx" in matches
    assert "PHP" in matches


def test_detect_cloudflare():
    f = _fetch(headers={"CF-RAY": "abc123-IAD", "Server": "cloudflare"})
    matches = {m.name for m in fingerprint(f)}
    assert "Cloudflare" in matches


def test_detect_wordpress():
    f = _fetch(text='<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>')
    matches = {m.name for m in fingerprint(f)}
    assert "WordPress" in matches


def test_detect_nextjs():
    f = _fetch(text='<html><script src="/_next/static/chunks/main.js"></script></html>')
    matches = {m.name for m in fingerprint(f)}
    assert "Next.js" in matches


def test_detect_react_from_script():
    f = _fetch(text='<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>')
    matches = {m.name for m in fingerprint(f)}
    assert "React" in matches


def test_detect_jquery_version():
    f = _fetch(text='<script src="/js/jquery-3.7.1.min.js"></script>')
    matches = {m.name: m for m in fingerprint(f)}
    assert "jQuery" in matches
    assert matches["jQuery"].version == "3.7.1"


def test_detect_stripe_and_recaptcha():
    f = _fetch(text='<script src="https://js.stripe.com/v3/"></script><script src="https://www.google.com/recaptcha/api.js"></script>')
    matches = {m.name for m in fingerprint(f)}
    assert "Stripe" in matches
    assert "reCAPTCHA" in matches


def test_no_false_positive_on_blank_page():
    f = _fetch(text="<html><body>hello</body></html>")
    assert fingerprint(f) == []
