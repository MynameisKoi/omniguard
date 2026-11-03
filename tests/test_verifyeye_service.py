"""Unit and integration tests for VerifyEye Ingress service endpoints and heuristics."""

import importlib.util
import os
import sys
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ingress_root = os.path.join(repo_root, "verifyeye-ingress")
if ingress_root not in sys.path:
    sys.path.insert(0, ingress_root)

# Load verifyeye-ingress/service.py under a distinct module name to avoid collision with spectrac2-engine/service
service_file = os.path.join(ingress_root, "service.py")
spec = importlib.util.spec_from_file_location("verifyeye_service_mod", service_file)
ve_service = importlib.util.module_from_spec(spec)
sys.modules["verifyeye_service_mod"] = ve_service
spec.loader.exec_module(ve_service)

app = ve_service.app
_registrable = ve_service._registrable
_submits_off_domain = ve_service._submits_off_domain

client = TestClient(app)


def test_registrable_helper():
    assert _registrable("auth.company.com") == "company.com"
    assert _registrable("company.com") == "company.com"
    assert _registrable("sub.corp.local") == "corp.local"
    assert _registrable("") == ""


def test_submits_off_domain_helper():
    base_url = "https://login.company.com/auth"

    # Same domain (relative action)
    assert not _submits_off_domain(base_url, ["/api/v1/login"])

    # Same registrable domain (different subdomain)
    assert not _submits_off_domain(base_url, ["https://api.company.com/login"])

    # Off-domain harvest endpoint
    assert _submits_off_domain(base_url, ["https://evil-phish-collector.com/harvest"])


def test_verifyeye_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_verify_phishing_with_brand():
    mock_result = {
        "url": "http://evil-spoof.com/login",
        "title": "Google Sign-In",
        "credential_form": True,
        "brand_target": "Google",
        "form_actions": ["http://harvester-c2.com/collect"],
    }
    with patch.object(ve_service, "analyze_page", return_value=mock_result):
        res = client.post("/verify", json={"url": "http://evil-spoof.com/login"})
        assert res.status_code == 200
        data = res.json()
        assert data["phishing"] is True
        assert data["confidence"] == 0.95
        assert data["brand"] == "Google"
        assert data["off_domain"] is True
        assert data["credential_form"] is True


def test_verify_phishing_without_brand():
    mock_result = {
        "url": "http://generic-portal.net/form",
        "title": "Portal Login",
        "credential_form": True,
        "brand_target": None,
        "form_actions": ["http://external-drop.net/submit"],
    }
    with patch.object(ve_service, "analyze_page", return_value=mock_result):
        res = client.post("/verify", json={"url": "http://generic-portal.net/form"})
        assert res.status_code == 200
        data = res.json()
        assert data["phishing"] is True
        assert data["confidence"] == 0.8
        assert data["off_domain"] is True


def test_verify_legitimate_credential_form():
    mock_result = {
        "url": "https://accounts.google.com/signin",
        "title": "Sign in – Google accounts",
        "credential_form": True,
        "brand_target": "Google",
        "form_actions": ["https://accounts.google.com/checkcookie"],
    }
    with patch.object(ve_service, "analyze_page", return_value=mock_result):
        res = client.post("/verify", json={"url": "https://accounts.google.com/signin"})
        assert res.status_code == 200
        data = res.json()
        assert data["phishing"] is False
        assert data["confidence"] == 0.5
        assert data["off_domain"] is False


def test_verify_non_credential_page():
    mock_result = {
        "url": "https://wikipedia.org/wiki/Main_Page",
        "title": "Wikipedia",
        "credential_form": False,
        "brand_target": None,
        "form_actions": [],
    }
    with patch.object(ve_service, "analyze_page", return_value=mock_result):
        res = client.post("/verify", json={"url": "https://wikipedia.org/wiki/Main_Page"})
        assert res.status_code == 200
        data = res.json()
        assert data["phishing"] is False
        assert data["confidence"] == 0.1
