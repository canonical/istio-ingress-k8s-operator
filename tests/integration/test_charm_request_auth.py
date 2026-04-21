# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import requests
import yaml
from helpers import (
    get_auth_policy_spec,
    get_k8s_service_address,
    get_request_auth_spec,
)
from jubilant import Juju, all_active

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}

IPA_TESTER = "ra-tester"
MOCK_OAUTH2 = "mock-oauth2"
REQUEST_AUTH_RELATION = "istio-request-auth"


@pytest.mark.setup
@pytest.mark.dependency(name="test_deploy_dependencies")
def test_deploy_dependencies(
    juju: Juju, istio_core_juju: Juju, tester_http_charm, tester_mock_oauth2_charm
):
    """Deploy tester-http and mock-oauth2-server charms."""
    juju.deploy(
        tester_http_charm,
        app=IPA_TESTER,
        resources={"echo-server-image": "jmalloc/echo-server:v0.3.7"},
    )
    juju.deploy(
        tester_mock_oauth2_charm,
        app=MOCK_OAUTH2,
        resources={"mock-oauth2-server-image": "ghcr.io/navikt/mock-oauth2-server:2.1.10"},
    )
    juju.wait(
        lambda s: all_active(s, IPA_TESTER, MOCK_OAUTH2),
        timeout=1000,
        delay=5,
        successes=3,
    )


@pytest.mark.dependency(name="test_deployment", depends=["test_deploy_dependencies"])
def test_deployment(juju: Juju, istio_ingress_charm, resources):
    juju.deploy(istio_ingress_charm, resources=resources, app=APP_NAME, trust=True)
    juju.wait(lambda s: all_active(s, APP_NAME), timeout=1000, delay=5, successes=3)


@pytest.mark.dependency(name="test_relate_ingress", depends=["test_deployment"])
def test_relate_ingress(juju: Juju):
    """Relate tester to istio-ingress via IPA so we get an HTTP route."""
    juju.integrate(f"{IPA_TESTER}:ingress", f"{APP_NAME}:ingress")
    juju.wait(
        lambda s: all_active(s, APP_NAME, IPA_TESTER),
        timeout=1000,
        delay=5,
        successes=3,
    )


@pytest.mark.dependency(name="test_request_without_auth", depends=["test_relate_ingress"])
def test_request_without_auth(juju: Juju):
    """Before request-auth is configured, requests should succeed without a token."""
    istio_ingress_address = get_k8s_service_address(juju.model, f"{APP_NAME}-istio")
    tester_url = f"http://{istio_ingress_address}/{juju.model}-{IPA_TESTER}"
    resp = requests.get(tester_url)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"


@pytest.mark.dependency(
    name="test_configure_request_auth", depends=["test_request_without_auth"]
)
def test_configure_request_auth(juju: Juju):
    """Configure JWT rules on the tester and relate request-auth to istio-ingress."""
    # Relate request-auth first (publish_data needs an active relation)
    juju.integrate(f"{IPA_TESTER}:{REQUEST_AUTH_RELATION}", f"{APP_NAME}:{REQUEST_AUTH_RELATION}")

    # Get issuer info from mock-oauth2
    issuer_result = juju.run(f"{MOCK_OAUTH2}/0", "get-issuer-info")
    issuer_url = issuer_result.results["issuer"]
    jwks_url = issuer_result.results["jwks-url"]

    # Set request-auth config on the tester (triggers relation-changed on the provider)
    juju.run(
        f"{IPA_TESTER}/0",
        "set-request-auth",
        {"issuer": issuer_url, "jwks-uri": jwks_url},
    )

    # Wait for the charm to reconcile the new data
    juju.wait(
        lambda s: all_active(s, APP_NAME, IPA_TESTER),
        timeout=1000,
        delay=5,
        successes=3,
    )


@pytest.mark.dependency(
    name="test_request_authentication_resource", depends=["test_configure_request_auth"]
)
def test_request_authentication_resource(juju: Juju):
    """Verify the RequestAuthentication K8s resource was created with correct spec."""
    ra_name = f"request-auth-{IPA_TESTER}-{APP_NAME}"
    ra_spec = get_request_auth_spec(juju.model, ra_name)
    assert ra_spec is not None, f"RequestAuthentication '{ra_name}' not found."

    # Verify targetRefs points to the gateway
    assert "targetRefs" in ra_spec, "'targetRefs' missing in RequestAuthentication spec."
    target_ref = ra_spec["targetRefs"][0]
    assert target_ref["kind"] == "Gateway", f"Expected Gateway targetRef, got {target_ref['kind']}"

    # Verify jwtRules
    assert "jwtRules" in ra_spec, "'jwtRules' missing in RequestAuthentication spec."
    jwt_rules = ra_spec["jwtRules"]
    assert len(jwt_rules) >= 1, "Expected at least one JWT rule."

    issuer_result = juju.run(f"{MOCK_OAUTH2}/0", "get-issuer-info")
    expected_issuer = issuer_result.results["issuer"]
    assert jwt_rules[0]["issuer"] == expected_issuer, (
        f"Expected issuer '{expected_issuer}', got '{jwt_rules[0]['issuer']}'"
    )


@pytest.mark.dependency(
    name="test_deny_policy_exists", depends=["test_configure_request_auth"]
)
def test_deny_policy_exists(juju: Juju):
    """Verify the DENY AuthorizationPolicy for JWT enforcement was created."""
    policy_name = f"deny-without-jwt-{APP_NAME}"
    policy_spec = get_auth_policy_spec(juju.model, policy_name)
    assert policy_spec is not None, f"DENY AuthorizationPolicy '{policy_name}' not found."
    assert policy_spec["action"] == "DENY", f"Expected DENY action, got {policy_spec.get('action')}"

    # Verify notRequestPrincipals rule (denies requests without a validated JWT)
    rules = policy_spec.get("rules", [])
    assert len(rules) >= 1, "Expected at least one rule in DENY policy."
    from_rules = rules[0].get("from", [])
    assert len(from_rules) >= 1, "Expected at least one 'from' in DENY policy rule."
    not_principals = from_rules[0].get("source", {}).get("notRequestPrincipals", [])
    assert "*" in not_principals, "Expected '*' in notRequestPrincipals."


@pytest.mark.dependency(
    name="test_request_denied_without_token",
    depends=["test_deny_policy_exists"],
)
def test_request_denied_without_token(juju: Juju):
    """Requests without a JWT should be denied (403)."""
    istio_ingress_address = get_k8s_service_address(juju.model, f"{APP_NAME}-istio")
    tester_url = f"http://{istio_ingress_address}/{juju.model}-{IPA_TESTER}"
    resp = requests.get(tester_url)
    assert resp.status_code == 403, f"Expected 403 without token, got {resp.status_code}"


@pytest.mark.dependency(
    name="test_request_allowed_with_valid_token",
    depends=["test_deny_policy_exists"],
)
def test_request_allowed_with_valid_token(juju: Juju):
    """Requests with a valid JWT from mock-oauth2 should succeed (200)."""
    # Get a token from mock-oauth2
    token_result = juju.run(f"{MOCK_OAUTH2}/0", "get-token")
    access_token = token_result.results["access-token"]

    istio_ingress_address = get_k8s_service_address(juju.model, f"{APP_NAME}-istio")
    tester_url = f"http://{istio_ingress_address}/{juju.model}-{IPA_TESTER}"
    resp = requests.get(tester_url, headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 200, f"Expected 200 with valid token, got {resp.status_code}"


@pytest.mark.dependency(
    name="test_remove_request_auth_relation",
    depends=["test_request_denied_without_token", "test_request_allowed_with_valid_token"],
)
def test_remove_request_auth_relation(juju: Juju):
    """Breaking the request-auth relation should clean up RA and DENY policy."""
    juju.remove_relation(
        f"{IPA_TESTER}:{REQUEST_AUTH_RELATION}", f"{APP_NAME}:{REQUEST_AUTH_RELATION}"
    )
    juju.wait(
        lambda s: all_active(s, APP_NAME, IPA_TESTER),
        timeout=1000,
        delay=5,
        successes=3,
    )

    # Verify RequestAuthentication is removed
    ra_name = f"request-auth-{IPA_TESTER}-{APP_NAME}"
    ra_spec = get_request_auth_spec(juju.model, ra_name)
    assert ra_spec is None, f"Expected RequestAuthentication '{ra_name}' to be removed."

    # Verify DENY policy is removed
    policy_name = f"deny-without-jwt-{APP_NAME}"
    policy_spec = get_auth_policy_spec(juju.model, policy_name)
    assert policy_spec is None, f"Expected DENY policy '{policy_name}' to be removed."


@pytest.mark.dependency(
    name="test_request_allowed_after_relation_break",
    depends=["test_remove_request_auth_relation"],
)
def test_request_allowed_after_relation_break(juju: Juju):
    """After removing request-auth, requests without a token should succeed again."""
    istio_ingress_address = get_k8s_service_address(juju.model, f"{APP_NAME}-istio")
    tester_url = f"http://{istio_ingress_address}/{juju.model}-{IPA_TESTER}"
    resp = requests.get(tester_url)
    assert resp.status_code == 200, f"Expected 200 after relation break, got {resp.status_code}"
