# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from unittest.mock import MagicMock, patch

import pytest
import scenario
from canonical_service_mesh.models.istio import JWTRule
from charmlibs.interfaces.istio_request_auth import JWTRule as InterfaceJWTRule

from charm import IstioIngressCharm


def _make_request_auth_relation(issuer="https://issuer.example.com", jwks_uri="https://issuer.example.com/jwks"):
    """Create an istio-request-auth relation with JWT rule data in the remote app databag."""
    rules = [
        InterfaceJWTRule(
            issuer=issuer,
            jwks_uri=jwks_uri,
            forward_original_token=True,
        ).model_dump()
    ]
    return scenario.Relation(
        endpoint="istio-request-auth",
        interface="istio_request_auth",
        remote_app_data={"jwt_rules": json.dumps(rules)},
    )


def test_construct_request_authentication(istio_ingress_context):
    """Test that RA resource has correct targetRef, issuer, and jwksUri."""
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm

        jwt_rules = [
            JWTRule(
                issuer="https://issuer.example.com",
                jwksUri="https://issuer.example.com/jwks",
                forwardOriginalToken=True,
            )
        ]
        ra = charm._construct_request_authentication("my-app", jwt_rules)

        assert ra.metadata.name == f"request-auth-my-app-{charm.app.name}"
        assert ra.spec["targetRefs"][0]["kind"] == "Gateway"
        assert ra.spec["targetRefs"][0]["name"] == charm.app.name
        assert ra.spec["jwtRules"][0]["issuer"] == "https://issuer.example.com"
        assert ra.spec["jwtRules"][0]["jwksUri"] == "https://issuer.example.com/jwks"
        assert ra.spec["jwtRules"][0]["forwardOriginalToken"] is True


def test_construct_deny_without_jwt_policy(istio_ingress_context):
    """Test that DENY policy uses notRequestPrincipals targeting the Gateway."""
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        policy = charm._construct_deny_without_jwt_policy()

        assert policy.metadata.name == f"deny-without-jwt-{charm.app.name}"
        assert policy.spec["action"] == "DENY"
        assert policy.spec["targetRefs"][0]["kind"] == "Gateway"
        assert policy.spec["rules"][0]["from"][0]["source"]["notRequestPrincipals"] == ["*"]


def test_convert_to_jwt_rules(istio_ingress_context):
    """Test conversion from interface JWTRule models to Istio CRD JWTRule models."""
    interface_jwt_rules = [
        InterfaceJWTRule(
            issuer="https://issuer.example.com",
            jwks_uri="https://issuer.example.com/jwks",
            audiences=["my-audience"],
            forward_original_token=True,
        )
    ]
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        jwt_rules = charm._convert_to_jwt_rules(interface_jwt_rules)

        assert len(jwt_rules) == 1
        assert jwt_rules[0].issuer == "https://issuer.example.com"
        assert jwt_rules[0].jwksUri == "https://issuer.example.com/jwks"
        assert jwt_rules[0].audiences == ["my-audience"]
        assert jwt_rules[0].forwardOriginalToken is True


@patch.object(IstioIngressCharm, "_get_request_auth_resource_manager")
def test_sync_request_authentication_with_data(mock_get_krm, istio_ingress_context):
    """Test that sync creates RA resources when relation data exists."""
    mock_krm = MagicMock()
    mock_get_krm.return_value = mock_krm

    relation = _make_request_auth_relation()
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[relation], leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        charm._sync_request_authentication()

        mock_krm.reconcile.assert_called_once()
        resources = mock_krm.reconcile.call_args[0][0]
        assert len(resources) == 1
        assert resources[0].spec["jwtRules"][0]["issuer"] == "https://issuer.example.com"


@patch.object(IstioIngressCharm, "_get_request_auth_resource_manager")
def test_sync_request_authentication_without_data(mock_get_krm, istio_ingress_context):
    """Test that sync reconciles empty when no relation exists."""
    mock_krm = MagicMock()
    mock_get_krm.return_value = mock_krm

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        charm._sync_request_authentication()

        mock_krm.reconcile.assert_called_once_with([])


@pytest.mark.parametrize(
    "has_request_auth, has_forward_auth, expect_deny_policy",
    [
        (True, False, True),
        (True, True, False),
        (False, False, False),
    ],
)
@patch.object(IstioIngressCharm, "_get_deny_auth_policy_resource_manager")
def test_sync_deny_auth_policy(
    mock_get_prm,
    has_request_auth,
    has_forward_auth,
    expect_deny_policy,
    istio_ingress_context,
):
    """Test deny policy is only created when request-auth is active and forward-auth is absent."""
    mock_prm = MagicMock()
    mock_get_prm.return_value = mock_prm

    relations = []
    if has_request_auth:
        relations.append(_make_request_auth_relation())
    if has_forward_auth:
        relations.append(
            scenario.Relation(
                endpoint="forward-auth",
                interface="forward_auth",
                remote_app_data={
                    "decisions_address": "http://auth-service:80",
                    "app_names": json.dumps(["my-app"]),
                    "headers": json.dumps([]),
                },
            )
        )

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=relations, leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        charm._sync_deny_auth_policy()

        mock_prm.reconcile.assert_called_once()
        raw_policies = mock_prm.reconcile.call_args[1]["raw_policies"]
        if expect_deny_policy:
            assert len(raw_policies) == 1
            assert raw_policies[0].spec["action"] == "DENY"
        else:
            assert len(raw_policies) == 0


@patch.object(IstioIngressCharm, "_get_request_auth_resource_manager")
def test_sync_request_authentication_blocks_on_malformed_apps(mock_get_krm, istio_ingress_context):
    """Test that sync returns malformed apps and reconciles empty when any app has invalid rules."""
    mock_krm = MagicMock()
    mock_get_krm.return_value = mock_krm

    # Create a relation with an empty databag (connected but no valid jwt_rules)
    malformed_relation = scenario.Relation(
        endpoint="istio-request-auth",
        interface="istio_request_auth",
        remote_app_data={},
    )
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[malformed_relation], leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        malformed_apps = charm._sync_request_authentication()

        assert malformed_apps is not None
        assert len(malformed_apps) == 1
        mock_krm.reconcile.assert_called_once_with([])


@patch.object(IstioIngressCharm, "_get_request_auth_resource_manager")
def test_sync_request_authentication_blocks_when_mix_of_valid_and_malformed(mock_get_krm, istio_ingress_context):
    """Test that even one malformed app causes all RequestAuth resources to be cleared."""
    mock_krm = MagicMock()
    mock_get_krm.return_value = mock_krm

    valid_relation = _make_request_auth_relation()
    malformed_relation = scenario.Relation(
        endpoint="istio-request-auth",
        interface="istio_request_auth",
        remote_app_name="malformed-app",
        remote_app_data={},
    )
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[valid_relation, malformed_relation], leader=True),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        malformed_apps = charm._sync_request_authentication()

        assert malformed_apps is not None
        assert "malformed-app" in malformed_apps
        mock_krm.reconcile.assert_called_once_with([])
