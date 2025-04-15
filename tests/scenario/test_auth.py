# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from unittest.mock import patch

import pytest
import scenario
from ops import ActiveStatus, BlockedStatus

from charm import IstioIngressCharm


@pytest.mark.parametrize(
    "forward_auth_relation, expected_decision",
    [
        # When a forward-auth relation exists, its decisions address should be used.
        (
            scenario.Relation(
                endpoint="forward-auth",
                interface="forward_auth",
                remote_app_data={
                    "decisions_address": "http://auth-service:80",
                    "app_names": json.dumps(["my-app"]),
                    "headers": json.dumps([]),
                },
            ),
            "http://auth-service:80",
        ),
        # When no forward-auth relation exists, expected decision remains None.
        (None, None),
    ],
)
# to verify it is called
@patch.object(IstioIngressCharm, "_sync_ext_authz_auth_policy")
# to verify it is called
@patch.object(IstioIngressCharm, "_publish_to_istio_ingress_config_relation")
# to skip side effects
@patch.object(IstioIngressCharm, "_setup_proxy_pebble_service")
# so that gateway readiness passes
@patch.object(IstioIngressCharm, "_is_ready", return_value=True)
def test_ext_authz_setup(
    mock_is_ready,
    mock_setup,
    mock_publish,
    mock_sync,
    forward_auth_relation,
    expected_decision,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test external authorization configuration setup for when we have a valid ingress-config and different forward_auth situations."""
    relations = []
    if forward_auth_relation:
        relations.append(forward_auth_relation)

    ingress_config_relation = scenario.Relation(
        endpoint="istio-ingress-config",
        interface="istio_ingress_config",
        remote_app_data={"ext_authz_provider_name": "foo"},
    )
    relations.append(ingress_config_relation)

    state = scenario.State(relations=relations, leader=True)
    out = istio_ingress_context.run(istio_ingress_context.on.config_changed(), state)

    mock_publish.assert_called_once_with(expected_decision)
    mock_sync.assert_called_once_with(expected_decision)
    assert isinstance(out.unit_status, ActiveStatus)
    assert out.unit_status.message.startswith("Serving at")


@pytest.mark.parametrize(
    "forward_auth_relation, ingress_config_relation, expected_message",
    [
        # Scenario A: No decisions address provided, with no ingress-config relation.
        (
            scenario.Relation(
                endpoint="forward-auth",
                interface="forward_auth",
                remote_app_data={},  # forward-auth relation has empty data
            ),
            None,  # ingress-config relation is absent
            "Authentication configuration incomplete; ingress is disabled.",
        ),
        # Scenario B: Decisions address provided, but ingress-config relation is present with empty data.
        (
            scenario.Relation(
                endpoint="forward-auth",
                interface="forward_auth",
                remote_app_data={
                    "decisions_address": "http://auth-service:80",
                    "app_names": json.dumps(["my-app"]),
                    "headers": json.dumps([]),
                },
            ),
            scenario.Relation(
                endpoint="istio-ingress-config",
                interface="istio_ingress_config",
                remote_app_data={},  # ingress-config relation exists but has empty data
            ),
            "Ingress configuration relation missing, yet valid authentication configuration are provided.",
        ),
    ],
)
def test_auth_and_ingress_incomplete(
    forward_auth_relation,
    ingress_config_relation,
    expected_message,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test external authorization configuration setup when the forward-auth or ingress-config relation is incomplete or missing."""
    relations = []
    if forward_auth_relation:
        relations.append(forward_auth_relation)
    if ingress_config_relation:
        relations.append(ingress_config_relation)

    state = scenario.State(relations=relations, leader=True)

    with patch.object(istio_ingress_charm, "_remove_gateway_resources") as mock_remove:
        out = istio_ingress_context.run(istio_ingress_context.on.config_changed(), state)
        assert isinstance(out.unit_status, BlockedStatus)
        assert out.unit_status.message == expected_message
        mock_remove.assert_called_once()
