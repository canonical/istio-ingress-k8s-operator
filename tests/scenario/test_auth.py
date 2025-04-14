# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from unittest.mock import patch

import pytest
import scenario
from ops import ActiveStatus, BlockedStatus

from charm import IstioIngressCharm

# Test external authorization configuration setup for when we have a valid ingress-config relation in two scenarios:
#   - When a forward-auth relation exists, its decisions address should be used.
#   - When no forward-auth relation exists, the decisions address should be None, which would then clear the ingress-config databag.
# The test patches:
# - _is_ready to always return True (so that gateway readiness passes),
# - _setup_proxy_pebble_service (to skip side effects),
# - _publish_ext_authz_config and _sync_ext_authz_config to verify they are called.


@pytest.mark.parametrize(
    "forward_auth_present, expected_decision",
    [
        (True, "http://auth-service:80"),  # Forward-auth relation exists.
        (False, None),  # No forward-auth relation.
    ],
)
@patch.object(IstioIngressCharm, "_sync_ext_authz_config")
@patch.object(IstioIngressCharm, "_publish_ext_authz_config")
@patch.object(IstioIngressCharm, "_setup_proxy_pebble_service")
@patch.object(IstioIngressCharm, "_is_ready", return_value=True)
def test_ext_authz_setup(
    mock_is_ready,
    mock_setup,
    mock_publish,
    mock_sync,
    forward_auth_present,
    expected_decision,
    istio_ingress_charm,
    istio_ingress_context,
):
    relations = []
    if forward_auth_present:
        fwd_auth_relation = scenario.Relation(
            endpoint="forward-auth",
            interface="forward_auth",
            remote_app_data={
                "decisions_address": expected_decision,
                "app_names": json.dumps(["my-app"]),
                "headers": json.dumps([]),
            },
        )
        relations.append(fwd_auth_relation)

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


# Test external authorization configuration setup when the forward-auth or ingress-config relation is incomplete or missing:
#   - Scenario A: The forward-auth relation is present but provides no decisions address.
#   - Scenario B: The forward-auth relation provides a decisions address, but the ingress-config relation exists with incomplete data.
# In both scenarios, the charm is expected to set a BlockedStatus and call _remove_gateway_resources.


@pytest.mark.parametrize(
    "fwd_remote_data, ingress_relation_present, expected_message",
    [
        # Scenario A: No decisions address provided.
        (
            {},  # forward-auth remote_app_data is empty
            False,  # No ingress-config relation
            "Authentication configuration incomplete; ingress is disabled.",
        ),
        # Scenario B: Decisions address provided but ingress-config is not ready (empty data).
        (
            {
                "decisions_address": "http://auth-service:80",
                "app_names": json.dumps(["my-app"]),
                "headers": json.dumps([]),
            },
            True,  # ingress-config relation exists (but will be not ready)
            "Ingress configuration relation missing, yet valid authentication configuration are provided.",
        ),
    ],
)
def test_auth_and_ingress_incomplete(
    fwd_remote_data,
    ingress_relation_present,
    expected_message,
    istio_ingress_charm,
    istio_ingress_context,
):

    fwd_auth_relation = scenario.Relation(
        endpoint="forward-auth",
        interface="forward_auth",
        remote_app_data=fwd_remote_data,
    )
    relations = [fwd_auth_relation]
    if ingress_relation_present:
        ingress_config_relation = scenario.Relation(
            endpoint="istio-ingress-config",
            interface="istio_ingress_config",
            remote_app_data={},
        )
        relations.append(ingress_config_relation)

    state = scenario.State(relations=relations, leader=True)

    with patch.object(istio_ingress_charm, "_remove_gateway_resources") as mock_remove:
        out = istio_ingress_context.run(istio_ingress_context.on.config_changed(), state)
        assert isinstance(out.unit_status, BlockedStatus)
        assert out.unit_status.message == expected_message
        mock_remove.assert_called_once()
