# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from typing import Optional
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
import scenario
from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Secret
from ops import ActiveStatus

from charm import IstioIngressCharm


def test_construct_gateway(istio_ingress_charm, istio_ingress_context):
    """Assert that the Gateway definition is constructed as expected."""
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm = manager.charm
        gateway = charm._construct_gateway()

        # Simple spot check of the Gateway object
        assert gateway.spec["listeners"][0]["name"] == "http"

        # Assert that TLS is not configured
        assert gateway.spec["listeners"][0].get("tls", None) is None

        # And that we configure no hostname
        assert gateway.spec["listeners"][0].get("hostname", None) is None


@patch("charm.IstioIngressCharm._get_lb_external_address", new_callable=PropertyMock)
def test_construct_gateway_with_loadbalancer_address(
    mock_get_lb_external_address, istio_ingress_charm, istio_ingress_context
):
    """Assert that when a LoadBalancer address is available, the Gateway definition uses that hostname."""
    hostname = "example.com"
    mock_get_lb_external_address.return_value = hostname
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm = manager.charm
        gateway = charm._construct_gateway()

        # Assert that the Gateway has an http listener with the correct configurations
        _validate_gateway_listener(gateway, "http", hostname, tls_secret_name=None)


@patch(
    "charm.IstioIngressCharm._get_lb_external_address",
    new_callable=PropertyMock,
    return_value=None,
)
def test_construct_gateway_with_tls(
    mock_get_lb_external_address, istio_ingress_charm, istio_ingress_context
):
    """Assert that when TLS is configured, the Gateway definition is constructed using TLS as expected."""
    hostname = "example.com"
    mock_get_lb_external_address.return_value = hostname
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm = manager.charm
        tls_secret_name = "tls-secret"
        gateway = charm._construct_gateway(tls_secret_name=tls_secret_name)

        # Assert that the Gateway has http and https listeners with the correct configurations.
        _validate_gateway_listener(gateway, "http", hostname, tls_secret_name=None)
        _validate_gateway_listener(gateway, "https", hostname, tls_secret_name=tls_secret_name)


def test_sync_gateway_resources_without_tls(istio_ingress_charm, istio_ingress_context):
    """Test that when we have no TLS relation, the Gateway has only an http listener."""
    mock_krm = MagicMock()
    mock_krm_factory = MagicMock(return_value=mock_krm)

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm = manager.charm
        charm._get_gateway_resource_manager = mock_krm_factory
        charm._sync_gateway_resources()

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_gateway_resource_manager().reconcile.assert_called_once()

        # Assert that the Gateway resource has been created with only an http listener
        gateway = charm._get_gateway_resource_manager().reconcile.call_args[0][0][0]
        _validate_gateway_listener(gateway, "http", tls_secret_name=None)

        with pytest.raises(KeyError):
            _get_listener_given_name(gateway, "https")


@patch(
    "charm.IstioIngressCharm._get_lb_external_address",
    new_callable=PropertyMock,
    return_value=None,
)
def test_sync_gateway_resources_with_tls_without_loadbalancer_address(
    istio_ingress_charm, istio_ingress_context
):
    """Test that when we have a full TLS relation but no LoadBalancer address, the Gateway has only an http listener."""
    mock_krm = MagicMock()
    mock_krm_factory = MagicMock(return_value=mock_krm)

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[generate_certificates_relation()["relation"]]),
    ) as manager:
        charm = manager.charm
        charm._get_gateway_resource_manager = mock_krm_factory
        charm._sync_gateway_resources()

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_gateway_resource_manager().reconcile.assert_called_once()

        # Assert that the Gateway resource has been created with only an http listener
        gateway = charm._get_gateway_resource_manager().reconcile.call_args[0][0][0]
        _validate_gateway_listener(gateway, "http", tls_secret_name=None)

        with pytest.raises(KeyError):
            _get_listener_given_name(gateway, "https")


@patch("charm.IstioIngressCharm._get_lb_external_address", new_callable=PropertyMock)
def test_sync_gateway_resources_with_tls_with_loadbalancer_address(
    mock_get_lb_external_address, istio_ingress_charm, istio_ingress_context
):
    """Test that when we have a TLS relation and a LoadBalancer address, the Gateway has http and https listeners."""
    mock_krm = MagicMock()
    mock_krm_factory = MagicMock(return_value=mock_krm)
    hostname = "example.com"
    mock_get_lb_external_address.return_value = hostname
    certificate_info = generate_certificates_relation()

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[certificate_info["relation"]]),
    ) as manager:
        charm = manager.charm
        charm._get_gateway_resource_manager = mock_krm_factory
        charm._sync_gateway_resources()

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_gateway_resource_manager().reconcile.assert_called_once()

        # Assert that we have created a certificate secret as expected
        secret = charm._get_gateway_resource_manager().reconcile.call_args[0][0][0]
        assert secret.stringData["tls.crt"] == certificate_info["certificate_string"]

        # Assert that the Gateway was created and has http and https listeners with the correct configurations.
        gateway = charm._get_gateway_resource_manager().reconcile.call_args[0][0][1]
        _validate_gateway_listener(gateway, "http", hostname, tls_secret_name=None)
        _validate_gateway_listener(
            gateway, "https", hostname, tls_secret_name=charm._certificate_secret_name
        )


def test_sync_gateway_resources_with_tls_with_external_hostname_config(
    istio_ingress_charm, istio_ingress_context
):
    """Asserts that a gateway with complete TLS relation and a external_hostname config creates a gateway with TLS."""
    mock_krm = MagicMock()
    mock_krm_factory = MagicMock(return_value=mock_krm)

    hostname = "foo.bar"
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(
            config={"external_hostname": hostname},
            relations=[generate_certificates_relation(subject=hostname)["relation"]],
        ),
    ) as manager:
        charm = manager.charm
        charm._get_gateway_resource_manager = mock_krm_factory
        charm._sync_gateway_resources()

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_gateway_resource_manager().reconcile.assert_called_once()

        # Assert that we have created a certificate secret as expected
        secret = charm._get_gateway_resource_manager().reconcile.call_args[0][0][0]
        assert secret.stringData.get("tls.crt", None) is not None

        # Assert that the Gateway was created and has http and https listeners with the correct configurations.
        gateway = charm._get_gateway_resource_manager().reconcile.call_args[0][0][1]
        _validate_gateway_listener(gateway, "http", hostname, tls_secret_name=None)
        _validate_gateway_listener(
            gateway, "https", hostname, tls_secret_name=charm._certificate_secret_name
        )


@pytest.mark.parametrize(
    "tls_secret",
    [
        None,
        Secret(
            metadata=ObjectMeta(name="secret"),
            stringData={
                "tls.crt": "tls.crt",
                "tls.key": "tls.key",
            },
        ),
    ],
)
@patch("charm.IstioIngressCharm._get_gateway_resource_manager")
@patch("charm.IstioIngressCharm._construct_gateway_tls_secret")
@patch("charm.IstioIngressCharm._construct_gateway")
def test_sync_gateway_resources_with_tls(
    mocked_construct_gateway,
    mocked_construct_gateway_tls_secret,
    _mocked_get_gateway_resource_manager,
    tls_secret,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Tests whether Gateway resources are created with TLS configuration, when available."""
    mocked_construct_gateway_tls_secret.return_value = tls_secret
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm = manager.charm
        charm._sync_gateway_resources()
        # Assert that the Gateway resource has been created with expected secret name
        secret_name = tls_secret.metadata.name if tls_secret else None
        mocked_construct_gateway.assert_called_once_with(tls_secret_name=secret_name)


def test_construct_gateway_tls_secret_with_certificates(
    istio_ingress_charm, istio_ingress_context
):
    """Assert that when certificates are provided, construct_gateway_tls_secret returns the expected Secret."""
    certificate_relation_info = generate_certificates_relation()
    certificate_string = certificate_relation_info["certificate_string"]
    certificate_relation = certificate_relation_info["relation"]

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[certificate_relation]),
    ) as manager:
        charm = manager.charm
        secret = charm._construct_gateway_tls_secret()
        assert secret.stringData["tls.crt"] == certificate_string


def test_construct_gateway_tls_secret_without_certificates(
    istio_ingress_charm, istio_ingress_context
):
    """Assert that when no certificates are provided, the construct_gateway_tls_secret returns None."""
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(relations=[]),
    ) as manager:
        charm = manager.charm
        secret = charm._construct_gateway_tls_secret()
        assert secret is None


def generate_certificates_relation(subject="example.com"):
    requirer_private_key = generate_private_key()

    csr = generate_csr(
        private_key=requirer_private_key,
        subject=subject,
    )
    provider_private_key = generate_private_key()
    provider_ca_certificate = generate_ca(
        private_key=provider_private_key,
        subject=subject,
    )
    certificate = generate_certificate(
        ca_key=provider_private_key,
        csr=csr,
        ca=provider_ca_certificate,
    )

    to_return = {
        "csr_string": csr.decode(),
        "provider_ca_certificate_string": provider_ca_certificate.decode(),
        "certificate_string": certificate.decode(),
    }

    to_return["relation"] = scenario.Relation(
        endpoint="certificates",
        interface="tls-certificates",
        remote_app_name="certificate-requirer",
        local_unit_data={
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": to_return["csr_string"],
                        "ca": False,
                    }
                ]
            )
        },
        remote_app_data={
            "certificates": json.dumps(
                [
                    {
                        "certificate": to_return["certificate_string"],
                        "certificate_signing_request": to_return["csr_string"],
                        "ca": to_return["provider_ca_certificate_string"],
                    }
                ]
            ),
        },
    )
    return to_return


def _validate_gateway_listener(
    gateway,
    listener_name: str,
    hostname: Optional[str] = None,
    tls_secret_name: Optional[str] = None,
):
    """Validates the Gateway object has the listener with expected configuration."""
    listener = _get_listener_given_name(gateway, listener_name)
    if hostname:
        assert listener.get("hostname", None) == hostname
    if tls_secret_name:
        assert len(listener["tls"]["certificateRefs"]) == 1
        assert listener["tls"]["certificateRefs"][0]["name"] == tls_secret_name
    else:
        assert listener.get("tls", None) is None


def _get_listener_given_name(gateway, name: str):
    """Helper function to get a listener from a Gateway by name."""
    for listener in gateway.spec["listeners"]:
        if listener["name"] == name:
            return listener
    raise KeyError(f"Listener with name {name} not found")


def test_construct_hpa(istio_ingress_charm, istio_ingress_context):
    """Assert that the HPA definition is constructed as expected."""
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(leader=True, planned_units=3),
    ) as manager:
        charm = manager.charm

        hpa = charm._construct_hpa(charm.model.app.planned_units())
        assert hpa.metadata.name == charm.app.name
        assert hpa.metadata.namespace == charm.model.name

        spec = hpa.spec
        assert spec.minReplicas == charm.model.app.planned_units()
        assert spec.maxReplicas == charm.model.app.planned_units()

        ref = spec.scaleTargetRef
        assert ref.apiVersion == "apps/v1"
        assert ref.kind == "Deployment"
        assert ref.name == "istio-ingress-k8s-istio"


@pytest.mark.parametrize("planned_units", [1, 3, 5])
@patch.object(IstioIngressCharm, "_is_ready", return_value=True)
@patch.object(IstioIngressCharm, "_setup_proxy_pebble_service")
@patch.object(IstioIngressCharm, "_get_hpa_resource_manager")
def test_sync_all_triggers_hpa_reconcile(
    mock_get_hpa,
    mock_setup_proxy,
    mock_is_ready,
    istio_ingress_charm,
    istio_ingress_context,
    planned_units,
):
    """Assert that HPA reconciliation is invoked at the end of _sync_all_resources."""
    mock_manager = mock_get_hpa.return_value
    state = scenario.State(relations=[], leader=True, planned_units=planned_units)

    result = istio_ingress_context.run(istio_ingress_context.on.config_changed(), state)

    mock_get_hpa.assert_called_once()
    mock_manager.reconcile.assert_called_once()

    hpa_list = mock_manager.reconcile.call_args.args[0]
    assert len(hpa_list) == 1
    hpa = hpa_list[0]
    assert hpa.spec.minReplicas == planned_units
    assert hpa.spec.maxReplicas == planned_units

    assert isinstance(result.unit_status, ActiveStatus)
    assert result.unit_status.message.startswith("Serving at")


@pytest.mark.parametrize("leader,call_count", [(True, 1), (False, 0)])
@patch.object(IstioIngressCharm, "_get_hpa_resource_manager")
def test_on_remove_hpa_deleted_only_if_leader(
    mock_get_hpa, istio_ingress_charm, istio_ingress_context, leader, call_count
):
    """Assert that _on_remove() deletes the HPA only if the unit is leader."""
    state = scenario.State(relations=[], leader=leader)
    istio_ingress_context.run(istio_ingress_context.on.remove(), state)

    manager = mock_get_hpa.return_value
    assert manager.delete.call_count == call_count
