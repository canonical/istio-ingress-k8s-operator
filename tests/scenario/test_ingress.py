# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
import scenario

from charm import IstioIngressCharm
from tests.scenario.test_gateway import generate_certificates_relation


@pytest.fixture()
def mock_ingress_requirer_data():
    mock_ingress_requirer_data = MagicMock()
    mock_ingress_requirer_data.app.name = "app-name"
    mock_ingress_requirer_data.app.model = "app-namespace"
    mock_ingress_requirer_data.app.port = 80
    mock_ingress_requirer_data.app.strip_prefix = True
    return mock_ingress_requirer_data


def test_construct_httproute(
    istio_ingress_charm, istio_ingress_context, mock_ingress_requirer_data
):
    """Test that the _construct_httproute method constructs an HTTPRoute object correctly."""
    prefix = "prefix"
    section_name = "section"

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        httproute = charm._construct_httproute(
            data=mock_ingress_requirer_data,
            prefix=prefix,
            section_name=section_name,
        )

        # Assert that we have a single rule and spot check that rule for correctness
        assert len(httproute.spec["parentRefs"]) == 1
        assert httproute.spec["parentRefs"][0]["sectionName"] == section_name
        assert len(httproute.spec["rules"]) == 1
        assert (
            httproute.spec["rules"][0]["backendRefs"][0]["port"]
            == mock_ingress_requirer_data.app.port
        )


def test_construct_redirect_to_https_httproute(
    istio_ingress_charm, istio_ingress_context, mock_ingress_requirer_data
):
    """Test that _construct_redirect_to_https_httproute constructs an HTTPRoute for redirecting to HTTPS correctly."""
    prefix = "prefix"
    section_name = "section"

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        httproute = charm._construct_redirect_to_https_httproute(
            data=mock_ingress_requirer_data,
            prefix=prefix,
            section_name=section_name,
        )

        # Assert that we have a single rule that has a redirect filter and no backend refs
        assert len(httproute.spec["parentRefs"]) == 1
        assert httproute.spec["parentRefs"][0]["sectionName"] == section_name
        assert len(httproute.spec["rules"]) == 1
        assert len(httproute.spec["rules"][0]["backendRefs"]) == 0
        assert len(httproute.spec["rules"][0]["filters"]) == 1
        assert httproute.spec["rules"][0]["filters"][0]["type"] == "RequestRedirect"


def generate_ingress_relation_data(name, model, port=80, ip="1.2.3.4", host=None):
    if host is None:
        host = f"{name}.example.com"
    return scenario.Relation(
        endpoint="ingress",
        interface="ingress",
        remote_app_name=name,
        remote_app_data={
            "name": json.dumps(name),
            "model": json.dumps(model),
            "port": json.dumps(port),
        },
        remote_units_data={
            0: {
                "host": json.dumps(host),
                "ip": json.dumps(ip),
            },
        },
    )


@pytest.mark.parametrize(
    "ingress_relations, n_routes_expected",
    [
        # no relations
        ([], 0),
        # with a single relation that has all data
        ([generate_ingress_relation_data("remote-app0", "remote-model0")], 1),
        # with multiple relations that have all data
        (
            [
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                generate_ingress_relation_data("remote-app1", "remote-model1"),
            ],
            2,
        ),
        # with multiple relations, some of which are not complete (do not have full data yet) and should be skipped
        (
            [
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                scenario.Relation(
                    endpoint="ingress",
                    interface="ingress",
                    remote_app_name="incomplete-app",
                ),
            ],
            1,
        ),
    ],
)
@patch(
    "charm.IstioIngressCharm._external_host", new_callable=PropertyMock, return_value="example.com"
)
def test_sync_ingress_resources(
    _mock_external_host,
    ingress_relations,
    n_routes_expected,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test that the _sync_ingress_resources constructs HTTP routes when TLS is not configured."""
    mock_krm = MagicMock()
    mock_krm_factory = MagicMock(return_value=mock_krm)

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(
            relations=ingress_relations,
            leader=True,
        ),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        charm._get_ingress_resource_manager = mock_krm_factory
        charm._sync_ingress_resources()

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_ingress_resource_manager().reconcile.assert_called_once()

        # Assert that _+_______________________
        resources = charm._get_ingress_resource_manager().reconcile.call_args[0][0]

        assert len(resources) == n_routes_expected
        for route in resources:
            assert len(route.spec["parentRefs"]) == 1
            assert route.spec["parentRefs"][0]["sectionName"] == "http"


@pytest.mark.parametrize(
    "ingress_relations, n_routes_expected",
    [
        # no relations
        ([], 0),
        # with a single relation that has all data
        ([generate_ingress_relation_data("remote-app0", "remote-model0")], 2),
        # with multiple relations that have all data
        (
            [
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                generate_ingress_relation_data("remote-app1", "remote-model1"),
            ],
            4,
        ),
        # with multiple relations, some of which are not complete (do not have full data yet) and should be skipped
        (
            [
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                scenario.Relation(
                    endpoint="ingress",
                    interface="ingress",
                    remote_app_name="incomplete-app",
                ),
            ],
            2,
        ),
    ],
)
@patch(
    "charm.IstioIngressCharm._external_host", new_callable=PropertyMock, return_value="example.com"
)
def test_sync_ingress_resources_with_tls(
    _mock_external_host,
    ingress_relations,
    n_routes_expected,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test that the _sync_ingress_resources constructs HTTP redirect and HTTPS routes when TLS is configured."""
    mock_krm = MagicMock()
    mock_krm_factory = MagicMock(return_value=mock_krm)

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(
            relations=ingress_relations
            + [generate_certificates_relation(subject="example.com")["relation"]],
            leader=True,
        ),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        charm._get_ingress_resource_manager = mock_krm_factory
        charm._sync_ingress_resources()

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_ingress_resource_manager().reconcile.assert_called_once()

        # Assert that _+_______________________
        resources = charm._get_ingress_resource_manager().reconcile.call_args[0][0]

        assert len(resources) == n_routes_expected
        # If TLS is configured, HTTP routes should be redirects and HTTPS routes should route to a parentRef
        for route in resources:
            if route.spec["parentRefs"][0]["sectionName"] == "http":
                assert len(route.spec["rules"]) == 1
                assert len(route.spec["rules"][0]["filters"]) == 1
                assert route.spec["rules"][0]["filters"][0]["type"] == "RequestRedirect"
            elif route.spec["parentRefs"][0]["sectionName"] == "https":
                assert len(route.spec["parentRefs"]) == 1
                assert route.spec["parentRefs"][0]["sectionName"] == "https"
            else:
                raise AssertionError("Unexpected section name")