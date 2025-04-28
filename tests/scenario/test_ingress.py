# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
import scenario
from ops import ActiveStatus

from charm import IstioIngressCharm, RouteInfo, get_unauthenticated_paths
from models import HTTPRouteFilterType
from tests.scenario.test_gateway import generate_certificates_relation


@pytest.mark.parametrize(
    "strip_prefix, filters",
    [
        # If strip_prefix == True, we should have a URLRewrite filter with ReplacePrefixMatch of "/"
        (
            True,
            [
                {
                    "type": HTTPRouteFilterType.URLRewrite,
                    "urlRewrite": {
                        "path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}
                    },
                }
            ],
        ),
        (False, []),
    ],
)
def test_construct_httproute_with_strip_prefix(
    strip_prefix, filters, istio_ingress_charm, istio_ingress_context
):
    """Test that the _construct_httproute method constructs an HTTPRoute object correctly."""
    service_name = "app_name"
    namespace = "model"
    port = 1234
    prefix = "prefix"
    section_name = "section"

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        httproute = charm._construct_httproute(
            service_name=service_name,
            namespace=namespace,
            port=port,
            prefix=prefix,
            section_name=section_name,
            strip_prefix=strip_prefix,
        )

        assert httproute.spec["rules"][0]["filters"] == filters


def test_construct_httproute(istio_ingress_charm, istio_ingress_context):
    """Test that the _construct_httproute method constructs an HTTPRoute object correctly."""
    service_name = "app_name"
    namespace = "model"
    port = 1234
    strip_prefix = False
    prefix = "prefix"
    section_name = "section"

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        httproute = charm._construct_httproute(
            service_name=service_name,
            namespace=namespace,
            port=port,
            strip_prefix=strip_prefix,
            prefix=prefix,
            section_name=section_name,
        )

        # Assert that we have a single rule and spot check that rule for correctness
        assert len(httproute.spec["parentRefs"]) == 1
        assert httproute.spec["parentRefs"][0]["sectionName"] == section_name
        assert len(httproute.spec["rules"]) == 1
        assert httproute.spec["rules"][0]["backendRefs"][0]["port"] == port


def test_construct_ingress_auth_policy(istio_ingress_charm, istio_ingress_context):
    """Test that the _construct_ingress_auth_policy method constructs an Authorization Policy object correctly."""
    target_name = "app-name"
    target_namespace = "app-namespace"
    target_port = 80

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        auth_policy = charm._construct_auth_policy_from_ingress_to_target(
            target_name=target_name,
            target_namespace=target_namespace,
            target_port=target_port,
        )

        # Verify the AuthorizationPolicy resource
        assert auth_policy.metadata.name == f"{target_name}-{charm.app.name}-{target_namespace}-l4"
        assert auth_policy.metadata.namespace == "app-namespace"

        # Check spec rules
        assert len(auth_policy.spec["rules"]) == 1
        rule = auth_policy.spec["rules"][0]

        # Verify `to` field
        assert rule["to"] == [{"operation": {"ports": ["80"]}}]

        # Verify `from` field (principals)
        principals = rule["from"][0]["source"]["principals"]
        expected_principal = f"cluster.local/ns/{charm.model.name}/sa/{charm.managed_name}"
        assert principals == [expected_principal]

        # Verify workload selector
        assert auth_policy.spec["selector"] == {
            "matchLabels": {"app.kubernetes.io/name": "app-name"}
        }


def test_construct_redirect_to_https_httproute(istio_ingress_charm, istio_ingress_context):
    """Test that _construct_redirect_to_https_httproute constructs an HTTPRoute for redirecting to HTTPS correctly."""
    app_name = "app-name"
    model = "model-name"
    prefix = "prefix"
    section_name = "section"

    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        httproute = charm._construct_redirect_to_https_httproute(
            app_name=app_name,
            model=model,
            prefix=prefix,
            section_name=section_name,
        )

        # Assert that we have a single rule that has a redirect filter and no backend refs
        assert len(httproute.spec["parentRefs"]) == 1
        assert httproute.metadata.name == f"{app_name}-{section_name}-{charm.app.name}"
        assert httproute.spec["parentRefs"][0]["sectionName"] == section_name
        assert len(httproute.spec["rules"]) == 1
        assert len(httproute.spec["rules"][0].get("backendRefs", [])) == 0
        assert len(httproute.spec["rules"][0]["filters"]) == 1
        assert httproute.spec["rules"][0]["filters"][0]["type"] == "RequestRedirect"


def generate_ingress_relation_data(
    name, model, port=80, ip="1.2.3.4", host=None, strip_prefix=False, endpoint="ingress"
):
    if host is None:
        host = f"{name}.example.com"
    return scenario.Relation(
        endpoint=endpoint,
        interface="ingress",
        remote_app_name=name,
        remote_app_data={
            "name": json.dumps(name),
            "model": json.dumps(model),
            "port": json.dumps(port),
            "strip-prefix": json.dumps(strip_prefix),
        },
        remote_units_data={
            0: {
                "host": json.dumps(host),
                "ip": json.dumps(ip),
            },
        },
    )


@pytest.mark.parametrize(
    "routes, expected_ingressed_prefixes",
    [
        # no relations
        ([], []),
        # with a single relation that has all data
        (
            [
                RouteInfo(
                    service_name="remote-app0",
                    namespace="remote-model0",
                    port=1234,
                    strip_prefix=False,
                    prefix="/path0",
                ),
            ],
            ["/path0"],
        ),
        # with multiple relations that have all data
        (
            [
                RouteInfo(
                    service_name="remote-app0",
                    namespace="remote-model0",
                    port=1234,
                    strip_prefix=False,
                    prefix="/path0",
                ),
                RouteInfo(
                    service_name="remote-app1",
                    namespace="remote-model1",
                    port=1234,
                    strip_prefix=False,
                    prefix="/path1",
                ),
            ],
            [
                "/path0",
                "/path1",
            ],
        ),
    ],
)
@patch(
    "charm.IstioIngressCharm._ingress_url", new_callable=PropertyMock, return_value="example.com"
)
def test_sync_ingress_resources(
    _mock_ingress_url,
    routes,
    expected_ingressed_prefixes,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test that the _sync_ingress_resources constructs HTTP routes when TLS is not configured."""
    # Mock Kubernetes Resource Managers
    mock_ingress_manager = MagicMock()
    mock_auth_manager = MagicMock()
    mock_ingress_manager_factory = MagicMock(return_value=mock_ingress_manager)
    mock_auth_manager_factory = MagicMock(return_value=mock_auth_manager)

    # Initialize charm in test scenario
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(
            leader=True,
        ),
    ) as manager:
        charm: IstioIngressCharm = manager.charm

        # Patch the managers into the charm
        charm._get_ingress_route_resource_manager = mock_ingress_manager_factory
        charm._get_ingress_auth_policy_resource_manager = mock_auth_manager_factory

        # Call the method under test
        charm._sync_ingress_resources(routes=routes)

        # Assertions: Managers' reconcile methods are called once
        mock_ingress_manager.reconcile.assert_called_once()
        mock_auth_manager.reconcile.assert_called_once()

        # Retrieve the resources passed to reconcile
        ingress_resources = mock_ingress_manager.reconcile.call_args[0][0]
        auth_resources = mock_auth_manager.reconcile.call_args[0][0]

        # Assertions: Check resource counts
        assert len(ingress_resources) == len(expected_ingressed_prefixes)
        assert len(auth_resources) == len(expected_ingressed_prefixes)

        # Assertions: Verify each ingress resource's structure
        for route, prefix in zip(ingress_resources, expected_ingressed_prefixes):
            assert len(route.spec["parentRefs"]) == 1
            assert route.spec["parentRefs"][0]["sectionName"] == "http"
            assert route.spec["rules"][0]["matches"][0]["path"]["value"] == prefix

        # Assertions: Verify authorization resources
        for auth in auth_resources:
            assert auth.metadata.name is not None
            assert auth.metadata.namespace is not None


@pytest.mark.parametrize(
    "routes, n_routes_expected",
    [
        # no relations
        ([], 0),
        # with a single relation that has all data
        (
            [
                RouteInfo(
                    service_name="remote-app0",
                    namespace="remote-model0",
                    port=1234,
                    strip_prefix=False,
                    prefix="/path0",
                ),
            ],
            2,
        ),
        # with multiple relations that have all data
        (
            [
                RouteInfo(
                    service_name="remote-app0",
                    namespace="remote-model0",
                    port=1234,
                    strip_prefix=False,
                    prefix="/path0",
                ),
                RouteInfo(
                    service_name="remote-app1",
                    namespace="remote-model1",
                    port=1234,
                    strip_prefix=False,
                    prefix="/path1",
                ),
            ],
            4,
        ),
    ],
)
@patch(
    "charm.IstioIngressCharm._ingress_url", new_callable=PropertyMock, return_value="example.com"
)
def test_sync_ingress_resources_with_tls(
    _mock_ingress_url,
    routes,
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
            relations=[generate_certificates_relation(subject="example.com")["relation"]],
            leader=True,
        ),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        charm._get_ingress_route_resource_manager = mock_krm_factory
        charm._sync_ingress_resources(routes=routes)

        # Assert that we've tried to reconcile the kubernetes resources
        charm._get_ingress_route_resource_manager().reconcile.assert_called_once()

        # Assert that _+_______________________
        resources = charm._get_ingress_route_resource_manager().reconcile.call_args[0][0]

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


@pytest.mark.parametrize(
    "ingress_relations, paths_expected, unauthenticated_paths_expected",
    [
        # no relations
        ([], {}, []),
        # with a single relation that has all data
        (
            [generate_ingress_relation_data("remote-app0", "remote-model0")],
            # (app-name, ingress-relation-name): [list of paths for this app],
            {("remote-app0", "ingress"): ["/remote-model0-remote-app0"]},
            [],
        ),
        # with multiple related apps on `ingress`
        (
            [
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                generate_ingress_relation_data("remote-app1", "remote-model1"),
                generate_ingress_relation_data("remote-app2", "remote-model2"),
            ],
            # (app-name, ingress-relation-name): [list of paths for this app],
            {
                ("remote-app0", "ingress"): ["/remote-model0-remote-app0"],
                ("remote-app1", "ingress"): ["/remote-model1-remote-app1"],
                ("remote-app2", "ingress"): ["/remote-model2-remote-app2"],
            },
            [],
        ),
        # with multiple related apps on `ingress` and `ingress-unauthenticated`
        (
            [
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                generate_ingress_relation_data(
                    "remote-app1", "remote-model1", endpoint="ingress-unauthenticated"
                ),
                generate_ingress_relation_data("remote-app2", "remote-model2"),
            ],
            # (app-name, ingress-relation-name): [list of paths for this app],
            {
                ("remote-app0", "ingress"): ["/remote-model0-remote-app0"],
                ("remote-app1", "ingress-unauthenticated"): ["/remote-model1-remote-app1"],
                ("remote-app2", "ingress"): ["/remote-model2-remote-app2"],
            },
            ["/remote-model1-remote-app1/*"],
        ),
    ],
)
@patch(
    "charm.IstioIngressCharm._ingress_url", new_callable=PropertyMock, return_value="example.com"
)
def test_get_routes(
    _mock_ingress_url,
    ingress_relations,
    paths_expected,
    unauthenticated_paths_expected,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test that .get_routes returns the expected routes for given ingress relations."""
    with istio_ingress_context(
        istio_ingress_context.on.update_status(),
        state=scenario.State(
            relations=ingress_relations,
            leader=True,
        ),
    ) as manager:
        charm: IstioIngressCharm = manager.charm
        routes = charm._get_routes()
        unauthenticated_paths_actual = get_unauthenticated_paths(routes)

        # Extract the paths requested by these routes to compare to expected
        path_map_actual = {
            k: [r["prefix"] for r in route_data["routes"]] for k, route_data in routes.items()
        }
        assert path_map_actual == paths_expected
        assert unauthenticated_paths_actual == unauthenticated_paths_expected


@pytest.mark.parametrize(
    "ingress_relations, expected_ingress_data_sent",
    [
        # Apps related to this charm on both ingress relations
        (
            # List of ingress relations, using either ingress endpoint
            (
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                generate_ingress_relation_data(
                    "remote-app1", "remote-model1", endpoint="ingress-unauthenticated"
                ),
            ),
            # List of the "ingress" part of the ingress relation data that is sent by this charm to the remote app
            # Each row corresponds to a specific ingress relation in the previous tuple
            (
                {"ingress": json.dumps({"url": "http://example.com/remote-model0-remote-app0"})},
                {"ingress": json.dumps({"url": "http://example.com/remote-model1-remote-app1"})},
            ),
        ),
        # App is related to us on multiple ingress endpoints, requiring deduplication
        (
            (
                generate_ingress_relation_data("remote-app0", "remote-model0"),
                generate_ingress_relation_data(
                    "remote-app1", "remote-model1", endpoint="ingress-unauthenticated"
                ),
                generate_ingress_relation_data("remote-app2", "remote-model2"),
                generate_ingress_relation_data(
                    "remote-app2", "remote-model2", endpoint="ingress-unauthenticated"
                ),
            ),
            (
                {"ingress": json.dumps({"url": "http://example.com/remote-model0-remote-app0"})},
                {"ingress": json.dumps({"url": "http://example.com/remote-model1-remote-app1"})},
                {},  # removed because it is a duplicate
                {},  # removed because it is a duplicate
            ),
        ),
    ],
)
@patch("charm.IstioIngressCharm._is_ready", return_value=True)
@patch(
    "charm.IstioIngressCharm._ingress_url", new_callable=PropertyMock, return_value="example.com"
)
def test_ingress_e2e(
    _mock_ingress_url,
    _mock_is_ready,
    ingress_relations,
    expected_ingress_data_sent,
    istio_ingress_charm,
    istio_ingress_context,
):
    """Test end-to-end operation of the charm with ingress relations.

    In particular, this test is important to assert that
    * we publish the ingress url back to related applications.
    * we handle duplicated ingress requests correctly (the charm does not break, but we do not provide an ingress)

    These functionalities are not tested elsewhere.
    """
    state_out = istio_ingress_context.run(
        istio_ingress_context.on.config_changed(),
        state=scenario.State(
            relations=ingress_relations,
            leader=True,
            containers=[
                scenario.Container(
                    "metrics-proxy",
                    can_connect=True,
                )
            ],
        ),
    )

    # Assert all relations have been told their ingress url
    for i, relation in enumerate(ingress_relations):
        assert state_out.get_relation(relation.id).local_app_data == expected_ingress_data_sent[i]

    assert isinstance(state_out.unit_status, ActiveStatus)
