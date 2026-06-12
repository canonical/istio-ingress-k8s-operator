# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the upstream-ingress chaining feature."""

from unittest.mock import PropertyMock, patch

import pytest
from charmlibs.interfaces.istio_ingress_route import (
    BackendRef as LibBackendRef,
)
from charmlibs.interfaces.istio_ingress_route import (
    GRPCMethodMatch,
    IstioIngressRouteConfig,
    ProtocolType,
)
from charmlibs.interfaces.istio_ingress_route import (
    GRPCRoute as LibGRPCRoute,
)
from charmlibs.interfaces.istio_ingress_route import (
    GRPCRouteMatch as LibGRPCRouteMatch,
)
from charmlibs.interfaces.istio_ingress_route import (
    HTTPPathMatch as LibHTTPPathMatch,
)
from charmlibs.interfaces.istio_ingress_route import (
    HTTPRoute as LibHTTPRoute,
)
from charmlibs.interfaces.istio_ingress_route import (
    HTTPRouteMatch as LibHTTPRouteMatch,
)
from charmlibs.interfaces.istio_ingress_route import (
    Listener as LibListener,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from ops.testing import Harness

from charm import IstioIngressCharm


@pytest.fixture()
def harness():
    harness = Harness(IstioIngressCharm)
    harness.set_model_name("istio-system")
    yield harness
    harness.cleanup()


def test_ingress_url_cascades_through_upstream(harness):
    """When upstream ingress is ready, _ingress_url returns the upstream URL with scheme stripped."""
    harness.begin()
    charm = harness.charm
    charm._ingress_url_ = None

    with patch.object(
        charm.upstream_ingress, "is_ready", return_value=True
    ), patch.object(
        IngressPerAppRequirer, "url", new_callable=PropertyMock, return_value="https://upstream.example.com/model-app/"
    ):
        assert charm._ingress_url == "upstream.example.com/model-app"


def test_ingress_url_falls_back_without_upstream(harness):
    """Without upstream, _ingress_url returns external_hostname or LB address."""
    harness.begin()
    charm = harness.charm
    charm._ingress_url_ = None

    with patch.object(
        charm.upstream_ingress, "is_ready", return_value=False
    ), patch(
        "charm.IstioIngressCharm._get_lb_external_address",
        new_callable=PropertyMock,
        return_value="10.1.1.1",
    ):
        assert charm._ingress_url == "10.1.1.1"


def test_ingress_url_with_scheme_uses_upstream(harness):
    """_ingress_url_with_scheme returns the full cascaded URL including the upstream's scheme."""
    harness.begin()
    charm = harness.charm
    charm._ingress_url_ = None

    with patch.object(
        charm.upstream_ingress, "is_ready", return_value=True
    ), patch.object(
        IngressPerAppRequirer, "url", new_callable=PropertyMock, return_value="https://upstream.example.com/model-app/"
    ):
        assert charm._ingress_url_with_scheme() == "https://upstream.example.com/model-app"


def test_construct_gateway_uses_local_address_not_upstream(harness):
    """The Gateway K8s resource hostname should use the local address, not the cascaded upstream."""
    harness.update_config({"external_hostname": "local.example.com"})
    harness.begin()
    charm = harness.charm
    http_listener = LibListener(port=8080, protocol=ProtocolType.HTTP)
    grpc_listener = LibListener(port=9090, protocol=ProtocolType.GRPC)

    istio_ingress_route_configs = {
        ("app1", "istio-ingress-route"): {
            "config": IstioIngressRouteConfig(
                model="model1",
                listeners=[http_listener, grpc_listener],
                http_routes=[
                    LibHTTPRoute(
                        name="http-route",
                        listener=http_listener,
                        backends=[LibBackendRef(service="svc", port=80)],
                        matches=[
                            LibHTTPRouteMatch(
                                path=LibHTTPPathMatch(type="PathPrefix", value="/api")
                            )
                        ],
                    )
                ],
                grpc_routes=[
                    LibGRPCRoute(
                        name="grpc-route",
                        listener=grpc_listener,
                        backends=[LibBackendRef(service="grpc-svc", port=9000)],
                        matches=[LibGRPCRouteMatch(method=GRPCMethodMatch(service="MyService"))],
                    )
                ],
            )
        }
    }

    with patch.object(
        charm.upstream_ingress, "is_ready", return_value=True
    ), patch.object(
        IngressPerAppRequirer, "url", new_callable=PropertyMock, return_value="https://upstream.example.com/model-app/"
    ):
        ipa_routes, istio_ingress_routes = charm._get_all_listeners("my-tls-secret",istio_ingress_route_configs)
        gateway = charm._construct_gateway(ipa_routes + istio_ingress_routes)
        for gw in gateway.spec["listeners"]:
            assert gw["hostname"] == "local.example.com"
