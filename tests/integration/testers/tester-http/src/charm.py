#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
from charms.istio_ingress_k8s.v0.istio_ingress_route import (
    BackendRef,
    HTTPPathMatch,
    HTTPPathMatchType,
    HTTPRoute,
    HTTPRouteMatch,
    IstioIngressRouteConfig,
    IstioIngressRouteRequirer,
    Listener,
    PathModifier,
    PathModifierType,
    ProtocolType,
    URLRewriteFilter,
    URLRewriteSpec,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus
from ops.pebble import Layer


class HTTPTesterCharm(CharmBase):
    def __init__(self, framework):
        super().__init__(framework)
        self.unit.set_ports(8080)

        # IPA interface support
        self.ipa = IngressPerAppRequirer(self, port=8080, relation_name="ingress")
        # Useful for manual testing of duplicated ingresses
        self.ipa2 = IngressPerAppRequirer(self, port=8080, relation_name="ingress-2")

        # istio-ingress-route interface support
        self.istio_ingress_route = IstioIngressRouteRequirer(
            self, relation_name="istio-ingress-route"
        )

        self.framework.observe(self.on.echo_server_pebble_ready, self._on_pebble_ready)
        self.framework.observe(
            self.istio_ingress_route.on.ready, self._on_istio_ingress_route_ready
        )

    def _on_pebble_ready(self, _):
        container = self.unit.get_container("echo-server")
        if not container.can_connect():
            self.unit.status = WaitingStatus("Waiting for Pebble ready")
            return

        layer = Layer(
            {
                "summary": "echo server layer",
                "description": "pebble config layer for echo server",
                "services": {
                    "echo-server": {
                        "override": "replace",
                        "command": "/bin/echo-server",
                        "startup": "enabled",
                    }
                },
            }
        )

        container.add_layer("echo-server", layer, combine=True)
        container.autostart()
        self.unit.status = ActiveStatus("Echo server running")

        # Configure istio-ingress-route if relation exists
        if self.model.get_relation("istio-ingress-route"):
            self._configure_istio_ingress_route()

    def _on_istio_ingress_route_ready(self, _):
        """Handle istio-ingress-route relation ready."""
        self._configure_istio_ingress_route()

    def _configure_istio_ingress_route(self):
        """Configure HTTP routes via istio-ingress-route."""
        # Define listener on custom port 8080
        http_listener = Listener(port=8080, protocol=ProtocolType.HTTP)

        # Configure multiple HTTP routes for testing
        config = IstioIngressRouteConfig(
            model=self.model.name,
            listeners=[http_listener],
            http_routes=[
                # Route 1: /api path
                HTTPRoute(
                    name="api-route",
                    listener=http_listener,
                    matches=[
                        HTTPRouteMatch(
                            path=HTTPPathMatch(type=HTTPPathMatchType.PathPrefix, value="/api")
                        )
                    ],
                    backends=[BackendRef(service=self.app.name, port=8080)],
                ),
                # Route 2: /health path
                HTTPRoute(
                    name="health-route",
                    listener=http_listener,
                    matches=[
                        HTTPRouteMatch(
                            path=HTTPPathMatch(type=HTTPPathMatchType.PathPrefix, value="/health")
                        )
                    ],
                    backends=[BackendRef(service=self.app.name, port=8080)],
                ),
                # Route 3: /old-api path with URLRewrite filter
                HTTPRoute(
                    name="rewrite-route",
                    listener=http_listener,
                    matches=[
                        HTTPRouteMatch(
                            path=HTTPPathMatch(type=HTTPPathMatchType.PathPrefix, value="/old-api")
                        )
                    ],
                    backends=[BackendRef(service=self.app.name, port=8080)],
                    filters=[
                        URLRewriteFilter(
                            urlRewrite=URLRewriteSpec(
                                path=PathModifier(
                                    type=PathModifierType.ReplacePrefixMatch,
                                    value="/api"
                                )
                            )
                        )
                    ],
                ),
            ],
        )
        self.istio_ingress_route.submit_config(config)


if __name__ == "__main__":
    main(HTTPTesterCharm)
