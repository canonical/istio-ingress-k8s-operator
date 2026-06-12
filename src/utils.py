#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for istio-ingress charm.

This module contains normalization, deduplication, and helper functions used by the charm.
Functions here are source-agnostic and work on normalized data structures.
"""
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, TypedDict

from canonical_service_mesh.models import (
    AllowedRoutes,
    BackendRef,
    GatewayTLSConfig,
    GRPCMethodMatch,
    GRPCRouteMatch,
    GRPCRouteResource,
    GRPCRouteResourceSpec,
    GRPCRouteRule,
    HTTPPathMatch,
    HTTPRouteMatch,
    HTTPRouteResource,
    HTTPRouteResourceSpec,
    HTTPRouteRule,
    Listener,
    Metadata,
    ParentRef,
    SecretObjectReference,
)
from charmlibs.interfaces.istio_ingress_route import (
    PathModifier,
    PathModifierType,
    RequestRedirectFilter,
    RequestRedirectSpec,
    URLRewriteFilter,
    URLRewriteSpec,
    to_gateway_protocol,
)
from ops import EventBase

HTTPRouteFilter = URLRewriteFilter | RequestRedirectFilter
GRPCRouteFilter = RequestRedirectFilter

logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================
INGRESS_AUTHENTICATED_NAME = "ingress"
INGRESS_UNAUTHENTICATED_NAME = "ingress-unauthenticated"
ISTIO_INGRESS_ROUTE_AUTHENTICATED_NAME = "istio-ingress-route"
ISTIO_INGRESS_ROUTE_UNAUTHENTICATED_NAME = "istio-ingress-route-unauthenticated"
ROUTE_LISTENER_PORT_LABEL = "istio-ingress.juju.is/listener_port"
ROUTE_LISTENER_PROTOCOL_LABEL = "istio-ingress.juju.is/listener_protocol"
ROUTE_SOURCE_APP_LABEL = "istio-ingress.juju.is/source_app"
ROUTE_SOURCE_RELATION_LABEL = "istio-ingress.juju.is/source_relation"

# ============================================================================
# Exception Classes
# ============================================================================
class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class DisabledCertHandler:
    """A mock CertHandler class that mimics being unavailable."""

    available: bool = False
    server_cert = None
    private_key = None


class RefreshCerts(EventBase):
    """Event raised when the charm wants the certs to be refreshed."""


# ============================================================================
# Adapter Schemas
# ============================================================================
class RouteInfo(TypedDict):
    """Class to hold route information."""

    service_name: str
    namespace: str
    port: int
    strip_prefix: bool
    prefix: Optional[str]


# ============================================================================
# Adapters
# ============================================================================
def normalize_ipa_listeners(tls_secret_name: Optional[str], hostname: Optional[str]) -> List[Listener]:
    """Normalize IPA listeners to common format.

    IPA always uses standard ports: 80 for HTTP, 443 for HTTPS.

    Args:
        tls_secret_name: Name of TLS secret if TLS is enabled
        hostname: the hostname to be used with the generated Listeners

    Returns:
        List of normalized listeners (http-80, and https-443 if TLS enabled)
    """
    listeners: List[Listener] = [
        Listener(
            name="http-80",
            port=80,
            protocol="HTTP",
            allowedRoutes=AllowedRoutes(namespaces={"from": "All"}),
            hostname=hostname,
            tls=None,
        )
    ]

    if tls_secret_name:
        listeners.append(
            Listener(
                name="",
                port=443,
                protocol="HTTPS",
                allowedRoutes=AllowedRoutes(namespaces={"from": "All"}),
                hostname=hostname,
                tls=create_gateway_tls_config(tls_secret_name)
            )
        )

    return listeners


def normalize_istio_ingress_route_listeners(
    istio_ingress_route_configs: dict, tls_secret_name: Optional[str], hostname: Optional[str]
) -> List[Listener]:
    """Normalize istio-ingress-route listeners to common format.

    Args:
        istio_ingress_route_configs: Dict mapping (app_name, relation_name) to config data
        tls_secret_name: Name of TLS secret if TLS is enabled
        hostname: the hostname to be used with the generated Listeners

    Returns:
        List of normalized listeners
    """
    listeners: List[Listener] = []

    for (app_name, _), config_data in istio_ingress_route_configs.items():
        config = config_data["config"]
        if not config:
            continue

        for listener in config.listeners:
            # Apply TLS upgrade
            gateway_protocol = to_gateway_protocol(
                listener.protocol, tls_enabled=tls_secret_name is not None
            )

            tls_config = None
            if tls_secret_name is not None:
                tls_config = create_gateway_tls_config(tls_secret_name)

            listeners.append(
                Listener(
                    name="",
                    port=listener.port,
                    protocol=gateway_protocol,
                    allowedRoutes=AllowedRoutes(namespaces={"from": "All"}),
                    hostname=hostname,
                    tls=tls_config,
                )
            )

    return listeners


def _create_http_redirect_route(
    service_name: str,
    namespace: str,
    prefix: str,
    source_app: str,
    source_relation: str,
    ingress_app_name: str,
    ingress_model_name: str
) -> HTTPRouteResource:
    """Create an HTTP->HTTPS redirect route between the standard http-80 and https-443 listeners.

    Args:
        service_name: Name of the backend service
        namespace: Namespace of the route
        prefix: URL path prefix
        source_app: Source application name
        source_relation: Source relation name
        ingress_app_name: Name of the ingress charm app
        ingress_model_name: Name of the ingress charm's model

    Returns:
        HTTPRoute with RequestRedirect filter
    """
    section_name = "http-80"
    route_name = f"{service_name}-httproute-{section_name}-{ingress_app_name}"

    filters: List[HTTPRouteFilter] = []
    filters.append(
        RequestRedirectFilter(
            requestRedirect=RequestRedirectSpec(scheme="https", statusCode=301)
        )  # https redirection without port spec will always redirect to the standard 443 port.
    )

    return HTTPRouteResource(
        metadata=Metadata(
            name=route_name,
            namespace=namespace,
            labels={
                ROUTE_LISTENER_PORT_LABEL: "80",
                ROUTE_LISTENER_PROTOCOL_LABEL: "HTTP",
                ROUTE_SOURCE_APP_LABEL: source_app,
                ROUTE_SOURCE_RELATION_LABEL: source_relation
            }
        ),
        spec=HTTPRouteResourceSpec(
            parentRefs=[
                ParentRef(name=ingress_app_name,namespace=ingress_model_name,sectionName=section_name),
            ],
            rules=[
                HTTPRouteRule(
                    matches=[HTTPRouteMatch(path=HTTPPathMatch(type="PathPrefix", value=prefix))],  # Already charm HTTPRouteMatch models
                    backendRefs=[],  # No backends for redirect routes
                    filters=filters,
                )
            ],
        ),
    )


def normalize_ipa_routes(
    application_route_data: dict, is_tls_enabled: bool, ingress_app_name: str, ingress_model_name: str
) -> List[HTTPRouteResource]:
    """Normalize IPA routes to common format with complete conversion to charm models.

    Converts IPA raw route data to fully normalized K8s Gateway API format using charm Pydantic models.
    IPA routes are always HTTPRoutes on standard ports (80/443).

    Args:
        application_route_data: Dict mapping (app_name, relation_name) to route data
        is_tls_enabled: Whether TLS is enabled
        ingress_app_name: Name of the ingress charm app (used in route naming)
        ingress_model_name: Name of the ingress charm's model

    Returns:
        List of normalized HTTP routes with charm models (HTTPRouteMatch, BackendRef, HTTPRouteFilter)
    """
    routes: List[HTTPRouteResource] = []

    for (app_name, relation_name), route_data in application_route_data.items():
        for route in route_data["routes"]:
            # Common data for all routes
            matches = [
                HTTPRouteMatch(
                    path=HTTPPathMatch(type="PathPrefix", value=route["prefix"])
                )
            ]
            backend_refs = [
                BackendRef(
                    name=route["service_name"],
                    port=route["port"],
                    namespace=route["namespace"],
                )
            ]

            # Build filters for URLRewrite if needed
            filters: List[HTTPRouteFilter] = []
            if route["strip_prefix"]:
                filters.append(
                    URLRewriteFilter(
                        urlRewrite=URLRewriteSpec(
                            path=PathModifier(
                                type=PathModifierType.ReplacePrefixMatch,
                                value="/"
                            )
                        )
                    )
                )

            if is_tls_enabled:
                # Create HTTP->HTTPS redirect route
                routes.append(
                    _create_http_redirect_route(
                        service_name=route["service_name"],
                        namespace=route["namespace"],
                        prefix=route["prefix"],
                        source_app=app_name,
                        source_relation=relation_name,
                        ingress_app_name=ingress_app_name,
                        ingress_model_name=ingress_model_name
                    )
                )

                # Create HTTPS route with backends
                section_name = "https-443"
                route_name = f"{route['service_name']}-httproute-{section_name}-{ingress_app_name}"
                routes.append(
                    HTTPRouteResource(
                        metadata=Metadata(
                            name=route_name,
                            namespace=route["namespace"],
                            labels={
                                ROUTE_LISTENER_PORT_LABEL: "443",
                                ROUTE_LISTENER_PROTOCOL_LABEL: "HTTPS",
                                ROUTE_SOURCE_APP_LABEL: app_name,
                                ROUTE_SOURCE_RELATION_LABEL: relation_name,
                            }
                        ),
                        spec=HTTPRouteResourceSpec(
                            parentRefs=[
                                ParentRef(name=ingress_app_name,namespace=ingress_model_name,sectionName=section_name)
                            ],
                            rules=[
                                HTTPRouteRule(
                                    matches=matches,  # Already charm HTTPRouteMatch models
                                    backendRefs=backend_refs,  # Already charm BackendRef models
                                    filters=filters if filters else None,
                                )
                            ],
                        ),
                    ),
                )
            else:
                # Create HTTP route
                section_name = "http-80"
                route_name = f"{route['service_name']}-httproute-{section_name}-{ingress_app_name}"
                routes.append(
                    HTTPRouteResource(
                        metadata=Metadata(
                            name=route_name,
                            namespace=route["namespace"],
                            labels={
                                ROUTE_LISTENER_PORT_LABEL: "80",
                                ROUTE_LISTENER_PROTOCOL_LABEL: "HTTP",
                                ROUTE_SOURCE_APP_LABEL: app_name,
                                ROUTE_SOURCE_RELATION_LABEL: relation_name,
                            }
                        ),
                        spec=HTTPRouteResourceSpec(
                            parentRefs=[
                                ParentRef(name=ingress_app_name,namespace=ingress_model_name,sectionName=section_name)
                            ],
                            rules=[
                                HTTPRouteRule(
                                    matches=matches,  # Already charm HTTPRouteMatch models
                                    backendRefs=backend_refs,  # Already charm BackendRef models
                                    filters=filters if filters else None,
                                )
                            ],
                        ),
                    )
                )

    return routes


def normalize_istio_ingress_route_http_routes(
    istio_ingress_route_configs: dict, is_tls_enabled: bool, ingress_app_name: str, ingress_model_name: str
) -> List[HTTPRouteResource]:
    """Normalize istio-ingress-route HTTP routes to common format with complete conversion to charm models.

    Converts library models (from istio_ingress_route relation) to charm Pydantic models.
    This ensures complete normalization to K8s Gateway API format.

    Args:
        istio_ingress_route_configs: Dict mapping (app_name, relation_name) to config data
        is_tls_enabled: Whether TLS is enabled
        ingress_app_name: Name of the ingress charm app (used in route naming)
        ingress_model_name: Name of the ingress charm's model

    Returns:
        List of normalized HTTP routes with charm models (HTTPRouteMatch, BackendRef, HTTPRouteFilter)
    """
    routes: List[HTTPRouteResource] = []

    for (app_name, relation_name), config_data in istio_ingress_route_configs.items():
        config = config_data["config"]
        if not config:
            continue

        for http_route in config.http_routes:
            # Determine Gateway protocol for this listener
            gateway_protocol = to_gateway_protocol(
                http_route.listener.protocol, tls_enabled=is_tls_enabled
            )

            # Convert library HTTPRouteMatch models to charm models
            matches = []
            for lib_match in http_route.matches or []:
                if lib_match.path:
                    matches.append(
                        HTTPRouteMatch(
                            path=HTTPPathMatch(
                                type=lib_match.path.type,
                                value=lib_match.path.value,
                            )
                        )
                    )

            # Convert library BackendRef models to charm models
            backend_refs = []
            for lib_backend in http_route.backends or []:
                backend_refs.append(
                    BackendRef(
                        name=lib_backend.service,
                        port=lib_backend.port,
                        namespace=config.model,
                    )
                )

            # Library filters are directly compatible - no conversion needed!
            filters = list(http_route.filters) if http_route.filters else []

            # Derive route name
            # Format: {app_name}-{http_route.name}-httproute-{section_name}-{ingress_app_name}
            # Example: myapp-api-route-httproute-http-8080-istio-ingress-k8s
            section_name = f"{gateway_protocol.lower()}-{http_route.listener.port}"
            route_name = f"{app_name}-{http_route.name}-httproute-{section_name}-{ingress_app_name}"

            routes.append(
                HTTPRouteResource(
                    metadata=Metadata(
                        name=route_name,
                        namespace=config.model,
                        labels={
                            ROUTE_LISTENER_PORT_LABEL: str(http_route.listener.port),
                            ROUTE_LISTENER_PROTOCOL_LABEL: gateway_protocol,
                            ROUTE_SOURCE_APP_LABEL: app_name,
                            ROUTE_SOURCE_RELATION_LABEL: relation_name,
                        }
                    ),
                    spec=HTTPRouteResourceSpec(
                        parentRefs=[
                            ParentRef(name=ingress_app_name,namespace=ingress_model_name,sectionName=section_name)
                        ],
                        rules=[
                            HTTPRouteRule(
                                matches=matches,  # Already charm HTTPRouteMatch models
                                backendRefs=backend_refs,  # Already charm BackendRef models
                                filters=filters if filters else None,
                            )
                        ],
                    ),
                )
            )

    return routes


def normalize_istio_ingress_route_grpc_routes(
    istio_ingress_route_configs: dict, is_tls_enabled: bool, ingress_app_name: str, ingress_model_name: str
) -> List[GRPCRouteResource]:
    """Normalize istio-ingress-route gRPC routes to common format with complete conversion to charm models.

    Converts library models (from istio_ingress_route relation) to charm Pydantic models (from models.py).
    This ensures complete normalization to K8s Gateway API format.

    Args:
        istio_ingress_route_configs: Dict mapping (app_name, relation_name) to config data
        is_tls_enabled: Whether TLS is enabled
        ingress_app_name: Name of the ingress charm app (used in route naming)
        ingress_model_name: Name of the ingress charm's model

    Returns:
        List of normalized gRPC routes with charm models (GRPCRouteMatch, BackendRef, HTTPRouteFilter)
    """
    routes: List[GRPCRouteResource] = []

    for (app_name, relation_name), config_data in istio_ingress_route_configs.items():
        config = config_data["config"]
        if not config:
            continue

        for grpc_route in config.grpc_routes:
            # Determine Gateway protocol for this listener
            gateway_protocol = to_gateway_protocol(
                grpc_route.listener.protocol, tls_enabled=is_tls_enabled
            )

            # Convert library GRPCRouteMatch models to charm models
            matches = []
            for lib_match in grpc_route.matches or []:
                if lib_match.method:
                    matches.append(
                        GRPCRouteMatch(
                            method=GRPCMethodMatch(
                                service=lib_match.method.service,
                                method=lib_match.method.method,
                            )
                        )
                    )

            # Convert library BackendRef models to charm models
            backend_refs = []
            for lib_backend in grpc_route.backends or []:
                backend_refs.append(
                    BackendRef(
                        name=lib_backend.service,
                        port=lib_backend.port,
                        namespace=config.model,
                    )
                )

            # GRPCRouteFilter not yet implemented - leave empty for now
            filters: List[GRPCRouteFilter] = []
            # TODO: When GRPCRouteFilter is implemented, use:
            # filters = list(grpc_route.filters) if grpc_route.filters else []

            # Derive route name
            # Format: {app_name}-{grpc_route.name}-grpcroute-{section_name}-{ingress_app_name}
            # Example: myapp-user-service-grpcroute-http-9090-istio-ingress-k8s
            section_name = f"{gateway_protocol.lower()}-{grpc_route.listener.port}"
            route_name = f"{app_name}-{grpc_route.name}-grpcroute-{section_name}-{ingress_app_name}"

            routes.append(
                GRPCRouteResource(
                    metadata=Metadata(
                        name=route_name,
                        namespace=config.model,
                        labels={
                            ROUTE_LISTENER_PORT_LABEL: str(grpc_route.listener.port),
                            ROUTE_LISTENER_PROTOCOL_LABEL: gateway_protocol,
                            ROUTE_SOURCE_APP_LABEL: app_name,
                            ROUTE_SOURCE_RELATION_LABEL: relation_name,
                        }
                    ),
                    spec=GRPCRouteResourceSpec(
                        parentRefs=[
                            ParentRef(name=ingress_app_name,namespace=ingress_model_name,sectionName=section_name)
                        ],
                        rules=[
                            GRPCRouteRule(
                                matches=matches,  # Already charm GRPCRouteMatch models
                                backendRefs=backend_refs,  # Already charm BackendRef models
                                filters=filters if filters else None,
                            )
                        ],
                    ),
                )
            )

    return routes


# ============================================================================
# Generic Processing Functions (work on normalized data)
# ============================================================================
def deduplicate_listeners(all_listeners: List[Listener]) -> List[Listener]:
    """Merge listeners by deduplicating on (port, gateway_protocol).

    Keeps the first occurrence of each unique (port, protocol) combination.
    This handles cases where both IPA and istio-ingress-route request the same port.

    For example, given input:
        [
            Listener(port=80, protocol="HTTP", name="x", ...),
            Listener(port=443, protocol="HTTPS", ...),
            Listener(port=80, protocol="HTTP", name="y" ...),  # Duplicate
            Listener(port=8080, protocol="HTTP", ...),
        ]

    This function would return:
        [
            Listener(port=80, protocol="HTTP", name="x", ...),    # First wins
            Listener(port=443, protocol="HTTPS", ...),
            Listener(port=8080, protocol="HTTP", ...),
        ]

    Args:
        all_listeners: Combined list of all normalized listeners from all sources

    Returns:
        List of unique listeners (first occurrence wins for each unique port/protocol pair)
    """
    seen: Dict[Tuple[int, str], Listener] = {}

    for listener in all_listeners:
        key = (listener.port, listener.protocol)
        if key not in seen:
            seen[key] = listener

    return list(seen.values())


def deduplicate_http_routes(
    all_http_routes: List[HTTPRouteResource],
) -> Tuple[List[HTTPRouteResource], Set[Tuple[str, str]]]:
    """Deduplicate HTTP routes by finding conflicts on (listener_port, listener_protocol, path).

    Routes from the same app can share the same path. Routes from different apps cannot.
    When a conflict is detected, ALL routes from ALL conflicting apps are removed.

    What constitutes a conflict:
    - Two or more routes from DIFFERENT apps requesting the same path on the same listener
    - Listener is identified by (port, protocol) combination
    - Path must match exactly

    Non-conflict examples:
    - App A: path="/api" on HTTP:80
      App A: path="/api" on HTTP:80  (same app = OK, multiple routes allowed)
    - App A: path="/api" on HTTP:80
      App B: path="/users" on HTTP:80  (different paths = OK)
    - App A: path="/api" on HTTP:80
      App B: path="/api" on HTTP:8080  (different listeners = OK)

    For example, given input:
        [
            _HTTPRoute(name="r0", listener_port=80, listener_protocol="HTTP",
                      path="/api", source_app="app0", source_relation="ingress"),  # <-- Duplicate /api
            _HTTPRoute(name="r1", listener_port=80, listener_protocol="HTTP",
                      path="/users", source_app="app1", source_relation="ingress"),
            _HTTPRoute(name="r2", listener_port=80, listener_protocol="HTTP",
                      path="/api", source_app="app2", source_relation="istio-ingress-route"),  # <-- Duplicate /api
            _HTTPRoute(name="r3", listener_port=443, listener_protocol="HTTPS",
                      path="/admin", source_app="app3", source_relation="ingress"),  # <-- Duplicate /admin
            _HTTPRoute(name="r4", listener_port=443, listener_protocol="HTTPS",
                      path="/admin", source_app="app4", source_relation="ingress"),  # <-- Duplicate /admin
        ]

    This function would return:
        (
            [
                _HTTPRoute(...path="/users"...),  # No conflict
            ],
            {("app0", "ingress"), ("app2", "istio-ingress-route"), ("app3", "ingress"), ("app4", "ingress")},
            True  # has_conflicts
        )

    The routes for /api on HTTP:80 and /admin on HTTPS:443 would be removed because multiple
    apps requested them. The /users route would remain because only one app requested it.

    Note: This function does NOT modify the original data structures. Use clear_conflicting_routes()
    to apply the clearing to the original application_route_data and istio_ingress_route_configs.

    TODO: The caller should set BlockedStatus when has_conflicts is True, since this is a
    user-actionable error. See: https://github.com/canonical/istio-ingress-k8s-operator/issues/57

    Args:
        all_http_routes: Combined list of all normalized HTTP routes from all sources

    Returns:
        Tuple of (valid_routes, apps_to_clear, has_conflicts) where:
        - valid_routes: List of non-conflicting routes
        - apps_to_clear: Set of (app_name, relation_name) tuples that have conflicts
    """
    # Group routes by (listener_port, listener_protocol, path)
    # Extract path from first match in matches list
    route_groups: Dict[Tuple[int, str, str], List[HTTPRouteResource]] = defaultdict(list)

    for route in all_http_routes:
        # Extract path from first HTTPRouteMatch
        key = (
              get_listener_port_from_label(route.metadata),
              get_listener_protocol_from_label(route.metadata),
              _get_first_rules_first_http_path(route),
        )
        route_groups[key].append(route)

    valid_routes: List[HTTPRouteResource] = []
    apps_to_clear: Set[Tuple[str, str]] = set()

    for key, routes in route_groups.items():
        # Get unique apps requesting this route
        unique_apps = {get_requesting_app_and_relation_forom_label(r.metadata) for r in routes}

        if len(unique_apps) > 1:
            # Conflict detected - multiple apps want the same route
            listener_port, listener_protocol, path = key
            logger.error(
                f"Route conflict detected: Multiple applications requesting "
                f"{listener_protocol}:{listener_port}{path}. "
                f"Conflicting apps: {', '.join(f'{app}/{rel}' for app, rel in unique_apps)}. "
                f"No route will be created for this path."
            )
            # Mark all conflicting apps for clearing
            apps_to_clear.update(unique_apps)
        else:
            # No conflict - keep all routes (may be multiple from same app)
            valid_routes.extend(routes)

    return valid_routes, apps_to_clear


def deduplicate_grpc_routes(
    all_grpc_routes: List[GRPCRouteResource],
) -> Tuple[List[GRPCRouteResource], Set[Tuple[str, str]]]:
    """Deduplicate gRPC routes by finding conflicts on (listener_port, listener_protocol, grpc_path).

    Routes from the same app can share the same gRPC path. Routes from different apps cannot.
    When a conflict is detected, ALL routes from ALL conflicting apps are removed.

    What constitutes a conflict:
    - Two or more routes from DIFFERENT apps requesting the same gRPC method on the same listener
    - Listener is identified by (port, protocol) combination
    - gRPC path format: /service/method or /service/*

    Non-conflict examples:
    - App A: /UserService/GetUser on HTTP:8080
      App A: /UserService/GetUser on HTTP:8080  (same app = OK)
    - App A: /UserService/GetUser on HTTP:8080
      App B: /OrderService/GetOrder on HTTP:8080  (different services = OK)
    - App A: /UserService/GetUser on HTTP:8080
      App B: /UserService/GetUser on HTTP:9090  (different listeners = OK)

    Important: HTTP and gRPC routes on the same port CAN coexist because they use different
    match criteria (HTTP uses path matching, gRPC uses method matching). This function only
    checks for conflicts between gRPC routes.

    For example, given input:
        [
            _GRPCRoute(name="r0", listener_port=8080, listener_protocol="HTTP",
                      grpc_path="/UserService/GetUser", source_app="app0", ...),  # <-- Duplicate
            _GRPCRoute(name="r1", listener_port=8080, listener_protocol="HTTP",
                      grpc_path="/OrderService/GetOrder", source_app="app1", ...),
            _GRPCRoute(name="r2", listener_port=8080, listener_protocol="HTTP",
                      grpc_path="/UserService/GetUser", source_app="app2", ...),  # <-- Duplicate
        ]

    This function would return:
        (
            [
                _GRPCRoute(...grpc_path="/OrderService/GetOrder"...),  # No conflict
            ],
            {("app0", "istio-ingress-route"), ("app2", "istio-ingress-route")},
            True  # has_conflicts
        )

    Note: This function does NOT modify the original data structures. Use clear_conflicting_routes()
    to apply the clearing to the original istio_ingress_route_configs.

    TODO: The caller should set BlockedStatus when has_conflicts is True, since this is a
    user-actionable error. See: https://github.com/canonical/istio-ingress-k8s-operator/issues/57

    Args:
        all_grpc_routes: Combined list of all normalized gRPC routes from all sources

    Returns:
        Tuple of (valid_routes, apps_to_clear, has_conflicts) where:
        - valid_routes: List of non-conflicting routes
        - apps_to_clear: Set of (app_name, relation_name) tuples that have conflicts
        - has_conflicts: True if any conflicts were detected (caller should set BlockedStatus)
    """
    # Group routes by (listener_port, listener_protocol, grpc_path)
    # Extract grpc_path from first match in matches list
    route_groups: Dict[Tuple[int, str, str], List[GRPCRouteResource]] = defaultdict(list)

    for route in all_grpc_routes:
        key = (
            get_listener_port_from_label(route.metadata),
            get_listener_protocol_from_label(route.metadata),
            _get_first_rules_first_grpc_path(route)
        )
        route_groups[key].append(route)

    valid_routes: List[GRPCRouteResource] = []
    apps_to_clear: Set[Tuple[str, str]] = set()

    for key, routes in route_groups.items():
        # Get unique apps requesting this route
        unique_apps = {get_requesting_app_and_relation_forom_label(r.metadata) for r in routes}

        if len(unique_apps) > 1:
            # Conflict detected - multiple apps want the same route
            listener_port, listener_protocol, grpc_path = key
            logger.error(
                f"gRPC route conflict detected: Multiple applications requesting "
                f"{listener_protocol}:{listener_port}{grpc_path}. "
                f"Conflicting apps: {', '.join(f'{app}/{rel}' for app, rel in unique_apps)}. "
                f"No route will be created for this path."
            )
            # Mark all conflicting apps for clearing
            apps_to_clear.update(unique_apps)
        else:
            # No conflict - keep all routes (may be multiple from same app)
            valid_routes.extend(routes)

    return valid_routes, apps_to_clear


def clear_conflicting_routes(
    application_route_data: Dict,
    istio_ingress_route_configs: Dict,
    apps_to_clear: Set[Tuple[str, str]],
) -> None:
    """Clear routes for applications that have conflicts, modifying the input in place.

    This function applies the conflict resolution determined by deduplicate_http_routes()
    and deduplicate_grpc_routes() to the original data structures. For any app that has
    ANY conflicting route, ALL of its routes are removed.

    For example, given:
        apps_to_clear = {("app0", "ingress"), ("app2", "istio-ingress-route")}

        application_route_data = {
            ("app0", "ingress"): {"handler": ..., "routes": [{"prefix": "/api"}]},
            ("app1", "ingress"): {"handler": ..., "routes": [{"prefix": "/users"}]},
        }

        istio_ingress_route_configs = {
            ("app2", "istio-ingress-route"): {"handler": ..., "config": IstioIngressRouteConfig(...)},
            ("app3", "istio-ingress-route"): {"handler": ..., "config": IstioIngressRouteConfig(...)},
        }

    After calling this function:
        application_route_data = {
            ("app0", "ingress"): {"handler": ..., "routes": []},  # <-- Cleared
            ("app1", "ingress"): {"handler": ..., "routes": [{"prefix": "/users"}]},
        }

        istio_ingress_route_configs = {
            ("app2", "istio-ingress-route"): {"handler": ..., "config": IstioIngressRouteConfig(
                http_routes=[], grpc_routes=[]  # <-- Cleared
            )},
            ("app3", "istio-ingress-route"): {"handler": ..., "config": IstioIngressRouteConfig(...)},
        }

    Note: This function does not remove keys from the data structures because we still need
    those later in case we need to nullify what we've previously sent via the relation.

    Side effects: Modifies application_route_data and istio_ingress_route_configs in place.

    Args:
        application_route_data: IPA route data dict (modified in place)
        istio_ingress_route_configs: istio-ingress-route config data dict (modified in place)
        apps_to_clear: Set of (app_name, relation_name) tuples to clear
    """
    for app_name, relation_name in apps_to_clear:
        app_key = (app_name, relation_name)

        # Clear from IPA routes
        if app_key in application_route_data:
            application_route_data[app_key]["routes"] = []
            logger.debug(f"Cleared IPA routes for {app_name}/{relation_name} due to conflict")

        # Clear from istio-ingress-route configs
        if app_key in istio_ingress_route_configs:
            config = istio_ingress_route_configs[app_key]["config"]
            if config:
                config.http_routes = []
                config.grpc_routes = []
                logger.debug(
                    f"Cleared istio-ingress-route routes for {app_name}/{relation_name} due to conflict"
                )


# ============================================================================
# Helper Functions
# ============================================================================
def get_unauthenticated_paths(application_route_data):
    """Return a list of the paths requested through the Gateway on the unauthenticated ingress."""
    unauthenticated_paths = []
    for (_, endpoint), route_data in application_route_data.items():
        if endpoint == INGRESS_UNAUTHENTICATED_NAME:
            for route in route_data["routes"]:
                # Ensure subpaths are also unauthenticated by appending /*
                prefix = route["prefix"].rstrip("/")
                unauthenticated_paths.extend([prefix, prefix + "/*"])
    return unauthenticated_paths


def _extract_http_unauthenticated_paths(http_routes):
    """Extract HTTP paths that should be unauthenticated.

    Args:
        http_routes: List of HTTP route configurations

    Returns:
        List of HTTP path strings
    """
    paths = []
    for http_route in http_routes:
        for match in http_route.matches or []:
            if match.path:
                # Ensure subpaths are also unauthenticated by appending /*
                path = match.path.value.rstrip("/")
                paths.extend([path, path + "/*"])
    return paths


def _extract_grpc_unauthenticated_paths(grpc_routes):
    """Extract gRPC paths that should be unauthenticated.

    Args:
        grpc_routes: List of gRPC route configurations

    Returns:
        List of gRPC path strings in format /service/method
    """
    paths = []
    for grpc_route in grpc_routes:
        for match in grpc_route.matches or []:
            if match.method:
                service = match.method.service
                method = match.method.method
                if method:
                    # Specific method: /service/method
                    paths.append(f"/{service}/{method}")
                else:
                    # All methods on service: /service/*
                    paths.append(f"/{service}/*")
    return paths


def get_unauthenticated_paths_from_istio_ingress_route_configs(istio_ingress_route_configs):
    """Return a list of paths from istio-ingress-route-unauthenticated configs.

    Args:
        istio_ingress_route_configs: Dict mapping (app_name, relation_name) to {"handler": ..., "config": ...}

    Returns:
        List of path strings that should be unauthenticated (HTTP paths and gRPC fully-qualified names)
    """
    unauthenticated_paths = []
    for (_, relation_name), config_data in istio_ingress_route_configs.items():
        if relation_name == ISTIO_INGRESS_ROUTE_UNAUTHENTICATED_NAME:
            config = config_data["config"]
            if not config:
                continue

            # Extract paths from HTTP routes
            unauthenticated_paths.extend(_extract_http_unauthenticated_paths(config.http_routes))

            # Extract fully-qualified gRPC paths from gRPC routes
            unauthenticated_paths.extend(_extract_grpc_unauthenticated_paths(config.grpc_routes))

    return unauthenticated_paths


def get_relation_by_name_and_app(relations, remote_app_name):
    """Return the relation object associated with a given remote app."""
    for rel in relations:
        if rel.app.name == remote_app_name:
            return rel
    raise KeyError(f"Could not find relation with remote_app_name={remote_app_name}")


def create_gateway_tls_config(tls_secret_name: str) -> GatewayTLSConfig:
    """Return a simple GatewayTLSConfig object based on the provided tls_secret_name."""
    return GatewayTLSConfig(certificateRefs=[SecretObjectReference(name=tls_secret_name)])

def _get_first_rules_first_http_path(route: HTTPRouteResource) -> str:
    matches = route.spec.rules[0].matches
    return matches[0].path.value if matches else "/"


def _get_first_rules_first_grpc_path(route: GRPCRouteResource) -> str:
    matches = route.spec.rules[0].matches
    if matches and matches[0].method:
        method_match = matches[0].method
        service = method_match.service or ""
        method = method_match.method or "*"
        return f"/{service}/{method}"
    else:
        return "/*"

def get_listener_port_from_label(metadata: Metadata) -> int:
    """Extract the listener port from the metadata of a GRPCRouteResource or HTTPRouteResource using its labels."""
    assert metadata.labels is not None
    return int(metadata.labels[ROUTE_LISTENER_PORT_LABEL])

def get_listener_protocol_from_label(metadata: Metadata) -> str:
    """Extract the listener protocol from the metadata of a GRPCRouteResource or HTTPRouteResource using its labels."""
    assert metadata.labels is not None
    return str(metadata.labels[ROUTE_LISTENER_PROTOCOL_LABEL])

def get_requesting_app_and_relation_forom_label(metadata: Metadata) -> Tuple[str,str]:
    """Extract the name of the requesting app and relation from the metadata of a GRPCRouteResource or HTTPRouteResource using its labels."""
    assert metadata.labels is not None
    source_app = str(metadata.labels[ROUTE_SOURCE_APP_LABEL])
    source_relation = str(metadata.labels[ROUTE_SOURCE_RELATION_LABEL])
    return (source_app,source_relation)
