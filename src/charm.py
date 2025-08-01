#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""
import hashlib
import ipaddress
import logging
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, TypedDict, cast
from urllib.parse import urlparse

from charms.istio_k8s.v0.istio_ingress_config import IngressConfigProvider
from charms.oauth2_proxy_k8s.v0.forward_auth import ForwardAuthRequirer, ForwardAuthRequirerConfig
from charms.observability_libs.v1.cert_handler import CertHandler
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.autoscaling_v2 import (
    CrossVersionObjectReference,
    HorizontalPodAutoscalerSpec,
)
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.autoscaling_v2 import HorizontalPodAutoscaler
from lightkube.resources.core_v1 import Secret, Service
from lightkube.types import PatchType
from lightkube_extensions.batch import KubernetesResourceManager, create_charm_default_labels
from ops import BlockedStatus, EventBase, main
from ops.charm import CharmBase
from ops.model import ActiveStatus, MaintenanceStatus
from ops.pebble import ChangeError, Layer

from models import (
    Action,
    AllowedRoutes,
    AuthorizationPolicyResource,
    AuthorizationPolicySpec,
    AuthRule,
    BackendRef,
    From,
    GatewayTLSConfig,
    HTTPRequestRedirectFilter,
    HTTPRouteFilter,
    HTTPRouteFilterType,
    HTTPRouteResource,
    HTTPRouteResourceSpec,
    HTTPURLRewriteFilter,
    IstioGatewayResource,
    IstioGatewaySpec,
    Listener,
    Match,
    Metadata,
    Operation,
    ParentRef,
    PathMatch,
    PolicyTargetReference,
    Provider,
    Rule,
    SecretObjectReference,
    Source,
    To,
    WorkloadSelector,
)

logger = logging.getLogger(__name__)


RESOURCE_TYPES = {
    "Gateway": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    ),
    "HTTPRoute": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes"
    ),
    "GRPCRoute": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "GRPCRoute", "grpcroutes"
    ),
    "ReferenceGrant": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1beta1", "ReferenceGrant", "referencegrants"
    ),
    "AuthorizationPolicy": create_namespaced_resource(
        "security.istio.io",
        "v1",
        "AuthorizationPolicy",
        "authorizationpolicies",
    ),
}

GATEWAY_RESOURCE_TYPES = {RESOURCE_TYPES["Gateway"], Secret, HorizontalPodAutoscaler}
INGRESS_RESOURCE_TYPES = {
    RESOURCE_TYPES["GRPCRoute"],
    RESOURCE_TYPES["ReferenceGrant"],
    RESOURCE_TYPES["HTTPRoute"],
}
INGRESS_AUTHENTICATED_NAME = "ingress"
INGRESS_UNAUTHENTICATED_NAME = "ingress-unauthenticated"
AUTHORIZATION_POLICY_RESOURCE_TYPES = {RESOURCE_TYPES["AuthorizationPolicy"]}

GATEWAY_SCOPE = "istio-gateway"
INGRESS_SCOPE = "istio-ingress"
INGRESS_AUTH_POLICY_SCOPE = "istio-ingress-authorization-policy"
EXTZ_AUTH_POLICY_SCOPE = "external-authorizer-authorization-policy"

INGRESS_CONFIG_RELATION = "istio-ingress-config"
FORWARD_AUTH_RELATION = "forward-auth"
PEERS_RELATION = "peers"


class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class DisabledCertHandler:
    """A mock CertHandler class that mimics being unavailable."""

    available: bool = False
    server_cert = None
    private_key = None


class RefreshCerts(EventBase):
    """Event raised when the charm wants the certs to be refreshed."""


class RouteInfo(TypedDict):
    """Class to hold route information."""

    service_name: str
    namespace: str
    port: int
    strip_prefix: bool
    prefix: Optional[str]


@trace_charm(
    tracing_endpoint="_charm_tracing_endpoint",
    extra_types=[
        MetricsEndpointProvider,
    ],
    # we don't add a cert because istio does TLS his way
    # TODO: fix when https://github.com/canonical/istio-beacon-k8s-operator/issues/33 is closed
)
class IstioIngressCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        # Add a custom event that we can emit to request a cert refresh
        self.on.define_event("refresh_certs", RefreshCerts)

        self._ingress_url_ = None

        self.managed_name = f"{self.app.name}-istio"
        self._lightkube_field_manager: str = self.app.name
        self._lightkube_client = None

        # Map of ingress_relation_name to the handler that manages that relation
        self.ingress_relation_handlers = {
            INGRESS_AUTHENTICATED_NAME: IPAv2(
                charm=self,
                relation_name=INGRESS_AUTHENTICATED_NAME,
            ),
            INGRESS_UNAUTHENTICATED_NAME: IPAv2(
                charm=self,
                relation_name=INGRESS_UNAUTHENTICATED_NAME,
            ),
        }
        self.telemetry_labels = generate_telemetry_labels(self.app.name, self.model.name)
        # Configure Observability
        self._scraping = MetricsEndpointProvider(
            self,
            jobs=[{"static_configs": [{"targets": ["*:15090"]}]}],
        )
        self.charm_tracing = TracingEndpointRequirer(
            self, relation_name="charm-tracing", protocols=["otlp_http"]
        )
        self._charm_tracing_endpoint = (
            self.charm_tracing.get_endpoint("otlp_http") if self.charm_tracing.relations else None
        )
        self.forward_auth = ForwardAuthRequirer(self)
        self.ingress_config = IngressConfigProvider(
            relation_mapping=self.model.relations, app=self.app
        )
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.forward_auth.on.auth_config_changed, self._handle_auth_config)
        self.framework.observe(self.forward_auth.on.auth_config_removed, self._handle_auth_config)
        self.framework.observe(self.on.remove, self._on_remove)
        for relation_handler in self.ingress_relation_handlers.values():
            self.framework.observe(
                relation_handler.on.data_provided, self._on_ingress_data_provided
            )
            self.framework.observe(relation_handler.on.data_removed, self._on_ingress_data_removed)
        self.framework.observe(
            self.on.metrics_proxy_pebble_ready, self._metrics_proxy_pebble_ready
        )
        self.framework.observe(
            self.on[INGRESS_CONFIG_RELATION].relation_changed, self._handle_ingress_config
        )
        self.framework.observe(
            self.on[INGRESS_CONFIG_RELATION].relation_broken, self._handle_ingress_config
        )
        self.framework.observe(self.on.leader_elected, self._handle_ingress_config)
        self.framework.observe(self.on[PEERS_RELATION].relation_changed, self._on_peers_changed)
        self.framework.observe(self.on[PEERS_RELATION].relation_departed, self._on_peers_changed)

        # During the initialisation of the charm, we do not have a LoadBalancer and thus a LoadBalancer external IP.
        # If we need that IP to request the certs, disable cert handling until we have it.
        if (external_hostname := self._ingress_url) is None:
            logger.debug(
                "External hostname is not set and no load balancer ip available.  TLS certificate generation disabled"
            )
            self._cert_handler = DisabledCertHandler()
        else:
            self._cert_handler = CertHandler(
                self,
                key="istio-ingress-cert",  # TODO: how is this key used?  if we have two ingresses, do we get issues?
                peer_relation_name=PEERS_RELATION,
                certificates_relation_name="certificates",
                sans=[external_hostname],
                cert_subject=external_hostname,
                # Use a custom event for the charm to signal to the library that we may have changed something
                # meaningful for the CSR.  CertHandler will only regenerate the CSR and obtain new certs if it detects
                # a change when handling this event.
                refresh_events=[self.on.refresh_certs],
            )
            self.framework.observe(
                self._cert_handler.on.cert_changed, self._on_cert_handler_cert_changed
            )

    @property
    def lightkube_client(self):
        """Returns a lightkube client configured for this charm."""
        if self._lightkube_client is None:
            self._lightkube_client = Client(
                namespace=self.model.name, field_manager=self._lightkube_field_manager
            )
        return self._lightkube_client

    def _setup_proxy_pebble_service(self):
        """Define and start the metrics broadcast proxy Pebble service."""
        proxy_container = self.unit.get_container("metrics-proxy")
        if not proxy_container.can_connect():
            return
        proxy_layer = Layer(
            {
                "summary": "Metrics Broadcast Proxy Layer",
                "description": "Pebble layer for the metrics broadcast proxy",
                "services": {
                    "metrics-proxy": {
                        "override": "replace",
                        "summary": "Metrics Broadcast Proxy",
                        "command": f"metrics-proxy --labels {self.format_labels(self.telemetry_labels)}",
                        "startup": "enabled",
                    }
                },
            }
        )

        proxy_container.add_layer("metrics-proxy", proxy_layer, combine=True)

        try:
            proxy_container.replan()
        except ChangeError as e:
            logger.error(f"Error while replanning proxy container: {e}")

    def _get_gateway_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=GATEWAY_SCOPE
            ),
            resource_types=GATEWAY_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _get_ingress_route_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=INGRESS_SCOPE
            ),
            resource_types=INGRESS_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _get_ingress_auth_policy_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=INGRESS_AUTH_POLICY_SCOPE
            ),
            resource_types=AUTHORIZATION_POLICY_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _get_extz_auth_policy_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=EXTZ_AUTH_POLICY_SCOPE
            ),
            resource_types=AUTHORIZATION_POLICY_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _on_cert_handler_cert_changed(self, _):
        """Event handler for when tls certificates have changed."""
        self._sync_all_resources()

    def _on_config_changed(self, _):
        """Event handler for config changed."""
        self._sync_all_resources()

    def _on_start(self, _):
        """Event handler for start."""
        self._sync_all_resources()

    def _metrics_proxy_pebble_ready(self, _):
        """Event handler for metrics_proxy_pebble_ready."""
        self._sync_all_resources()

    def _handle_ingress_config(self, _):
        """Event handler for ingress_config relation events."""
        self._sync_all_resources()

    def _handle_auth_config(self, _):
        """Event handler for forward_auth config changes."""
        self._sync_all_resources()

    def _on_peers_changed(self, _):
        """Event handler for whenever peer topology changes."""
        self._sync_all_resources()

    def _on_remove(self, _):
        """Event handler for remove.

        The objective of this handler is to remove all application-scoped resources when the application is being scaled
        to 0 or removed.  We intentionally do not put this removal action behind a leader guard (eg, behind
        `if self.unit.is_leader()`) for the reasons discussed
        [here](https://github.com/canonical/istio-ingress-k8s-operator/issues/16).
        """
        # if there are still units left, skip removal
        if self.model.app.planned_units() > 0:
            logger.info(
                "Handling remove event: skipping resource removal because application is not scaling to 0."
            )
            return
        logger.info(
            "Handling remove event: Attempting to remove application resources because application is scaling to 0."
        )

        # Removing tailing ingresses
        kim = self._get_ingress_route_resource_manager()
        kim.delete()

        self._remove_gateway_resources()

        kam = self._get_ingress_auth_policy_resource_manager()
        kam.delete()

        keam = self._get_extz_auth_policy_resource_manager()
        keam.delete()

    def _on_ingress_data_provided(self, _):
        """Handle a unit providing data requesting IPU."""
        self._sync_all_resources()

    def _on_ingress_data_removed(self, _):
        """Handle a unit removing the data needed to provide ingress."""
        self._sync_all_resources()

    def _remove_gateway_resources(self):
        kgm = self._get_gateway_resource_manager()
        kgm.delete()

    def _is_deployment_ready(self) -> bool:
        """Check if the deployment is ready after 10 attempts."""
        timeout = int(self.config["ready-timeout"])
        check_interval = 10
        attempts = timeout // check_interval

        for _ in range(attempts):
            try:
                deployment = self.lightkube_client.get(
                    Deployment, name=self.managed_name, namespace=self.model.name
                )
                if (
                    deployment.status
                    and deployment.status.readyReplicas == deployment.status.replicas
                ):
                    return True
                logger.warning("Deployment not ready, retrying...")
            except ApiError:
                logger.warning("Deployment not found, retrying...")

            time.sleep(check_interval)

        return False

    def _is_load_balancer_ready(self) -> bool:
        """Wait for the LoadBalancer to be created."""
        timeout = int(self.config["ready-timeout"])
        check_interval = 10
        attempts = timeout // check_interval

        for _ in range(attempts):
            lb_status = self._get_lb_external_address
            if lb_status:
                return True

            logger.warning("Loadbalancer not ready, retrying...")
            time.sleep(check_interval)
        return False

    @property
    def _get_lb_external_address(self) -> Optional[str]:
        try:
            lb = self.lightkube_client.get(
                Service, name=self.managed_name, namespace=self.model.name
            )
        except ApiError:
            return None

        if not (status := getattr(lb, "status", None)):
            return None
        if not (load_balancer_status := getattr(status, "loadBalancer", None)):
            return None
        if not (ingress_addresses := getattr(load_balancer_status, "ingress", None)):
            return None
        if not (ingress_address := ingress_addresses[0]):
            return None

        return ingress_address.hostname or ingress_address.ip

    def _is_ready(self) -> bool:
        if not self._is_deployment_ready():
            self.unit.status = BlockedStatus(
                "Gateway k8s deployment not ready, is istio properly installed?"
            )
            return False
        if not self._is_load_balancer_ready():
            self.unit.status = BlockedStatus(
                "Gateway load balancer is unable to obtain an IP or hostname from the cluster."
            )
            return False

        return True

    def _construct_gateway_tls_secret(self):
        """Return the TLS secret resource for the gateway if TLS is configured, otherwise None."""
        if not self._cert_handler.available:
            return None

        return Secret(
            metadata=ObjectMeta(name=self._certificate_secret_name),
            stringData={
                "tls.crt": self._cert_handler.server_cert,
                "tls.key": self._cert_handler.private_key,
            },
        )

    def _construct_gateway(self, tls_secret_name: Optional[str] = None):
        """Construct the Gateway resource for the ingress.

        Gateway will always enable HTTP on port 80 and, if TLS is configured, HTTPS on port 443.

        Args:
            tls_secret_name (str): (Optional) The name of the secret containing the TLS certificates.  If specified, the
                                   gateway will be configured to use TLS with this secret for the certificates.
        """
        allowed_routes = AllowedRoutes(namespaces={"from": "All"})
        hostname = self._ingress_url if self._is_valid_hostname(self._ingress_url) else None
        listeners = [
            Listener(
                name="http",
                port=80,
                protocol="HTTP",
                allowedRoutes=allowed_routes,
                hostname=hostname,
            )
        ]

        if tls_secret_name:
            listeners.append(
                Listener(
                    name="https",
                    port=443,
                    protocol="HTTPS",
                    allowedRoutes=allowed_routes,
                    tls=GatewayTLSConfig(
                        certificateRefs=[SecretObjectReference(name=tls_secret_name)]
                    ),
                    hostname=hostname,
                )
            )

        gateway = IstioGatewayResource(
            metadata=Metadata(
                name=self.app.name,
                namespace=self.model.name,
                labels={**self.telemetry_labels},
            ),
            spec=IstioGatewaySpec(
                gatewayClassName="istio",
                listeners=listeners,
            ),
        )
        gateway_resource = RESOURCE_TYPES["Gateway"]
        return gateway_resource(
            metadata=ObjectMeta.from_dict(gateway.metadata.model_dump()),
            spec=gateway.spec.model_dump(exclude_none=True),
        )

    def _construct_httproute(
        self,
        service_name: str,
        namespace: str,
        port: int,
        strip_prefix: bool,
        prefix: str,
        section_name: str,
    ):
        http_route = HTTPRouteResource(
            metadata=Metadata(
                name=service_name + "-" + section_name + "-" + self.app.name,
                namespace=namespace,
            ),
            spec=HTTPRouteResourceSpec(
                parentRefs=[
                    ParentRef(
                        name=self.app.name,
                        namespace=self.model.name,
                        sectionName=section_name,
                    )
                ],
                rules=[
                    Rule(
                        matches=[Match(path=PathMatch(value=prefix))],
                        backendRefs=[
                            BackendRef(
                                name=service_name,
                                port=port,
                                namespace=namespace,
                            )
                        ],
                        filters=(
                            [
                                HTTPRouteFilter(
                                    type=HTTPRouteFilterType.URLRewrite,
                                    urlRewrite=HTTPURLRewriteFilter(),
                                )
                            ]
                            if strip_prefix
                            else []
                        ),
                    )
                ],
                # TODO: uncomment the below when support is added for both wildcards and using subdomains
                # hostnames=[udata.host for udata in data.units],
            ),
        )
        http_resource = RESOURCE_TYPES["HTTPRoute"]
        return http_resource(
            metadata=ObjectMeta.from_dict(http_route.metadata.model_dump()),
            # Export without unset and None because None means nil in Kubernetes, which is not what we want.
            spec=http_route.spec.model_dump(exclude_none=True),
        )

    def _construct_auth_policy_from_ingress_to_target(
        self, target_name: str, target_namespace: str, target_port: int
    ):
        """Return an AuthorizationPolicy that allows the ingress workload to communicate with the target workload."""
        auth_policy = AuthorizationPolicyResource(
            metadata=Metadata(
                name=target_name + "-" + self.app.name + "-" + target_namespace + "-l4",
                namespace=target_namespace,
            ),
            spec=AuthorizationPolicySpec(
                rules=[
                    AuthRule(
                        to=[To(operation=Operation(ports=[str(target_port)]))],
                        from_=[  # type: ignore # this is accessible via an alias "from"
                            # The ServiceAccount that is used to deploy the Gateway (ingress) workload
                            From(
                                source=Source(
                                    principals=[
                                        _get_peer_identity_for_juju_application(
                                            self.managed_name, self.model.name
                                        )
                                    ]
                                )
                            )
                        ],
                    )
                ],
                selector=WorkloadSelector(matchLabels={"app.kubernetes.io/name": target_name}),
                action=Action.allow,
            ),
        )
        auth_resource = RESOURCE_TYPES["AuthorizationPolicy"]
        return auth_resource(
            metadata=ObjectMeta.from_dict(auth_policy.metadata.model_dump()),
            # by_alias=True because the model includes an alias for the `from` field
            # exclude_unset=True because unset fields will be treated as their default values in Kubernetes
            # exclude_none=True because null values in this data always mean the Kubernetes default
            spec=auth_policy.spec.model_dump(by_alias=True, exclude_unset=True, exclude_none=True),
        )

    def _construct_ext_authz_policy(
        self, ext_authz_provider_name: str, unauthenticated_paths: List[str]
    ):
        """Return an AuthorizationPolicy that applies authentication to all paths except unauthenticated_paths."""
        if unauthenticated_paths:
            auth_rule = AuthRule(
                to=[To(operation=Operation(notPaths=unauthenticated_paths))],
            )
        else:
            auth_rule = AuthRule()

        ext_authz_policy = AuthorizationPolicyResource(
            metadata=Metadata(
                name=f"ext-authz-{self.app.name}",
                namespace=self.model.name,
            ),
            spec=AuthorizationPolicySpec(
                rules=[auth_rule],
                targetRefs=[
                    PolicyTargetReference(
                        kind="Gateway",
                        group="gateway.networking.k8s.io",
                        name=self.app.name,
                    )
                ],
                action=Action.custom,
                provider=Provider(name=ext_authz_provider_name),
            ),
        )
        auth_resource = RESOURCE_TYPES["AuthorizationPolicy"]
        return auth_resource(
            metadata=ObjectMeta.from_dict(ext_authz_policy.metadata.model_dump()),
            # by_alias=True because the model includes an alias for the `from` field
            # exclude_unset=True because unset fields will be treated as their default values in Kubernetes
            # exclude_none=True because null values in this data always mean the Kubernetes default
            spec=ext_authz_policy.spec.model_dump(
                by_alias=True, exclude_unset=True, exclude_none=True
            ),
        )

    def _construct_redirect_to_https_httproute(
        self, app_name: str, model: str, prefix: str, section_name: str
    ):
        http_route = HTTPRouteResource(
            metadata=Metadata(
                name=app_name + "-" + section_name + "-" + self.app.name,
                namespace=model,
            ),
            spec=HTTPRouteResourceSpec(
                parentRefs=[
                    ParentRef(
                        name=self.app.name,
                        namespace=self.model.name,
                        sectionName=section_name,
                    )
                ],
                rules=[
                    Rule(
                        matches=[Match(path=PathMatch(value=prefix))],
                        filters=[
                            HTTPRouteFilter(
                                type=HTTPRouteFilterType.RequestRedirect,
                                requestRedirect=HTTPRequestRedirectFilter(
                                    scheme="https", statusCode=301
                                ),
                            )
                        ],
                    )
                ],
                # TODO: uncomment the below when support is added for both wildcards and using subdomains
                # hostnames=[udata.host for udata in data.units],
            ),
        )
        http_resource = RESOURCE_TYPES["HTTPRoute"]
        return http_resource(
            metadata=ObjectMeta.from_dict(http_route.metadata.model_dump()),
            # Export without unset and None because None means nil in Kubernetes, which is not what we want.
            spec=http_route.spec.model_dump(exclude_none=True),
        )

    def _construct_hpa(self, unit_count: int) -> HorizontalPodAutoscaler:
        return HorizontalPodAutoscaler(
            metadata=ObjectMeta(name=self.app.name, namespace=self.model.name),
            spec=HorizontalPodAutoscalerSpec(
                scaleTargetRef=CrossVersionObjectReference(
                    apiVersion="apps/v1",
                    kind="Deployment",
                    name=self.managed_name,
                ),
                minReplicas=unit_count,
                maxReplicas=unit_count,
            ),
        )

    def _sync_all_resources(self):
        """Synchronize all resources including authentication, gateway, ingress, and certificates.

        Flow:
        * Check authentication configuration.
        * Publish or clear the auth_decisions_address in ingress-config, if related.
        * If auth relation exists but no decisions address, set to blocked and remove gateway.
        * Fetch route information from the ingress relation
        * Synchronize external authorization configuration.
            - If missing valid ingress-config relation when auth is provided, set to blocked and remove gateway.
        * Reconcile HPA and gateway resources to align replicas with unit count and ensure gateway readiness.
        * Validate the external hostname.
        * Synchronize ingress resources
        * Publish route information to ingressed applications
        * Set up the proxy service
        * Update forward auth relation data with ingressed apps.
        * Request certificate inspection.
        """
        if not self.unit.is_leader():
            self.unit.status = ActiveStatus("Backup unit; standing by for leader takeover")
            return

        # Check authentication configuration.
        auth_decisions_address = self._get_oauth_decisions_address()

        # Publish or clear the auth_decisions_address in ingress-config, if related.
        if self.model.get_relation(INGRESS_CONFIG_RELATION):
            self._publish_to_istio_ingress_config_relation(auth_decisions_address)

        # If auth relation exists but no decisions address, set to blocked and remove gateway.
        if self.model.get_relation(FORWARD_AUTH_RELATION) and not auth_decisions_address:
            self.unit.status = BlockedStatus(
                "Authentication configuration incomplete; ingress is disabled."
            )
            self._remove_gateway_resources()
            return

        # Construct route information from the ingress relation
        application_route_data = self._get_routes()
        deduplicate_app_route_data(application_route_data)
        # TODO: Capture a BlockedStatus here if there's duplicates
        #  (https://github.com/canonical/istio-ingress-k8s-operator/issues/57)
        unauthenticated_paths = get_unauthenticated_paths(application_route_data)

        # Synchronize external authorization configuration.
        if not self.ingress_config.is_ready() and auth_decisions_address:
            self.unit.status = BlockedStatus(
                "Ingress configuration relation missing, yet valid authentication configuration are provided."
            )
            self._remove_gateway_resources()
            return
        self._sync_ext_authz_auth_policy(auth_decisions_address, unauthenticated_paths)

        # Reconcile HPA and gateway resources

        self._sync_gateway_resources()
        self.unit.status = MaintenanceStatus("Validating gateway readiness")
        if not self._is_ready():
            return

        # Validate external hostname.
        if not self._ingress_url:
            self.unit.status = BlockedStatus(
                "Invalid hostname provided, Please ensure this adheres to RFC 1123."
            )
            return

        # Synchronize ingress resources
        try:
            # Extract just a list of the routes to be created
            routes_to_create = [
                route
                for route_data in application_route_data.values()
                for route in route_data["routes"]
            ]
            self._sync_ingress_resources(routes=routes_to_create)
        except ApiError as e:
            logger.error("Ingress sync failed: %s", e)
            self.unit.status = BlockedStatus("Issue with setting up an ingress")
            return

        # Publish route information to ingressed applications
        self._publish_routes_to_ingressed_applications(application_route_data)

        # Set up the proxy service.
        self._setup_proxy_pebble_service()

        # Update forward auth relation data with ingressed apps.
        if self.model.get_relation(FORWARD_AUTH_RELATION):
            ingressed_apps = [app for app, _ in application_route_data.keys()]
            self.forward_auth.update_requirer_relation_data(
                ForwardAuthRequirerConfig(ingress_app_names=ingressed_apps)
            )

        self.unit.status = ActiveStatus(f"Serving at {self._ingress_url}")

        # Request certificate inspection.
        # Request a cert refresh in case configuration has changed
        # The cert handler will only refresh if it detects a meaningful change
        logger.info(
            "Requesting CertHandler inspect certs to decide if our CSR has changed and we should re-request"
        )
        self.on.refresh_certs.emit()

    def _get_oauth_decisions_address(self) -> Optional[str]:
        """Retrieve the auth configuration decisions_address if it exists.

        Returns:
            The decisions_address if available; otherwise, None.
        """
        auth_info = self.forward_auth.get_provider_info()
        if not auth_info:
            logger.debug("Auth relation exists but auth_info is missing.")
            return None

        if not auth_info.decisions_address:
            logger.debug("Auth relation exists but decisions_address is missing.")
            return None

        return auth_info.decisions_address

    def _get_routes(self):
        """Return the routes requested by all applications on all ingress relations, and associated relation_handlers.

        Returns:
            A dict mapping (app_name, relation_name): {"handler": relation_handler, "routes": routes}, where
            relation_handler is a valid serializer and deserializer for this (app_name, relation_name)'s relation data.
        """
        routes = {}
        for relation_name in self.ingress_relation_handlers.keys():
            for app_name, app_route_data in self._get_routes_from_ingress(relation_name).items():
                route_key = (app_name, relation_name)
                routes[route_key] = app_route_data

        return routes

    def _get_routes_from_ingress(self, relation_name: str):
        """Retrieve all routes from the given relation, and associated relation_handlers.

        Args:
            relation_name: The name of the ingress relation.

        Returns:
            A dict of {app_name: {"handler": relation_handler, "routes": List[RouteInfo])}.  In the case where a related
            app has not provided any data yet, [RouteInfo] will be an empty list.
        """
        # {key: {"handler": relation_handler, "routes": [RouteInfo]}}
        application_route_data = {}

        # Presently, each relation endpoint supports a single relation handler, so we can just look it up.
        # But in future if we support ingress v2 and v3 simultaneously, we'd need to include in the below loop something
        # to inspect each related app and choose a handler.
        relation_handler = self.ingress_relation_handlers[relation_name]

        for rel in self.model.relations[relation_name]:
            key = rel.app.name
            if key not in application_route_data:
                application_route_data[key] = {"handler": relation_handler, "routes": []}

            if not rel.active or not relation_handler.is_ready(rel):
                # No active routes for this related application
                continue

            data = relation_handler.get_data(rel)
            application_route_data[key]["routes"].append(
                RouteInfo(
                    service_name=data.app.name,
                    namespace=data.app.model,
                    port=data.app.port,
                    # For data.app.strip_prefix, an omitted value (None) equates to False
                    strip_prefix=data.app.strip_prefix or False,
                    prefix=self._generate_default_path(data.app.name, data.app.model),
                )
            )
        return application_route_data

    def _publish_routes_to_ingressed_applications(self, route_data):
        """Update the ingress relation for all routes."""
        ingress_url = self._ingress_url_with_scheme()
        for (app_name, relation_name), this_route_data in route_data.items():
            relation_handler = this_route_data["handler"]
            routes = this_route_data["routes"]
            rel = get_relation_by_name_and_app(self.model.relations[relation_name], app_name)

            if len(routes) != 1:
                if len(routes) > 1:
                    # This is unsupported and should never happen, but just in case.
                    logger.error(
                        f"Cannot publish routes to {app_name} in {relation_name} because there are too many routes."
                        f"  Expected <=1 route, got {routes}"
                    )
                relation_handler.wipe_ingress_data(rel)
                continue

            relation_handler.publish_url(rel, ingress_url + routes[0]["prefix"])

    def _publish_to_istio_ingress_config_relation(self, decisions_address: Optional[str]):
        if not decisions_address:
            self.ingress_config.clear()
            return

        parsed_url = urlparse(decisions_address)
        service_name = parsed_url.hostname
        port = parsed_url.port
        # TODO: Below probably needs to be leader guarded
        # we should think about this as part of working on #issues/16
        self.ingress_config.publish(ext_authz_service_name=service_name, ext_authz_port=str(port))

    def _sync_ext_authz_auth_policy(
        self, auth_decisions_address: Optional[str], unauthenticated_paths: List[str]
    ):
        """Reconcile the AuthorizationPolicy that applies authentication to this gateway."""
        policy_manager = self._get_extz_auth_policy_resource_manager()
        resources = []

        if self.ingress_config.is_ready() and auth_decisions_address:
            provider_name = self.ingress_config.get_ext_authz_provider_name()
            resources.append(self._construct_ext_authz_policy(provider_name, unauthenticated_paths=unauthenticated_paths))  # type: ignore

        policy_manager.reconcile(resources)

    def _sync_gateway_resources(self):
        unit_count = self.model.app.planned_units()
        krm = self._get_gateway_resource_manager()
        resources_list = []
        tls_secret_name = None

        # Skip reconciliation if no units are left (unit_count < 1):
        #  - This typically indicates an application removal event; we rely on the remove hook for cleanup.
        #  - Attempting to reconcile with an HPA that sets replicas to zero is invalid.
        #  - This guard exists because some events can call _sync_all_resources before the remove hook runs,
        #    leading to k8s validation webhook errors when planned_units is 0.
        if unit_count > 0:
            if secret := self._construct_gateway_tls_secret():
                resources_list.append(secret)
                if secret.metadata is None:
                    raise ValueError("Unexpected error: secret.metadata is None")
                tls_secret_name = secret.metadata.name

            resources_list.append(self._construct_gateway(tls_secret_name=tls_secret_name))
            resources_list.append(self._construct_hpa(unit_count))

        krm.reconcile(resources_list)

        # TODO: Delete below line when we figure out a way to unset hostname on reconcile if set to empty/invalid/unset
        # this is due to the fact that the patch method used in lk.apply is patch.APPLY (https://github.com/gtsystem/lightkube/blob/75c71426d23963be94412ca6f26f77a7a61ab363/lightkube/core/client.py#L759)
        # when we omit a field like hostname from the patch, apply does not remove the existing value
        # it assumes that the omission means "do not change this field," not "delete this field."
        # also worth noting that setting the value to None to remove it will result into a validation webhook error firing from k8s side
        if not self._is_valid_hostname(self._ingress_url):
            self._remove_hostname_if_present()

    def _remove_hostname_if_present(self):
        """Remove the 'hostname' field from the first listener of the Gateway resource if it is present.

        This is necessary because lightkube.apply with patch.APPLY
        does not remove fields; it assumes omission means "do not change this field."
        Setting the value to None results in a validation error from Kubernetes.
        """
        try:
            existing_gateway = self.lightkube_client.get(
                RESOURCE_TYPES["Gateway"], name=self.app.name, namespace=self.model.name
            )
            if existing_gateway.spec and "listeners" in existing_gateway.spec:
                patches = []
                for i, listener in enumerate(existing_gateway.spec["listeners"]):
                    if "hostname" in listener:
                        patches.append({"op": "remove", "path": f"/spec/listeners/{i}/hostname"})

                if patches:
                    self.lightkube_client.patch(
                        RESOURCE_TYPES["Gateway"],
                        name=self.app.name,
                        namespace=self.model.name,
                        obj=patches,
                        patch_type=PatchType.JSON,
                    )
        except ApiError:
            return

    def _sync_ingress_resources(self, routes: List[RouteInfo]):
        """Synchronize the ingress resources to reflect the desired routes."""
        if not self.unit.is_leader():
            raise RuntimeError("Ingress can only be provided on the leader unit.")

        httproutes = []
        ingress_to_workload_authorization_policies = []

        # If we can construct a gateway Secret, TLS is enabled so we should configure the routes accordingly
        is_tls_enabled = self._construct_gateway_tls_secret() is not None

        for route in routes:
            if not route["prefix"]:
                # This should never happen
                raise RuntimeError(f"Missing prefix in route: {route}")

            if is_tls_enabled:
                # TLS is configured, so we enable HTTPS route and redirect HTTP to HTTPS
                httproutes.append(
                    self._construct_redirect_to_https_httproute(
                        app_name=route["service_name"],
                        model=route["namespace"],
                        prefix=route["prefix"],
                        section_name="http",
                    )
                )
                httproutes.append(
                    self._construct_httproute(
                        service_name=route["service_name"],
                        namespace=route["namespace"],
                        port=route["port"],
                        strip_prefix=route["strip_prefix"],
                        prefix=route["prefix"],
                        section_name="https",
                    )
                )
            else:
                # Else, we enable only an HTTP route
                httproutes.append(
                    self._construct_httproute(
                        service_name=route["service_name"],
                        namespace=route["namespace"],
                        port=route["port"],
                        strip_prefix=route["strip_prefix"],
                        prefix=route["prefix"],
                        section_name="http",
                    )
                )

            ingress_to_workload_authorization_policies.append(
                self._construct_auth_policy_from_ingress_to_target(
                    target_name=route["service_name"],
                    target_namespace=route["namespace"],
                    target_port=route["port"],
                )
            )

        krm = self._get_ingress_route_resource_manager()
        kam = self._get_ingress_auth_policy_resource_manager()
        krm.reconcile(httproutes)
        kam.reconcile(ingress_to_workload_authorization_policies)

    def _ingress_url_with_scheme(self) -> str:
        """Return the url to the ingress managed by this charm, including scheme.

        See _ingress_url for more details.

        This may return None if no ingress load balancer exists.
        """
        scheme = "https" if self._construct_gateway_tls_secret() is not None else "http"
        return f"{scheme}://{self._ingress_url}"

    @property
    def _ingress_url(self) -> Optional[str]:
        """Return the external address for the ingress gateway.

        This will return one of (in order of preference):
        1. the value cached from a previous call to _ingress_url, even if this value has since changed
        2. the `external-hostname` config if that is set
        3. the load balancer address for the ingress gateway, if it exists and has an IP
        4. None

        Preference is given to the previously cached value because this charm may make several calls to this method in
        a single charm execution and the value of the load balancer address may change during that time.  Without this
        preference, we could request certs for one hostname and then serve traffic on another.

        Only use this directly when _ingress_url is allowed to be None.
        """
        if self._ingress_url_ is not None:
            return self._ingress_url_

        if external_hostname := self.model.config.get("external_hostname"):
            hostname = cast(str, external_hostname)
            if self._is_valid_hostname(hostname):
                self._ingress_url_ = hostname
                return self._ingress_url_
            logger.error("Invalid hostname provided, Please ensure this adheres to RFC 1123")
            return None

        if lb_external_address := self._get_lb_external_address:
            self._ingress_url_ = lb_external_address
            return self._ingress_url_

        logger.debug(
            "Load balancer address not available.  This is likely a transient issue that will resolve itself, but"
            " could be because the cluster does not have a load balancer provider.  Defaulting to this charm's fqdn."
        )

        return None

    @staticmethod
    def _generate_default_path(app_name: str, model: str) -> str:
        """Generate the default path for an ingressed route."""
        app_name = app_name.replace("/", "-")
        return f"/{model}-{app_name}"

    def _is_valid_hostname(self, hostname: Optional[str]) -> bool:
        # https://gateway-api.sigs.k8s.io/reference/spec/#gateway.networking.k8s.io/v1.Hostname
        """Check if the provided hostname is a valid DNS hostname according to RFC 1123.

        Doesn't support wildcard prefixes. This function ensures that the hostname conforms
        to the DNS naming conventions, excluding wildcards and IP addresses.

        Args:
            hostname (str): The hostname to validate.

        Returns:
            bool: True if the hostname is valid, False otherwise.
        """
        # Validate the hostname length
        if not hostname or not (1 <= len(hostname) <= 253):
            return False

        try:
            ipaddress.ip_address(hostname)
            # This is an IP address, so it is not a valid hostname
            return False
        except ValueError:
            # This is not an IP address, so it might be a valid hostname
            pass

        # Regex to match gateway hostname specs https://github.com/kubernetes-sigs/gateway-api/blob/6446fac9325dbb570675f7b85d58727096bf60a6/apis/v1/shared_types.go#L523
        # Below is the original regex used to validate hosts, as part of this dev iteration below will be omitted in favor of a regex with no wildcard support.
        # TODO: uncomment the below when support is added for both wildcards and using subdomains
        # hostname_regex = re.compile(
        #     r"^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
        # )

        # Regex with no wildcard (*) or IP support.
        hostname_regex = re.compile(
            r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
        )

        # Check if the hostname matches the required pattern
        if not hostname_regex.match(hostname):
            return False

        return True

    @property
    def _certificate_secret_name(self) -> str:
        """Return the name of the Kubernetes secret used to hold TLS certificate information."""
        return f"{self.app.name}-tls-certificate"

    @staticmethod
    def format_labels(label_dict: Dict[str, str]) -> str:
        """Format a dictionary into a comma-separated string of key=value pairs."""
        return ",".join(f"{key}={value}" for key, value in label_dict.items())


def _get_peer_identity_for_juju_application(app_name, namespace):
    """Return a Juju application's peer identity.

    Format returned is defined by `principals` in
    [this reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/#Source):

    This function relies on the Juju convention that each application gets a ServiceAccount of the same name in the same
    namespace.
    """
    return f"cluster.local/ns/{namespace}/sa/{app_name}"


def get_relation_by_name_and_app(relations, remote_app_name):
    """Return the relation object associated with a given remote app."""
    for rel in relations:
        if rel.app.name == remote_app_name:
            return rel
    raise KeyError(f"Could not find relation with remote_app_name={remote_app_name}")


def deduplicate_app_route_data(application_route_data) -> bool:
    """Remove all routes from any applications that request the same route prefix, editing the input in place.

    For example, given input:
    application_route_data = {
        (app0, ingress-relation-A): {"handler": f, "routes"=[RouteInfo(path="path0")],  # <-- Duplicate path0
        (app1, ingress-relation-A): {"handler": f, "routes"=[RouteInfo(path="path1")],
        (app2, ingress-relation-B): {"handler": f, "routes"=[RouteInfo(path="path0")],  # <-- Duplicate path0
        (app3, ingress-relation-B): {"handler": f, "routes"=[RouteInfo(path="path3")],  # <-- Duplicate path3
        (app4, ingress-relation-B): {"handler": f, "routes"=[RouteInfo(path="path3")],  # <-- Duplicate path3
    }

    This function would return only:
    {
        (app0, ingress-relation-A): {"handler": f, "routes"=[],                         # <-- Duplicate path0
        (app1, ingress-relation-A): {"handler": f, "routes"=[RouteInfo(path="path1")],
        (app2, ingress-relation-B): {"handler": f, "routes"=[],                         # <-- Duplicate path0
        (app3, ingress-relation-B): {"handler": f, "routes"=[],                         # <-- Duplicate path3
        (app4, ingress-relation-B): {"handler": f, "routes"=[],                         # <-- Duplicate path3
    }
    because all other entries have collisions.

    Note that this function does not remove keys from the route map because we still need those later in case we need to
    nullify what we've previously sent to them via the ingress relation.

    Side effects: this modifies the input in place.

    Return:
        bool: True if duplicate routes were removed, False otherwise.
    """
    # Work on a copy so we don't modify the source object
    prefix_to_app_map = defaultdict(list)
    for route_key, route_data in application_route_data.items():
        for route in route_data["routes"]:
            prefix_to_app_map[route["prefix"]].append(route_key)

    # Select only prefixes that have multiple routes using them
    duplicate_prefix_to_app_map = {
        prefix: route_keys
        for prefix, route_keys in prefix_to_app_map.items()
        if len(route_keys) > 1
    }

    # For any app that has one or more duplicate routes, remove all routes for that app
    for prefix, route_keys in duplicate_prefix_to_app_map.items():
        duplicated_app_list = ", ".join(
            [
                f"app {app_name} in relation {relation_name}"
                for app_name, relation_name in route_keys
            ]
        )
        logger.error(
            f"Ingress through prefix {prefix} requested by more than one application.  Got requests from '{duplicated_app_list}'"
        )
        for route_key in route_keys:
            # Remove all routes for this key
            application_route_data[route_key]["routes"] = {}

    return len(duplicate_prefix_to_app_map) > 0


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


def generate_telemetry_labels(app_name: str, model_name: str) -> Dict[str, str]:
    """Generate telemetry labels for the application, ensuring it is always <=63 characters and usually unique.

    The telemetry labels need to be unique for each application in order to prevent one application from scraping
    another's metrics (eg: istio-beacon scraping the workloads of istio-ingress).  Ideally, this would be done by
    including model_name and app_name in the label key or value, but Kubernetes label keys and values have a 63
    character limit.  This, thus function returns:
    * a label with a key that includes model_name and app_name, if that key is less than 63 characters
    * a label with a key that is truncated to 63 characters but includes a hash of the full model_name and app_name, to
      attempt to ensure uniqueness.

    The hash is included because simply truncating the model or app names may lead to collisions.  Consider if
    istio-beacon is deployed to two different models of names `really-long-model-name1` and `really-long-model-name2`,
    they'd truncate to the same key.  To reduce this risk, we also include a hash of the model and app names which very
    likely differs between two applications.
    """
    key = f"charms.canonical.com/{model_name}.{app_name}.telemetry"
    if len(key) > 63:
        # Truncate the key to fit within the 63-character limit.  Include a hash of the real model_name.app_name to
        # avoid collisions with some other truncated key.
        hash = hashlib.md5(f"{model_name}.{app_name}".encode()).hexdigest()[:10]
        key = f"charms.canonical.com/{model_name[:10]}.{app_name[:10]}.{hash}.telemetry"
    return {
        key: "aggregated",
    }


if __name__ == "__main__":
    main(IstioIngressCharm)
