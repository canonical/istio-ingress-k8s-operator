#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import logging
import re
import time
from typing import Any, Dict, Optional, cast
from urllib.parse import urlparse

from charms.istio_k8s.v0.istio_ingress_config import IngressConfigProvider
from charms.oauth2_proxy_k8s.v0.forward_auth import ForwardAuthRequirer
from charms.observability_libs.v1.cert_handler import CertHandler
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2
from charms.traefik_k8s.v2.ingress import IngressRequirerData
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Secret, Service
from lightkube.types import PatchType
from lightkube_extensions.batch import KubernetesResourceManager, create_charm_default_labels
from ops import BlockedStatus, EventBase, main
from ops.charm import CharmBase
from ops.model import ActiveStatus, MaintenanceStatus
from ops.pebble import ChangeError, Layer

# from lightkube.models.meta_v1 import Patch
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

GATEWAY_RESOURCE_TYPES = {RESOURCE_TYPES["Gateway"], Secret}
INGRESS_RESOURCE_TYPES = {
    RESOURCE_TYPES["GRPCRoute"],
    RESOURCE_TYPES["ReferenceGrant"],
    RESOURCE_TYPES["HTTPRoute"],
}
AUTHORIZATION_POLICY_RESOURCE_TYPES = {RESOURCE_TYPES["AuthorizationPolicy"]}
GATEWAY_SCOPE = "istio-gateway"
INGRESS_SCOPE = "istio-ingress"
INGRESS_AUTH_POLICY_SCOPE = "istio-ingress-authorization-policy"
EXTZ_AUTH_POLICY_SCOPE = "external-authorizer-authorization-policy"

INGRESS_CONFIG_RELATION = "istio-ingress-config"
FORWARD_AUTH_RELATION = "forward-auth"


class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class DisabledCertHandler:
    """A mock CertHandler class that mimics being unavailable."""

    available: bool = False
    server_cert = None
    private_key = None


class RefreshCerts(EventBase):
    """Event raised when the charm wants the certs to be refreshed."""


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

        self._external_host_ = None

        self.managed_name = f"{self.app.name}-istio"
        self._lightkube_field_manager: str = self.app.name
        self._lightkube_client = None

        self.ingress_per_appv2 = IPAv2(charm=self)
        self.telemetry_labels = {
            f"charms.canonical.com/{self.model.name}.{self.app.name}.telemetry": "aggregated"
        }
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
        self.framework.observe(self.forward_auth.on.auth_config_changed, self._handle_auth_config)
        self.framework.observe(self.forward_auth.on.auth_config_removed, self._handle_auth_config)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(
            self.ingress_per_appv2.on.data_provided, self._on_ingress_data_provided
        )
        self.framework.observe(
            self.ingress_per_appv2.on.data_removed, self._on_ingress_data_removed
        )
        self.framework.observe(
            self.on.metrics_proxy_pebble_ready, self._metrics_proxy_pebble_ready
        )
        self.framework.observe(
            self.on[INGRESS_CONFIG_RELATION].relation_changed, self._handle_ingress_config
        )
        self.framework.observe(
            self.on[INGRESS_CONFIG_RELATION].relation_broken, self._handle_ingress_config
        )
        # During the initialisation of the charm, we do not have a LoadBalancer and thus a LoadBalancer external IP.
        # If we need that IP to request the certs, disable cert handling until we have it.
        if (external_hostname := self._external_host) is None:
            logger.debug(
                "External hostname is not set and no load balancer ip available.  TLS certificate generation disabled"
            )
            self._cert_handler = DisabledCertHandler()
        else:
            self._cert_handler = CertHandler(
                self,
                key="istio-ingress-cert",  # TODO: how is this key used?  if we have two ingresses, do we get issues?
                peer_relation_name="peers",
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

    def _get_ingress_resource_manager(self):
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

    def _metrics_proxy_pebble_ready(self, _):
        """Event handler for metrics_proxy_pebble_ready."""
        self._sync_all_resources()

    def _handle_ingress_config(self, _):
        """Event handler for ingress_config relation events."""
        self._sync_all_resources()

    def _handle_auth_config(self, _):
        """Event handler for forward_auth config changes."""
        self._sync_all_resources()

    def _on_remove(self, _):
        """Event handler for remove."""
        # Removing tailing ingresses
        kim = self._get_ingress_resource_manager()
        kim.delete()

        kgm = self._get_gateway_resource_manager()
        kgm.delete()

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
        hostname = self._external_host if self._is_valid_hostname(self._external_host) else None
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

    def _construct_httproute(self, data: IngressRequirerData, prefix: str, section_name: str):
        http_route = HTTPRouteResource(
            metadata=Metadata(
                name=data.app.name + "-" + section_name,
                namespace=data.app.model,
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
                                name=data.app.name,
                                port=data.app.port,
                                namespace=data.app.model,
                            )
                        ],
                        filters=(
                            [
                                HTTPRouteFilter(
                                    type=HTTPRouteFilterType.URLRewrite,
                                    urlRewrite=HTTPURLRewriteFilter(),
                                )
                            ]
                            if data.app.strip_prefix
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

    def _construct_ingress_auth_policy(self, data: IngressRequirerData):

        auth_policy = AuthorizationPolicyResource(
            metadata=Metadata(
                name=data.app.name + "-" + self.app.name + "-" + data.app.model + "-l4",
                namespace=data.app.model,
            ),
            spec=AuthorizationPolicySpec(
                rules=[
                    AuthRule(
                        to=[To(operation=Operation(ports=[str(data.app.port)]))],
                        from_=[  # type: ignore # this is accessible via an alias
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
                selector=WorkloadSelector(matchLabels={"app.kubernetes.io/name": data.app.name}),
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

    def _construct_ext_authz_policy(self, ext_authz_provider_name: str):

        ext_authz_policy = AuthorizationPolicyResource(
            metadata=Metadata(
                name=f"ext-authz-{self.app.name}",
                namespace=self.model.name,
            ),
            spec=AuthorizationPolicySpec(
                rules=[AuthRule()],
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
        self, data: IngressRequirerData, prefix: str, section_name: str
    ):
        http_route = HTTPRouteResource(
            metadata=Metadata(
                name=data.app.name + "-" + section_name,
                namespace=data.app.model,
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

    def _sync_all_resources(self):
        """Synchronize all resources including authentication, gateway, ingress, and certificates.

        Flow:
        1. Check authentication configuration.
            - If auth relation exists but no decisions address, set to blocked and remove gateway.
        2. Publish or clear the auth_decisions_address in ingress-config, if related.
        3. Synchronize gateway resources and validate readiness.
        4. Validate the external hostname.
        5. Synchronize external authorization configuration.
            - If missing valid ingress-config relation when auth is provided, set to blocked and remove gateway.
        6. Synchronize ingress resources and set up the proxy service.
        7. Request certificate inspection.
        """
        # 1. Validate authentication configuration.
        auth_decisions_address = self._get_decisions_address()
        if self._is_auth_related() and not auth_decisions_address:
            self.unit.status = BlockedStatus(
                "Authentication configuration incomplete; ingress is disabled."
            )
            self._remove_gateway_resources()
            return

        # 2. Update ingress-config with the external authorization address if related.
        if self._is_ingress_config_related():
            self._publish_ext_authz_config(auth_decisions_address)

        # 2. Synchronize gateway resources and check readiness.
        self._sync_gateway_resources()
        self.unit.status = MaintenanceStatus("Validating gateway readiness")
        if not self._is_ready():
            return

        # 3. Validate external hostname.
        if not self._external_host:
            self.unit.status = BlockedStatus(
                "Invalid hostname provided, Please ensure this adheres to RFC 1123."
            )
            return

        # 5. Synchronize external authorization configuration if both ingress-config is ready and decisions address is present.
        if not self.ingress_config.is_ready() and auth_decisions_address:
            self.unit.status = BlockedStatus(
                "Ingress configuration relation missing, yet valid authentication configuration are provided."
            )
            self._remove_gateway_resources()
            return
        self._sync_ext_authz_config(auth_decisions_address)

        # 5. Synchronize ingress resources and set up the proxy service.
        try:
            self._sync_ingress_resources()
            self._setup_proxy_pebble_service()
            self.unit.status = ActiveStatus(f"Serving at {self._external_host}")
        except (DataValidationError, ApiError) as e:
            logger.error("Ingress sync failed: %s", e)
            self.unit.status = BlockedStatus("Issue with setting up an ingress")
            return

        # 6. Request certificate inspection.
        # Request a cert refresh in case configuration has changed
        # The cert handler will only refresh if it detects a meaningful change
        logger.info(
            "Requesting CertHandler inspect certs to decide if our CSR has changed and we should re-request"
        )
        self.on.refresh_certs.emit()

    def _is_auth_related(self) -> bool:
        """Check if the auth relation is established.

        Returns:
            True if an auth relation exists and has an associated app;
            otherwise, False.
        """
        relation = self.model.get_relation(FORWARD_AUTH_RELATION)
        if relation and relation.app:
            logger.debug("Auth relation is established.")
            return True
        logger.debug("Auth relation or its associated app is missing.")
        return False

    def _get_decisions_address(self) -> Optional[str]:
        """Retrieve the auth configuration decisions_address if it exists.

        This function assumes that an auth relation exists and checks whether
        the provider info includes a valid decisions_address.

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

    def _is_ingress_config_related(self) -> bool:
        """Check if the ingress-config relation is established.

        Returns:
            True if an ingress-config relation exists and has an associated app;
            otherwise, False.
        """
        relation = self.model.get_relation(INGRESS_CONFIG_RELATION)
        if relation and relation.app:
            logger.debug("Ingress config relation is established.")
            return True
        logger.debug("Ingress config or its associated app is missing.")
        return False

    def _publish_ext_authz_config(self, decisions_address: Optional[str]):
        """Publish the external authorization service configuration using the provided decisions_address."""
        if not decisions_address:
            self.ingress_config.clear()
            return

        parsed_url = urlparse(decisions_address)
        service_name = parsed_url.hostname
        port = parsed_url.port
        self.ingress_config.publish(ext_authz_service_name=service_name, ext_authz_port=str(port))

    def _sync_ext_authz_config(self, auth_decisions_address: Optional[str]):
        policy_manager = self._get_extz_auth_policy_resource_manager()
        resources = []

        if self.ingress_config.is_ready() and auth_decisions_address:
            provider_name = self.ingress_config.get_ext_authz_provider_name()
            resources.append(self._construct_ext_authz_policy(provider_name))  # type: ignore

        policy_manager.reconcile(resources)

    def _sync_gateway_resources(self):
        krm = self._get_gateway_resource_manager()

        resources_list = []
        tls_secret_name = None
        if secret := self._construct_gateway_tls_secret():
            resources_list.append(secret)
            if secret.metadata is None:
                raise ValueError("Unexpected error: secret.metadata is None")
            tls_secret_name = secret.metadata.name
        resources_list.append(self._construct_gateway(tls_secret_name=tls_secret_name))
        krm.reconcile(resources_list)

        # TODO: Delete below line when we figure out a way to unset hostname on reconcile if set to empty/invalid/unset
        # this is due to the fact that the patch method used in lk.apply is patch.APPLY (https://github.com/gtsystem/lightkube/blob/75c71426d23963be94412ca6f26f77a7a61ab363/lightkube/core/client.py#L759)
        # when we omit a field like hostname from the patch, apply does not remove the existing value
        # it assumes that the omission means "do not change this field," not "delete this field."
        # also worth noting that setting the value to None to remove it will result into a validation webhook error firing from k8s side
        if not self._is_valid_hostname(self._external_host):
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

    def _sync_ingress_resources(self):
        current_ingresses = []
        current_policies = []
        relation_mappings = {}
        if not self.unit.is_leader():
            raise RuntimeError("Ingress can only be provided on the leader unit.")

        krm = self._get_ingress_resource_manager()
        kam = self._get_ingress_auth_policy_resource_manager()

        # If we can construct a gateway Secret, TLS is enabled so we should configure the routes accordingly
        is_tls_enabled = self._construct_gateway_tls_secret() is not None

        for rel in self.model.relations["ingress"]:

            if not self.ingress_per_appv2.is_ready(rel):
                self.ingress_per_appv2.wipe_ingress_data(rel)
                continue

            data = self.ingress_per_appv2.get_data(rel)
            prefix = self._generate_prefix(data.app.model_dump(by_alias=True))
            ingress_resources_to_append = []
            ingress_policies_to_append = []
            if is_tls_enabled:
                # TLS is configured, so we enable HTTPS route and redirect HTTP to HTTPS
                ingress_resources_to_append.append(
                    self._construct_redirect_to_https_httproute(data, prefix, section_name="http")
                )
                ingress_resources_to_append.append(
                    self._construct_httproute(data, prefix, section_name="https")
                )
            else:
                # Else, we enable only an HTTP route
                ingress_resources_to_append.append(
                    self._construct_httproute(data, prefix, section_name="http")
                )

            ingress_policies_to_append.append(self._construct_ingress_auth_policy(data))

            if rel.active:
                current_ingresses.extend(ingress_resources_to_append)
                current_policies.extend(ingress_policies_to_append)
                external_url = self._generate_external_url(prefix)
                relation_mappings[rel] = external_url

        try:
            krm.reconcile(current_ingresses)
            kam.reconcile(current_policies)
            for relation, url in relation_mappings.items():
                self.ingress_per_appv2.wipe_ingress_data(relation)
                logger.debug(f"Publishing external URL for {relation.app.name}: {url}")
                self.ingress_per_appv2.publish_url(relation, url)

        except ApiError:
            raise

    def _generate_external_url(self, prefix: str) -> str:
        """Generate external URL for the ingress."""
        scheme = "https" if self._construct_gateway_tls_secret() is not None else "http"
        return f"{scheme}://{self._external_host}{prefix}"

    @property
    def _external_host(self) -> Optional[str]:
        """Return the external address for the ingress gateway.

        This will return one of (in order of preference):
        1. the value cached from a previous call to _external_host, even if this value has since changed
        2. the `external-hostname` config if that is set
        3. the load balancer address for the ingress gateway, if it exists and has an IP
        4. None

        Preference is given to the previously cached value because this charm may make several calls to this method in
        a single charm execution and the value of the load balancer address may change during that time.  Without this
        preference, we could request certs for one hostname and then serve traffic on another.

        Only use this directly when external_host is allowed to be None.
        """
        if self._external_host_ is not None:
            return self._external_host_

        if external_hostname := self.model.config.get("external_hostname"):
            hostname = cast(str, external_hostname)
            if self._is_valid_hostname(hostname):
                self._external_host_ = hostname
                return self._external_host_
            logger.error("Invalid hostname provided, Please ensure this adheres to RFC 1123")
            return None

        if lb_external_address := self._get_lb_external_address:
            self._external_host_ = lb_external_address
            return self._external_host_

        logger.debug(
            "Load balancer address not available.  This is likely a transient issue that will resolve itself, but"
            " could be because the cluster does not have a load balancer provider.  Defaulting to this charm's fqdn."
        )

        return None

    @staticmethod
    def _generate_prefix(data: Dict[str, Any]) -> str:
        """Generate prefix for the ingress configuration."""
        name = data["name"].replace("/", "-")
        return f"/{data['model']}-{name}"

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
        # Regex to match gateway hostname specs https://github.com/kubernetes-sigs/gateway-api/blob/6446fac9325dbb570675f7b85d58727096bf60a6/apis/v1/shared_types.go#L523
        # Below is the original regex used to validate hosts, as part of this dev iteration below will be omitted in favor of a regex with no wildcard support.
        # TODO: uncomment the below when support is added for both wildcards and using subdomains
        # hostname_regex = re.compile(
        #     r"^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z]([-a-z0-9]*[a-z0-9])?)*$"
        # )

        # Regex with no wildcard (*) or IP support.
        hostname_regex = re.compile(
            r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z]([-a-z0-9]*[a-z0-9])?)*$"
        )

        # Validate the hostname length
        if not hostname or not (1 <= len(hostname) <= 253):
            return False

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


if __name__ == "__main__":
    main(IstioIngressCharm)
