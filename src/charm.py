#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import logging
import re
import time
from typing import Any, Dict, Optional, cast

from charms.observability_libs.v1.cert_handler import CertHandler
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
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
from ops import BlockedStatus, EventBase
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus
from ops.pebble import ChangeError, Layer

# from lightkube.models.meta_v1 import Patch
from models import (
    AllowedRoutes,
    BackendRef,
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
    ParentRef,
    PathMatch,
    Rule,
    SecretObjectReference,
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
}

GATEWAY_RESOURCE_TYPES = {RESOURCE_TYPES["Gateway"], Secret}
INGRESS_RESOURCE_TYPES = {
    RESOURCE_TYPES["GRPCRoute"],
    RESOURCE_TYPES["ReferenceGrant"],
    RESOURCE_TYPES["HTTPRoute"],
}
GATEWAY_LABEL = "istio-gateway"
INGRESS_LABEL = "istio-ingress"


class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class DisabledCertHandler:
    """A mock CertHandler class that mimics being unavailable."""

    available: bool = False
    server_cert = None
    private_key = None


class RefreshCerts(EventBase):
    """Event raised when the charm wants the certs to be refreshed."""


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
        self.framework.observe(self.on.config_changed, self._on_config_changed)
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
                self.app.name, self.model.name, scope=GATEWAY_LABEL
            ),
            resource_types=GATEWAY_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _get_ingress_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=INGRESS_LABEL
            ),
            resource_types=INGRESS_RESOURCE_TYPES,  # pyright: ignore
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

    def _on_remove(self, _):
        """Event handler for remove."""
        # Removing tailing ingresses
        krm = self._get_ingress_resource_manager()
        krm.delete()

        krm = self._get_gateway_resource_manager()
        krm.delete()

    def _on_ingress_data_provided(self, _):
        """Handle a unit providing data requesting IPU."""
        self._sync_all_resources()

    def _on_ingress_data_removed(self, _):
        """Handle a unit removing the data needed to provide ingress."""
        self._sync_all_resources()

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
        self._sync_gateway_resources()

        self.unit.status = MaintenanceStatus("Validating gateway readiness")

        if self._is_ready():
            if not self._external_host:
                self.unit.status = BlockedStatus(
                    "Invalid hostname provided, Please ensure this adheres to RFC 1123."
                )
                return
            try:
                self._sync_ingress_resources()
                self._setup_proxy_pebble_service()
                self.unit.status = ActiveStatus(f"Serving at {self._external_host}")
            except DataValidationError or ApiError:
                self.unit.status = BlockedStatus("Issue with setting up an ingress")

            # Request a cert refresh in case configuration has changed
            # The cert handler will only refresh if it detects a meaningful change
            logger.info(
                "Requesting CertHandler inspect certs to decide if our CSR has changed and we should re-request"
            )
            self.on.refresh_certs.emit()

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
        relation_mappings = {}
        if not self.unit.is_leader():
            raise RuntimeError("Ingress can only be provided on the leader unit.")

        krm = self._get_ingress_resource_manager()

        # If we can construct a gateway Secret, TLS is enabled so we should configure the routes accordingly
        is_tls_enabled = self._construct_gateway_tls_secret() is not None

        for rel in self.model.relations["ingress"]:

            if not self.ingress_per_appv2.is_ready(rel):
                self.ingress_per_appv2.wipe_ingress_data(rel)
                continue

            data = self.ingress_per_appv2.get_data(rel)
            prefix = self._generate_prefix(data.app.model_dump(by_alias=True))
            resources_to_append = []
            if is_tls_enabled:
                # TLS is configured, so we enable HTTPS route and redirect HTTP to HTTPS
                resources_to_append.append(
                    self._construct_redirect_to_https_httproute(data, prefix, section_name="http")
                )
                resources_to_append.append(
                    self._construct_httproute(data, prefix, section_name="https")
                )
            else:
                # Else, we enable only an HTTP route
                resources_to_append.append(
                    self._construct_httproute(data, prefix, section_name="http")
                )

            if rel.active:
                current_ingresses.extend(resources_to_append)
                external_url = self._generate_external_url(prefix)
                relation_mappings[rel] = external_url

        try:
            krm.reconcile(current_ingresses)
            for relation, url in relation_mappings.items():
                self.ingress_per_appv2.wipe_ingress_data(relation)
                logger.debug(f"Publishing external URL for {relation.app.name}: {url}")
                self.ingress_per_appv2.publish_url(relation, url)

        except ApiError:
            raise

    def _generate_external_url(self, prefix: str) -> str:
        """Generate external URL for the ingress."""
        return f"http://{self._external_host}{prefix}"

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


if __name__ == "__main__":
    main(IstioIngressCharm)
