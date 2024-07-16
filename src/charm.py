#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import functools
import logging
import time
from typing import Any, Dict, Optional

from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2
from charms.traefik_k8s.v2.ingress import IngressRequirerData
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Service
from lightkube_extensions.batch import KubernetesResourceManager, create_charm_default_labels
from models import (
    BackendRef,
    GatewayResource,
    GatewaySpec,
    HTTPRouteResource,
    HTTPRouteResourceSpec,
    Match,
    Metadata,
    ParentRef,
    PathMatch,
    Rule,
    URLRewriteFilter,
)
from ops import BlockedStatus
from ops.charm import (
    CharmBase,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    MaintenanceStatus,
)

logger = logging.getLogger(__name__)

GATEWAY_RESOURCE_TYPES = {
    create_namespaced_resource("gateway.networking.k8s.io", "v1", "Gateway", "gateways"),
}
INGRESS_RESOURCE_TYPES = {
    create_namespaced_resource("gateway.networking.k8s.io", "v1", "GRPCRoute", "grpcroutes"),
    create_namespaced_resource(
        "gateway.networking.k8s.io", "v1beta1", "ReferenceGrant", "referencegrants"
    ),
    create_namespaced_resource("gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes"),
}
GATEWAY_LABEL = "istio-gateway"
INGRESS_LABEL = "istio-ingress"


class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class ExternalHostNotReadyError(Exception):
    """Raised when the ingress hostname is not ready but is assumed to be."""


class IstioIngressCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)

        self.managed_name = f"{self.app.name}-istio"
        self._lightkube_field_manager: str = self.app.name

        self.ingress_per_appv2 = IPAv2(charm=self)

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(
            self.ingress_per_appv2.on.data_provided, self._on_ingress_data_provided
        )
        self.framework.observe(
            self.ingress_per_appv2.on.data_removed, self._on_ingress_data_removed
        )

    @property
    def lightkube_client(self):
        """Returns a lightkube client configured for this charm."""
        return Client(namespace=self.model.name, field_manager=self._lightkube_field_manager)

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

    @property
    def _get_gateway_resource(self):
        return create_namespaced_resource("gateway.networking.k8s.io", "v1", "Gateway", "gateways")

    @property
    def _get_httproute_resource(self):
        return create_namespaced_resource(
            "gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes"
        )

    def _on_config_changed(self, _):
        """Event handler for config changed."""
        resources_list = []
        krm = self._get_gateway_resource_manager()

        self.unit.status = MaintenanceStatus("Setting up global istio-ingress gateway")
        resource_to_append = self._construct_gateway()
        resources_list.append(resource_to_append)
        krm.reconcile(resources_list)

        self.unit.status = MaintenanceStatus("Validating gateway readiness")

        if self._is_ready():
            self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _on_remove(self, _):
        """Event handler for remove."""
        # Removing tailing ingresses
        kim = self._get_ingress_resource_manager()
        kim.delete()

        kgm = self._get_gateway_resource_manager()
        kgm.delete()

    def _on_ingress_data_provided(self, _):
        """Handle a unit providing data requesting IPU."""
        if self._is_ready():
            self._sync_ingress_resources()
            self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _on_ingress_data_removed(self, _):
        """Handle a unit removing the data needed to provide ingress."""
        if self._is_ready():
            self._sync_ingress_resources()
            self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _is_deployment_ready(self) -> bool:
        """Check if the deployment is ready after 10 attempts."""
        attempts = 10

        for _ in range(attempts):
            time.sleep(10)

            try:
                deployment = self.lightkube_client.get(
                    Deployment, name=self.managed_name, namespace=self.model.name
                )
                if (
                    deployment.status
                    and deployment.status.readyReplicas == deployment.status.replicas
                ):
                    return True
            except ApiError as e:
                logger.error(f"Error checking gateway deployment status: {e}")

        return False

    def _is_load_balancer_ready(self) -> bool:
        """Wait for the LoadBalancer to be created."""
        attempts = 10

        for _ in range(attempts):
            time.sleep(10)

            lb_status = _get_loadbalancer_status(
                namespace=self.model.name, service_name=self.managed_name
            )
            if lb_status:
                return True
        return False

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

    def _construct_gateway(self):
        gateway = GatewayResource(
            metadata=Metadata(
                name=self.app.name,
                namespace=self.model.name,
            ),
            spec=GatewaySpec(),
        )
        gateway_resource = self._get_gateway_resource
        return gateway_resource(
            metadata=ObjectMeta.from_dict(gateway.metadata.dict()),
            spec=gateway.spec.dict(),
        )

    def _construct_httproute(self, data: IngressRequirerData, prefix: str):
        http_route = HTTPRouteResource(
            metadata=Metadata(
                name=data.app.name,
                namespace=data.app.model,
            ),
            spec=HTTPRouteResourceSpec(
                parentRefs=[
                    ParentRef(
                        name=self.app.name,
                        namespace=self.model.name,
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
                        filters=([URLRewriteFilter()] if data.app.strip_prefix else []),
                    )
                ],
            ),
        )
        http_resource = self._get_httproute_resource
        return http_resource(
            metadata=ObjectMeta.from_dict(http_route.metadata.dict()),
            spec=http_route.spec.dict(),
        )

    def _sync_ingress_resources(self):
        current_ingresses = []
        if not self.unit.is_leader():
            raise RuntimeError("Ingress can only be provided on the leader unit.")

        krm = self._get_ingress_resource_manager()
        for rel in self.model.relations["ingress"]:

            if not self.ingress_per_appv2.is_ready(rel):
                logger.debug(f"Provider {rel} not ready; resetting ingress configurations.")
                self.ingress_per_appv2.wipe_ingress_data(rel)
                continue

            try:
                data = self.ingress_per_appv2.get_data(rel)
            except DataValidationError as e:
                logger.error(f"Data validation error for relation {rel}: {e}.")
                raise e

            prefix = self._generate_prefix(data.app.dict(by_alias=True))
            resource_to_append = self._construct_httproute(data, prefix)

            if rel.active:
                current_ingresses.append(resource_to_append)

            self.ingress_per_appv2.wipe_ingress_data(rel)
            external_url = self._generate_external_url(prefix)
            logger.debug(f"Publishing external URL for {rel.app.name}: {external_url}")
            self.ingress_per_appv2.publish_url(rel, external_url)

        krm.reconcile(current_ingresses)

    def _generate_external_url(self, prefix: str) -> str:
        """Generate external URL for the ingress."""
        return f"http://{self.external_host}{prefix}"

    @property
    def external_host(self) -> str:
        """The external address for the ingress gateway.

        If the gateway isn't available or doesn't have a load balancer address yet, it will
        raise an exception.

        To prevent that from happening, ensure this is only accessed behind an is_ready guard.
        """
        host = self._external_host
        if host is None or not isinstance(host, str):
            raise ExternalHostNotReadyError()
        return host

    @property
    def _external_host(self) -> Optional[str]:
        """Determine the external address for the ingress gateway.

        It will prefer the `external-hostname` config if that is set, otherwise
        it will look up the load balancer address for the ingress gateway.

        If the gateway isn't available or doesn't have a load balancer address yet,
        returns None. Only use this directly when external_host is allowed to be None.
        """
        return _get_loadbalancer_status(namespace=self.model.name, service_name=self.managed_name)

    @staticmethod
    def _generate_prefix(data: Dict[str, Any]) -> str:
        """Generate prefix for the ingress configuration."""
        name = data["name"].replace("/", "-")
        return f"/{data['model']}-{name}"


@functools.lru_cache
def _get_loadbalancer_status(namespace: str, service_name: str) -> Optional[str]:
    client = Client()
    try:
        service = client.get(Service, name=service_name, namespace=namespace)
    except ApiError:
        return None

    if not (status := service.status):
        return None
    if not (load_balancer_status := status.loadBalancer):
        return None
    if not (ingress_addresses := load_balancer_status.ingress):
        return None
    if not (ingress_address := ingress_addresses[0]):
        return None

    return ingress_address.hostname or ingress_address.ip


if __name__ == "__main__":
    main(IstioIngressCharm)
