#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import functools
import logging
import time
from typing import Any, Dict, Optional

from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Service
from lightkube_helpers import KubernetesCRDManager
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

GATEWAY_RESOURCE = "gateway"
HTTPROUTE_RESOURCE = "http_route"


class IngressSetupError(Exception):
    """Error setting up ingress for some requirer."""


class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class ExternalHostNotReadyError(Exception):
    """Raised when the ingress hostname is not ready but is assumed to be."""


class IstioIngressCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)

        self.owner_labels = {"owner": f"{self.model.name}-{self.app.name}"}
        self.managed_name = f"{self.app.name}-istio"

        self.ingress_per_appv2 = IPAv2(charm=self)
        self.crd_manager = KubernetesCRDManager()

        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(
            self.ingress_per_appv2.on.data_provided, self._on_ingress_data_provided
        )
        self.framework.observe(
            self.ingress_per_appv2.on.data_removed, self._on_ingress_data_removed
        )

    def _on_start(self, _):
        """Event handler for start."""
        self.unit.status = MaintenanceStatus("Setting up global istio-ingress gateway")
        global_gateway = GatewayResource(
            metadata=Metadata(
                name=self.app.name, namespace=self.model.name, labels=self.owner_labels
            ),
            spec=GatewaySpec(),
        )

        self.crd_manager.create_resource(
            resource_type=GATEWAY_RESOURCE,
            meta_dict=global_gateway.metadata.dict(),
            spec_dict=global_gateway.spec.dict(),
        )

        self.unit.status = MaintenanceStatus("Validating gateway readiness")

        if not self._is_deployment_ready():
            self.unit.status = BlockedStatus(
                "Gateway k8s deployment not ready, is istio properly installed?"
            )

        if not self._is_load_balancer_ready():
            self.unit.status = BlockedStatus(
                "Gateway load balancer is unable to obtain an IP or hostname from the cluster."
            )

        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _on_remove(self, _):
        """Event handler for remove."""
        # Removing tailing ingresses
        tailing_routes = self.crd_manager.get_resource_by_labels(
            resource_type=HTTPROUTE_RESOURCE, label_selector=self.owner_labels
        )
        for route in tailing_routes:
            self.crd_manager.delete_resource(
                name=route["name"],
                namespace=route["namespace"],
                resource_type=route["resource_type"],
            )

        # Removing tailing global gateway
        self.crd_manager.delete_resource(
            resource_type=GATEWAY_RESOURCE, name=self.app.name, namespace=self.model.name
        )

    def _is_deployment_ready(self) -> bool:
        """Check if the deployment is ready after 10 attempts."""
        attempts = 10

        for _ in range(attempts):
            time.sleep(10)

            try:
                deployment = self.crd_manager.client.get(
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

    def _on_ingress_data_provided(self, _):
        """Handle a unit providing data requesting IPU."""
        self._sync_ingress_resources()
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _on_ingress_data_removed(self, _):
        """Handle a unit removing the data needed to provide ingress."""
        self._sync_ingress_resources()
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _sync_ingress_resources(self):
        current_ingresses = []

        for rel in self.model.relations["ingress"]:

            if not self.ingress_per_appv2.is_ready(rel):
                logger.debug(f"Provider {rel} not ready; resetting ingress configurations.")
                self.ingress_per_appv2.wipe_ingress_data(rel)
                continue

            if not rel.app:
                logger.error(f"No app on relation {rel}, Skipping ingress configuration.")
                continue

            try:
                data = self.ingress_per_appv2.get_data(rel)
            except DataValidationError as e:
                logger.error(
                    f"Data validation error for relation {rel}: {e}. Skipping ingress configuration."
                )
                continue

            prefix = self._generate_prefix(data.app.dict(by_alias=True))

            ingress_data = {
                "name": data.app.name,
                "namespace": data.app.model,
                "resource_type": HTTPROUTE_RESOURCE,
                "gateway_name": self.app.name,
                "gateway_model_name": self.model.name,
                "prefix": prefix,
                "strip_prefix": data.app.strip_prefix,
                "backend_svc": data.app.name,
                "backend_port": data.app.port,
            }
            if rel.active:
                current_ingresses.append((rel, ingress_data))

        routes_to_delete = self.crd_manager.find_resources_to_delete(
            incoming_resources=[ingress_data for _, ingress_data in current_ingresses],
            owner_label=self.owner_labels,
            resource_type=HTTPROUTE_RESOURCE,
        )

        for route in routes_to_delete:
            self.crd_manager.delete_resource(
                name=route["name"],
                namespace=route["namespace"],
                resource_type=route["resource_type"],
            )
        for rel, ingress_data in current_ingresses:
            self._create_ingress(rel, ingress_data)

    def _create_ingress(self, rel, ingress_data):
        http_resource = HTTPRouteResource(
            metadata=Metadata(
                name=ingress_data["name"],
                namespace=ingress_data["namespace"],
                labels=self.owner_labels,
            ),
            spec=HTTPRouteResourceSpec(
                parentRefs=[
                    ParentRef(
                        name=ingress_data["gateway_name"],
                        namespace=ingress_data["gateway_model_name"],
                    )
                ],
                rules=[
                    Rule(
                        matches=[Match(path=PathMatch(value=ingress_data["prefix"]))],
                        backendRefs=[
                            BackendRef(
                                name=ingress_data["backend_svc"],
                                port=ingress_data["backend_port"],
                                namespace=ingress_data["namespace"],
                            )
                        ],
                        filters=([URLRewriteFilter()] if ingress_data["strip_prefix"] else None),
                    )
                ],
            ),
        )

        self.crd_manager.create_resource(
            resource_type=HTTPROUTE_RESOURCE,
            meta_dict=http_resource.metadata.dict(),
            spec_dict=http_resource.spec.dict(),
        )
        # Publish external URL if this unit is the leader
        if self.unit.is_leader():
            self.ingress_per_appv2.wipe_ingress_data(rel)
            external_url = self._generate_external_url(ingress_data["prefix"])
            logger.debug(f"Publishing external URL for {rel.app.name}: {external_url}")
            self.ingress_per_appv2.publish_url(rel, external_url)

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
