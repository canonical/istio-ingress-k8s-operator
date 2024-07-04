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
from ops.charm import (
    CharmBase,
    RelationEvent,
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
        self.ingress_per_appv2 = IPAv2(charm=self)
        self.crd_manager = KubernetesCRDManager()
        self.owner_labels = {"owner": f"{self.model.name}-{self.app.name}"}
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(
            self.ingress_per_appv2.on.data_provided, self._on_ingress_data_provided
        )
        self.framework.observe(
            self.ingress_per_appv2.on.data_removed, self._on_ingress_data_removed
        )

    def _on_remove(self, _):
        """Event handler for remove."""
        self.unit.status = MaintenanceStatus("Removing istio-ingress Gateway")
        self.crd_manager.delete_resource(
            resource_type=GATEWAY_RESOURCE, name=self.app.name, namespace=self.model.name
        )

    def _on_start(self, _):
        """Event handler for start."""
        self.unit.status = MaintenanceStatus("Setting up istio-ingress Gateway")

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

        # Wait for the deployment and LoadBalancer
        self._wait_for_deployment_and_lb()
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _wait_for_deployment_and_lb(self):
        """Wait for the deployment to be ready and a LoadBalancer to be created."""
        deployment_ready = False
        lb_ready = False

        while not (deployment_ready and lb_ready):
            time.sleep(10)  # Wait a bit before checking again

            # Check if the deployment is ready
            try:
                deployment = self.crd_manager.client.get(
                    Deployment, name=f"{self.app.name}-istio", namespace=self.model.name
                )
                if deployment.status.readyReplicas == deployment.status.replicas:
                    deployment_ready = True
            except Exception as e:
                logger.error(f"Error checking deployment status: {e}")

            # Check if the LoadBalancer is created
            try:
                lb_service = self.crd_manager.client.get(
                    Service, name=f"{self.app.name}-istio", namespace=self.model.name
                )
                if lb_service.spec.type == "LoadBalancer":
                    lb_ready = True
            except Exception as e:
                logger.error(f"Error checking Service status: {e}")

    def _on_ingress_data_provided(self, event: RelationEvent):
        """Handle a unit providing data requesting IPU."""
        self.unit.status = MaintenanceStatus("Setting up an ingress")
        self._sync_ingress_resources(event.relation)
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _on_ingress_data_removed(self, event: RelationEvent):
        """Handle a unit removing the data needed to provide ingress."""
        self.unit.status = MaintenanceStatus("Setting up an ingress")
        self._sync_ingress_resources(event.relation)
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _sync_ingress_resources(self, event: RelationEvent):
        current_ingresses = []

        for rel in self.model.relations["ingress"]:

            if not self.ingress_per_appv2.is_ready(rel):
                logger.debug(f"Provider {rel} not ready; resetting ingress configurations.")
                self.ingress_per_appv2.wipe_ingress_data(rel)
                continue
                # raise IngressSetupError(
                #     f"Provider is not ready or using unknown version: ingress for {rel} wiped."
                # )

            if not rel.app:
                logger.error(f"No app on relation {rel}")
                continue

            try:
                data = self.ingress_per_appv2.get_data(rel)
            except DataValidationError as e:
                logger.error(f"Invalid data shared through {rel}... Error: {e}.")
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
            current_ingresses.append((rel, ingress_data))
            if self.unit.is_leader():
                external_url = self._generate_external_url(prefix)
                logger.debug(f"Publishing external URL for {rel.app.name}: {external_url}")
                self.ingress_per_appv2.publish_url(rel, external_url)

        routes_to_delete = self.crd_manager.find_resources_to_delete(
            incoming_resources=[ingress_data for _, ingress_data in current_ingresses],
            owner_label=self.owner_labels,
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
        return _get_loadbalancer_status(
            namespace=self.model.name, service_name=f"{self.app.name}-istio"
        )

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

    return ingress_address.ip


if __name__ == "__main__":
    main(IstioIngressCharm)
