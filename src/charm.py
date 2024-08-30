#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import logging
import re
import time
from typing import Any, Dict, Optional, cast

from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2
from charms.traefik_k8s.v2.ingress import IngressRequirerData
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Service
from lightkube.types import PatchType
from lightkube_extensions.batch import KubernetesResourceManager, create_charm_default_labels
from ops import BlockedStatus
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

# from lightkube.models.meta_v1 import Patch
from models import (
    AllowedRoutes,
    BackendRef,
    HTTPRouteResource,
    HTTPRouteResourceSpec,
    IstioGatewayResource,
    IstioGatewaySpec,
    Listener,
    Match,
    Metadata,
    ParentRef,
    PathMatch,
    Rule,
    URLRewriteFilter,
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


GATEWAY_RESOURCE_TYPES = {RESOURCE_TYPES["Gateway"]}
INGRESS_RESOURCE_TYPES = {
    RESOURCE_TYPES["GRPCRoute"],
    RESOURCE_TYPES["ReferenceGrant"],
    RESOURCE_TYPES["HTTPRoute"],
}
GATEWAY_LABEL = "istio-gateway"
INGRESS_LABEL = "istio-ingress"


class DataValidationError(RuntimeError):
    """Raised when data validation fails on IPU relation data."""


class IstioIngressCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)

        self.managed_name = f"{self.app.name}-istio"
        self._lightkube_field_manager: str = self.app.name
        self._lightkube_client = None

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
        if self._lightkube_client is None:
            self._lightkube_client = Client(
                namespace=self.model.name, field_manager=self._lightkube_field_manager
            )
        return self._lightkube_client

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

    def _on_config_changed(self, _):
        """Event handler for config changed."""
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

    def _construct_gateway(self):
        gateway = IstioGatewayResource(
            metadata=Metadata(
                name=self.app.name,
                namespace=self.model.name,
            ),
            spec=IstioGatewaySpec(
                gatewayClassName="istio",
                listeners=[
                    Listener(
                        name="default",
                        port=80,
                        protocol="HTTP",
                        allowedRoutes=AllowedRoutes(namespaces={"from": "All"}),
                        **(
                            {"hostname": self._external_host}
                            if self._is_valid_hostname(self._external_host)
                            else {}
                        ),
                    )
                ],
            ),
        )
        gateway_resource = RESOURCE_TYPES["Gateway"]
        return gateway_resource(
            metadata=ObjectMeta.from_dict(gateway.metadata.model_dump()),
            spec=gateway.spec.model_dump(exclude_none=True),
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
                # TODO: uncomment the below when support is added for both wildcards and using subdomains
                # hostnames=[udata.host for udata in data.units],
            ),
        )
        http_resource = RESOURCE_TYPES["HTTPRoute"]
        return http_resource(
            metadata=ObjectMeta.from_dict(http_route.metadata.model_dump()),
            spec=http_route.spec.model_dump(),
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
                self.unit.status = ActiveStatus(f"Serving at {self._external_host}")
            except DataValidationError or ApiError:
                self.unit.status = BlockedStatus("Issue with setting up an ingress")

    def _sync_gateway_resources(self):
        resources_list = []
        krm = self._get_gateway_resource_manager()

        resource_to_append = self._construct_gateway()
        resources_list.append(resource_to_append)
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
        for rel in self.model.relations["ingress"]:

            if not self.ingress_per_appv2.is_ready(rel):
                self.ingress_per_appv2.wipe_ingress_data(rel)
                continue

            data = self.ingress_per_appv2.get_data(rel)
            prefix = self._generate_prefix(data.app.model_dump(by_alias=True))
            resource_to_append = self._construct_httproute(data, prefix)

            if rel.active:
                current_ingresses.append(resource_to_append)
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
        """Determine the external address for the ingress gateway.

        It will prefer the `external-hostname` config if that is set, otherwise
        it will look up the load balancer address for the ingress gateway.

        If the gateway isn't available or doesn't have a load balancer address yet,
        returns None. Only use this directly when external_host is allowed to be None.
        """
        if external_hostname := self.model.config.get("external_hostname"):
            hostname = cast(str, external_hostname)
            if self._is_valid_hostname(hostname):
                return hostname
            logger.error("Invalid hostname provided, Please ensure this adheres to RFC 1123")
            return None

        return self._get_lb_external_address

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


if __name__ == "__main__":
    main(IstioIngressCharm)
