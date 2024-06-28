#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import functools
import logging
import time
from typing import Any, Dict, Optional, Union

from charms.traefik_k8s.v1.ingress import IngressPerAppProvider as IPAv1
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2
from httpx import HTTPStatusError
from jinja2 import Environment, FileSystemLoader
from lightkube.codecs import load_all_yaml
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError, LoadResourceError
from lightkube.generic_resource import load_in_cluster_generic_resources
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Service
from ops import Relation, RelationBrokenEvent
from ops.charm import (
    CharmBase,
    RelationEvent,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
)

logger = logging.getLogger(__name__)


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
        self.ingress_per_appv1 = IPAv1(charm=self)
        self.ingress_per_appv2 = IPAv2(charm=self)
        self.lk_client = Client(namespace=self.model.name, field_manager="lightkube")
        load_in_cluster_generic_resources(self.lk_client)

        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.remove, self._on_remove)
        # observe data_provided and data_removed events for all types of ingress we offer:
        for ingress in (self.ingress_per_appv1, self.ingress_per_appv2):
            self.framework.observe(ingress.on.data_provided, self._handle_ingress_data_provided)  # type: ignore
            self.framework.observe(ingress.on.data_removed, self._handle_ingress_data_removed)  # type: ignore

    def _load_template(self, template_name: str, **kwargs) -> str:
        """Load and render a template file."""
        env = Environment(loader=FileSystemLoader("src/templates"))
        template = env.get_template(template_name)
        return template.render(**kwargs)

    def _apply_resources(self, yaml_content: str) -> bool:
        """Apply the resources from the given YAML content."""
        try:
            for resource in load_all_yaml(yaml_content):
                self.lk_client.apply(resource)
            return True
        except LoadResourceError as e:
            logger.error(f"Error loading resources from YAML: {e}")
            return False

    def _delete_resources(self, yaml_content: str):
        """Delete the resources from the given YAML content."""
        for resource in load_all_yaml(yaml_content):
            try:
                self.lk_client.delete(
                    type(resource), resource.metadata.name, namespace=resource.metadata.namespace
                )
            except HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.info(f"Resource {resource.metadata.name} not found, skipping deletion.")
                else:
                    logger.error(f"HTTP error deleting resource {resource.metadata.name}: {e}")
                    logger.error(
                        f"You'll probably have to delete stuff manually in the {self.model.name} namespace"
                    )

    def _on_remove(self, _):
        """Event handler for remove."""
        self.unit.status = MaintenanceStatus("Removing istio-ingress Gateway")

        # Load and delete the Gateway YAML from a template file
        gateway_yaml = self._load_template(
            "gateway.yaml", app_name=self.app.name, model_name=self.model.name
        )
        self._delete_resources(gateway_yaml)

    def _on_start(self, _):
        """Event handler for start."""
        self.unit.status = MaintenanceStatus("Setting up istio-ingress Gateway")

        # Load and apply the Gateway YAML from a template file
        gateway_yaml = self._load_template(
            "gateway.yaml", app_name=self.app.name, model_name=self.model.name
        )
        # Apply the resources from the loaded YAML content
        if not self._apply_resources(gateway_yaml):
            # Set the charm state to blocked if applying resources failed
            self.unit.status = BlockedStatus(
                "Istio isn't properly installed or resources failed to apply"
            )
            return

        # Wait for the deployment and LoadBalancer
        self._wait_for_deployment_and_lb()

    def _wait_for_deployment_and_lb(self):
        """Wait for the deployment to be ready and a LoadBalancer to be created."""
        deployment_ready = False
        lb_ready = False

        while not (deployment_ready and lb_ready):
            time.sleep(10)  # Wait a bit before checking again

            # Check if the deployment is ready
            try:
                deployment = self.lk_client.get(
                    Deployment, name=f"{self.app.name}-istio", namespace=self.model.name
                )
                if deployment.status.readyReplicas == deployment.status.replicas:
                    deployment_ready = True
            except Exception as e:
                # Handle case where deployment might not yet exist
                logger.error(f"Error checking deployment status: {e}")

            # Check if the LoadBalancer is created
            try:
                lb_service = self.lk_client.get(
                    Service, name=f"{self.app.name}-istio", namespace=self.model.name
                )
                if lb_service.spec.type == "LoadBalancer":
                    lb_ready = True
            except Exception as e:
                # Handle case where services might not yet exist
                logger.error(f"Error checking Service status: {e}")

        # Set status to Active
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _handle_ingress_data_provided(self, event: RelationEvent):
        """Handle a unit providing data requesting IPU."""
        self.unit.status = MaintenanceStatus("Setting up an ingress")
        self._process_ingress_relation(event.relation)
        self.unit.status = ActiveStatus(f"Serving at {self._external_host}")

    def _handle_ingress_data_removed(self, event: RelationEvent):
        """Handle a unit removing the data needed to provide ingress."""
        self._wipe(event.relation, wipe_rel_data=not isinstance(event, RelationBrokenEvent))
        self.unit.status = BlockedStatus("Not yet implemented")

    def _process_ingress_relation(self, relation: Relation):

        provider = self._provider_from_relation(relation)
        if not provider.is_ready(relation):
            logger.debug(f"Provider {provider} not ready; resetting ingress configurations.")
            self._wipe(relation)
            raise IngressSetupError(f"provider is not ready: ingress for {relation} wiped.")
        rel = f"{relation.name}:{relation.id}"
        self.unit.status = MaintenanceStatus(f"updating ingress configuration for '{rel}'")
        logger.debug("Updating ingress for relation '%s'", rel)
        self._provide_ingress(relation, provider)  # type: ignore

    def _provider_from_relation(self, relation: Relation):
        """Return the correct IngressProvider based on a relation."""
        # first try to tell if remote is speaking v2
        if self.ingress_per_appv2.is_ready(relation):
            return self.ingress_per_appv2
        # if not: are we speaking v1?
        if self.ingress_per_appv1.is_ready(relation):
            # todo: only warn once per relation
            logger.warning(
                f"{relation} is using a deprecated ingress v1 protocol to talk to Istio Ingress. "
                f"Please inform the maintainers of "
                f"{getattr(relation.app, 'name', '<unknown remote>')!r} that they "
                f"should bump to v2."
            )
        # if neither ingress v1 nor v2 are ready, the relation is simply still empty and we
        # don't know yet what protocol we're speaking
        return self.ingress_per_appv1

    def _provide_ingress(
        self,
        relation: Relation,
        provider: Union[IPAv1, IPAv2],
    ):
        # to avoid long-gone units from lingering in the databag, we wipe it
        if self.unit.is_leader():
            provider.wipe_ingress_data(relation)

        # generate configs based on ingress type
        # this will also populate our databags with the urls
        if provider is self.ingress_per_appv2:
            config_getter = self._get_configs_per_app
        elif provider is self.ingress_per_appv1:
            logger.warning(
                "providing ingress over ingress v1: " "handling it as ingress per leader (legacy)"
            )
            config_getter = self._get_configs_per_leader
        else:
            raise ValueError(f"unknown provider: {provider}")

        config = config_getter(relation)
        self._push_configurations(relation, config)

    def _get_configs_per_leader(self, relation: Relation) -> Dict[str, Any]:
        """Generate ingress per leader config."""
        # this happens to be the same behaviour as ingress v1 (legacy) provided.
        ipa = self.ingress_per_appv1

        try:
            data = ipa.get_data(relation)
        except DataValidationError as e:
            logger.error(f"invalid data shared through {relation}... Error: {e}.")
            return {}

        prefix = self._get_prefix(data)  # type: ignore

        # Collecting all variables into a dictionary
        config = {
            "app_name": data["name"],
            "model_name": data["model"],
            "gateway_name": self.app.name,
            "gateway_model_name": self.model.name,
            "prefix": prefix,
            "strip_prefix": data.get("strip-prefix", False),
            "requester_svc": data["name"],
            "requester_port": data["port"],
        }
        if self.unit.is_leader():
            ipa.publish_url(relation, self._get_external_url(prefix))

        return config

    def _get_configs_per_app(self, relation: Relation) -> Dict[str, Any]:
        ipa = self.ingress_per_appv2
        if not relation.app:
            logger.error(f"no app on relation {relation}")
            return {}

        try:
            data = ipa.get_data(relation)
        except DataValidationError as e:
            logger.error(f"invalid data shared through {relation}... Error: {e}.")
            return {}

        prefix = self._get_prefix(data.app.dict(by_alias=True))

        # Collecting all variables into a dictionary
        config = {
            "app_name": data.app.name,
            "model_name": data.app.model,
            "gateway_name": self.app.name,
            "gateway_model_name": self.model.name,
            "prefix": prefix,
            "strip_prefix": data.app.strip_prefix,
            "requester_svc": data.app.name,
            "requester_port": data.app.port,
        }

        if self.unit.is_leader():
            external_url = self._get_external_url(prefix)
            logger.debug(f"publishing external url for {relation.app.name}: {external_url}")

            ipa.publish_url(relation, external_url)

        return config

    def _get_external_url(self, prefix):
        url = f"http://{self.external_host}{prefix}"
        return url

    def _push_configurations(self, relation: Relation, config: Dict[str, Any]):
        # Validate that requester_svc contains hosts
        if not config["requester_svc"]:
            self._wipe(relation)
            return
        httproute_yaml = self._load_template("httproute.yaml", **config)
        # Apply the resources from the loaded YAML content
        if not self._apply_resources(httproute_yaml):
            # Set the charm state to blocked if applying resources failed
            self.unit.status = BlockedStatus(
                "Istio isn't properly installed or resources failed to apply"
            )
            return

    def _wipe(self, relation: Relation, *, wipe_rel_data=True):
        logger.debug(f"Wiping ingress for the '{relation.name}:{relation.id}' relation")

        provider = self._provider_from_relation(relation)

        if provider is self.ingress_per_appv2:
            config_getter = self._get_configs_per_app
        elif provider is self.ingress_per_appv1:
            logger.warning(
                "providing ingress over ingress v1: " "handling it as ingress per leader (legacy)"
            )
            config_getter = self._get_configs_per_leader
        else:
            raise ValueError(f"unknown provider: {provider}")

        config = config_getter(relation)

        # Load and delete the HTTPRoute YAML from a template file
        # Load and delete the HTTPRoute YAML from a template file
        httproute_yaml = self._load_template("httproute.yaml", **config)
        self._delete_resources(httproute_yaml)

        # Wipe URLs sent to the requesting apps and units, as they are based on a gateway
        # address that is no longer valid.
        # Skip this for traefik-route because it doesn't have a `wipe_ingress_data` method.
        if wipe_rel_data and self.unit.is_leader():
            provider.wipe_ingress_data(relation)  # type: ignore  # this is an ingress-type relation

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
    def _get_prefix(data: Dict[str, Any]):
        name = data["name"].replace("/", "-")
        return f"/{data['model']}-{name}"


@functools.lru_cache
def _get_loadbalancer_status(namespace: str, service_name: str) -> Optional[str]:
    client = Client()  # type: ignore
    try:
        traefik_service = client.get(Service, name=service_name, namespace=namespace)
    except ApiError:
        return None

    if not (status := traefik_service.status):  # type: ignore
        return None
    if not (load_balancer_status := status.loadBalancer):
        return None
    if not (ingress_addresses := load_balancer_status.ingress):
        return None
    if not (ingress_address := ingress_addresses[0]):
        return None

    # `return ingress_address.hostname` removed since the hostname (external hostname)
    # is configured through juju config so it is not necessary to retrieve that from K8s.
    return ingress_address.ip


if __name__ == "__main__":
    main(IstioIngressCharm)  # type: ignore
