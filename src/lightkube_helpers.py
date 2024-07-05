#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""A helper module that extends lightkube functionality in managing k8s CRDs."""


import logging
from typing import Any, Dict, List, Optional

from httpx import HTTPStatusError
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import GenericNamespacedResource, create_namespaced_resource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Namespace

logger = logging.getLogger(__name__)


class KubernetesCRDManager:
    """CRDs Manager."""

    def __init__(self):
        self.client = Client(field_manager="lightkube")

        # Initialize resources
        self.resources = {
            "gateway": create_namespaced_resource(
                "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
            ),
            "gateway_class": create_namespaced_resource(
                "gateway.networking.k8s.io", "v1", "GatewayClass", "gatewayclasses"
            ),
            "grpc_route": create_namespaced_resource(
                "gateway.networking.k8s.io", "v1", "GRPCRoute", "grpcroutes"
            ),
            "reference_grant": create_namespaced_resource(
                "gateway.networking.k8s.io", "v1", "ReferenceGrant", "referencegrants"
            ),
            "http_route": create_namespaced_resource(
                "gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes"
            ),
        }

    def get_resource(
        self, resource_type: str, name: str, namespace: str
    ) -> Optional[GenericNamespacedResource]:
        """Return the specified resource by type and name in the given namespace.

        Args:
            resource_type (str): The type of the resource to retrieve.
            name (str): The name of the resource to retrieve.
            namespace (str): The namespace of the resource to retrieve.

        Returns:
            Optional[GenericNamespacedResource]: The retrieved resource if found, None if not found or an error occurred.
        """
        if resource_type in self.resources:
            try:
                resource = self.client.get(
                    self.resources[resource_type], name=name, namespace=namespace
                )
                return resource
            except HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.info(f"Resource {name} not found")
                else:
                    logger.error(f"HTTP error getting resource {name}: {e}")
        else:
            logger.error(f"Unsupported resource type: {resource_type}")

    def delete_resource(self, resource_type: str, name: str, namespace: str) -> None:
        """Delete the specified resource by type and name in the given namespace.

        Args:
            resource_type (str): The type of the resource to delete.
            name (str): The name of the resource to delete.
            namespace (str): The namespace of the resource to delete.
        """
        if resource_type in self.resources:
            try:
                self.client.delete(self.resources[resource_type], name=name, namespace=namespace)
            except HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.info(f"Resource {name} not found, skipping deletion.")
                else:
                    logger.error(f"HTTP error deleting resource {name}: {e}")
                    logger.error(
                        f"You'll probably have to delete resources manually in the {namespace} namespace"
                    )
        else:
            logger.error(f"Unsupported resource type: {resource_type}")

    def create_resource(
        self, resource_type: str, meta_dict: Dict[str, Any], spec_dict: Dict[str, Any]
    ) -> None:
        """Create a resource of the specified type in the given namespace.

        Args:
            resource_type (str): The type of the resource to create.
            meta_dict (Dict[str, Any]): Metadata for the resource.
            spec_dict (Dict[str, Any]): Specification for the resource.

        Returns:
            None
        """
        if resource_type in self.resources:
            resource_definition = self.resources[resource_type]
            resource = resource_definition(
                metadata=ObjectMeta.from_dict(meta_dict), spec=spec_dict
            )
            try:
                self.client.apply(resource)
            except ApiError:
                logger.error(f"Failed to create resource {resource_type}")
        else:
            logger.error(f"Unsupported resource type: {resource_type}")

    def get_resource_by_labels(
        self, resource_type: str, label_selector: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Return a list of dictionaries representing resources matching the given label selector.

        Args:
            resource_type (str): The type of the resource to search for.
            label_selector (Dict[str, Any]): Label selector to match against resources.

        Returns:
            List[Dict[str, str]]: A list of dictionaries, each containing 'name', 'namespace', and 'resource_type' of matched resources.
        """
        matched_resources = []

        if resource_type not in self.resources:
            logger.error(f"Unsupported resource type: {resource_type}")
            return matched_resources

        namespaces = self.client.list(Namespace)

        for ns in namespaces:

            if not ns.metadata or not ns.metadata.name:
                logger.warning("Skipping namespace with incomplete metadata.")
                continue

            results = self.client.list(
                self.resources[resource_type], namespace=ns.metadata.name, labels=label_selector
            )

            for matched_resource in results:

                if (
                    not matched_resource.metadata
                    or not matched_resource.metadata.name
                    or not matched_resource.metadata.namespace
                ):
                    logger.warning("Skipping resource with incomplete metadata.")
                    continue

                matched_resource_info = {
                    "name": matched_resource.metadata.name,
                    "namespace": matched_resource.metadata.namespace,
                    "resource_type": resource_type,
                }
                matched_resources.append(matched_resource_info)

        return matched_resources

    def find_resources_to_delete(
        self,
        incoming_resources: List[Dict[str, str]],
        owner_label: Dict[str, Any],
        resource_type: str,
    ) -> List[Dict[str, str]]:
        """Find k8s resources that should be deleted based on the incoming resources list and labels.

        Args:
            incoming_resources (List[Dict[str, str]]): List of incoming resources to compare against.
            owner_label (Dict[str, Any]): Label selector to match against existing resources.
            resource_type (str): Type of the resource to be filtered.

        Returns:
            List[Dict[str, str]]: List of dictionaries representing resources that should be deleted.
        """
        resources_to_delete = []

        if resource_type not in self.resources:
            logger.error(f"Unsupported resource type: {resource_type}")
            return resources_to_delete

        # Get all existing resources that match the owner_label
        existing_resources = self.get_resource_by_labels(resource_type, owner_label)

        # Determine resources to delete
        for existing_resource in existing_resources:
            # Extract specific keys for comparison
            existing_keys = {
                k: existing_resource[k] for k in ["name", "namespace", "resource_type"]
            }

            # Check if existing_keys match any incoming_resource's keys
            if existing_keys not in [
                {k: v for k, v in r.items() if k in existing_keys} for r in incoming_resources
            ]:
                resources_to_delete.append(existing_resource)

        return resources_to_delete
