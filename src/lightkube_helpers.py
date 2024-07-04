#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Lightkube Wrapper to manage k8s CRDs."""

import logging
from typing import Dict, List

from httpx import HTTPStatusError
from lightkube import Client
from lightkube.generic_resource import create_namespaced_resource
from lightkube.resources.core_v1 import Namespace

logger = logging.getLogger(__name__)


class KubernetesCRDManager:
    """CRDs Wrapper."""

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

    def get_resource(self, resource_type, name, namespace):
        """Return the specified resource by type and name."""
        if resource_type in self.resources:
            resource = self.client.get(
                self.resources[resource_type], name=name, namespace=namespace
            )
            return resource
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")

    def delete_resource(self, resource_type, name, namespace):
        """Delete the specified resource by type and name."""
        if resource_type in self.resources:
            resource = self.resources[resource_type]
            try:
                self.client.delete(resource, name=name, namespace=namespace)
            except HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.info(f"Resource {name} not found, skipping deletion.")
                else:
                    logger.error(f"HTTP error deleting resource {name}: {e}")
                    logger.error(
                        f"You'll probably have to delete resources manually in the {namespace} namespace"
                    )
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")

    def create_resource(self, resource_type, meta_dict, spec_dict):
        """Create a resource of the specified type in the given namespace."""
        if resource_type in self.resources:
            resource_definition = self.resources[resource_type]
            resource = resource_definition(metadata=meta_dict, spec=spec_dict)
            created_resource = self.client.apply(resource)
            return created_resource
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")

    def get_resource_by_labels(
        self, resource_type: str, label_selector: Dict[str, str]
    ) -> List[Dict[str, str]]:
        """Return a list of dictionaries with name and namespace of resources matching the given label selector."""
        matched_resources = []

        if resource_type not in self.resources:
            raise ValueError(f"Unsupported resource type: {resource_type}")

        resource = self.resources[resource_type]
        namespaces = self.client.list(Namespace)

        for ns in namespaces:
            results = self.client.list(resource, namespace=ns.metadata.name, labels=label_selector)

            for matched_resource in results:
                matched_resource_info = {
                    "name": matched_resource.metadata.name,
                    "namespace": matched_resource.metadata.namespace,
                    "resource_type": resource_type,
                }
                matched_resources.append(matched_resource_info)

        return matched_resources

    def find_resources_to_delete(
        self, incoming_resources: List[Dict[str, str]], owner_label: Dict[str, str]
    ):
        """Find resources that should be deleted based on the incoming resources list and owner label.

        Args:
        - incoming_resources (List[Dict[str, str]]): List of incoming resources to compare against.
        - owner_label (Dict[str, str]): Label selector to match against existing resources.

        Returns:
        List of dictionaries representing resources that should be deleted.
        """
        resources_to_delete = []

        # Get all existing resources that match the owner_label
        existing_resources = []
        for item in incoming_resources:
            resource_type = item.get("resource_type")
            existing_resources.extend(self.get_resource_by_labels(resource_type, owner_label))

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
