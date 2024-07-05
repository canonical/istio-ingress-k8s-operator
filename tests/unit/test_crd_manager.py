import unittest
from unittest.mock import MagicMock, patch

from httpx import HTTPStatusError
from lightkube.models.meta_v1 import ObjectMeta
from lightkube_helpers import KubernetesCRDManager


class TestKubernetesCRDManager(unittest.TestCase):

    @patch("lightkube_helpers.Client")
    def setUp(self, MockClient):
        self.mock_client = MockClient.return_value
        self.manager = KubernetesCRDManager()

    def test_get_resource_success(self):
        expected_resource = MagicMock()
        self.mock_client.get.return_value = expected_resource

        resource_type = "gateway"
        name = "test-gateway"
        namespace = "test-namespace"

        result = self.manager.get_resource(resource_type, name, namespace)

        self.assertEqual(result, expected_resource)
        self.mock_client.get.assert_called_once_with(
            self.manager.resources[resource_type], name=name, namespace=namespace
        )

    def test_get_resource_not_found(self):
        self.mock_client.get.side_effect = HTTPStatusError(
            response=MagicMock(status_code=404), message=None, request=None
        )

        resource_type = "gateway"
        name = "nonexistent-gateway"
        namespace = "test-namespace"

        result = self.manager.get_resource(resource_type, name, namespace)

        self.assertIsNone(result)
        self.mock_client.get.assert_called_once_with(
            self.manager.resources[resource_type], name=name, namespace=namespace
        )

    def test_delete_resource_success(self):
        resource_type = "gateway"
        name = "test-gateway"
        namespace = "test-namespace"

        self.manager.delete_resource(resource_type, name, namespace)

        self.mock_client.delete.assert_called_once_with(
            self.manager.resources[resource_type], name=name, namespace=namespace
        )

    def test_create_resource_success(self):
        resource_type = "gateway"
        meta_dict = {"name": "test-gateway", "namespace": "test-namespace"}
        spec_dict = {"spec_key": "spec_value"}

        self.manager.create_resource(resource_type, meta_dict, spec_dict)

        # Assert that apply was called with any instance of the expected resource type
        self.mock_client.apply.assert_called_once_with(
            self.manager.resources[resource_type](
                metadata=ObjectMeta.from_dict(meta_dict), spec=spec_dict
            )
        )

    def test_get_resource_by_labels(self):
        resource_type = "gateway"
        label_selector = {"app": "example-app"}

        expected_namespaces = [
            MagicMock(metadata=MagicMock(name="namespace1")),
            MagicMock(metadata=MagicMock(name="namespace2")),
        ]
        self.mock_client.list.return_value = expected_namespaces

        expected_resources = [
            MagicMock(metadata=MagicMock(name="resource1", namespace="namespace1")),
            MagicMock(metadata=MagicMock(name="resource2", namespace="namespace2")),
        ]
        self.mock_client.list.side_effect = [
            expected_resources[:1],  # First call returns resources for namespace1
            expected_resources[1:],  # Second call returns resources for namespace2
        ]

        result = self.manager.get_resource_by_labels(resource_type, label_selector)

        expected_result = [
            {"name": "resource1", "namespace": "namespace1", "resource_type": resource_type},
            {"name": "resource2", "namespace": "namespace2", "resource_type": resource_type},
        ]
        self.assertEqual(result, expected_result)

    def test_find_resources_to_delete(self):
        incoming_resources = [
            {
                "name": "existing-resource1",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
            {
                "name": "incoming-resource2",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
        ]
        owner_label = {"app": "example-app"}
        resource_type = "gateway"

        existing_resources = [
            {
                "name": "existing-resource1",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
            {
                "name": "existing-resource2",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
            {
                "name": "existing-resource3",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
        ]
        to_delete = [
            {
                "name": "existing-resource2",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
            {
                "name": "existing-resource3",
                "namespace": "test-namespace",
                "resource_type": "gateway",
            },
        ]
        self.manager.get_resource_by_labels = MagicMock(return_value=existing_resources)

        result = self.manager.find_resources_to_delete(
            incoming_resources, owner_label, resource_type
        )

        self.assertEqual(result, to_delete)
