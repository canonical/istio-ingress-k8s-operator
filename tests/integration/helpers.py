import logging
import subprocess
from typing import Any, Dict, Optional, cast

import lightkube
from lightkube.generic_resource import create_namespaced_resource
from lightkube.resources.core_v1 import Service
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


RESOURCE_TYPES = {
    "Gateway": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    ),
    "HTTPRoute": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes"
    ),
}


async def get_k8s_service_address(ops_test: OpsTest, service_name: str) -> Optional[str]:
    """Get the address of a LoadBalancer Kubernetes service using kubectl.

    Args:
        ops_test: pytest-operator plugin
        service_name: The name of the Kubernetes service

    Returns:
        The LoadBalancer service address as a string, or None if not found
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        svc = c.get(Service, namespace=model.name, name=service_name)
        return svc.status.loadBalancer.ingress[0].ip

    except Exception as e:
        logger.error("Error retrieving service address %s", e, exc_info=1)
        return None


async def get_listener_condition(ops_test: OpsTest, gateway_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the status of the listener from the Gateway resource as a dictionary.

    Args:
        ops_test: pytest-operator plugin
        gateway_name: Name of the Gateway resource.

    Returns:
        A dictionary representing the status of the first listener, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        gateway = c.get(RESOURCE_TYPES["Gateway"], namespace=model.name, name=gateway_name)
        return cast(dict, gateway.status["listeners"][0])

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


async def get_listener_spec(ops_test: OpsTest, gateway_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the spec of the listener from the Gateway resource as a dictionary.

    Args:
        ops_test: pytest-operator plugin
        gateway_name: Name of the Gateway resource.

    Returns:
        A dictionary representing the spec of the first listener, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        gateway = c.get(RESOURCE_TYPES["Gateway"], namespace=model.name, name=gateway_name)
        return gateway.spec["listeners"][0]

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


async def get_route_spec(ops_test: OpsTest, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the spec of the HTTPRoute resource.

    Args:
        ops_test: pytest-operator plugin
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the spec of the route, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        route = c.get(RESOURCE_TYPES["HTTPRoute"], namespace=model.name, name=route_name)
        return route.spec

    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


async def get_route_condition(ops_test: OpsTest, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the condition from the HTTPRoute resource.

    Args:
        ops_test: pytest-operator plugin
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the status of the parent gateway the route is attached to, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        route = c.get(RESOURCE_TYPES["HTTPRoute"], namespace=model.name, name=route_name)
        return cast(dict, route.status["parents"][0])
    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


def dequote(s: str):
    if isinstance(s, str) and s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s


def send_curl_request(url: str, header: str = None) -> bool:
    """Sends a curl request to the specified URL with an optional header.

    Returns True if the request returns a 200 status code, otherwise False.

    :param url: The URL to send the request to.
    :param header: Optional header to include in the request (e.g., "Host: example.com").
    :return: True if the response status is 200, False otherwise.
    """
    try:
        # Construct the curl command
        command = ["curl", "-o", "/dev/null", "-s", "-w", "%{http_code}", url]

        # If a header is provided, add it to the command
        if header:
            command.extend(["-H", header])

        # Run the curl command and capture the output
        result = subprocess.run(command, capture_output=True, text=True)
        status_code = result.stdout.strip()

        # Check if the status code is 200
        return status_code == "200"
    except Exception as e:
        logger.error("Error curling the specified URL: %s", e, exc_info=1)
        return False
