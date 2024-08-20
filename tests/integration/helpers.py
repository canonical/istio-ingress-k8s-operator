import asyncio
import json
import logging
from typing import Any, Dict, Optional

import sh
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


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
        result = sh.kubectl(
            *f"-n {model.name} get service/{service_name} -o=jsonpath='{{.status.loadBalancer.ingress[0].ip}}'".split()
        )
        ip_address = result.strip("'")
        return ip_address
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
        result = sh.kubectl(
            *f"-n {model.name} get gateway/{gateway_name} -o=jsonpath='{{.status.listeners[0]}}'".split()
        )
        if result:
            listener_status = json.loads(result[1:-1])
            return listener_status
        return None

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
        result = sh.kubectl(
            *f"-n {model.name} get gateway/{gateway_name} -o=jsonpath='{{.spec.listeners[0]}}'".split()
        )
        if result:
            listener_spec = json.loads(result[1:-1])
            return listener_spec
        return None

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


def get_route_spec(ops_test: OpsTest, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the spec of the HTTPRoute resource.

    Args:
        ops_test: pytest-operator plugin
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the spec of the route, or None if not found.
    """
    model = ops_test.model.info
    try:
        result = sh.kubectl(
            *f"-n {model.name} get httproute/{route_name} -o=jsonpath='{{.spec}}'".split()
        )
        if result:
            route_spec = json.loads(result[1:-1])
            return route_spec
        return None

    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


def get_route_condition(ops_test: OpsTest, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the condition from the HTTPRoute resource.

    Args:
        ops_test: pytest-operator plugin
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the status of the parent gateway the route is attached to, or None if not found.
    """
    model = ops_test.model.info
    try:
        result = sh.kubectl(
            *f"-n {model.name} get httproute/{route_name} -o=jsonpath='{{.status.parents[0]}}'".split()
        )
        if result:
            route_status = json.loads(result[1:-1])
            return route_status
        return None

    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


def dequote(s: str):
    if isinstance(s, str) and s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s


async def remove_application(
    ops_test: OpsTest, name: str, *, timeout: int = 60, force: bool = True
):
    # In CI, tests consistently timeout on `waiting: gateway address unavailable`.
    # Just in case there's an unreleased socket, let's try to remove istio-ingress more gently.

    app = ops_test.model.applications.get(name)
    if not app:
        return

    # Wrapping in `create_task` to be able to timeout with `wait`
    tasks = [asyncio.create_task(app.destroy(destroy_storage=True, force=False, no_wait=False))]
    await asyncio.wait(tasks, timeout=timeout)

    if not force:
        return

    # Now, after the workload has hopefully terminated, force removal of the juju leftovers
    await app.destroy(destroy_storage=True, force=True, no_wait=True)
