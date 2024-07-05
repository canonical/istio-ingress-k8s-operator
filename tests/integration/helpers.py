import asyncio
import logging
from typing import Optional

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
