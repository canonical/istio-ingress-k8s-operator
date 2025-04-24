# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import pytest
import yaml
from helpers import get_hpa
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


@dataclass
class CharmDeploymentConfiguration:
    entity_url: str  # aka charm name or local path to charm
    application_name: str
    channel: str
    trust: bool
    config: Optional[dict] = None


ISTIO_K8S = CharmDeploymentConfiguration(
    entity_url="istio-k8s", application_name="istio-k8s", channel="latest/edge", trust=True
)


@pytest.mark.abort_on_fail
async def test_deploy_dependencies(ops_test: OpsTest):
    """Deploy istio as a dependency."""
    # Deploy Istio-k8s
    await ops_test.model.deploy(**asdict(ISTIO_K8S))
    await ops_test.model.wait_for_idle(
        [
            ISTIO_K8S.application_name,
        ],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_deployment(ops_test: OpsTest, istio_ingress_charm):
    await ops_test.model.deploy(
        istio_ingress_charm, resources=resources, application_name=APP_NAME, trust=True
    ),
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
@pytest.mark.parametrize(
    "n_units",
    (
        # Scale up from 1 to 3
        3,
        # Scale down to 2
        2,
    ),
)
async def test_gateway_scaling(ops_test: OpsTest, n_units):
    """Tests that, when the application is scaled, the HPA managing replicas on the Gateway is scaled too.

    Note: This test is stateful and will leave the deployment at a scale of 2.
    """
    await ops_test.model.applications[APP_NAME].scale(n_units)
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)

    hpa = await get_hpa(ops_test.model.name, APP_NAME)

    assert hpa is not None
    assert hpa.spec.minReplicas == n_units
    assert hpa.spec.maxReplicas == n_units

    assert await wait_for_hpa_current_replicas(
        ops_test.model.name, APP_NAME, n_units
    ), f"Expected currentReplicas to be {n_units}, got {hpa.status.currentReplicas}"


async def wait_for_hpa_current_replicas(
    namespace, hpa_name, expected_replicas, retries=10, delay=10
):
    for _ in range(retries):
        hpa = await get_hpa(namespace, hpa_name)
        if hpa.status.currentReplicas == expected_replicas:
            return True
        await asyncio.sleep(delay)
    return False
