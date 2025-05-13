# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from dataclasses import asdict
from pathlib import Path
from time import sleep

import jubilant
import pytest
import yaml
from helpers import ISTIO_K8S, get_hpa, scale_application

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


@pytest.mark.setup
def test_deploy_dependencies(juju: jubilant.Juju):
    """Deploy istio-k8s as a dependency."""
    juju.deploy(**asdict(ISTIO_K8S))
    juju.wait(lambda status: jubilant.all_active(status, ISTIO_K8S.app), timeout=120)


@pytest.mark.setup
def test_deployment(juju: jubilant.Juju, istio_ingress_charm):
    juju.deploy(istio_ingress_charm, app=APP_NAME, resources=resources, trust=True)
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME), timeout=120)


@pytest.mark.parametrize(
    "n_units",
    (
        # Scale up from 1 to 3
        3,
        # Scale down to 2
        2,
    ),
)
def test_gateway_scaling(juju: jubilant.Juju, n_units):
    """Tests that, when the application is scaled, the HPA managing replicas on the Gateway is scaled too.

    Note: This test is stateful and will leave the deployment at a scale of 2.
    """
    scale_application(juju, APP_NAME, n_units)
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME), timeout=120)

    hpa = get_hpa(juju.model, APP_NAME)

    assert hpa is not None
    assert hpa.spec.minReplicas == n_units
    assert hpa.spec.maxReplicas == n_units

    assert wait_for_hpa_current_replicas(
        juju.model, APP_NAME, n_units
    ), f"Expected currentReplicas to be {n_units}, got {hpa.status.currentReplicas}"


def wait_for_hpa_current_replicas(namespace, hpa_name, expected_replicas, retries=10, delay=10):
    for _ in range(retries):
        hpa = get_hpa(namespace, hpa_name)
        if hpa.status.currentReplicas == expected_replicas:
            return True
        sleep(delay)
    return False
