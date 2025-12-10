# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml
from conftest import get_unit_info
from helpers import istio_k8s
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
TESTER_HTTP = "tester-http"
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


@pytest.mark.abort_on_fail
async def test_deploy_istio(ops_test: OpsTest):
    """Deploy istio-k8s."""
    await ops_test.model.deploy(**asdict(istio_k8s))
    await ops_test.model.wait_for_idle([istio_k8s.application_name], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_deploy_istio_ingress(ops_test: OpsTest, istio_ingress_charm):
    """Deploy istio-ingress-k8s."""
    await ops_test.model.deploy(
        istio_ingress_charm, resources=resources, application_name=APP_NAME, trust=True
    )
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_deploy_tester_http(ops_test: OpsTest, tester_http_charm):
    """Deploy tester-http."""
    await ops_test.model.deploy(
        tester_http_charm,
        application_name=TESTER_HTTP,
        resources={"echo-server-image": "jmalloc/echo-server:v0.3.7"},
    )
    await ops_test.model.wait_for_idle([TESTER_HTTP], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_relate_gateway_metadata(ops_test: OpsTest):
    """Relate tester-http to istio-ingress-k8s via gateway-metadata."""
    await ops_test.model.add_relation(
        f"{TESTER_HTTP}:gateway-metadata", f"{APP_NAME}:gateway-metadata"
    )
    await ops_test.model.wait_for_idle([APP_NAME, TESTER_HTTP], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_gateway_metadata_content(ops_test: OpsTest):
    """Validate that gateway metadata is correctly published."""
    # Get the relation data from the requirer side (tester-http)
    # Note: We query from the requirer side because juju show-unit doesn't show
    # the provider's own application-data when querying the provider unit
    unit_info = get_unit_info(f"{TESTER_HTTP}/0", ops_test.model_full_name)

    # Find the gateway-metadata relation
    relations = unit_info["relation-info"]
    gateway_metadata_relation = None
    for relation in relations:
        if relation["endpoint"] == "gateway-metadata":
            gateway_metadata_relation = relation
            break

    assert gateway_metadata_relation is not None, "gateway-metadata relation not found"

    # Get the application data (where the provider publishes metadata)
    app_data = gateway_metadata_relation.get("application-data", {})
    assert "metadata" in app_data, "metadata key not found in relation databag"

    # Parse and validate the metadata
    metadata = json.loads(app_data["metadata"])

    # Expected values based on charm implementation
    # managed_name = f"{app_name}-istio" (from charm.py:161)
    expected_deployment = f"{APP_NAME}-istio"
    expected_service_account = f"{APP_NAME}-istio"

    # Validate metadata fields
    assert metadata["namespace"] == ops_test.model.name, \
        f"Expected namespace {ops_test.model.name}, got {metadata['namespace']}"
    assert metadata["gateway_name"] == APP_NAME, \
        f"Expected gateway_name {APP_NAME}, got {metadata['gateway_name']}"
    assert metadata["deployment_name"] == expected_deployment, \
        f"Expected deployment_name {expected_deployment}, got {metadata['deployment_name']}"
    assert metadata["service_account"] == expected_service_account, \
        f"Expected service_account {expected_service_account}, got {metadata['service_account']}"

    logger.info(f"Gateway metadata validated successfully: {metadata}")
