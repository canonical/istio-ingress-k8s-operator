# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import pytest
import yaml
from conftest import (
    assert_can_connect,
    get_relation_data,
)
from helpers import (
    dequote,
    get_k8s_service_address,
    get_listener_condition,
    get_listener_spec,
    get_route_condition,
    get_route_spec,
    remove_application,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]


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
async def test_deploy_dependencies(ops_test: OpsTest, ipa_tester_charm):

    # Not the model name just an alias
    await ops_test.track_model("istio-core")
    istio_core = ops_test.models.get("istio-core")

    # Deploy Istio-k8s
    await istio_core.model.deploy(**asdict(ISTIO_K8S))
    await istio_core.model.wait_for_idle(
        [
            ISTIO_K8S.application_name,
        ],
        status="active",
        timeout=1000,
    )

    # Deploy ipa-tester
    await ops_test.model.deploy(ipa_tester_charm, application_name="ipa-tester"),
    await ops_test.model.wait_for_idle(
        [
            "ipa-tester",
        ],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_deployment(ops_test: OpsTest, istio_ingress_charm):
    await ops_test.model.deploy(istio_ingress_charm, application_name=APP_NAME, trust=True),
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_relate(ops_test: OpsTest):
    await ops_test.model.add_relation("ipa-tester:ingress", "istio-ingress-k8s:ingress")
    await ops_test.model.wait_for_idle([APP_NAME, "ipa-tester"])


@pytest.mark.abort_on_fail
async def test_ipa_charm_has_ingress(ops_test: OpsTest):
    data = get_relation_data(
        requirer_endpoint="ipa-tester/0:ingress",
        provider_endpoint="istio-ingress-k8s/0:ingress",
        model=ops_test.model_full_name,
    )

    provider_app_data = yaml.safe_load(data.provider.application_data["ingress"])
    url = provider_app_data["url"]

    requirer_app_data = data.requirer.application_data
    model = dequote(requirer_app_data["model"])

    # Rel data assertions
    assert dequote(requirer_app_data["name"]) == "ipa-tester"
    assert dequote(requirer_app_data["port"]) == "80"
    assert not requirer_app_data.get("host")
    assert dequote(data.requirer.unit_data["host"]) == "foo.bar"

    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")

    assert url == f"http://{istio_ingress_address}/{model}-ipa-tester"

    url_parts = urlparse(url)
    ip = url_parts.hostname
    port = url_parts.port or 80
    assert_can_connect(ip, port)


@pytest.mark.abort_on_fail
async def test_route_validity(ops_test: OpsTest):
    data = get_relation_data(
        requirer_endpoint="ipa-tester/0:ingress",
        provider_endpoint="istio-ingress-k8s/0:ingress",
        model=ops_test.model_full_name,
    )

    requirer_app_data = data.requirer.application_data

    listener_condition = await get_listener_condition(ops_test, "istio-ingress-k8s")
    route_condition = await get_route_condition(ops_test, requirer_app_data["name"])
    listener_spec = await get_listener_spec(ops_test, "istio-ingress-k8s")
    route_spec = await get_route_spec(ops_test, requirer_app_data["name"])

    assert listener_condition["attachedRoutes"] == 1
    assert listener_condition["conditions"][0]["message"] == "No errors found"
    assert listener_condition["conditions"][0]["reason"] == "Accepted"

    assert route_condition["conditions"][0]["message"] == "Route was valid"
    assert route_condition["conditions"][0]["reason"] == "Accepted"
    assert route_condition["controllerName"] == "istio.io/gateway-controller"

    assert listener_spec["hostname"] == "*.foo.bar"
    assert route_spec["hostnames"][0] == "bar.foo.bar"


@pytest.mark.abort_on_fail
async def test_remove_relation(ops_test: OpsTest):
    await ops_test.juju("remove-relation", "ipa-tester:ingress", "istio-ingress-k8s:ingress")
    await ops_test.model.wait_for_idle([APP_NAME, "ipa-tester"], status="active")


async def test_cleanup(ops_test):
    await remove_application(ops_test, APP_NAME, timeout=60)
