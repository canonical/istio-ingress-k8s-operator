# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path
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
    remove_application,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]


@pytest.mark.abort_on_fail
async def test_deployment(ops_test: OpsTest, istio_ingress_charm, ipa_tester_charm):
    await asyncio.gather(
        ops_test.model.deploy(istio_ingress_charm, application_name=APP_NAME),
        ops_test.model.deploy(ipa_tester_charm, "ipa-tester"),
    )
    await ops_test.model.wait_for_idle([APP_NAME, "ipa-tester"], status="active", timeout=1000)


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
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")

    assert url == f"http://{istio_ingress_address}/{model}-ipa-tester"

    url_parts = urlparse(url)
    ip = url_parts.hostname
    port = url_parts.port or 80
    assert_can_connect(ip, port)


@pytest.mark.abort_on_fail
async def test_remove_relation(ops_test: OpsTest):
    await ops_test.juju("remove-relation", "ipa-tester:ingress", "istio-ingress-k8s:ingress")
    await ops_test.model.wait_for_idle([APP_NAME, "ipa-tester"], status="active")


async def test_cleanup(ops_test):
    await remove_application(ops_test, APP_NAME, timeout=60)
