# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import pytest
import requests
import yaml
from conftest import (
    get_relation_data,
)
from helpers import (
    dequote,
    get_k8s_service_address,
    get_listener_condition,
    get_listener_spec,
    get_route_condition,
    send_http_request,
    send_http_request_with_custom_ca,
)
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
IPA_TESTER = "ipa-tester"
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
async def test_deploy_dependencies(ops_test: OpsTest, ipa_tester_charm):
    """Deploys dependencies across two models: one for Istio and one for ipa-tester.

    This test uses a multi-model approach to isolate Istio and the ipa-tester in
    separate Kubernetes namespaces. It deploys Istio in the 'istio-core' model
    and ipa-tester in the main test model.
    """
    # Instantiate a second model for istio-core.  ops_test automatically gives it a unique name,
    # but we provide a user-friendly alias of "istio-core"
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
    await ops_test.model.deploy(
        ipa_tester_charm,
        application_name=IPA_TESTER,
        resources={"echo-server-image": "jmalloc/echo-server:v0.3.7"},
    ),
    await ops_test.model.wait_for_idle(
        [
            IPA_TESTER,
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
async def test_relate(ops_test: OpsTest):
    await ops_test.model.add_relation("ipa-tester:ingress", "istio-ingress-k8s:ingress")
    await ops_test.model.wait_for_idle([APP_NAME, IPA_TESTER])


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


@pytest.mark.abort_on_fail
@pytest.mark.parametrize(
    "external_hostname, expected_hostname",
    [
        ("foo.bar", "foo.bar"),  # Initial valid hostname
        ("bar.foo", "bar.foo"),  # Change to a new valid hostname
        ("", None),  # Remove hostname
    ],
)
async def test_route_validity(
    ops_test: OpsTest, external_hostname: str, expected_hostname: Optional[str]
):
    await ops_test.model.applications[APP_NAME].set_config(
        {"external_hostname": external_hostname}
    )
    await ops_test.model.wait_for_idle([APP_NAME, IPA_TESTER])

    model = ops_test.model.name

    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")
    tester_url = f"http://{istio_ingress_address}/{model}-{IPA_TESTER}"

    listener_condition = await get_listener_condition(ops_test, "istio-ingress-k8s")
    route_condition = await get_route_condition(ops_test, f"{IPA_TESTER}-http")
    listener_spec = await get_listener_spec(ops_test, "istio-ingress-k8s")

    assert listener_condition["attachedRoutes"] == 1
    assert listener_condition["conditions"][0]["message"] == "No errors found"
    assert listener_condition["conditions"][0]["reason"] == "Accepted"

    assert route_condition["conditions"][0]["message"] == "Route was valid"
    assert route_condition["conditions"][0]["reason"] == "Accepted"
    assert route_condition["controllerName"] == "istio.io/gateway-controller"

    if not expected_hostname:
        assert "hostname" not in listener_spec
        assert send_http_request(tester_url)
    else:
        assert listener_spec["hostname"] == expected_hostname
        assert send_http_request(tester_url, {"Host": expected_hostname})
        assert not send_http_request(tester_url)
        assert not send_http_request(tester_url, {"Host": "random.hostname"})


@pytest.fixture(scope="module")
async def deploy_and_relate_certificate_provider(ops_test: OpsTest):
    """Deploy the self-signed-certificates charm to the primary model and relate it to istio-ingress-k8s.

    Returns the certificate provider's application name.

    Note that this fixture does not wait_for_idle.  The caller should do that if needed.
    """
    # Deploy and relate to a certificate provider
    self_signed_certificates = "self-signed-certificates"
    await ops_test.model.deploy(self_signed_certificates)
    await ops_test.model.add_relation(
        f"{self_signed_certificates}:certificates", f"{APP_NAME}:certificates"
    )
    yield self_signed_certificates
    # TODO: Should we remove this application after yield?  As is, we leave the test with TLS enabled.  Given that its
    #  module scope, removing it here might not actually fire till the end of the test suite anyway.  Not sure.


@pytest.mark.abort_on_fail
@pytest.mark.parametrize(
    "external_hostname",
    [
        "",  # Use default (empty) hostname
        # Change to a new valid hostname.  This will reuse the existing relation to the cert provider, so it tests both
        # whether we can handle different hostnames and whether we can change the hostname while TLS is provided
        "foo.bar",
    ],
)
@pytest.mark.abort_on_fail
async def test_gateway_with_tls(
    external_hostname, ops_test: OpsTest, deploy_and_relate_certificate_provider
):
    """Test that, when connected to a TLS cert provider, the gateway is configured with TLS and http is redirected."""
    self_signed_certificates = deploy_and_relate_certificate_provider

    await ops_test.model.applications[APP_NAME].set_config(
        {"external_hostname": external_hostname}
    )

    # Wait for everything to settle before obtaining the ca_certificate
    await ops_test.model.wait_for_idle(
        [APP_NAME, IPA_TESTER, self_signed_certificates], status="active", timeout=1000
    )
    ca_certificate = await get_ca_certificate(
        ops_test.model.units[f"{self_signed_certificates}/0"]
    )

    # Build the ingress URL
    model = ops_test.model.name
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")
    tester_url = f"{istio_ingress_address}/{model}-{IPA_TESTER}"
    tester_url_http = f"http://{tester_url}"

    # If the ingress is configured to use a hostname, set the Host header
    headers = {}
    hostname = (await ops_test.model.applications[APP_NAME].get_config())["external_hostname"].get(
        "value", None
    )
    if hostname:
        headers["Host"] = hostname

    # Assert that http request is redirected to https
    resp = requests.get(url=tester_url_http, headers=headers, allow_redirects=False)
    assert resp.status_code == 301, "http request was not redirected to https"
    assert resp.headers.get("Location").startswith(
        "https://"
    ), "http request was not redirected to https"

    # Assert that https request works with the given ca-bundle
    if hostname:
        url = f"https://{hostname}/{model}-{IPA_TESTER}"
        resolve_netloc_to_ip = istio_ingress_address
    else:
        url = f"https://{istio_ingress_address}/{model}-{IPA_TESTER}"
        resolve_netloc_to_ip = None
    assert (
        send_http_request_with_custom_ca(
            url, ca_certificate, resolve_netloc_to_ip=resolve_netloc_to_ip
        )
        == 200
    ), "Failed to send request to endpoint with custom CA"


async def get_ca_certificate(unit: Unit) -> str:
    """Return the CA certificate from a self-signed-certificate unit using the get-ca-certificate action."""
    action = await unit.run_action("get-ca-certificate")
    result = await action.wait()
    return result.results["ca-certificate"]


@pytest.mark.abort_on_fail
async def test_remove_relation(ops_test: OpsTest):
    await ops_test.juju("remove-relation", "ipa-tester:ingress", "istio-ingress-k8s:ingress")
    await ops_test.model.wait_for_idle([APP_NAME, IPA_TESTER], status="active")
