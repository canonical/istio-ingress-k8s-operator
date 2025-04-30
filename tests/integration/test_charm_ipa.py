# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import jubilant
import pytest
import requests
import yaml
from helpers import (
    ISTIO_K8S,
    dequote,
    get_auth_policy_spec,
    get_k8s_service_address,
    get_listener_condition,
    get_listener_spec,
    get_relation_data,
    get_route_condition,
    send_http_request,
    send_http_request_with_custom_ca,
)

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
IPA_TESTER = "ipa-tester"
IPA_TESTER_UNAUTHENTICATED = "ipa-tester-unauthenticated"
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


@pytest.mark.setup
def test_deploy_dependencies(
    juju: jubilant.Juju, juju_istio_system: jubilant.Juju, ipa_tester_charm
):
    """Deploys dependencies across two models: one for Istio and one for ipa-tester.

    This test uses a multi-model approach to isolate Istio and the ipa-tester in
    separate Kubernetes namespaces. It deploys Istio in the 'istio-core' model
    and ipa-tester in the main test model.
    """
    # Deploy Istio-k8s in a side model
    juju_istio_system.deploy(**asdict(ISTIO_K8S))

    # And testers in the primary model
    juju.deploy(
        ipa_tester_charm,
        app=IPA_TESTER,
        resources={"echo-server-image": "jmalloc/echo-server:v0.3.7"},
    )
    juju.deploy(
        ipa_tester_charm,
        app=IPA_TESTER_UNAUTHENTICATED,
        resources={"echo-server-image": "jmalloc/echo-server:v0.3.7"},
    )

    # Then wait for everything to be up
    juju.wait(
        lambda status: jubilant.all_active(status, IPA_TESTER, IPA_TESTER_UNAUTHENTICATED),
        timeout=120,
    )
    juju_istio_system.wait(lambda status: jubilant.all_active(status, ISTIO_K8S.app), timeout=120)


@pytest.mark.setup
def test_deployment(juju: jubilant.Juju, istio_ingress_charm):
    juju.deploy(istio_ingress_charm, app=APP_NAME, resources=resources, trust=True)
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME), timeout=120)


def test_relate(juju: jubilant.Juju):
    juju.integrate(f"{IPA_TESTER}:ingress", "istio-ingress-k8s:ingress")
    juju.integrate(f"{IPA_TESTER_UNAUTHENTICATED}:ingress", "istio-ingress-k8s:ingress")
    juju.wait(
        lambda status: jubilant.all_active(
            status, APP_NAME, IPA_TESTER, IPA_TESTER_UNAUTHENTICATED
        ),
        timeout=120,
    )


def test_ipa_charm_has_ingress(juju: jubilant.Juju):
    """Spot check directly on the relation data that we have provided an ingress."""
    data = get_relation_data(
        juju=juju,
        requirer_endpoint="ipa-tester/0:ingress",
        provider_endpoint="istio-ingress-k8s/0:ingress",
    )

    provider_app_data = yaml.safe_load(data.provider.application_data["ingress"])
    url = provider_app_data["url"]

    requirer_app_data = data.requirer.application_data
    model = dequote(requirer_app_data["model"])

    istio_ingress_address = get_k8s_service_address(juju.model, "istio-ingress-k8s-istio")

    assert url == f"http://{istio_ingress_address}/{model}-ipa-tester"


def test_auth_policy_validity(juju: jubilant.Juju):
    for ipa_tester in [IPA_TESTER, IPA_TESTER_UNAUTHENTICATED]:

        policy_name = f"{ipa_tester}-{APP_NAME}-{juju.model}-l4"

        # Retrieve the AuthorizationPolicy spec
        policy_spec = get_auth_policy_spec(juju.model, policy_name)

        # Ensure the policy spec is not None
        assert policy_spec is not None, f"AuthorizationPolicy '{policy_name}' not found."

        # Validate the 'rules' structure
        assert "rules" in policy_spec, "'rules' field is missing in the AuthorizationPolicy spec."
        rules = policy_spec["rules"]
        assert len(rules) == 1, "Expected exactly one rule in AuthorizationPolicy spec."

        # Validate the 'to' field inside the rule
        to_rules = rules[0].get("to", [])
        assert len(to_rules) == 1, "'to' field should contain exactly one operation."
        assert "operation" in to_rules[0], "Missing 'operation' in the 'to' field."
        assert to_rules[0]["operation"]["ports"] == [
            "8080"
        ], "Port mismatch in the AuthorizationPolicy."

        # Validate the 'from' field inside the rule
        from_rules = rules[0].get("from", [])
        assert len(from_rules) == 1, "'from' field should contain exactly one source."
        assert "source" in from_rules[0], "Missing 'source' in the 'from' field."
        principals = from_rules[0]["source"].get("principals", [])
        assert len(principals) == 1, "Expected exactly one principal in the 'source' field."
        assert (
            principals[0] == f"cluster.local/ns/{juju.model}/sa/istio-ingress-k8s-istio"
        ), "Principal does not match expected format."

        # Validate 'selector' field
        assert (
            "selector" in policy_spec
        ), "'selector' field is missing in the AuthorizationPolicy spec."
        match_labels = policy_spec["selector"].get("matchLabels", {})
        assert (
            match_labels.get("app.kubernetes.io/name") == ipa_tester
        ), "AuthorizationPolicy selector does not match the expected app name."


@pytest.mark.parametrize(
    "external_hostname, expected_hostname",
    [
        ("foo.bar", "foo.bar"),  # Initial valid hostname
        ("bar.foo", "bar.foo"),  # Change to a new valid hostname
        ("", None),  # Remove hostname
    ],
)
def test_route_validity(
    juju: jubilant.Juju, external_hostname: str, expected_hostname: Optional[str]
):
    """Test that routes to apps related on the ingress and ingress-unauthenticated endpoints work as expected."""
    juju.config(APP_NAME, {"external_hostname": external_hostname})
    juju.wait(
        lambda status: jubilant.all_active(
            status, APP_NAME, IPA_TESTER, IPA_TESTER_UNAUTHENTICATED
        ),
        timeout=120,
    )

    istio_ingress_address = get_k8s_service_address(juju.model, f"{APP_NAME}-istio")

    listener_condition = get_listener_condition(juju.model, "istio-ingress-k8s")
    listener_spec = get_listener_spec(juju.model, "istio-ingress-k8s")

    assert listener_condition["attachedRoutes"] == 2
    assert listener_condition["conditions"][0]["message"] == "No errors found"
    assert listener_condition["conditions"][0]["reason"] == "Accepted"

    for ipa_tester in [IPA_TESTER, IPA_TESTER_UNAUTHENTICATED]:
        tester_url = f"http://{istio_ingress_address}/{juju.model}-{ipa_tester}"
        route_condition = get_route_condition(juju.model, f"{ipa_tester}-http-{APP_NAME}")

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
def deploy_and_relate_certificate_provider(juju: jubilant.Juju):
    """Deploy the self-signed-certificates charm to the primary model and relate it to istio-ingress-k8s.

    Returns the certificate provider's application name.

    Note that this fixture does not wait_for_idle.  The caller should do that if needed.
    """
    # Deploy and relate to a certificate provider
    self_signed_certificates = "self-signed-certificates"
    juju.deploy(self_signed_certificates)
    juju.integrate(f"{self_signed_certificates}:certificates", f"{APP_NAME}:certificates")
    yield self_signed_certificates
    juju.remove_application(self_signed_certificates, destroy_storage=True)


@pytest.mark.parametrize(
    "external_hostname",
    [
        "",  # Use default (empty) hostname
        # Change to a new valid hostname.  This will reuse the existing relation to the cert provider, so it tests both
        # whether we can handle different hostnames and whether we can change the hostname while TLS is provided
        "foo.bar",
    ],
)
def test_gateway_with_tls(
    external_hostname, juju: jubilant.Juju, deploy_and_relate_certificate_provider
):
    """Test that, when connected to a TLS cert provider, the gateway is configured with TLS and http is redirected."""
    self_signed_certificates = deploy_and_relate_certificate_provider

    juju.config(APP_NAME, {"external_hostname": external_hostname})

    # Wait for everything to settle before obtaining the ca_certificate
    juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, IPA_TESTER, self_signed_certificates),
        timeout=300,
    )
    ca_certificate_task = juju.run(f"{self_signed_certificates}/0", "get-ca-certificate")
    ca_certificate = ca_certificate_task.results["ca-certificate"]

    # Build the ingress URL
    istio_ingress_address = get_k8s_service_address(juju.model, "istio-ingress-k8s-istio")
    tester_url = f"{istio_ingress_address}/{juju.model}-{IPA_TESTER}"
    tester_url_http = f"http://{tester_url}"

    # If the ingress is configured to use a hostname, set the Host header
    headers = {}
    hostname = juju.config(APP_NAME).get("external_hostname", None)
    if hostname:
        headers["Host"] = hostname

    # Assert that http request is redirected to https
    # This is a bit racey with istio's pushing of configuration, so we retry it a few times.
    # Anything more than a few seconds here means something went wrong
    max_retries = 5
    for i in range(max_retries):
        try:
            resp = requests.get(url=tester_url_http, headers=headers, allow_redirects=False)
            assert resp.status_code == 301, "http request was not redirected to https"
            assert resp.headers.get("Location").startswith(
                "https://"
            ), "http request was not redirected to https"
            break
        except AssertionError as e:
            if i == max_retries - 1:
                raise e
            logger.info(f"Failed to confirm http redirection on attempt {i+1}/{max_retries}.")
            time.sleep(5)
            continue

    # Assert that https request works with the given ca-bundle
    if hostname:
        url = f"https://{hostname}/{juju.model}-{IPA_TESTER}"
        resolve_netloc_to_ip = istio_ingress_address
    else:
        url = f"https://{istio_ingress_address}/{juju.model}-{IPA_TESTER}"
        resolve_netloc_to_ip = None
    assert (
        send_http_request_with_custom_ca(
            url, ca_certificate, resolve_netloc_to_ip=resolve_netloc_to_ip
        )
        == 200
    ), "Failed to send request to endpoint with custom CA"


@pytest.mark.teardown
def test_remove_relation(juju: jubilant.Juju):
    juju.remove_relation(f"{IPA_TESTER}:ingress", "istio-ingress-k8s:ingress")
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME, IPA_TESTER))
