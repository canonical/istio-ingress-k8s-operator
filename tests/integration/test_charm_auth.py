# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import pytest
import yaml
from helpers import (
    get_auth_policy_spec,
    get_configmap_data,
    get_k8s_service_address,
    get_listener_condition,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}

CORE_JUJU_MODEL = "istio-core"
INGRESS_CONFIG_RELATION = "istio-ingress-config"
FORWARD_AUTH_RELATION = "forward-auth"


@dataclass
class CharmDeploymentConfiguration:
    entity_url: str  # Charm name or local path to charm
    application_name: str
    channel: str
    trust: bool
    config: Optional[dict] = None


ISTIO_K8S = CharmDeploymentConfiguration(
    entity_url="istio-k8s", application_name="istio-k8s", channel="latest/edge", trust=True
)

OAUTH2_K8S = CharmDeploymentConfiguration(
    entity_url="oauth2-proxy-k8s",
    application_name="oauth2-proxy-k8s",
    channel="latest/edge",
    trust=True,
)


@pytest.mark.abort_on_fail
async def test_deploy_dependencies(ops_test: OpsTest, ipa_tester_charm):
    # Deploy Istio-k8s in a separate model and oauth2 istio-ingress-k8s in the primary model.
    await ops_test.track_model(CORE_JUJU_MODEL)
    istio_core = ops_test.models.get(CORE_JUJU_MODEL)

    await istio_core.model.deploy(**asdict(ISTIO_K8S))
    await istio_core.model.wait_for_idle(
        [ISTIO_K8S.application_name], status="active", timeout=1000
    )

    await ops_test.model.deploy(**asdict(OAUTH2_K8S))
    await ops_test.model.wait_for_idle(
        [OAUTH2_K8S.application_name], status="active", timeout=1000
    )


@pytest.mark.abort_on_fail
async def test_deployment(ops_test: OpsTest, istio_ingress_charm):
    await ops_test.model.deploy(
        istio_ingress_charm, resources=resources, application_name=APP_NAME, trust=True
    )
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_relations_setup(ops_test: OpsTest):
    istio_core = ops_test.models.get(CORE_JUJU_MODEL)

    await ops_test.model.add_relation(
        f"{OAUTH2_K8S.application_name}:{FORWARD_AUTH_RELATION}", APP_NAME
    )
    await istio_core.model.create_offer(
        endpoint=INGRESS_CONFIG_RELATION,
        offer_name=INGRESS_CONFIG_RELATION,
        application_name=ISTIO_K8S.application_name,
    )
    await ops_test.model.consume(f"admin/{ops_test.model.name}.{INGRESS_CONFIG_RELATION}")
    await ops_test.model.add_relation(INGRESS_CONFIG_RELATION, APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, OAUTH2_K8S.application_name], status="active", timeout=1000
    )
    await istio_core.model.wait_for_idle(
        [ISTIO_K8S.application_name], status="active", timeout=1000
    )


@pytest.mark.abort_on_fail
async def test_verify_initial_ext_authz_configuration(ops_test: OpsTest):
    """Initial configuration verification."""
    istio_core = ops_test.models.get(CORE_JUJU_MODEL)
    policy_name = f"ext-authz-{APP_NAME}"
    await assert_config_state(ops_test, istio_core, policy_name)


@pytest.mark.abort_on_fail
async def test_oauth2_proxy_relation_break_and_recovery(ops_test: OpsTest):
    """Test breaking and recovering the oauth2-proxy:forward-auth relation."""
    istio_core = ops_test.models.get(CORE_JUJU_MODEL)
    policy_name = f"ext-authz-{APP_NAME}"

    await ops_test.juju(
        "remove-relation",
        f"{OAUTH2_K8S.application_name}:{FORWARD_AUTH_RELATION}",
        APP_NAME,
    )

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, OAUTH2_K8S.application_name], status="active", timeout=1000
    )
    await istio_core.model.wait_for_idle(
        [ISTIO_K8S.application_name], status="active", timeout=1000
    )

    # After breaking the relation, expect the policy to be removed and the extensionProviders cleared.
    policy_spec = await get_auth_policy_spec(istio_core.model.name, policy_name)
    assert not policy_spec
    mesh_config = await load_mesh_config(ops_test)
    extension_providers = mesh_config.get("extensionProviders", [])
    assert not extension_providers

    # Re-establish the relation and verify the config state.
    await ops_test.model.add_relation(
        f"{OAUTH2_K8S.application_name}:{FORWARD_AUTH_RELATION}", APP_NAME
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, OAUTH2_K8S.application_name], status="active", timeout=1000
    )
    await istio_core.model.wait_for_idle(
        [ISTIO_K8S.application_name], status="active", timeout=1000
    )

    await assert_config_state(ops_test, istio_core, policy_name)


@pytest.mark.abort_on_fail
async def test_istio_ingress_config_relation_break_and_recovery(ops_test: OpsTest):
    """Test breaking and recovering the istio-ingress-config to istio-ingress-k8s relation."""
    istio_core = ops_test.models.get(CORE_JUJU_MODEL)
    policy_name = f"ext-authz-{APP_NAME}"

    await ops_test.juju("remove-relation", INGRESS_CONFIG_RELATION, APP_NAME)

    # After breaking the relation, expect the istio-ingress to be in a blocked state
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=1000)

    # Gateway should be removed and ingress should be disabled
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")
    assert not istio_ingress_address
    gateway_listener_condition = await get_listener_condition(ops_test, APP_NAME)
    assert not gateway_listener_condition

    # Re-establish the relation and verify the config state.
    await ops_test.model.add_relation(INGRESS_CONFIG_RELATION, APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, OAUTH2_K8S.application_name], status="active", timeout=1000
    )
    await ops_test.models.get(CORE_JUJU_MODEL).model.wait_for_idle(
        [ISTIO_K8S.application_name], status="active", timeout=1000
    )

    await assert_config_state(ops_test, istio_core, policy_name)


async def load_mesh_config(ops_test: OpsTest) -> dict:
    """Load and parse the mesh configuration from the Istio ConfigMap."""
    istio_cm_data = await get_configmap_data(ops_test.model.name, "istio")
    assert istio_cm_data, "Failed to retrieve 'istio' ConfigMap."

    mesh_config_yaml = istio_cm_data.get("mesh")
    assert mesh_config_yaml, "'mesh' key not found in ConfigMap data."
    return yaml.safe_load(mesh_config_yaml)


def get_envoy_authz(mesh_config: dict, provider_name: str) -> dict:
    """Extract the envoyExtAuthzHttp config for the matching provider."""
    extension_providers = mesh_config.get("extensionProviders", [])
    assert extension_providers, "'extensionProviders' not found or empty in mesh config."

    matching_provider = next(
        (p for p in extension_providers if p.get("name") == provider_name), None
    )
    assert matching_provider, f"Provider '{provider_name}' not found in extensionProviders."

    envoy_authz = matching_provider.get("envoyExtAuthzHttp")
    assert envoy_authz, f"envoyExtAuthzHttp config missing for provider '{provider_name}'."
    return envoy_authz


async def assert_config_state(ops_test: OpsTest, istio_core, policy_name: str) -> None:
    """Assert that the config state is as expected.

    - AuthorizationPolicy exists with action 'CUSTOM'.
    - The provider exists and its name is present.
    - The Istio mesh config contains an extensionProvider with the proper envoy config.
    - The envoyExtAuthzHttp has a matching provider.
    """
    policy_spec = await get_auth_policy_spec(istio_core.model.name, policy_name)
    assert policy_spec, f"AuthorizationPolicy '{policy_name}' not found."
    assert policy_spec["action"] == "CUSTOM", f"Unexpected action {policy_spec.get('action')}"

    provider = policy_spec["provider"]
    provider_name = provider.get("name", "")
    assert provider_name, "Provider name missing in policy."

    mesh_config = await load_mesh_config(ops_test)
    envoy_authz = get_envoy_authz(mesh_config, provider_name)

    expected_service = f"{OAUTH2_K8S.application_name}.{istio_core.model.name}.svc.cluster.local"
    assert (
        envoy_authz.get("service") == expected_service
    ), f"Expected service '{expected_service}', got '{envoy_authz.get('service')}'"
