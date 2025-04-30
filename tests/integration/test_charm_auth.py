# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from dataclasses import asdict
from pathlib import Path

import jubilant
import pytest
import yaml
from helpers import (
    ISTIO_K8S,
    CharmDeploymentConfiguration,
    get_auth_policy_spec,
    get_configmap_data,
    get_k8s_service_address,
    get_listener_condition,
)
from jubilant import all_active

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}

CORE_ISTIO_MODEL = "istio-core"
INGRESS_CONFIG_RELATION = "istio-ingress-config"
FORWARD_AUTH_RELATION = "forward-auth"


OAUTH2_K8S = CharmDeploymentConfiguration(
    charm="oauth2-proxy-k8s",
    app="oauth2-proxy-k8s",
    channel="latest/edge",
    trust=True,
)


@pytest.mark.setup
def test_deploy_dependencies(juju: jubilant.Juju, juju_istio_system: jubilant.Juju):
    """Deploys dependencies across two models: one for istio-k8s and one for the rest."""
    juju_istio_system.deploy(**asdict(ISTIO_K8S))

    juju.deploy(**asdict(OAUTH2_K8S))

    juju_istio_system.wait(lambda status: jubilant.all_active(status, ISTIO_K8S.app))

    juju.wait(lambda status: jubilant.all_active(status, OAUTH2_K8S.app), timeout=300)


def test_deployment(juju: jubilant.Juju, istio_ingress_charm):
    juju.deploy(istio_ingress_charm, app=APP_NAME, resources=resources, trust=True)
    juju.wait(lambda status: all_active(status, APP_NAME), timeout=120)


def test_relations_setup(juju: jubilant.Juju, juju_istio_system: jubilant.Juju):
    juju_istio_system.offer(
        ISTIO_K8S.app,
        INGRESS_CONFIG_RELATION,
    )
    # Consume the offer
    # TODO after https://github.com/canonical/jubilant/issues/129: Use jubilant's native consume
    consume_args = ("consume", f"admin/{juju_istio_system.model}.{INGRESS_CONFIG_RELATION}")
    juju.cli(*consume_args)

    juju.integrate(f"{OAUTH2_K8S.app}:{FORWARD_AUTH_RELATION}", APP_NAME)
    juju.integrate(INGRESS_CONFIG_RELATION, APP_NAME)

    juju.wait(lambda status: all_active(status, APP_NAME, OAUTH2_K8S.app), timeout=300)
    juju_istio_system.wait(lambda status: all_active(status, ISTIO_K8S.app), timeout=300)


def test_verify_initial_ext_authz_configuration(
    juju: jubilant.Juju, juju_istio_system: jubilant.Juju
):
    """Initial configuration verification."""
    policy_name = f"ext-authz-{APP_NAME}"
    assert_config_state(juju.model, juju_istio_system.model, policy_name)


def test_oauth2_proxy_relation_break_and_recovery(
    juju: jubilant.Juju, juju_istio_system: jubilant.Juju
):
    """Test breaking and recovering the oauth2-proxy:forward-auth relation."""
    policy_name = f"ext-authz-{APP_NAME}"

    juju.remove_relation(f"{OAUTH2_K8S.app}:{FORWARD_AUTH_RELATION}", APP_NAME)

    juju.wait(lambda status: all_active(status, APP_NAME, OAUTH2_K8S.app), timeout=300)
    juju_istio_system.wait(lambda status: all_active(status, ISTIO_K8S.app), timeout=120)

    # After breaking the relation, expect the policy to be removed and the extensionProviders cleared.
    policy_spec = get_auth_policy_spec(juju.model, policy_name)
    assert not policy_spec
    mesh_config = load_mesh_config(juju_istio_system.model)
    extension_providers = mesh_config.get("extensionProviders", [])
    assert not extension_providers

    # Re-establish the relation and verify the config state.
    juju.integrate(f"{OAUTH2_K8S.app}:{FORWARD_AUTH_RELATION}", APP_NAME)
    juju.wait(lambda status: all_active(status, APP_NAME, OAUTH2_K8S.app), timeout=300)
    juju_istio_system.wait(lambda status: all_active(status, ISTIO_K8S.app), timeout=120)

    assert_config_state(juju.model, juju_istio_system.model, policy_name)


def test_istio_ingress_config_relation_break_and_recovery(
    juju: jubilant.Juju, juju_istio_system: jubilant.Juju
):
    """Test breaking and recovering the istio-ingress-config to istio-ingress-k8s relation."""
    policy_name = f"ext-authz-{APP_NAME}"

    juju.remove_relation(INGRESS_CONFIG_RELATION, APP_NAME)
    # After breaking the relation, expect the istio-ingress to be in a blocked state
    juju.wait(lambda status: jubilant.all_blocked(status, APP_NAME), timeout=300)

    # Gateway should be removed and ingress should be disabled
    istio_ingress_address = get_k8s_service_address(juju.model, "istio-ingress-k8s-istio")
    assert not istio_ingress_address
    gateway_listener_condition = get_listener_condition(juju.model, APP_NAME)
    assert not gateway_listener_condition

    # Re-establish the relation and verify the config state.
    juju.integrate(INGRESS_CONFIG_RELATION, APP_NAME)
    juju.wait(lambda status: all_active(status, APP_NAME, OAUTH2_K8S.app), timeout=300)
    juju_istio_system.wait(lambda status: all_active(status, ISTIO_K8S.app), timeout=180)

    assert_config_state(juju.model, juju_istio_system.model, policy_name)


def load_mesh_config(model_name: str) -> dict:
    """Load and parse the mesh configuration from the Istio ConfigMap."""
    istio_cm_data = get_configmap_data(model_name, "istio")
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


def assert_config_state(primary_model: str, istio_system_model: str, policy_name: str) -> None:
    """Assert that the config state is as expected.

    - AuthorizationPolicy exists with action 'CUSTOM'.
    - The provider exists and its name is present.
    - The Istio mesh config contains an extensionProvider with the proper envoy config.
    - The envoyExtAuthzHttp has a matching provider.

    Args:
        primary_model: The model name for the primary components of the test
        istio_system_model: The model name for the istio system components of the test
        policy_name: Name of the AuthorizationPolicy resource.

    """
    policy_spec = get_auth_policy_spec(primary_model, policy_name)
    assert policy_spec, f"AuthorizationPolicy '{policy_name}' not found."
    assert policy_spec["action"] == "CUSTOM", f"Unexpected action {policy_spec.get('action')}"

    provider = policy_spec["provider"]
    provider_name = provider.get("name", "")
    assert provider_name, "Provider name missing in policy."

    mesh_config = load_mesh_config(istio_system_model)
    envoy_authz = get_envoy_authz(mesh_config, provider_name)

    expected_service = f"{OAUTH2_K8S.app}.{primary_model}.svc.cluster.local"
    assert (
        envoy_authz.get("service") == expected_service
    ), f"Expected service '{expected_service}', got '{envoy_authz.get('service')}'"
