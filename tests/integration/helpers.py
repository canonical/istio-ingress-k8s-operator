import logging
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Optional, cast
from urllib.parse import urlparse

import lightkube
import requests
from lightkube.generic_resource import create_namespaced_resource
from lightkube.resources.autoscaling_v2 import HorizontalPodAutoscaler
from lightkube.resources.core_v1 import ConfigMap, Service
from pytest_operator.plugin import OpsTest
from requests.adapters import DEFAULT_POOLBLOCK, DEFAULT_POOLSIZE, DEFAULT_RETRIES, HTTPAdapter

logger = logging.getLogger(__name__)

@dataclass
class CharmDeploymentConfiguration:
    entity_url: str  # aka charm name or local path to charm
    application_name: str
    channel: str
    trust: bool
    config: Optional[dict] = None


istio_k8s = CharmDeploymentConfiguration(
    entity_url="istio-k8s", application_name="istio-k8s", channel="2/edge", trust=True
)

oauth_k8s = CharmDeploymentConfiguration(
    entity_url="oauth2-proxy-k8s",
    application_name="oauth2-proxy-k8s",
    channel="latest/edge",
    trust=True,
)

RESOURCE_TYPES = {
    "Gateway": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    ),
    "HTTPRoute": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes"
    ),
    "AuthorizationPolicy": create_namespaced_resource(
        "security.istio.io",
        "v1",
        "AuthorizationPolicy",
        "authorizationpolicies",
    ),
}


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
        c = lightkube.Client()
        svc = c.get(Service, namespace=model.name, name=service_name)
        return svc.status.loadBalancer.ingress[0].ip

    except Exception as e:
        logger.error("Error retrieving service address %s", e, exc_info=1)
        return None


async def get_listener_condition(ops_test: OpsTest, gateway_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the status of the listener from the Gateway resource as a dictionary.

    Args:
        ops_test: pytest-operator plugin
        gateway_name: Name of the Gateway resource.

    Returns:
        A dictionary representing the status of the first listener, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        gateway = c.get(RESOURCE_TYPES["Gateway"], namespace=model.name, name=gateway_name)
        return cast(dict, gateway.status["listeners"][0])

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


async def get_listener_spec(ops_test: OpsTest, gateway_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the spec of the listener from the Gateway resource as a dictionary.

    Args:
        ops_test: pytest-operator plugin
        gateway_name: Name of the Gateway resource.

    Returns:
        A dictionary representing the spec of the first listener, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        gateway = c.get(RESOURCE_TYPES["Gateway"], namespace=model.name, name=gateway_name)
        return gateway.spec["listeners"][0]

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


async def get_route_spec(ops_test: OpsTest, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the spec of the HTTPRoute resource.

    Args:
        ops_test: pytest-operator plugin
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the spec of the route, or None if not found.
    """
    model = ops_test.model.info
    try:
        c = lightkube.Client()
        route = c.get(RESOURCE_TYPES["HTTPRoute"], namespace=model.name, name=route_name)
        return route.spec

    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


async def get_auth_policy_spec(model_name: str, policy_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the spec of the AuthorizationPolicy resource.

    Args:
        model_name: Name of the juju model.
        policy_name: Name of the AuthorizationPolicy resource.

    Returns:
        A dictionary representing the spec of the policy, or None if not found.
    """
    try:
        c = lightkube.Client()
        policy = c.get(
            RESOURCE_TYPES["AuthorizationPolicy"], namespace=model_name, name=policy_name
        )
        return policy.spec

    except Exception as e:
        logger.error("Error retrieving AuthorizationPolicy condition: %s", e, exc_info=1)
        return None


async def get_configmap_data(model_name: str, cm_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the data of the ConfigMap resource.

    Args:
        model_name: Name of the juju model.
        cm_name: Name of the ConfigMap resource.

    Returns:
        A dictionary representing the data of the ConfigMap, or None if not found.
    """
    try:
        c = lightkube.Client()
        cm = c.get(ConfigMap, name=cm_name, namespace=model_name)
        return cm.data

    except Exception as e:
        logger.error("Error retrieving ConfigMap: %s", e, exc_info=1)
        return None


async def get_route_condition(ops_test: OpsTest, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the condition from the HTTPRoute resource.

    Args:
        ops_test: pytest-operator plugin
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the status of the parent gateway the route is attached to, or None if not found.
    """
    model = ops_test.model.name
    try:
        c = lightkube.Client()
        route = c.get(RESOURCE_TYPES["HTTPRoute"], namespace=model, name=route_name)
        return cast(dict, route.status["parents"][0])
    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


async def get_hpa(namespace: str, hpa_name: str) -> Optional[HorizontalPodAutoscaler]:
    """Retrieve the HPA resource so we can inspect .spec and .status directly.

    Args:
        namespace: Namespace of the HPA resource.
        hpa_name: Name of the HPA resource.

    Returns:
        The HorizontalPodAutoscaler object or None if not found / on error.
    """
    try:
        c = lightkube.Client()
        return c.get(HorizontalPodAutoscaler, namespace=namespace, name=hpa_name)
    except Exception as e:
        logger.error("Error retrieving HPA %s: %s", hpa_name, e, exc_info=True)
        return None


def dequote(s: str):
    if isinstance(s, str) and s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s


def send_http_request(url: str, headers: Optional[dict] = None) -> bool:
    """Sends an request to the specified URL with an optional header.

    Returns True if the request returns a 200 status code, otherwise False.

    :param url: The URL to send the request to.
    :param headers: Optional header to include in the request (e.g., {"Host": "example.com").
    :return: True if the response status is 200, False otherwise.
    """
    resp = requests.get(url=url, headers=headers)
    return resp.status_code == 200


def send_http_request_with_custom_ca(
    url: str, ca_cert: str, resolve_netloc_to_ip: str = None
) -> int:
    """Sends a request to the specified URL with an optional CA certificate and DNS resolution.

    :param url: The URL to send the request to.
    :param ca_cert: Custom CA certificate to use for the request.
    :param resolve_netloc_to_ip: Optional IP to resolve the url.netloc to.  Useful if we're testing a URL deployed
                                 without a real host, but that we want the request to appear like it is entering a host
    :return: The status code of the response.
    """
    netloc = urlparse(url).netloc
    if resolve_netloc_to_ip is None:
        resolve_netloc_to_ip = netloc
    headers = {"Host": netloc}

    # Use a custom session to handle the custom SSL context and DNS resolution
    session = requests.Session()
    session.mount(
        "https://", DNSResolverHTTPSAdapter(netloc, resolve_netloc_to_ip, ca_cert=ca_cert)
    )
    response = session.get(url=url, headers=headers)
    return response.status_code


class DNSResolverHTTPSAdapter(HTTPAdapter):
    """A combined DNS resolver and custom CA Certificate adapter for requests.

    This adapter:
     * resolves hostname to a given IP address
     * uses a custom CA certificate to validate TLS connections instead of the system CA bundle

    From: https://github.com/canonical/gateway-api-integrator-operator/blob/main/tests/integration/helper.py and
    https://stackoverflow.com/a/77577017/5394584
    """

    def __init__(
        self,
        hostname,
        ip,
        ca_cert: Optional[str] = None,
    ):
        """Initialize the dns resolver.

        Args:
            hostname: DNS entry to resolve.
            ip: Target IP address.
            ca_cert: Custom CA certificate to use for the request.
        """
        self.hostname = hostname
        self.ip = ip
        self.ca_cert = ca_cert
        super().__init__(
            pool_connections=DEFAULT_POOLSIZE,
            pool_maxsize=DEFAULT_POOLSIZE,
            max_retries=DEFAULT_RETRIES,
            pool_block=DEFAULT_POOLBLOCK,
        )

    def init_poolmanager(self, *args, **kwargs):
        """Initialize the pool manager with the custom CA certificate."""
        if self.ca_cert:
            context = ssl.create_default_context(cadata=self.ca_cert)
        else:
            context = ssl.create_default_context()
            context.load_default_certs()
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)

    # Ignore pylint rule as this is the parent method signature
    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):  # pylint: disable=too-many-arguments, too-many-positional-arguments
        """Wrap HTTPAdapter send to modify the outbound request.

        Args:
            request: Outbound HTTP request.
            stream: argument used by parent method.
            timeout: argument used by parent method.
            verify: argument used by parent method.
            cert: argument used by parent method.
            proxies: argument used by parent method.

        Returns:
            Response: HTTP response after modification.
        """
        connection_pool_kwargs = self.poolmanager.connection_pool_kw

        result = urlparse(request.url)
        if result.hostname == self.hostname:
            ip = self.ip
            if result.scheme == "https" and ip:
                request.url = request.url.replace(
                    "https://" + result.hostname,
                    "https://" + ip,
                )
                connection_pool_kwargs["server_hostname"] = result.hostname
                connection_pool_kwargs["assert_hostname"] = result.hostname
                request.headers["Host"] = result.hostname
            else:
                connection_pool_kwargs.pop("server_hostname", None)
                connection_pool_kwargs.pop("assert_hostname", None)

        return super().send(request, stream, timeout, verify, cert, proxies)
