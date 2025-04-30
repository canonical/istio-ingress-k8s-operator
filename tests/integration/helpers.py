import dataclasses
import logging
import ssl
from typing import Any, Dict, Optional, cast
from urllib.parse import urlparse

import jubilant
import lightkube
import requests
import yaml
from lightkube.generic_resource import create_namespaced_resource
from lightkube.resources.autoscaling_v2 import HorizontalPodAutoscaler
from lightkube.resources.core_v1 import ConfigMap, Service
from requests.adapters import DEFAULT_POOLBLOCK, DEFAULT_POOLSIZE, DEFAULT_RETRIES, HTTPAdapter

logger = logging.getLogger(__name__)

_JUJU_KEYS = ("egress-subnets", "ingress-address", "private-address")


@dataclasses.dataclass()
class CharmDeploymentConfiguration:
    charm: str  # aka charm name or local path to charm
    app: str
    channel: str
    trust: bool
    config: Optional[dict] = None


ISTIO_K8S = CharmDeploymentConfiguration(
    charm="istio-k8s", app="istio-k8s", channel="latest/edge", trust=True
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


def get_k8s_service_address(namespace: str, service_name: str) -> Optional[str]:
    """Get the address of a LoadBalancer Kubernetes service using kubectl.

    Args:
        namespace: The namespace of the Kubernetes resource
        service_name: The name of the Kubernetes service

    Returns:
        The LoadBalancer service address as a string, or None if not found
    """
    try:
        c = lightkube.Client()
        svc = c.get(Service, namespace=namespace, name=service_name)
        return svc.status.loadBalancer.ingress[0].ip

    except Exception as e:
        logger.error("Error retrieving service address %s", e, exc_info=1)
        return None


def get_listener_condition(namespace: str, gateway_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the status of the listener from the Gateway resource as a dictionary.

    Args:
        namespace: The namespace of the Kubernetes resource
        gateway_name: Name of the Gateway resource.

    Returns:
        A dictionary representing the status of the first listener, or None if not found.
    """
    try:
        c = lightkube.Client()
        gateway = c.get(RESOURCE_TYPES["Gateway"], namespace=namespace, name=gateway_name)
        return cast(dict, gateway.status["listeners"][0])

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


def get_listener_spec(namespace: str, gateway_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the spec of the listener from the Gateway resource as a dictionary.

    Args:
        namespace: The namespace of the Kubernetes resource
        gateway_name: Name of the Gateway resource.

    Returns:
        A dictionary representing the spec of the first listener, or None if not found.
    """
    try:
        c = lightkube.Client()
        gateway = c.get(RESOURCE_TYPES["Gateway"], namespace=namespace, name=gateway_name)
        return gateway.spec["listeners"][0]

    except Exception as e:
        logger.error("Error retrieving Gateway listener condition: %s", e, exc_info=1)
        return None


def get_route_spec(namespace: str, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the spec of the HTTPRoute resource.

    Args:
        namespace: The namespace of the Kubernetes resource
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the spec of the route, or None if not found.
    """
    try:
        c = lightkube.Client()
        route = c.get(RESOURCE_TYPES["HTTPRoute"], namespace=namespace, name=route_name)
        return route.spec

    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


def get_auth_policy_spec(namespace: str, policy_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the spec of the AuthorizationPolicy resource.

    Args:
        namespace: The namespace of the Kubernetes resource
        policy_name: Name of the AuthorizationPolicy resource.

    Returns:
        A dictionary representing the spec of the policy, or None if not found.
    """
    try:
        c = lightkube.Client()
        policy = c.get(
            RESOURCE_TYPES["AuthorizationPolicy"], namespace=namespace, name=policy_name
        )
        return policy.spec

    except Exception as e:
        logger.error("Error retrieving AuthorizationPolicy condition: %s", e, exc_info=1)
        return None


def get_configmap_data(namespace: str, cm_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the data of the ConfigMap resource.

    Args:
        namespace: The namespace of the Kubernetes resource
        cm_name: Name of the ConfigMap resource.

    Returns:
        A dictionary representing the data of the ConfigMap, or None if not found.
    """
    try:
        c = lightkube.Client()
        cm = c.get(ConfigMap, name=cm_name, namespace=namespace)
        return cm.data

    except Exception as e:
        logger.error("Error retrieving ConfigMap: %s", e, exc_info=1)
        return None


def get_route_condition(namespace, route_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve and check the condition from the HTTPRoute resource.

    Args:
        namespace: Name of the Kubernetes namespace.
        route_name: Name of the HTTPRoute resource.

    Returns:
        A dictionary representing the status of the parent gateway the route is attached to, or None if not found.
    """
    try:
        c = lightkube.Client()
        route = c.get(RESOURCE_TYPES["HTTPRoute"], namespace=namespace, name=route_name)
        return cast(dict, route.status["parents"][0])
    except Exception as e:
        logger.error("Error retrieving HTTPRoute condition: %s", e, exc_info=1)
        return None


def get_hpa(namespace: str, hpa_name: str) -> Optional[HorizontalPodAutoscaler]:
    """Retrieve the HPA resource so we can inspect .spec and .status directly.

    Args:
        namespace: The namespace of the Kubernetes resource
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


def scale_application(juju: jubilant.Juju, app: str, scale: int):
    args = ["scale-application", app, str(scale)]
    juju.cli(*args)


@dataclasses.dataclass()
class UnitRelationData:
    unit_name: str
    endpoint: str
    leader: bool
    application_data: Dict[str, str]
    unit_data: Dict[str, str]


def remove_default_unit_data_keys(data: dict):
    """Remove the default keys added to all relations, editing data in place."""
    for key in _JUJU_KEYS:
        if key in data:
            del data[key]


def get_content(
    juju: jubilant.Juju, app: str, other_app, include_default_juju_keys: bool = False
) -> UnitRelationData:
    """Get the content of the databag of `obj`, as seen from `other_obj`."""
    unit_name, endpoint = app.split(":")
    other_unit_name, other_endpoint = other_app.split(":")

    unit_data, app_data, leader = get_databags(
        juju, unit_name, endpoint, other_unit_name, other_endpoint
    )

    if not include_default_juju_keys:
        remove_default_unit_data_keys(unit_data)

    return UnitRelationData(unit_name, endpoint, leader, app_data, unit_data)


def get_databags(juju: jubilant.Juju, local_unit, local_endpoint, remote_unit, remote_endpoint):
    """Get the databags of local unit and its leadership status.

    Given a remote unit and the remote endpoint name.

    Args:
        juju: A jubilant.Juju configured to the model containing both local and remote units
        local_unit: Name of the local unit
        local_endpoint: Name of the local endpoint
        remote_unit: Name of the remote unit
        remote_endpoint: Name of the remote endpoint
    """
    local_data = get_unit_info(juju, local_unit)
    leader = local_data["leader"]

    remote_data = get_unit_info(juju, remote_unit)
    relation_info = remote_data.get("relation-info")
    if not relation_info:
        raise RuntimeError(f"{remote_unit} has no relations")

    raw_data = get_relation_by_endpoint(relation_info, local_endpoint, remote_endpoint, local_unit)
    unit_data = raw_data["related-units"][local_unit]["data"]
    app_data = raw_data["application-data"]
    return unit_data, app_data, leader


def get_unit_info(juju: jubilant.Juju, unit_name: str) -> dict:
    """Return unit-info data structure as a dictionary.

    for example:

    istio-ingress-k8s/0:
      opened-ports: []
      charm: local:focal/istio-ingress-k8s-1
      leader: true
      relation-info:
      - endpoint: ingress-per-unit
        related-endpoint: ingress
        application-data:
          _supported_versions: '- v1'
        related-units:
          prometheus-k8s/0:
            in-scope: true
            data:
              egress-subnets: 10.152.183.150/32
              ingress-address: 10.152.183.150
              private-address: 10.152.183.150
      provider-id: istio-ingress-k8s-0
      address: 10.1.232.144
    """
    args = ("show-unit", unit_name)
    raw_data = juju.cli(*args)
    data = yaml.safe_load(raw_data)

    try:
        return data[unit_name]
    except KeyError as e:
        raise KeyError(f"Unit {unit_name} not found") from e


def get_relation_by_endpoint(relations, local_endpoint, remote_endpoint, remote_obj):
    matches = [
        r
        for r in relations
        if (
            (r["endpoint"] == local_endpoint and r["related-endpoint"] == remote_endpoint)
            or (r["endpoint"] == remote_endpoint and r["related-endpoint"] == local_endpoint)
        )
        and remote_obj in r["related-units"]
    ]
    if not matches:
        raise ValueError(
            f"no matches found with endpoint=="
            f"{local_endpoint} "
            f"in {remote_obj} (matches={matches})"
        )
    if len(matches) > 1:
        raise ValueError(
            "multiple matches found with endpoint=="
            f"{local_endpoint} "
            f"in {remote_obj} (matches={matches})"
        )
    return matches[0]


@dataclasses.dataclass()
class RelationData:
    provider: UnitRelationData
    requirer: UnitRelationData


def get_relation_data(
    *,
    juju: jubilant.Juju,
    provider_endpoint: str,
    requirer_endpoint: str,
    include_default_juju_keys: bool = False,
):
    """Get relation databags for a juju relation.

    >>> get_relation_data('prometheus/0:ingress', 'istio-ingress/1:ingress-per-unit')
    """
    provider_data = get_content(
        juju, provider_endpoint, requirer_endpoint, include_default_juju_keys
    )
    requirer_data = get_content(
        juju, requirer_endpoint, provider_endpoint, include_default_juju_keys
    )
    return RelationData(provider=provider_data, requirer=requirer_data)
