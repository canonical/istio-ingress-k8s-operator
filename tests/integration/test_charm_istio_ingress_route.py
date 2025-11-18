# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from dataclasses import asdict
from pathlib import Path

import lightkube
import pytest
import yaml
from helpers import (
    get_ca_certificate,
    get_grpc_route_condition,
    get_http_response,
    get_k8s_service_address,
    get_route_condition,
    get_route_spec,
    istio_k8s,
    send_grpc_request,
    send_grpc_request_with_tls,
    send_http_request,
    send_http_request_with_custom_ca,
)
from lightkube.generic_resource import create_namespaced_resource
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
TESTER_HTTP = "tester-http"
TESTER_GRPC = "tester-grpc"
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


@pytest.mark.abort_on_fail
async def test_deploy_dependencies(ops_test: OpsTest):
    """Deploys dependencies across two models: one for Istio and one for testers.

    This test uses a multi-model approach to isolate Istio and the testers in
    separate Kubernetes namespaces. It deploys Istio in the 'istio-core' model
    and testers in the main test model.
    """
    # Instantiate a second model for istio-core.  ops_test automatically gives it a unique name,
    # but we provide a user-friendly alias of "istio-core"
    await ops_test.track_model("istio-core")
    istio_core = ops_test.models.get("istio-core")

    # Deploy Istio-k8s
    await istio_core.model.deploy(**asdict(istio_k8s))
    await istio_core.model.wait_for_idle(
        [
            istio_k8s.application_name,
        ],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_deployment(ops_test: OpsTest, istio_ingress_charm):
    await ops_test.model.deploy(
        istio_ingress_charm, resources=resources, application_name=APP_NAME, trust=True
    )
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_deploy_testers(ops_test: OpsTest, tester_http_charm, tester_grpc_charm):
    """Deploy HTTP tester, gRPC tester, and self-signed-certificates charms."""
    await ops_test.model.deploy(
        tester_http_charm,
        application_name=TESTER_HTTP,
        resources={"echo-server-image": "jmalloc/echo-server:v0.3.7"},
    )
    await ops_test.model.deploy(
        tester_grpc_charm,
        application_name=TESTER_GRPC,
        resources={"grpc-server-image": "moul/grpcbin:latest"},
    )
    await ops_test.model.deploy("self-signed-certificates")
    await ops_test.model.wait_for_idle(
        [TESTER_HTTP, TESTER_GRPC, "self-signed-certificates"],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_relate_tester_http(ops_test: OpsTest):
    """Relate tester-http to istio-ingress-k8s via istio-ingress-route."""
    await ops_test.model.add_relation(
        f"{TESTER_HTTP}:istio-ingress-route", f"{APP_NAME}:istio-ingress-route"
    )
    await ops_test.model.wait_for_idle([APP_NAME, TESTER_HTTP], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_relate_tester_grpc(ops_test: OpsTest):
    """Relate tester-grpc to istio-ingress-k8s via istio-ingress-route."""
    await ops_test.model.add_relation(
        f"{TESTER_GRPC}:istio-ingress-route", f"{APP_NAME}:istio-ingress-route"
    )
    await ops_test.model.wait_for_idle([APP_NAME, TESTER_GRPC], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_http_routes_validity(ops_test: OpsTest):
    """Test that HTTP routes from tester-http are correctly configured."""
    # Get the Gateway with all listeners
    gateway_resource = create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    )
    c = lightkube.Client()
    gateway = c.get(gateway_resource, namespace=ops_test.model.name, name="istio-ingress-k8s")

    # Find the http-8080 listener
    listener_condition = None
    listener_spec = None
    for listener in gateway.status["listeners"]:
        if listener["name"] == "http-8080":
            listener_condition = listener
            break
    for listener in gateway.spec["listeners"]:
        if listener["name"] == "http-8080":
            listener_spec = listener
            break

    assert listener_condition is not None, "Listener http-8080 not found in Gateway status"
    assert listener_spec is not None, "Listener http-8080 not found in Gateway spec"

    # Should have 3 HTTP routes attached (api-route, health-route, and rewrite-route from tester-http)
    assert listener_condition["attachedRoutes"] == 3
    assert listener_condition["conditions"][0]["message"] == "No errors found"
    assert listener_condition["conditions"][0]["reason"] == "Accepted"
    assert listener_spec["port"] == 8080
    assert listener_spec["protocol"] == "HTTP"

    # Test api-route
    api_route_name = f"{TESTER_HTTP}-api-route-httproute-http-8080-{APP_NAME}"
    api_route_condition = await get_route_condition(ops_test, api_route_name)
    assert api_route_condition["conditions"][0]["message"] == "Route was valid"
    assert api_route_condition["conditions"][0]["reason"] == "Accepted"
    assert api_route_condition["controllerName"] == "istio.io/gateway-controller"

    # Test health-route
    health_route_name = f"{TESTER_HTTP}-health-route-httproute-http-8080-{APP_NAME}"
    health_route_condition = await get_route_condition(ops_test, health_route_name)
    assert health_route_condition["conditions"][0]["message"] == "Route was valid"
    assert health_route_condition["conditions"][0]["reason"] == "Accepted"

    # Test rewrite-route
    rewrite_route_name = f"{TESTER_HTTP}-rewrite-route-httproute-http-8080-{APP_NAME}"
    rewrite_route_condition = await get_route_condition(ops_test, rewrite_route_name)
    assert rewrite_route_condition["conditions"][0]["message"] == "Route was valid"
    assert rewrite_route_condition["conditions"][0]["reason"] == "Accepted"


@pytest.mark.abort_on_fail
async def test_http_routes_connectivity(ops_test: OpsTest):
    """Test that HTTP routes are accessible via the ingress gateway."""
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")

    # Test /api endpoint
    api_url = f"http://{istio_ingress_address}:8080/api"
    assert send_http_request(api_url), f"Failed to reach {api_url}"

    # Test /health endpoint
    health_url = f"http://{istio_ingress_address}:8080/health"
    assert send_http_request(health_url), f"Failed to reach {health_url}"


@pytest.mark.abort_on_fail
async def test_http_route_urlrewrite_filter(ops_test: OpsTest):
    """Test that URLRewrite filter correctly rewrites request paths."""
    route_name = f"{TESTER_HTTP}-rewrite-route-httproute-http-8080-{APP_NAME}"
    route_spec = await get_route_spec(ops_test, route_name)

    # Verify filter exists and is configured correctly
    assert route_spec is not None, f"HTTPRoute {route_name} not found"
    assert "rules" in route_spec and len(route_spec["rules"]) > 0

    rule = route_spec["rules"][0]
    assert rule.get("filters") and len(rule["filters"]) == 1

    filter_spec = rule["filters"][0]
    assert filter_spec["type"] == "URLRewrite"
    assert filter_spec["urlRewrite"]["path"]["type"] == "ReplacePrefixMatch"
    assert filter_spec["urlRewrite"]["path"]["replacePrefixMatch"] == "/api"

    # Test end-to-end: verify echo server receives rewritten path
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")
    response = get_http_response(f"http://{istio_ingress_address}:8080/old-api/test")

    assert response.status_code == 200, \
        f"Request failed with status {response.status_code}: {response.text}"

    # Echo server returns plain text with request details
    # Second line contains the method and path, e.g., "GET /api/test HTTP/1.1"
    lines = response.text.strip().split('\n')
    request_line = lines[2] if len(lines) > 2 else ""
    assert "/api/test" in request_line, \
        f"Expected rewritten path '/api/test' in request line, got: {request_line}"


@pytest.mark.abort_on_fail
async def test_grpc_routes_validity(ops_test: OpsTest):
    """Test that gRPC routes from tester-grpc are correctly configured."""
    # Get the Gateway with all listeners
    gateway_resource = create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    )
    c = lightkube.Client()
    gateway = c.get(gateway_resource, namespace=ops_test.model.name, name="istio-ingress-k8s")

    # Find the http-9000 listener
    listener_condition = None
    listener_spec = None
    for listener in gateway.status["listeners"]:
        if listener["name"] == "http-9000":
            listener_condition = listener
            break
    for listener in gateway.spec["listeners"]:
        if listener["name"] == "http-9000":
            listener_spec = listener
            break

    assert listener_condition is not None, "Listener http-9000 not found in Gateway status"
    assert listener_spec is not None, "Listener http-9000 not found in Gateway spec"

    # Should have 3 gRPC routes attached (empty-route, headersunary-route, reflection-route from tester-grpc)
    assert listener_condition["attachedRoutes"] == 3
    assert listener_condition["conditions"][0]["message"] == "No errors found"
    assert listener_condition["conditions"][0]["reason"] == "Accepted"
    assert listener_spec["port"] == 9000
    assert listener_spec["protocol"] == "HTTP"

    # Test empty-route
    empty_route_name = f"{TESTER_GRPC}-empty-route-grpcroute-http-9000-{APP_NAME}"
    empty_route_condition = await get_grpc_route_condition(ops_test, empty_route_name)
    assert empty_route_condition["conditions"][0]["message"] == "Route was valid"
    assert empty_route_condition["conditions"][0]["reason"] == "Accepted"
    assert empty_route_condition["controllerName"] == "istio.io/gateway-controller"

    # Test headersunary-route
    headersunary_route_name = f"{TESTER_GRPC}-headersunary-route-grpcroute-http-9000-{APP_NAME}"
    headersunary_route_condition = await get_grpc_route_condition(ops_test, headersunary_route_name)
    assert headersunary_route_condition["conditions"][0]["message"] == "Route was valid"
    assert headersunary_route_condition["conditions"][0]["reason"] == "Accepted"

    # Test reflection-route
    reflection_route_name = f"{TESTER_GRPC}-reflection-route-grpcroute-http-9000-{APP_NAME}"
    reflection_route_condition = await get_grpc_route_condition(ops_test, reflection_route_name)
    assert reflection_route_condition["conditions"][0]["message"] == "Route was valid"
    assert reflection_route_condition["conditions"][0]["reason"] == "Accepted"


@pytest.mark.abort_on_fail
async def test_grpc_routes_connectivity(ops_test: OpsTest):
    """Test that gRPC routes are accessible via the ingress gateway."""
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")

    # Test Empty method (takes EmptyMessage)
    assert send_grpc_request(
        istio_ingress_address, 9000, "grpcbin.GRPCBin", "Empty"
    ), "Failed to call grpcbin.GRPCBin/Empty"

    # Test HeadersUnary method (takes EmptyMessage)
    assert send_grpc_request(
        istio_ingress_address, 9000, "grpcbin.GRPCBin", "HeadersUnary"
    ), "Failed to call grpcbin.GRPCBin/HeadersUnary"


@pytest.mark.abort_on_fail
async def test_relate_certificates(ops_test: OpsTest):
    """Relate self-signed-certificates to istio-ingress-k8s and configure external_hostname."""
    await ops_test.model.add_relation(
        "self-signed-certificates:certificates", f"{APP_NAME}:certificates"
    )

    # Configure external_hostname to enable TLS
    await ops_test.model.applications[APP_NAME].set_config(
        {"external_hostname": "test.example.com"}
    )

    await ops_test.model.wait_for_idle(
        [APP_NAME, "self-signed-certificates"],
        status="active",
        timeout=1000
    )


@pytest.mark.abort_on_fail
async def test_tls_http_routes_validity(ops_test: OpsTest):
    """Test that HTTP routes correctly upgrade to HTTPS listeners."""
    gateway_resource = create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    )
    c = lightkube.Client()
    gateway = c.get(gateway_resource, namespace=ops_test.model.name, name="istio-ingress-k8s")

    # Verify HTTPS listener for HTTP routes (port 8080 -> https-8080)
    https_8080_listener_condition = None
    https_8080_listener_spec = None
    for listener in gateway.status["listeners"]:
        if listener["name"] == "https-8080":
            https_8080_listener_condition = listener
            break
    for listener in gateway.spec["listeners"]:
        if listener["name"] == "https-8080":
            https_8080_listener_spec = listener
            break

    assert https_8080_listener_condition is not None, "Listener https-8080 not found in Gateway status"
    assert https_8080_listener_spec is not None, "Listener https-8080 not found in Gateway spec"
    assert https_8080_listener_condition["attachedRoutes"] == 3, "Expected 3 HTTP routes attached to https-8080"
    assert https_8080_listener_spec["port"] == 8080
    assert https_8080_listener_spec["protocol"] == "HTTPS"

    # Verify HTTP routes moved to HTTPS listener
    api_route_name = f"{TESTER_HTTP}-api-route-httproute-https-8080-{APP_NAME}"
    api_route_condition = await get_route_condition(ops_test, api_route_name)
    assert api_route_condition["conditions"][0]["message"] == "Route was valid"
    assert api_route_condition["conditions"][0]["reason"] == "Accepted"

    health_route_name = f"{TESTER_HTTP}-health-route-httproute-https-8080-{APP_NAME}"
    health_route_condition = await get_route_condition(ops_test, health_route_name)
    assert health_route_condition["conditions"][0]["message"] == "Route was valid"
    assert health_route_condition["conditions"][0]["reason"] == "Accepted"

    rewrite_route_name = f"{TESTER_HTTP}-rewrite-route-httproute-https-8080-{APP_NAME}"
    rewrite_route_condition = await get_route_condition(ops_test, rewrite_route_name)
    assert rewrite_route_condition["conditions"][0]["message"] == "Route was valid"
    assert rewrite_route_condition["conditions"][0]["reason"] == "Accepted"


@pytest.mark.abort_on_fail
async def test_tls_http_routes_connectivity(ops_test: OpsTest):
    """Test that HTTP routes are accessible via HTTPS."""
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")

    # Get CA certificate from certificate provider
    cert_unit = ops_test.model.applications["self-signed-certificates"].units[0]
    ca_cert = await get_ca_certificate(cert_unit)

    external_hostname = "test.example.com"

    # Test /api endpoint with TLS
    api_url = f"https://{external_hostname}:8080/api"
    assert (
        send_http_request_with_custom_ca(
            api_url, ca_cert, resolve_netloc_to_ip=istio_ingress_address
        )
        == 200
    ), f"Failed to reach {api_url} with TLS"

    # Test /health endpoint with TLS
    health_url = f"https://{external_hostname}:8080/health"
    assert (
        send_http_request_with_custom_ca(
            health_url, ca_cert, resolve_netloc_to_ip=istio_ingress_address
        )
        == 200
    ), f"Failed to reach {health_url} with TLS"


@pytest.mark.abort_on_fail
async def test_tls_grpc_routes_validity(ops_test: OpsTest):
    """Test that gRPC routes correctly upgrade to HTTPS listeners."""
    gateway_resource = create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    )
    c = lightkube.Client()
    gateway = c.get(gateway_resource, namespace=ops_test.model.name, name="istio-ingress-k8s")

    # Verify HTTPS listener for gRPC routes (port 9000 -> https-9000)
    https_9000_listener_condition = None
    https_9000_listener_spec = None
    for listener in gateway.status["listeners"]:
        if listener["name"] == "https-9000":
            https_9000_listener_condition = listener
            break
    for listener in gateway.spec["listeners"]:
        if listener["name"] == "https-9000":
            https_9000_listener_spec = listener
            break

    assert https_9000_listener_condition is not None, "Listener https-9000 not found in Gateway status"
    assert https_9000_listener_spec is not None, "Listener https-9000 not found in Gateway spec"
    assert https_9000_listener_condition["attachedRoutes"] == 3, "Expected 3 gRPC routes attached to https-9000"
    assert https_9000_listener_spec["port"] == 9000
    assert https_9000_listener_spec["protocol"] == "HTTPS"

    # Verify gRPC routes moved to HTTPS listener
    empty_route_name = f"{TESTER_GRPC}-empty-route-grpcroute-https-9000-{APP_NAME}"
    empty_route_condition = await get_grpc_route_condition(ops_test, empty_route_name)
    assert empty_route_condition["conditions"][0]["message"] == "Route was valid"
    assert empty_route_condition["conditions"][0]["reason"] == "Accepted"

    headersunary_route_name = f"{TESTER_GRPC}-headersunary-route-grpcroute-https-9000-{APP_NAME}"
    headersunary_route_condition = await get_grpc_route_condition(ops_test, headersunary_route_name)
    assert headersunary_route_condition["conditions"][0]["message"] == "Route was valid"
    assert headersunary_route_condition["conditions"][0]["reason"] == "Accepted"

    reflection_route_name = f"{TESTER_GRPC}-reflection-route-grpcroute-https-9000-{APP_NAME}"
    reflection_route_condition = await get_grpc_route_condition(ops_test, reflection_route_name)
    assert reflection_route_condition["conditions"][0]["message"] == "Route was valid"
    assert reflection_route_condition["conditions"][0]["reason"] == "Accepted"


@pytest.mark.abort_on_fail
async def test_tls_grpc_routes_connectivity(ops_test: OpsTest):
    """Test that gRPC routes are accessible via HTTPS."""
    istio_ingress_address = await get_k8s_service_address(ops_test, "istio-ingress-k8s-istio")

    # Get CA certificate from certificate provider
    cert_unit = ops_test.model.applications["self-signed-certificates"].units[0]
    ca_cert = await get_ca_certificate(cert_unit)

    external_hostname = "test.example.com"

    # Test Empty method with TLS
    assert send_grpc_request_with_tls(
        istio_ingress_address, 9000, "grpcbin.GRPCBin", "Empty", ca_cert, hostname=external_hostname
    ), "Failed to call grpcbin.GRPCBin/Empty with TLS"

    # Test HeadersUnary method with TLS
    assert send_grpc_request_with_tls(
        istio_ingress_address, 9000, "grpcbin.GRPCBin", "HeadersUnary", ca_cert, hostname=external_hostname
    ), "Failed to call grpcbin.GRPCBin/HeadersUnary with TLS"

