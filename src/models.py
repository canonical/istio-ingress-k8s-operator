#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""This module defines Pydantic schemas for various resources used in the Kubernetes Gateway API."""
from typing import Dict, List, Optional

from charms.istio_ingress_k8s.v0.istio_ingress_route import GRPCRouteFilter, HTTPRouteFilter
from pydantic import BaseModel

# TODO: Deduplicate and consolidate the mix-n-match of models between here and istio_ingress_route lib. See https://github.com/canonical/istio-ingress-k8s-operator/issues/117.


# Global metadata schema
class Metadata(BaseModel):
    """Global metadata schema for Kubernetes resources."""

    name: str
    namespace: str
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None


# Gateway schema
class AllowedRoutes(BaseModel):
    """AllowedRoutes defines namespaces from which traffic is allowed."""

    namespaces: Dict[str, str]


class SecretObjectReference(BaseModel):
    """SecretObjectReference defines a reference to a Kubernetes secret."""

    group: Optional[str] = None
    kind: Optional[str] = None
    name: str
    namespace: Optional[str] = None


class GatewayTLSConfig(BaseModel):
    """GatewayTLSConfig defines the TLS configuration for a listener."""

    certificateRefs: Optional[List[SecretObjectReference]] = None
    # Not yet implemented:
    # mode
    # frontendValidation
    # options


class Listener(BaseModel):
    """Listener defines a port and protocol configuration."""

    name: str
    port: int
    protocol: str
    allowedRoutes: AllowedRoutes  # noqa: N815
    hostname: Optional[str] = None
    tls: Optional[GatewayTLSConfig] = None


class IstioGatewaySpec(BaseModel):
    """GatewaySpec defines the specification of a gateway."""

    gatewayClassName: str  # noqa: N815
    listeners: List[Listener]


class IstioGatewayResource(BaseModel):
    """GatewayResource defines the structure of a Gateway Kubernetes resource."""

    metadata: Metadata
    spec: IstioGatewaySpec


# HTTPRoute schema
class ParentRef(BaseModel):
    """ParentRef specifies the parent gateway resource for this route."""

    name: str
    namespace: str
    sectionName: str


class HTTPPathMatch(BaseModel):
    """HTTPPathMatch defines the type and value of path matching."""

    type: str = "PathPrefix"
    value: str


class HTTPRouteMatch(BaseModel):
    """HTTPRouteMatch defines the path matching configuration."""

    path: HTTPPathMatch


class BackendRef(BaseModel):
    """BackendRef specifies the backend service reference that traffic will be routed to."""

    name: str
    port: int
    namespace: str


class HTTPRouteRule(BaseModel):
    """HTTPRouteRule defines the routing rule configuration."""

    matches: List[HTTPRouteMatch]
    backendRefs: Optional[List[BackendRef]] = []  # noqa: N815
    filters: Optional[List[HTTPRouteFilter]] = []


class HTTPRouteResourceSpec(BaseModel):
    """HTTPRouteResourceSpec defines the specification of an HTTPRoute Kubernetes resource."""

    parentRefs: List[ParentRef]  # noqa: N815
    rules: List[HTTPRouteRule]

    # TODO: uncomment the below when support is added for both wildcards and using subdomains
    # hostnames: Optional[List[str]] = []


class HTTPRouteResource(BaseModel):
    """HTTPRouteResource defines the structure of an HTTPRoute Kubernetes resource."""

    metadata: Metadata
    spec: HTTPRouteResourceSpec


# GRPCRoute schema
class GRPCMethodMatch(BaseModel):
    """GRPCMethodMatch defines the gRPC method matching configuration."""

    service: Optional[str] = None
    method: Optional[str] = None


class GRPCRouteMatch(BaseModel):
    """GRPCRouteMatch defines the matching configuration for gRPC routes."""

    method: Optional[GRPCMethodMatch] = None


class GRPCRouteRule(BaseModel):
    """GRPCRouteRule defines the routing rule configuration for gRPC routes."""

    matches: Optional[List[GRPCRouteMatch]] = None
    backendRefs: Optional[List[BackendRef]] = []  # noqa: N815
    filters: Optional[List[GRPCRouteFilter]] = []


class GRPCRouteResourceSpec(BaseModel):
    """GRPCRouteResourceSpec defines the specification of a GRPCRoute Kubernetes resource."""

    parentRefs: List[ParentRef]  # noqa: N815
    rules: List[GRPCRouteRule]


class GRPCRouteResource(BaseModel):
    """GRPCRouteResource defines the structure of a GRPCRoute Kubernetes resource."""

    metadata: Metadata
    spec: GRPCRouteResourceSpec
