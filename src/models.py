#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""This module defines Pydantic schemas for various resources used in the Kubernetes Gateway API."""

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict


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


class Listener(BaseModel):
    """Listener defines a port and protocol configuration."""

    model_config = ConfigDict(extra="allow")

    name: str
    port: int
    protocol: str
    allowedRoutes: AllowedRoutes  # noqa: N815


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


class PathMatch(BaseModel):
    """PathMatch defines the type and value of path matching."""

    type: str = "PathPrefix"
    value: str


class Match(BaseModel):
    """Match defines the path matching configuration."""

    path: PathMatch


class PrefixPathConfig(BaseModel):
    """PrefixPathConfig defines the configuration for prefix-based path matching."""

    type: str = "ReplacePrefixMatch"
    replacePrefixMatch: str = "/"  # noqa: N815


class URLRewriteConfig(BaseModel):
    """URLRewriteConfig defines the configuration for URL rewriting."""

    path: PrefixPathConfig = PrefixPathConfig()


class URLRewriteFilter(BaseModel):
    """URLRewriteFilter defines the URL rewriting filter."""

    type: str = "URLRewrite"
    urlRewrite: URLRewriteConfig = URLRewriteConfig()  # noqa: N815


class BackendRef(BaseModel):
    """BackendRef specifies the backend service reference that traffic will be routed to."""

    name: str
    port: int
    namespace: str


class Rule(BaseModel):
    """Rule defines the routing rule configuration."""

    matches: List[Match]
    backendRefs: List[BackendRef]  # noqa: N815
    filters: Optional[List[URLRewriteFilter]] = []


class HTTPRouteResourceSpec(BaseModel):
    """HTTPRouteResourceSpec defines the specification of an HTTPRoute Kubernetes resource."""

    parentRefs: List[ParentRef]  # noqa: N815
    rules: List[Rule]


class HTTPRouteResource(BaseModel):
    """HTTPRouteResource defines the structure of an HTTPRoute Kubernetes resource."""

    metadata: Metadata
    spec: HTTPRouteResourceSpec
