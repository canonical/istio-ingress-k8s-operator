#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""This module defines Pydantic schemas for various resources used in the Kubernetes Gateway API."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


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

    namespaces: Dict[str, str] = {"from": "All"}


class Listener(BaseModel):
    """Listener defines a port and protocol configuration."""

    name: str = "default"
    port: int = 80
    protocol: str = "HTTP"
    allowedRoutes: AllowedRoutes = AllowedRoutes()  # noqa: N815


class GatewaySpec(BaseModel):
    """GatewaySpec defines the specification of a gateway."""

    gatewayClassName: str = "istio"  # noqa: N815
    listeners: List[Listener] = Field(default_factory=lambda: [Listener()])


class GatewayResource(BaseModel):
    """GatewayResource defines the structure of a Gateway Kubernetes resource."""

    metadata: Metadata
    spec: GatewaySpec


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
    filters: Optional[List[URLRewriteFilter]] = None


class HTTPRouteResourceSpec(BaseModel):
    """HTTPRouteResourceSpec defines the specification of an HTTPRoute Kubernetes resource."""

    parentRefs: List[ParentRef]  # noqa: N815
    rules: List[Rule]


class HTTPRouteResource(BaseModel):
    """HTTPRouteResource defines the structure of an HTTPRoute Kubernetes resource."""

    metadata: Metadata
    spec: HTTPRouteResourceSpec
