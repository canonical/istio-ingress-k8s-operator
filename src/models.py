#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""This module defines Pydantic schemas for various resources used in the Kubernetes Gateway API."""
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


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


class HTTPRouteFilterType(str, Enum):
    """HTTPRouteFilterType defines the type of HTTP filter."""

    ExtensionRef = "ExtensionRef"
    RequestHeaderModifier = "RequestHeaderModifier"
    RequestMirror = "RequestMirror"
    RequestRedirect = "RequestRedirect"
    ResponseHeaderModifier = "ResponseHeaderModifier"
    URLRewrite = "URLRewrite"


class HTTPURLRewriteFilter(BaseModel):
    """URLRewriteConfig defines the configuration for URL rewriting."""

    path: PrefixPathConfig = PrefixPathConfig()


class HTTPRequestRedirectFilter(BaseModel):
    """HTTPRequestRedirectConfig defines the configuration for request redirection."""

    scheme: str
    statusCode: int
    # Not implemented
    # hostname
    # path
    # port


class HTTPRouteFilter(BaseModel):
    """HTTPRouteFilter defines the HTTP filter configuration."""

    type: HTTPRouteFilterType
    requestRedirect: Optional[HTTPRequestRedirectFilter] = None
    urlRewrite: Optional[HTTPURLRewriteFilter] = None


class BackendRef(BaseModel):
    """BackendRef specifies the backend service reference that traffic will be routed to."""

    name: str
    port: int
    namespace: str


class Rule(BaseModel):
    """Rule defines the routing rule configuration."""

    matches: List[Match]
    backendRefs: Optional[List[BackendRef]] = []  # noqa: N815
    filters: Optional[List[HTTPRouteFilter]] = []


class HTTPRouteResourceSpec(BaseModel):
    """HTTPRouteResourceSpec defines the specification of an HTTPRoute Kubernetes resource."""

    parentRefs: List[ParentRef]  # noqa: N815
    rules: List[Rule]

    # TODO: uncomment the below when support is added for both wildcards and using subdomains
    # hostnames: Optional[List[str]] = []


class HTTPRouteResource(BaseModel):
    """HTTPRouteResource defines the structure of an HTTPRoute Kubernetes resource."""

    metadata: Metadata
    spec: HTTPRouteResourceSpec


# Authrization Policy schema
# Below is stripped down to cater for only L4 needed policies for ingress


class Action(str, Enum):
    """Action is a type that represents the action to take when a rule matches."""

    allow = "ALLOW"


class WorkloadSelector(BaseModel):
    """WorkloadSelector defines the selector for the policy."""

    matchLabels: Dict[str, str]


class Source(BaseModel):
    """Source defines the source of the policy."""

    principals: Optional[List[str]] = None


class From(BaseModel):
    """From defines the source of the policy."""

    source: Source


class Operation(BaseModel):
    """Operation defines the operation of the To model."""

    ports: Optional[List[str]] = None
    paths: Optional[List[str]] = None


class To(BaseModel):
    """To defines the destination of the policy."""

    operation: Optional[Operation] = None


class AuthRule(BaseModel):
    """AuthRule defines a policy rule."""

    from_: Optional[List[From]] = Field(default=None, alias="from")
    to: Optional[List[To]] = None
    # Allows us to populate with `Rule(from_=[From()])`.  Without this, we can only use they alias `from`, which is
    # protected, meaning we could only build rules from a dict like `Rule(**{"from": [From()]})`.
    model_config = ConfigDict(populate_by_name=True)


class AuthorizationPolicySpec(BaseModel):
    """AuthorizationPolicySpec defines the spec of an Istio AuthorizationPolicy Kubernetes resource."""

    action: Action = Action.allow
    rules: List[AuthRule]
    selector: WorkloadSelector


class AuthorizationPolicyResource(BaseModel):
    """AuthorizationPolicyResource defines the structure of an Istio AuthorizationPolicy Kubernetes resource."""

    metadata: Metadata
    spec: AuthorizationPolicySpec
