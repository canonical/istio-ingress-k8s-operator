from typing import Dict, List, Optional

from pydantic import BaseModel, Field


# Global metadata schema
class Metadata(BaseModel):
    name: str
    namespace: str
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None


# Gateway schema
class AllowedRoutes(BaseModel):
    namespaces: Dict[str, str] = {"from": "All"}


class Listener(BaseModel):
    name: str = "default"
    port: int = 80
    protocol: str = "HTTP"
    allowedRoutes: AllowedRoutes = AllowedRoutes()


class GatewaySpec(BaseModel):
    gatewayClassName: str = "istio"
    listeners: List[Listener] = Field(default_factory=lambda: [Listener()])


class GatewayResource(BaseModel):
    metadata: Metadata
    spec: GatewaySpec


# HTTPRoute schema
class ParentRef(BaseModel):
    name: str
    namespace: str


class PathMatch(BaseModel):
    type: str = "PathPrefix"
    value: str


class Match(BaseModel):
    path: PathMatch


class PrefixPathConfig(BaseModel):
    type: str = "ReplacePrefixMatch"
    replacePrefixMatch: str = "/"


class URLRewriteConfig(BaseModel):
    path: PrefixPathConfig = PrefixPathConfig()


class URLRewriteFilter(BaseModel):
    type: str = "URLRewrite"
    urlRewrite: URLRewriteConfig = URLRewriteConfig()


class BackendRef(BaseModel):
    name: str
    port: int
    namespace: str


class Rule(BaseModel):
    matches: List[Match]
    backendRefs: List[BackendRef]
    filters: Optional[List[URLRewriteFilter]] = None


class HTTPRouteResourceSpec(BaseModel):
    parentRefs: List[ParentRef]
    rules: List[Rule]


class HTTPRouteResource(BaseModel):
    metadata: Metadata
    spec: HTTPRouteResourceSpec
