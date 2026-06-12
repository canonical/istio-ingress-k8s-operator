#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from canonical_service_mesh.models import (
    GRPCRouteResource,
    GRPCRouteResourceSpec,
    GRPCRouteRule,
    HTTPRouteResource,
    HTTPRouteResourceSpec,
    HTTPRouteRule,
    Metadata,
)

from utils import (
    ROUTE_LISTENER_PORT_LABEL,
    ROUTE_LISTENER_PROTOCOL_LABEL,
    ROUTE_SOURCE_APP_LABEL,
    ROUTE_SOURCE_RELATION_LABEL,
)


def dict_to_httproute(d) -> HTTPRouteResource :
    return HTTPRouteResource(
        metadata=Metadata(
            name=d["name"],
            namespace=d["namespace"],
            labels={
                ROUTE_LISTENER_PORT_LABEL: str(d["listener_port"]),
                ROUTE_LISTENER_PROTOCOL_LABEL: d["listener_protocol"],
                ROUTE_SOURCE_APP_LABEL: d["source_app"],
                ROUTE_SOURCE_RELATION_LABEL: d["source_relation"],
            }
        ),
        spec=HTTPRouteResourceSpec(
            parentRefs = d["parentRefs"] if "parentRefs" in d else [],
            rules=[
                HTTPRouteRule(
                    matches=d["matches"],
                    backendRefs=d["backend_refs"],
                    filters=d["filters"],
                )
            ],
        ),
    )


def dict_to_grpcroute(d) -> GRPCRouteResource:
    return GRPCRouteResource(
        metadata=Metadata(
            name=d["name"],
            namespace=d["namespace"],
            labels={
                ROUTE_LISTENER_PORT_LABEL: str(d["listener_port"]),
                ROUTE_LISTENER_PROTOCOL_LABEL: d["listener_protocol"],
                ROUTE_SOURCE_APP_LABEL: d["source_app"],
                ROUTE_SOURCE_RELATION_LABEL: d["source_relation"],
            }
        ),
        spec=GRPCRouteResourceSpec(
            parentRefs=[], # TODO
            rules=[
                GRPCRouteRule(
                    matches=d["matches"],
                    backendRefs=d["backend_refs"],
                    filters=d["filters"] if "filters" in d and d["filters"] else None,
                )
            ],
        ),
    )
