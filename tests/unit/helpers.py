#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from canonical_service_mesh.models import (
    HTTPRouteResource,
    HTTPRouteResourceSpec,
    HTTPRouteRule,
    Metadata,
)

from utils import HTTPRoute


def dict_to_httproute(d) -> HTTPRoute :
    return HTTPRoute(
        resource=HTTPRouteResource(
                metadata=Metadata(
                    name=d["name"],
                    namespace=d["namespace"],
                ),
                spec=HTTPRouteResourceSpec(
                    parentRefs=[],
                    rules=[
                        HTTPRouteRule(
                            matches=d["matches"],
                            backendRefs=d["backend_refs"],
                            filters=d["filters"],
                        )
                    ],
                ),
            ),
        listener_port=d["listener_port"],
        listener_protocol=d["listener_protocol"],
        source_app=d["source_app"],
        source_relation=d["source_relation"],
    )
