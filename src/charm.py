#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Ingress Charm."""

import logging

import ops
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider as IPAv2

logger = logging.getLogger(__name__)


class IstioIngressCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)

        self.ingress_per_appv2 = IPAv2(charm=self)

        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.ingress_per_appv2.on.data_provided, self._handle_ingress_data_provided)  # type: ignore
        self.framework.observe(self.ingress_per_appv2.on.data_removed, self._handle_ingress_data_removed)  # type: ignore

    def _on_start(self, _):
        """Event handler for start."""
        self.unit.status = ops.ActiveStatus()

    def _handle_ingress_data_provided(self, _):
        """Handle a unit providing data requesting IPU."""
        self.unit.status = ops.BlockedStatus("Not yet implemented")

    def _handle_ingress_data_removed(self, _):
        """Handle a unit removing the data needed to provide ingress."""
        self.unit.status = ops.BlockedStatus("Not yet implemented")


if __name__ == "__main__":
    ops.main(IstioIngressCharm)  # type: ignore
