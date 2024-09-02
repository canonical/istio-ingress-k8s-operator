#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus
from ops.pebble import Layer


class IPARequirerMock(CharmBase):
    def __init__(self, framework):
        super().__init__(framework)
        self.unit.set_ports(8080)
        self.ipa = IngressPerAppRequirer(self, port=8080)

        self.framework.observe(self.on.echo_server_pebble_ready, self._on_pebble_ready)

    def _on_pebble_ready(self, _):
        container = self.unit.get_container("echo-server")
        if not container.can_connect():
            self.unit.status = WaitingStatus("Waiting for Pebble ready")
            return

        layer = Layer(
            {
                "summary": "echo server layer",
                "description": "pebble config layer for echo server",
                "services": {
                    "echo-server": {
                        "override": "replace",
                        "command": "/bin/echo-server",
                        "startup": "enabled",
                    }
                },
            }
        )

        container.add_layer("echo-server", layer, combine=True)
        container.autostart()
        self.unit.status = ActiveStatus("Echo server running")


if __name__ == "__main__":
    main(IPARequirerMock)
