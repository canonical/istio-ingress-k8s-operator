# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import scenario

from charm import IstioIngressCharm


def test_relation_changed_status():
    ctx = scenario.Context(IstioIngressCharm)
    state = scenario.State()
    out = ctx.run("start", state)
    assert out.unit_status.name == "active"
