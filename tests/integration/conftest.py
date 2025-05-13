# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from pytest_jubilant import pack_charm
from pytest_jubilant.main import TempModelFactory

logger = logging.getLogger(__name__)

_JUJU_DATA_CACHE = {}
_JUJU_KEYS = ("egress-subnets", "ingress-address", "private-address")


@pytest.fixture(scope="module")
def juju_istio_system(temp_model_factory: TempModelFactory):
    """Return a Juju client configured for the istio-system model, automatically creating that model as needed."""
    yield temp_model_factory.get_juju(suffix="istio-system")


def _pack_ingress_charm():
    # Convenience for using pre-packed charm in CI
    if charm_file := os.environ.get("CHARM_PATH"):
        return Path(charm_file)

    # Intermittent issue where charmcraft fails to build the charm for an unknown reason.
    # Retry building the charm
    for _ in range(3):
        logger.info("packing...")
        try:
            pth = pack_charm().charm.absolute()
        except subprocess.CalledProcessError:
            logger.warning("Failed to pack. Trying again!")
            continue
        return pth
    raise ValueError("Failed to pack")


def _pack_ipa_tester_charm():
    # TODO: This is basically duplicated with the above _pack_ingress_charm because the above needs to handle the
    #  CHARM_PATH environment variable.  We should modify the CI so testers can be packed externally like the main
    #  charm, and this helper should collapse into a generic version of the one above.
    charm_path = (Path(__file__).parent / "testers" / "ipa").absolute()

    # Intermittent issue where charmcraft fails to build the charm for an unknown reason.
    # Retry building the charm
    for _ in range(3):
        logger.info("packing...")
        try:
            pth = pack_charm(charm_path).charm.absolute()
        except subprocess.CalledProcessError:
            logger.warning("Failed to pack. Trying again!")
            continue
        return pth
    raise ValueError("Failed to pack")


@pytest.fixture(scope="module")
def istio_ingress_charm():
    return _pack_ingress_charm()


@pytest.fixture(scope="module", autouse=True)
def copy_traefik_library_into_tester_charms():
    """Ensure the tester charms have the requisite libraries."""
    libraries = [
        "traefik_k8s/v2/ingress.py",
    ]
    for tester in ["ipa"]:
        for lib in libraries:
            install_path = f"tests/integration/testers/{tester}/lib/charms/{lib}"
            os.makedirs(os.path.dirname(install_path), exist_ok=True)
            shutil.copyfile(f"lib/charms/{lib}", install_path)


@pytest.fixture(scope="module")
def ipa_tester_charm():
    return _pack_ipa_tester_charm()
