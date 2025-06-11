# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import functools
import logging
import os
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict

import pytest
import yaml
from charmed_service_mesh_helpers.testing.charm_dependency_management import CharmManifest, CharmManifestEntry, charm_manifest  # pytest fixture
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

_JUJU_DATA_CACHE = {}
_JUJU_KEYS = ("egress-subnets", "ingress-address", "private-address")

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
ISTIO_INGRESS_RESOURCES = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


class Store(defaultdict):
    def __init__(self):
        super(Store, self).__init__(Store)

    def __getattr__(self, key):
        """Override __getattr__ so dot syntax works on keys."""
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        """Override __setattr__ so dot syntax works on keys."""
        self[key] = value


store = Store()


def timed_memoizer(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        fname = func.__qualname__
        logger.info("Started: %s" % fname)
        start_time = datetime.now()
        if fname in store.keys():
            ret = store[fname]
        else:
            logger.info("Return for {} not cached".format(fname))
            ret = await func(*args, **kwargs)
            store[fname] = ret
        logger.info("Finished: {} in: {} seconds".format(fname, datetime.now() - start_time))
        return ret

    return wrapper


@pytest.fixture(scope="module")
@timed_memoizer
async def istio_ingress_charm(ops_test: OpsTest, charm_manifest: CharmManifest) -> Path:
    """Istio Ingress charm used for integration testing."""
    # If the CHARM_PATH environment variable is set, use the charm from the path.
    # TODO: This could be removed if we use the manifest lookup to provide built charms in CI.
    if charm_file := os.environ.get("CHARM_PATH"):
        return CharmManifestEntry(
            channel="edge",  # Ignored for entity_url=filepath
            entity_url=Path(charm_file),
            trust=True,
            resources=ISTIO_INGRESS_RESOURCES,
        )

    # Otherwise, use what the manifest specifies if set
    try:
        return charm_manifest.get_charm_config("istio-ingress-k8s")
    except KeyError:
        # and if the manifest doesn't specify a charm, build the current directory.
        charm = await ops_test.build_charm(".")

        return CharmManifestEntry(
            channel="edge",  # Ignored for entity_url=filepath
            entity_url=charm,
            trust=True,
            resources=ISTIO_INGRESS_RESOURCES,
        )


@pytest.fixture(scope="module")
@timed_memoizer
async def ipa_tester_charm(ops_test: OpsTest):
    # TODO: Do the same as istio_ingress_charm fixture so it uses the manifest lookup
    charm_path = (Path(__file__).parent / "testers" / "ipa").absolute()

    # Update libraries in the tester charms
    root_lib_folder = Path(__file__).parent.parent.parent / "lib"
    tester_lib_folder = charm_path / "lib"

    if os.path.exists(tester_lib_folder):
        shutil.rmtree(tester_lib_folder)
    shutil.copytree(root_lib_folder, tester_lib_folder)

    charm = await ops_test.build_charm(charm_path, verbosity="debug")
    return charm

@dataclass
class UnitRelationData:
    unit_name: str
    endpoint: str
    leader: bool
    application_data: Dict[str, str]
    unit_data: Dict[str, str]


def purge(data: dict):
    for key in _JUJU_KEYS:
        if key in data:
            del data[key]


def get_content(
    obj: str, other_obj, include_default_juju_keys: bool = False, model: str = None
) -> UnitRelationData:
    """Get the content of the databag of `obj`, as seen from `other_obj`."""
    unit_name, endpoint = obj.split(":")
    other_unit_name, other_endpoint = other_obj.split(":")

    unit_data, app_data, leader = get_databags(
        unit_name, endpoint, other_unit_name, other_endpoint, model
    )

    if not include_default_juju_keys:
        purge(unit_data)

    return UnitRelationData(unit_name, endpoint, leader, app_data, unit_data)


def get_databags(local_unit, local_endpoint, remote_unit, remote_endpoint, model):
    """Get the databags of local unit and its leadership status.

    Given a remote unit and the remote endpoint name.
    """
    local_data = get_unit_info(local_unit, model)
    leader = local_data["leader"]

    data = get_unit_info(remote_unit, model)
    relation_info = data.get("relation-info")
    if not relation_info:
        raise RuntimeError(f"{remote_unit} has no relations")

    raw_data = get_relation_by_endpoint(relation_info, local_endpoint, remote_endpoint, local_unit)
    unit_data = raw_data["related-units"][local_unit]["data"]
    app_data = raw_data["application-data"]
    return unit_data, app_data, leader


def get_unit_info(unit_name: str, model: str = None) -> dict:
    """Return unit-info data structure.

     for example:

    istio-ingress-k8s/0:
      opened-ports: []
      charm: local:focal/istio-ingress-k8s-1
      leader: true
      relation-info:
      - endpoint: ingress-per-unit
        related-endpoint: ingress
        application-data:
          _supported_versions: '- v1'
        related-units:
          prometheus-k8s/0:
            in-scope: true
            data:
              egress-subnets: 10.152.183.150/32
              ingress-address: 10.152.183.150
              private-address: 10.152.183.150
      provider-id: istio-ingress-k8s-0
      address: 10.1.232.144
    """
    cmd = f"juju show-unit {unit_name}".split(" ")
    if model:
        cmd.insert(2, "-m")
        cmd.insert(3, model)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    raw_data = proc.stdout.read().decode("utf-8").strip()

    data = yaml.safe_load(raw_data) if raw_data else None

    if not data:
        raise ValueError(
            f"no unit info could be grabbed for {unit_name}; "
            f"are you sure it's a valid unit name?"
            f"cmd={' '.join(proc.args)}"
        )

    if unit_name not in data:
        raise KeyError(unit_name, f"not in {data!r}")

    unit_data = data[unit_name]
    _JUJU_DATA_CACHE[unit_name] = unit_data
    return unit_data


def get_relation_by_endpoint(relations, local_endpoint, remote_endpoint, remote_obj):
    matches = [
        r
        for r in relations
        if (
            (r["endpoint"] == local_endpoint and r["related-endpoint"] == remote_endpoint)
            or (r["endpoint"] == remote_endpoint and r["related-endpoint"] == local_endpoint)
        )
        and remote_obj in r["related-units"]
    ]
    if not matches:
        raise ValueError(
            f"no matches found with endpoint=="
            f"{local_endpoint} "
            f"in {remote_obj} (matches={matches})"
        )
    if len(matches) > 1:
        raise ValueError(
            "multiple matches found with endpoint=="
            f"{local_endpoint} "
            f"in {remote_obj} (matches={matches})"
        )
    return matches[0]


@dataclass
class RelationData:
    provider: UnitRelationData
    requirer: UnitRelationData


def get_relation_data(
    *,
    provider_endpoint: str,
    requirer_endpoint: str,
    include_default_juju_keys: bool = False,
    model: str = None,
):
    """Get relation databags for a juju relation.

    >>> get_relation_data('prometheus/0:ingress', 'istio-ingress/1:ingress-per-unit')
    """
    provider_data = get_content(
        provider_endpoint, requirer_endpoint, include_default_juju_keys, model
    )
    requirer_data = get_content(
        requirer_endpoint, provider_endpoint, include_default_juju_keys, model
    )
    return RelationData(provider=provider_data, requirer=requirer_data)


def pytest_addoption(parser):
    """Add the dependency-manifest option to pytest.

    To pass a manifesst when calling pytest, use:
        `pytest --dependency-manifest path/to/manifest.yaml --dependency-manifest http://url.to/manifest.yaml`
    """
    parser.addoption(
        "--dependency-manifest",
        action="append",  # Changed to append to support multiple files
        help="Path to a YAML manifest file or URL specifying charm dependencies. Can be specified multiple times.",
    )
