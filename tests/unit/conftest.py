#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
from charms.tempo_coordinator_k8s.v0 import charm_tracing
from lightkube import Client


@pytest.fixture(autouse=True)
def charm_tracing_buffer_to_tmp(tmp_path):
    with patch.object(charm_tracing, "BUFFER_DEFAULT_CACHE_FILE_NAME", tmp_path):
        yield


@pytest.fixture(autouse=True)
def mock_lightkube_client():
    """Global mock for the Lightkube Client to avoid loading kubeconfig in CI."""
    with patch.object(Client, "__init__", lambda self, *args, **kwargs: None):
        with patch.object(Client, "_client", create=True):
            with patch.object(Client, "get"):
                with patch.object(Client, "patch"):
                    with patch.object(Client, "list"):
                        yield
