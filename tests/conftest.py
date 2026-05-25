"""Shared pytest fixtures for the aiodhcpwatcher test suite."""

from collections.abc import Iterator

import pytest
from blockbuster import BlockBuster, blockbuster_ctx


@pytest.fixture(autouse=True)
def blockbuster() -> Iterator[BlockBuster]:
    """Fail the test if aiodhcpwatcher makes a blocking call in the event loop."""
    with blockbuster_ctx("aiodhcpwatcher") as bb:
        yield bb
