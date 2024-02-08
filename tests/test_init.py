import pytest

from aiodhcpwatcher import DHCPRequest, start


@pytest.mark.asyncio
async def test_start_stop():
    """Test start and stop."""

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        pass

    stop = start(_handle_dhcp_packet)
    stop()
