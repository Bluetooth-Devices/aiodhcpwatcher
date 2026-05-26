import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from scapy import (
    arch,  # noqa: F401
    interfaces,
)
from scapy.error import Scapy_Exception
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from aiodhcpwatcher import (
    AUTO_RECOVER_TIME,
    FILTER,
    AIODHCPWatcher,
    DHCPRequest,
    async_init,
    async_start,
    make_packet_handler,
)

utcnow = partial(datetime.now, timezone.utc)
_MONOTONIC_RESOLUTION = time.get_clock_info("monotonic").resolution

logging.basicConfig(level=logging.DEBUG)


def async_fire_time_changed(utc_datetime: datetime) -> None:
    timestamp = utc_datetime.timestamp()
    loop = asyncio.get_running_loop()
    for task in list(loop._scheduled):  # type: ignore[attr-defined]
        if not isinstance(task, asyncio.TimerHandle):
            continue
        if task.cancelled():
            continue

        mock_seconds_into_future = timestamp - time.time()
        future_seconds = task.when() - (loop.time() + _MONOTONIC_RESOLUTION)

        if mock_seconds_into_future >= future_seconds:
            task._run()
            task.cancel()


# connect b8:b7:f1:6d:b5:33 192.168.210.56
RAW_DHCP_REQUEST = (
    b"\xff\xff\xff\xff\xff\xff\xb8\xb7\xf1m\xb53\x08\x00E\x00\x01P\x06E"
    b"\x00\x00\xff\x11\xb4X\x00\x00\x00\x00\xff\xff\xff\xff\x00D\x00C\x01<"
    b"\x0b\x14\x01\x01\x06\x00jmjV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xb7\xf1m\xb53\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x039\x02\x05\xdc2\x04\xc0\xa8\xd286"
    b"\x04\xc0\xa8\xd0\x017\x04\x01\x03\x1c\x06\x0c\x07connect\xff\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

# connec\xdb b8:b7:f1:6d:b5:33 192.168.210.56
DHCP_REQUEST_BAD_UTF8 = (
    b"\xff\xff\xff\xff\xff\xff\xb8\xb7\xf1m\xb53\x08\x00E\x00\x01P\x06E"
    b"\x00\x00\xff\x11\xb4X\x00\x00\x00\x00\xff\xff\xff\xff\x00D\x00C\x01<"
    b"\x0b\x14\x01\x01\x06\x00jmjV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xb7\xf1m\xb53\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x039\x02\x05\xdc2\x04\xc0\xa8\xd286"
    b"\x04\xc0\xa8\xd0\x017\x04\x01\x03\x1c\x06\x0c\x07connec\xab\xff\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)
# ó b8:b7:f1:6d:b5:33 192.168.210.56
DHCP_REQUEST_IDNA = (
    b"\xff\xff\xff\xff\xff\xff\xb8\xb7\xf1m\xb53\x08\x00E\x00\x01P\x06E"
    b"\x00\x00\xff\x11\xb4X\x00\x00\x00\x00\xff\xff\xff\xff\x00D\x00C\x01<"
    b"\x0b\x14\x01\x01\x06\x00jmjV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xb7\xf1m\xb53\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x039\x02\x05\xdc2\x04\xc0\xa8\xd286"
    b"\x04\xc0\xa8\xd0\x017\x04\x01\x03\x1c\x06\x0c\x07xn--kda\xff\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

# iRobot-AE9EC12DD3B04885BCBFA36AFB01E1CC 50:14:79:03:85:2c 192.168.1.120
RAW_DHCP_RENEWAL = (
    b"\x00\x15\x5d\x8e\xed\x02\x50\x14\x79\x03\x85\x2c\x08\x00\x45\x00"
    b"\x01\x8e\x51\xd2\x40\x00\x40\x11\x63\xa1\xc0\xa8\x01\x78\xc0\xa8"
    b"\x01\x23\x00\x44\x00\x43\x01\x7a\x12\x09\x01\x01\x06\x00\xd4\xea"
    b"\xb2\xfd\xff\xff\x00\x00\xc0\xa8\x01\x78\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x50\x14\x79\x03\x85\x2c\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x03\x39\x02\x05"
    b"\xdc\x3c\x45\x64\x68\x63\x70\x63\x64\x2d\x35\x2e\x32\x2e\x31\x30"
    b"\x3a\x4c\x69\x6e\x75\x78\x2d\x33\x2e\x31\x38\x2e\x37\x31\x3a\x61"
    b"\x72\x6d\x76\x37\x6c\x3a\x51\x75\x61\x6c\x63\x6f\x6d\x6d\x20\x54"
    b"\x65\x63\x68\x6e\x6f\x6c\x6f\x67\x69\x65\x73\x2c\x20\x49\x6e\x63"
    b"\x20\x41\x50\x51\x38\x30\x30\x39\x0c\x27\x69\x52\x6f\x62\x6f\x74"
    b"\x2d\x41\x45\x39\x45\x43\x31\x32\x44\x44\x33\x42\x30\x34\x38\x38"
    b"\x35\x42\x43\x42\x46\x41\x33\x36\x41\x46\x42\x30\x31\x45\x31\x43"
    b"\x43\x37\x08\x01\x21\x03\x06\x1c\x33\x3a\x3b\xff"
)

# <no hostname> 60:6b:bd:59:e4:b4 192.168.107.151
RAW_DHCP_REQUEST_WITHOUT_HOSTNAME = (
    b"\xff\xff\xff\xff\xff\xff\x60\x6b\xbd\x59\xe4\xb4\x08\x00\x45\x00"
    b"\x02\x40\x00\x00\x00\x00\x40\x11\x78\xae\x00\x00\x00\x00\xff\xff"
    b"\xff\xff\x00\x44\x00\x43\x02\x2c\x02\x04\x01\x01\x06\x00\xff\x92"
    b"\x7e\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x60\x6b\xbd\x59\xe4\xb4\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x03\x3d\x07\x01"
    b"\x60\x6b\xbd\x59\xe4\xb4\x3c\x25\x75\x64\x68\x63\x70\x20\x31\x2e"
    b"\x31\x34\x2e\x33\x2d\x56\x44\x20\x4c\x69\x6e\x75\x78\x20\x56\x44"
    b"\x4c\x69\x6e\x75\x78\x2e\x31\x2e\x32\x2e\x31\x2e\x78\x32\x04\xc0"
    b"\xa8\x6b\x97\x36\x04\xc0\xa8\x6b\x01\x37\x07\x01\x03\x06\x0c\x0f"
    b"\x1c\x2a\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


async def _write_test_packets_to_pipe(w: int) -> None:
    for test_packet in (
        RAW_DHCP_REQUEST_WITHOUT_HOSTNAME,
        RAW_DHCP_REQUEST,
        RAW_DHCP_RENEWAL,
        RAW_DHCP_REQUEST_WITHOUT_HOSTNAME,
        DHCP_REQUEST_BAD_UTF8,
        DHCP_REQUEST_IDNA,
    ):
        os.write(w, test_packet)
        for _ in range(3):
            await asyncio.sleep(0)
        os.write(w, b"garbage")
        for _ in range(3):
            await asyncio.sleep(0)


class MockIface:
    index: int = 0

    def __init__(self) -> None:
        MockIface.index = MockIface.index + 1
        self.index: int = MockIface.index


class MockSocket:

    def __init__(self, reader: int, exc: type[Exception] | None = None) -> None:
        self._fileno = reader
        if reader != -1:
            # The real listen socket is set non-blocking in _make_listen_socket,
            # so the mock reads from a non-blocking fd too. This keeps os.read in
            # _on_data off the event loop's blocking radar (see blockbuster).
            os.set_blocking(reader, False)
        self.iface = MockIface()
        self.close = MagicMock()
        self.buffer = b""
        self.exc = exc

    def recv(self) -> Packet:
        if self.exc:
            raise self.exc
        raw = os.read(self._fileno, 1000000)
        try:
            packet = Ether(raw)
        except Exception:
            packet = Packet(raw)
        return packet

    def fileno(self) -> int:
        return self._fileno


@pytest_asyncio.fixture(autouse=True, scope="session")
async def _init_scapy():
    await async_init()


@pytest.mark.asyncio
async def test_start_stop():
    """Test start and stop."""
    (await async_start(lambda data: None))()


@pytest.mark.asyncio
async def test_watcher():
    """Test mocking a dhcp packet to the watcher."""
    requests: list[DHCPRequest] = []

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        requests.append(data)

    r, w = os.pipe()

    mock_socket = MockSocket(r)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        stop = await async_start(_handle_dhcp_packet)
        await _write_test_packets_to_pipe(w)

        stop()

    os.close(r)
    os.close(w)
    assert requests == [
        DHCPRequest(
            ip_address="192.168.107.151", hostname="", mac_address="60:6b:bd:59:e4:b4"
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="connect",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
        DHCPRequest(
            ip_address="192.168.1.120",
            hostname="iRobot-AE9EC12DD3B04885BCBFA36AFB01E1CC",
            mac_address="50:14:79:03:85:2c",
        ),
        DHCPRequest(
            ip_address="192.168.107.151", hostname="", mac_address="60:6b:bd:59:e4:b4"
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="connec�",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="ó",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
    ]


@pytest.mark.asyncio
async def test_watcher_fatal_exception(caplog: pytest.LogCaptureFixture) -> None:
    """Test mocking a dhcp packet to the watcher."""
    requests: list[DHCPRequest] = []

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        requests.append(data)

    r, w = os.pipe()

    mock_socket = MockSocket(r, ValueError)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        stop = await async_start(_handle_dhcp_packet)
        await _write_test_packets_to_pipe(w)

        stop()

    os.close(r)
    os.close(w)
    assert requests == []
    assert "Fatal error while processing dhcp packet" in caplog.text


@pytest.mark.asyncio
async def test_watcher_temp_exception(caplog: pytest.LogCaptureFixture) -> None:
    """Test mocking a dhcp packet to the watcher."""
    requests: list[DHCPRequest] = []

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        requests.append(data)

    r, w = os.pipe()
    mock_socket = MockSocket(r, OSError)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        stop = await async_start(_handle_dhcp_packet)
        await _write_test_packets_to_pipe(w)
    os.close(r)
    os.close(w)
    assert requests == []
    assert "Error while processing dhcp packet" in caplog.text

    r, w = os.pipe()
    mock_socket = MockSocket(r)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):

        async_fire_time_changed(utcnow() + timedelta(seconds=AUTO_RECOVER_TIME))
        await asyncio.sleep(0.1)

        await _write_test_packets_to_pipe(w)

        stop()

    os.close(r)
    os.close(w)
    assert requests == [
        DHCPRequest(
            ip_address="192.168.107.151", hostname="", mac_address="60:6b:bd:59:e4:b4"
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="connect",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
        DHCPRequest(
            ip_address="192.168.1.120",
            hostname="iRobot-AE9EC12DD3B04885BCBFA36AFB01E1CC",
            mac_address="50:14:79:03:85:2c",
        ),
        DHCPRequest(
            ip_address="192.168.107.151", hostname="", mac_address="60:6b:bd:59:e4:b4"
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="connec�",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="ó",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
    ]


@pytest.mark.asyncio
async def test_watcher_if_indexes(caplog: pytest.LogCaptureFixture) -> None:
    """Test mocking a dhcp packet to the watcher."""
    requests: list[DHCPRequest] = []

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        requests.append(data)

    r, w = os.pipe()
    mock_socket = MockSocket(r)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        stop = await async_start(_handle_dhcp_packet, if_indexes=[1, 2])
        await _write_test_packets_to_pipe(w)
        stop()

    os.close(r)
    os.close(w)
    assert requests == [
        DHCPRequest(
            ip_address="192.168.107.151", hostname="", mac_address="60:6b:bd:59:e4:b4"
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="connect",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
        DHCPRequest(
            ip_address="192.168.1.120",
            hostname="iRobot-AE9EC12DD3B04885BCBFA36AFB01E1CC",
            mac_address="50:14:79:03:85:2c",
        ),
        DHCPRequest(
            ip_address="192.168.107.151", hostname="", mac_address="60:6b:bd:59:e4:b4"
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="connec�",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
        DHCPRequest(
            ip_address="192.168.210.56",
            hostname="ó",
            mac_address="b8:b7:f1:6d:b5:33",
        ),
    ]


@pytest.mark.asyncio
async def test_watcher_stop_after_temp_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test mocking a dhcp packet to the watcher."""
    requests: list[DHCPRequest] = []

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        requests.append(data)

    r, w = os.pipe()

    mock_socket = MockSocket(r, OSError)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        stop = await async_start(_handle_dhcp_packet)
        await _write_test_packets_to_pipe(w)

    os.close(r)
    os.close(w)
    assert requests == []
    assert "Error while processing dhcp packet" in caplog.text
    stop()

    r, w = os.pipe()
    mock_socket = MockSocket(r)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):

        async_fire_time_changed(utcnow() + timedelta(seconds=30))
        await asyncio.sleep(0)
        await _write_test_packets_to_pipe(w)

        stop()

    os.close(r)
    os.close(w)
    assert requests == []


@pytest.mark.asyncio
async def test_setup_fails_broken_filtering(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the setup fails when filtering is broken."""
    caplog.set_level(logging.DEBUG)
    with patch(
        "scapy.arch.common.compile_filter",
        side_effect=Scapy_Exception,
    ):
        (await async_start(lambda data: None))()
    assert (
        "Cannot watch for dhcp packets without a functional packet filter"
        in caplog.text
    )


@pytest.mark.asyncio
async def test_setup_fails_as_root(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the setup fails as root."""
    with (
        patch("os.geteuid", return_value=0),
        patch("scapy.arch.common.compile_filter"),
        patch.object(
            interfaces,
            "resolve_iface",
            side_effect=Scapy_Exception,
        ),
    ):
        (await async_start(lambda data: None))()
    assert "Cannot watch for dhcp packets" in caplog.text


@pytest.mark.asyncio
async def test_setup_fails_as_non_root(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the setup fails as root."""
    caplog.set_level(logging.DEBUG)
    with (
        patch("os.geteuid", return_value=10),
        patch("scapy.arch.common.compile_filter"),
        patch.object(
            interfaces,
            "resolve_iface",
            side_effect=Scapy_Exception,
        ),
    ):
        (await async_start(lambda data: None))()
    assert "Cannot watch for dhcp packets without root or CAP_NET_RAW" in caplog.text


@pytest.mark.asyncio
async def test_permission_denied_to_add_reader(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test permission denied to add reader."""
    loop = asyncio.get_running_loop()
    with (
        patch.object(loop, "add_reader", side_effect=PermissionError),
        patch("scapy.arch.common.compile_filter"),
        patch.object(
            interfaces,
            "resolve_iface",
        ),
    ):
        (await async_start(lambda data: None))()

    assert "Permission denied to watch for dhcp packets" in caplog.text


def test_hostname_idna_unicode_error_does_not_crash_handler() -> None:
    """
    A crafted DHCP hostname must not crash the packet handler.

    On Python < 3.13 the ``idna`` codec raises a bare ``UnicodeError`` (e.g.
    "label empty or too long") instead of ``UnicodeDecodeError`` for malformed
    hostnames. The handler previously caught only ``UnicodeDecodeError``, so an
    untrusted DHCP packet from the LAN could raise an uncaught exception inside
    the asyncio reader callback. This test simulates that codec behaviour in a
    version-independent way and asserts the handler swallows it and falls back
    to a lossy utf-8 decode.
    """
    from scapy.layers.dhcp import DHCP
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    class _IdnaUnicodeErrorBytes(bytes):
        """bytes whose idna decode raises a bare UnicodeError (pre-3.13)."""

        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            if encoding == "idna":
                raise UnicodeError("label empty or too long")
            return super().decode(encoding, errors)

    requests: list[DHCPRequest] = []
    handler = make_packet_handler(requests.append)

    packet = (
        Ether(src="b8:b7:f1:6d:b5:33")
        / IP(src="192.168.210.56")
        / DHCP(
            options=[
                ("message-type", 3),
                ("hostname", _IdnaUnicodeErrorBytes(b"xn--bad")),
                "end",
            ]
        )
    )

    # Must not raise, even though idna decode raises a bare UnicodeError.
    handler(packet)

    assert len(requests) == 1
    assert requests[0].hostname == "xn--bad"
    assert requests[0].ip_address == "192.168.210.56"
    assert requests[0].mac_address == "b8:b7:f1:6d:b5:33"


def test_handler_no_ether_layer_does_not_crash() -> None:
    """
    A packet without an Ethernet layer must not crash the handler.

    ``make_packet_handler`` is a public, exported entrypoint. Not every link
    layer carries an ``Ether`` header: Linux cooked captures (the ``any``
    pseudo-device uses an ``SLL`` header), PPP, tun, and some cellular/VPN
    interfaces have no Ethernet framing, so ``packet.getlayer(Ether)`` returns
    ``None``. The handler unconditionally read ``getlayer(Ether).src``, raising
    ``AttributeError: 'NoneType' object has no attribute 'src'`` on every DHCP
    packet seen on such an interface. With no MAC available the packet should
    simply be skipped, not crash the asyncio reader callback.
    """
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP

    requests: list[DHCPRequest] = []
    handler = make_packet_handler(requests.append)

    # IP present (requested_addr absent → renewal path), but no Ether layer.
    packet = (
        IP(src="192.168.1.50")
        / UDP(sport=68, dport=67)
        / BOOTP()
        / DHCP(options=[("message-type", 3), "end"])
    )
    assert packet.getlayer(Ether) is None

    # Must not raise; with no MAC the request is dropped.
    handler(packet)
    assert requests == []


def test_handler_no_ip_layer_does_not_crash() -> None:
    """
    A packet without an IP layer must not crash the handler.

    When a DHCP request carries no ``requested_addr`` option (e.g. a renewal),
    the handler falls back to ``packet.getlayer(IP).src``. If the packet has no
    IP layer that read raised ``AttributeError``. Such a packet has no usable
    client address and should be skipped rather than crash the handler.
    """
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP

    requests: list[DHCPRequest] = []
    handler = make_packet_handler(requests.append)

    # Ether present, but no IP layer and no requested_addr → IP.src fallback.
    packet = (
        Ether(src="aa:bb:cc:dd:ee:ff")
        / BOOTP()
        / DHCP(options=[("message-type", 3), "end"])
    )
    assert packet.getlayer(IP) is None

    # Must not raise; with no IP the request is dropped.
    handler(packet)
    assert requests == []


def test_all_exports_are_importable() -> None:
    """
    Every name advertised in ``__all__`` must be a real module attribute.

    Regression test: ``__all__`` listed ``"start"`` long after the
    module-level ``start`` function was renamed to ``async_start``, so
    ``from aiodhcpwatcher import *`` raised ``AttributeError: module
    'aiodhcpwatcher' has no attribute 'start'``.
    """
    import aiodhcpwatcher

    for name in aiodhcpwatcher.__all__:
        assert hasattr(
            aiodhcpwatcher, name
        ), f"{name!r} is declared in __all__ but not defined in the module"


def test_async_start_is_exported() -> None:
    """``async_start`` is the documented entrypoint and must be exported."""
    import aiodhcpwatcher

    assert "async_start" in aiodhcpwatcher.__all__


@pytest.mark.asyncio
async def test_invalid_file_descriptor(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test an invalid (-1) socket file descriptor is handled gracefully.

    On platforms such as Windows scapy's listen socket does not expose a
    selectable file descriptor, so fileno() returns -1 and add_reader would
    raise ValueError. The watcher must not crash.
    """
    mock_socket = MockSocket(-1)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=mock_socket,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        (await async_start(lambda data: None))()

    assert "valid file descriptor" in caplog.text


@pytest.mark.asyncio
async def test_add_reader_not_supported(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test add_reader being unsupported is handled gracefully.

    The Windows Proactor event loop does not implement add_reader, which
    raises NotImplementedError. The watcher must degrade gracefully.
    """
    loop = asyncio.get_running_loop()
    with (
        patch.object(loop, "add_reader", side_effect=NotImplementedError),
        patch("scapy.arch.common.compile_filter"),
        patch.object(interfaces, "resolve_iface"),
    ):
        (await async_start(lambda data: None))()

    assert "Cannot watch for dhcp packets" in caplog.text


def test_handler_ignores_non_dhcp_request_message_type() -> None:
    """
    A DHCP packet whose message-type is not REQUEST must be ignored.

    The handler only reports DHCP REQUEST packets (message-type 3). A packet
    carrying any other message-type (e.g. an ACK) must not invoke the callback.
    Building the options without a trailing ``"end"`` sentinel also exercises
    the natural loop-exit path of the option parser.
    """
    from scapy.layers.dhcp import DHCP
    from scapy.layers.inet import IP

    requests: list[DHCPRequest] = []
    handler = make_packet_handler(requests.append)

    # message-type 5 (ACK), no "end" sentinel → loop exhausts, then bail out.
    packet = (
        Ether(src="b8:b7:f1:6d:b5:33")
        / IP(src="192.168.210.56")
        / DHCP(options=[("message-type", 5)])
    )
    handler(packet)
    assert requests == []


@pytest.mark.asyncio
async def test_restart_soon_is_noop_when_timer_already_scheduled() -> None:
    """A second restart_soon() call must not schedule a second timer."""
    watcher = AIODHCPWatcher(lambda data: None)
    try:
        watcher.restart_soon()
        first_timer = watcher._restart_timer
        assert first_timer is not None

        watcher.restart_soon()
        # The existing timer is reused; no new one is scheduled.
        assert watcher._restart_timer is first_timer
    finally:
        watcher.stop()


@pytest.mark.asyncio
async def test_execute_restart_is_noop_when_shutdown() -> None:
    """_execute_restart() must not restart once the watcher is shut down."""
    watcher = AIODHCPWatcher(lambda data: None)
    watcher._shutdown = True

    watcher._execute_restart()

    # No restart task is created while the watcher is shut down.
    assert watcher._restart_task is None


@pytest.mark.asyncio
async def test_stop_cancels_pending_restart_task() -> None:
    """stop() must cancel and clear an in-flight restart task."""
    watcher = AIODHCPWatcher(lambda data: None)
    restart_task = MagicMock()
    watcher._restart_task = restart_task

    watcher.stop()

    restart_task.cancel.assert_called_once_with()
    assert watcher._restart_task is None


@pytest.mark.asyncio
async def test_start_skips_interface_when_no_socket_created(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    _start must move on when _make_listen_socket yields no socket.

    If the listen socket cannot be created for an interface, that interface is
    skipped; with no sockets at all the watcher logs that no readers were added.
    """
    caplog.set_level(logging.DEBUG)
    with (
        patch(
            "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket",
            return_value=None,
        ),
        patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"),
    ):
        (await async_start(lambda data: None))()

    assert "Not starting watcher because no readers added" in caplog.text


@pytest.mark.asyncio
async def test_async_start_is_noop_when_already_shutdown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """async_start() must do nothing once the watcher has been shut down."""
    caplog.set_level(logging.DEBUG)
    watcher = AIODHCPWatcher(lambda data: None)
    watcher.shutdown()

    await watcher.async_start()

    assert "Not starting watcher because it is shutdown" in caplog.text


@pytest.mark.asyncio
async def test_async_start_aborts_when_shutdown_during_init(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    async_start() must abort if shutdown happens during the executor init.

    _start runs in an executor and can take a while; if shutdown() is called
    in the meantime the watcher must not register any readers afterwards.
    """
    caplog.set_level(logging.DEBUG)
    watcher = AIODHCPWatcher(lambda data: None)

    def _start_then_shutdown(
        if_indexes: object = None,
    ) -> "object":
        # Simulate shutdown racing in while _start ran in the executor.
        watcher._shutdown = True
        return make_packet_handler(watcher._callback)

    with patch.object(watcher, "_start", side_effect=_start_then_shutdown):
        await watcher.async_start()

    assert "Not starting watcher because it is shutdown after init" in caplog.text


@pytest.mark.asyncio
async def test_on_data_ignores_blocking_io_error() -> None:
    """_on_data must swallow BlockingIOError from a non-blocking socket."""
    watcher = AIODHCPWatcher(lambda data: None)
    handler = MagicMock()

    class _Sock:
        def recv(self) -> None:
            raise BlockingIOError

    # Must not raise and must not forward anything to the handler.
    watcher._on_data(handler, _Sock())
    handler.assert_not_called()


@pytest.mark.asyncio
async def test_on_data_ignores_empty_read() -> None:
    """_on_data must not invoke the handler when recv() returns no data."""
    watcher = AIODHCPWatcher(lambda data: None)
    handler = MagicMock()

    class _Sock:
        def recv(self) -> bytes:
            return b""

    watcher._on_data(handler, _Sock())
    handler.assert_not_called()


@pytest.mark.asyncio
async def test_make_listen_socket_uses_pcap_fd_when_no_set_nonblock() -> None:
    """
    _make_listen_socket falls back to pcap_fd.setnonblock().

    Some scapy listen-socket classes expose no ``set_nonblock`` method but do
    expose a ``pcap_fd`` handle; the socket must be made non-blocking through it.
    """
    watcher = AIODHCPWatcher(lambda data: None)

    class _PcapFd:
        def __init__(self) -> None:
            self.setnonblock = MagicMock()

    class _Sock:
        def __init__(self) -> None:
            self.pcap_fd = _PcapFd()
            self.iface = MockIface()

        def fileno(self) -> int:
            return -1

    sock = _Sock()
    fake_iface = MagicMock()
    fake_iface.l2listen.return_value = lambda **kwargs: sock
    with patch("scapy.interfaces.resolve_iface", return_value=fake_iface):
        result = watcher._make_listen_socket(FILTER)

    assert result is sock
    sock.pcap_fd.setnonblock.assert_called_once_with(True)


@pytest.mark.asyncio
async def test_make_listen_socket_falls_back_to_fcntl() -> None:
    """
    _make_listen_socket uses fcntl when neither hook is available.

    For socket classes exposing neither ``set_nonblock`` nor ``pcap_fd``, the
    file descriptor must be switched to non-blocking via ``fcntl`` directly.
    """
    import fcntl

    watcher = AIODHCPWatcher(lambda data: None)
    r, w = os.pipe()
    try:

        class _Sock:
            def __init__(self, fd: int) -> None:
                self._fd = fd
                self.iface = MockIface()

            def fileno(self) -> int:
                return self._fd

        sock = _Sock(r)
        fake_iface = MagicMock()
        fake_iface.l2listen.return_value = lambda **kwargs: sock
        with patch("scapy.interfaces.resolve_iface", return_value=fake_iface):
            result = watcher._make_listen_socket(FILTER)

        assert result is sock
        assert fcntl.fcntl(r, fcntl.F_GETFL) & os.O_NONBLOCK
    finally:
        os.close(r)
        os.close(w)
