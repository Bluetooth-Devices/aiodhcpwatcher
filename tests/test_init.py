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

from aiodhcpwatcher import AUTO_RECOVER_TIME, DHCPRequest, async_init, async_start

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

    def __init__(self) -> None:
        self.index = 1


class MockSocket:

    def __init__(self, reader: int, exc: type[Exception] | None = None) -> None:
        self._fileno = reader
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
