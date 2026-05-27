"""
Benchmarks for the DHCP packet-handler hot path.

``make_packet_handler`` returns the function that runs for every DHCP packet
seen on the wire (Home Assistant's device discovery feeds it directly), so it
is the one piece of this library that lives on a hot path. These benchmarks
parse a fresh packet and dispatch it through the handler on every iteration,
mirroring what happens per received packet, so regressions in option parsing,
hostname decoding, or layer extraction surface as instruction-count changes.

Rejection paths are benchmarked alongside the kept-REQUEST path because on a
shared broadcast domain most captured packets are server-issued (OFFER/ACK)
and get discarded; a regression that re-walks the option list for those would
multiply the per-packet cost across the noisy majority of traffic.
"""

from pytest_codspeed import BenchmarkFixture
from scapy.compat import raw
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from aiodhcpwatcher import _init_scapy, make_packet_handler

ITERATIONS = 1000

# Load scapy's layers once, exactly as ``async_init`` does at startup, so the
# timed loop measures packet handling rather than first-import side effects.
_init_scapy()


def _build_request(mac: str, src_ip: str, options: list[object]) -> bytes:
    """Serialize a BOOTP/DHCP request to wire bytes for re-parsing in the loop."""
    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
        / IP(src=src_ip, dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")))
        / DHCP(options=options)
    )
    return raw(packet)


# A DHCP REQUEST carrying the requested address (option 50) and an ASCII
# hostname -- the common "client asks for a specific lease" case. The IP source
# is unused by the handler whenever option 50 is present.
REQUEST_WITH_HOSTNAME = _build_request(
    "b8:b7:f1:6d:b5:33",
    "192.168.210.1",
    [
        ("message-type", "request"),
        ("requested_addr", "192.168.210.56"),
        ("hostname", b"connect"),
        "end",
    ],
)

# A renewal omits option 50, so the handler falls back to the IP source address.
RENEWAL = _build_request(
    "50:14:79:03:85:2c",
    "192.168.1.120",
    [
        ("message-type", "request"),
        ("hostname", b"iRobot-AE9EC12DD3B04885BCBFA36AFB01E1CC"),
        "end",
    ],
)

# A hostname that the idna codec rejects (underscores are invalid), forcing the
# UnicodeError -> utf-8 decode fallback branch.
REQUEST_NON_IDNA_HOSTNAME = _build_request(
    "60:6b:bd:59:e4:b4",
    "192.168.107.1",
    [
        ("message-type", "request"),
        ("requested_addr", "192.168.107.151"),
        ("hostname", b"my_host\xff"),
        "end",
    ],
)

# A DHCP OFFER from a server -- carries a realistic full option list, but the
# handler must reject it (only REQUESTs are reported). This is the dominant
# rejection path on real networks.
OFFER = _build_request(
    "aa:bb:cc:dd:ee:01",
    "192.168.1.1",
    [
        ("message-type", "offer"),
        ("server_id", "192.168.1.1"),
        ("lease_time", 86400),
        ("subnet_mask", "255.255.255.0"),
        ("router", "192.168.1.1"),
        ("name_server", "192.168.1.1"),
        ("domain", "local"),
        "end",
    ],
)


def test_handle_request_with_hostname(benchmark: BenchmarkFixture) -> None:
    """Benchmark the requested_addr + ASCII hostname path."""
    handler = make_packet_handler(lambda request: None)
    data = REQUEST_WITH_HOSTNAME

    @benchmark
    def _() -> None:
        for _ in range(ITERATIONS):
            handler(Ether(data))


def test_handle_renewal_ip_src_fallback(benchmark: BenchmarkFixture) -> None:
    """Benchmark the renewal path that resolves the address from IP.src."""
    handler = make_packet_handler(lambda request: None)
    data = RENEWAL

    @benchmark
    def _() -> None:
        for _ in range(ITERATIONS):
            handler(Ether(data))


def test_handle_non_idna_hostname(benchmark: BenchmarkFixture) -> None:
    """Benchmark the utf-8 fallback path for hostnames idna cannot decode."""
    handler = make_packet_handler(lambda request: None)
    data = REQUEST_NON_IDNA_HOSTNAME

    @benchmark
    def _() -> None:
        for _ in range(ITERATIONS):
            handler(Ether(data))


def test_handle_offer_rejected(benchmark: BenchmarkFixture) -> None:
    """Benchmark the rejection path for non-REQUEST traffic (DHCP OFFER)."""
    handler = make_packet_handler(lambda request: None)
    data = OFFER

    @benchmark
    def _() -> None:
        for _ in range(ITERATIONS):
            handler(Ether(data))
