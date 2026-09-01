(usage)=

# Usage

Assuming that you've followed the {ref}`installation steps <installation>`, you're now ready to use this package.

## Quick start

`aiodhcpwatcher` watches the local network for DHCP `REQUEST` packets and invokes a callback for each one. The callback receives a `DHCPRequest` carrying the requested IP, the client hostname (decoded leniently — see [Hostname decoding](#hostname-decoding)), and the source MAC address.

```python
import asyncio
import aiodhcpwatcher

def on_dhcp_request(request: aiodhcpwatcher.DHCPRequest) -> None:
    print(f"{request.mac_address} requested {request.ip_address} ({request.hostname!r})")

async def run() -> None:
    shutdown = await aiodhcpwatcher.async_start(on_dhcp_request)
    try:
        await asyncio.Event().wait()
    finally:
        shutdown()

asyncio.run(run())
```

`async_start` returns the watcher's `shutdown` callable — call it (or rely on process exit) to stop watching, close the underlying sockets, and cancel any pending auto-recovery.

## Permissions

Packet capture requires `CAP_NET_RAW` (or running as root). Without it, `aiodhcpwatcher` logs a debug message and returns without raising — the callback simply will not fire. To grant the capability without running as root, on Linux:

```bash
sudo setcap cap_net_raw=eip $(readlink -f $(which python))
```

On macOS and the BSDs there is no `CAP_NET_RAW`. Capture goes through the BPF devices (`/dev/bpf*`), which are owned by root and not readable by other users by default, so a non-root process fails the same way: a debug log line and no callbacks. The usual fix is to make the BPF devices group-readable and add the user to that group. Wireshark ships a small launch daemon, ChmodBPF, that does this at every boot; on macOS with Homebrew:

```bash
brew install --cask wireshark-chmodbpf
sudo dseditgroup -o edit -a "$USER" -t user access_bpf
```

Log out and back in (or reboot) so the new group membership applies, then check that `ls -l /dev/bpf0` shows the `access_bpf` group. Running as root also works but is usually not what you want for a long-running service.

## Selecting interfaces

By default, the watcher listens on scapy's default interface. To watch specific interfaces, pass their indexes:

```python
import socket
indexes = [socket.if_nametoindex("eth0"), socket.if_nametoindex("wlan0")]
shutdown = await aiodhcpwatcher.async_start(on_dhcp_request, if_indexes=indexes)
```

If any interface fails to open (e.g. invalid index, missing capability), the watcher logs and stops — it does not partially start. Interfaces that open successfully but cannot be registered with the event loop (e.g. an `add_reader` failure on Windows) are closed individually while the rest keep running.

## Pre-initializing scapy

Importing scapy is slow because it probes the system for routing and interface information. `async_start` triggers this lazily on first use, which can stall the event loop. If you know you will start the watcher later, you can warm up scapy in the executor first:

```python
await aiodhcpwatcher.async_init()
# ... later ...
shutdown = await aiodhcpwatcher.async_start(on_dhcp_request)
```

`async_init` is a no-op after the first successful call.

## Auto-recovery

If the underlying socket raises an `OSError` while reading (e.g. an interface goes down), the watcher stops, then schedules a restart 30 seconds later. Callers do not need to handle transient socket failures manually.

## Hostname decoding

DHCP hostnames are supposed to be encoded with IDNA, but many clients send raw UTF-8 (or worse). The handler tries `idna` first and falls back to `utf-8` with `errors="replace"`, so untrusted DHCP traffic cannot crash the handler. The `hostname` field on `DHCPRequest` is always a `str` (possibly empty if no hostname option was present).

## Building a standalone packet handler

If you have your own packet source (a pcap file, a different sniffer), you can reuse the parsing logic directly:

```python
handler = aiodhcpwatcher.make_packet_handler(on_dhcp_request)
for packet in my_packet_source:
    handler(packet)
```

`make_packet_handler` returns a function that takes a scapy `Packet` and calls the callback only when the packet is a valid DHCP `REQUEST` with both an IP and a MAC address.
