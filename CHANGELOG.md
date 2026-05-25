# Changelog

## v1.2.5-rc.1 (2026-05-25)

### Bug fixes

- Export async_start in __all__ (was nonexistent 'start') ([`74bc51f`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/74bc51fb200fe6892eeda71e2f0efcc47e23a630))

## v1.2.4 (2026-05-25)

### Bug fixes

- Use github.ref for release checkout so forks work ([`03b23bd`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/03b23bd8091989ce3039860a6b677ce8299c1b9e))

## v1.2.3 (2026-05-25)

### Bug fixes

- Catch unicodeerror when decoding crafted dhcp hostname ([`720d506`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/720d50687d7be8b047356f5fa2e2ecd9eac4d026))

## v1.2.2 (2026-05-25)

### Bug fixes

- Repair ruff and mypy after autoupdate ([`1b1935a`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/1b1935a48e3f1b928047e4c4b65c780a514612a0))

## v1.2.1 (2025-08-12)

### Bug fixes

- Update format string as if_index may be a string on some platforms ([`4fb0474`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/4fb04742e28dc986cc6ee44ee015bcf237d2011d))

## v1.2.0 (2025-05-12)

### Features

- Add option to select multiple interfaces ([`69019b4`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/69019b43a8c96a6ffc947219373fa2e14587c8da))

## v1.1.1 (2025-02-22)

### Bug fixes

- Update repo links to use bluetooth-devices ([`1effe3f`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/1effe3fcfbfcb5c2310343930ccde4a400e34de7))

## v1.1.0 (2025-02-04)

### Features

- Change license to apache-2.0 ([`16f5a1b`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/16f5a1b3bf96526d5f745bcd0aac33ae408e68fc))

## v1.0.4 (2025-02-04)

### Bug fixes

- Update poetry to v2 + add license to metadata ([`52c6e80`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/52c6e8002d98b9960705fa0ea246099e3b62eeeb))

## v1.0.3 (2025-02-02)

### Bug fixes

- Handle network being temporarily unavailable ([`55d24dc`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/55d24dcd11cdf22a9a6bf4489e2b8a2791638f0e))

## v1.0.2 (2024-06-24)

### Bug fixes

- Licensing classifier ([`bdfa9ef`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/bdfa9ef9bc3cbb1fecbf6a5848615e5fd2e619fb))

## v1.0.1 (2024-03-15)

### Bug fixes

- Update readme example for breaking changes in 1.0.0 ([`fd53e64`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/fd53e64b64f74af02c68e7e13261cbf23370be11))

## v1.0.0 (2024-03-14)

### Bug fixes

- Run scapy filter creation in the executor ([`e5965d3`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/e5965d335b8e02745ab727acef34bbb96f6a6076))

## v0.8.2 (2024-03-14)

### Bug fixes

- Ensure all scapy modules are loaded in the executor ([`694c831`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/694c83121995ee756a50ef158be71bf50a600f65))

## v0.8.1 (2024-03-11)

### Bug fixes

- Add a guard for when the options tuple is only one item ([`37a7371`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/37a7371693f693871947638bf85c69d7a1636bc1))

## v0.8.0 (2024-02-09)

### Features

- Add support for setting nonblock with pcap ([`3287b50`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/3287b500ab4dc546257cdcb144746f7d8fa1d37c))

## v0.7.0 (2024-02-09)

### Features

- Add helper to load scapy in the executor since it can block the loop ([`0ec1983`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/0ec19835ccd52e5c71c5d15c5e48c0382b4aea4f))

## v0.6.0 (2024-02-08)

### Features

- Add test coverage for broken filtering ([`c23d934`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/c23d934e6f86c031bb25a309edaff607b255596d))

## v0.5.0 (2024-02-08)

### Features

- Decode hostnames using idna encoding ([`111cdfe`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/111cdfefcfc621c7ef3d001d8b9f8e2b85460ef2))

## v0.4.0 (2024-02-08)

### Features

- Increase coverage ([`6280898`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/6280898a4a55cc3e0feed3e6b78c453038419c5e))

## v0.3.3 (2024-02-08)

### Bug fixes

- Add checks for perm error setting up reader ([`58b4025`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/58b40253abcefb71deb17c7d87c706a3f47f15fe))

## v0.3.2 (2024-02-08)

### Bug fixes

- Ensure filter can be created on macos ([`8c00359`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/8c0035964b249eeedc684f19794a99d93a3317a0))

## v0.3.1 (2024-02-08)

### Bug fixes

- Import order ([`3acbb20`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/3acbb202a4cbfee1fa41595ac5b746c485c1c04e))

## v0.3.0 (2024-02-08)

### Features

- Refactor to make more testable ([`ddd6d84`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/ddd6d84c8246b05384b92fa7edf45fca5bed6a92))

## v0.2.0 (2024-02-08)

### Features

- Cleanups ([`fdfd1b6`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/fdfd1b66fc11a20930c8a869bcb8766c0156cb8c))

## v0.1.0 (2024-02-08)

### Features

- Init ([`188b4b3`](https://github.com/Bluetooth-Devices/aiodhcpwatcher/commit/188b4b315ce3303cdeab9eeb8fa8f8eed2e185ec))

## v0.0.0 (2024-02-08)
