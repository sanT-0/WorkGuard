# WorkGuard Endpoint Agent

This directory contains the WorkGuard endpoint agent implementation and simulator.

## Components
- `simulator.py`: High-fidelity Windows endpoint agent simulator matching [ENDPOINT_AGENT.md](../ENDPOINT_AGENT.md).
  - Enrolls devices using one-time CSPRNG codes.
  - Verifies Ed25519 signatures and RFC 8785 canonical JSON envelopes.
  - Simulates Windows Removable Storage (USB block), BitLocker disk encryption, App Control, and Defender read-back verification.
  - Reports status and security events.

## Usage
Run an automated verification cycle:
```bash
python simulator.py sync
```

Simulate unauthorized USB insertion and policy enforcement:
```bash
python simulator.py usb
```

Run as background daemon:
```bash
python simulator.py daemon
```
