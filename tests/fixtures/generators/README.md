# Fixture generators

This directory holds one script per fixture-generation *method*. Each fixture's
`provenance.json` points at a generator by exact path. Once a fixture depends on
a generator, do not delete or rewrite that script in place — a changed method
gets a new script or a new fixture.

## Lab captures on macOS (tcpdump sidecar)

Docker Desktop runs containers inside a Linux VM. Host `tcpdump` on `en0` only
sees the VM uplink, never container-to-container traffic.

For lab fixtures (Postfix/Dovecot/Cyrus + `openssl s_client`, Step 1+):

1. Create a user-defined Docker bridge network.
2. Attach the mail-server containers to that network.
3. Attach a `nicolaka/netshoot`-style sidecar to the *same* network with
   `--cap-add=NET_RAW --cap-add=NET_ADMIN`.
4. Run `tcpdump` in the sidecar against the bridge, not on the macOS host.

## Step 0

`empty_capture.py` crafts a handful of unrelated (non-mail) packets with Scapy
and writes `tests/fixtures/empty/capture.pcapng`.
