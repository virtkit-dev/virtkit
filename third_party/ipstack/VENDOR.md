# Vendored ipstack

Source: https://github.com/narrowlink/ipstack
Revision: `a343ea8c696e761acce8dbcd6687c862ecd8aacd` (crates.io 1.0.1)

The crates.io 1.0.1 sources are vendored (`Cargo.toml`, `Cargo.lock`, `LICENSE`, `README.md`,
`build.rs`, `src/`); `examples/` and `scripts/` are dropped. `Cargo.lock` is kept for a standalone build
of this workspace-excluded crate. The root workspace's `[patch.crates-io]` points the
`ipstack` dependency here, so the switch (`vk-driver/src/switch.rs`) builds against this copy.

## Local patches

+ `src/stream/tcb.rs` + `src/stream/tcp.rs` — reset a connection whose retransmissions are
  exhausted. Upstream drops the abandoned segment from the in-flight queue and leaves the
  connection Established: the peer never receives those bytes, its duplicate ACKs can no
  longer be served, and the application reads nothing for good. `collect_timed_out_inflight_packets`
  now also reports the exhaustion; the TCP task then sends RST|ACK, moves to Closed and exits,
  so the guest's socket errors out and the application can reconnect. Covered by
  `exhausted_retransmissions_are_reported`.

## Refreshing

Copy the new crates.io sources over this directory, re-apply the patch above, update the
revision here.
