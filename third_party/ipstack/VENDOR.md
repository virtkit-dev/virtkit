# Vendored ipstack

Source: https://github.com/virtkit-dev/ipstack
Revision: `2c064081044a669dcb08ada07641be928b24934a`

Our fork of [narrowlink/ipstack](https://github.com/narrowlink/ipstack), branched from
upstream `e1d8506`. Every fix the switch needs lives there as its own commit, written to go
upstream as a pull request; `git log` in the fork is the patch list. The local measured-RTO
test waits for acknowledgment processing and uses the resulting timeout, so scheduling
delays do not require its first RTT sample to hit the minimum exactly.

Refresh it with `third_party/ipstack/vendor.sh <fork checkout> [rev]`, which copies the
sources, trims the manifest down to what a patched crate outside the workspace can carry
(see the script's header) and regenerates `Cargo.lock`.

The root workspace's `[patch.crates-io]` points the `ipstack` dependency here, so the
switch (`vk-driver/src/switch.rs`) builds against this copy. Its requirement spells out the
fork's pre-release version, because a plain requirement matches none; keep the two in step
when the fork's version moves. Run the tests with `./dev.sh test -p ipstack`.
