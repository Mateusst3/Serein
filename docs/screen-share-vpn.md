# VPN for outgoing screen-share media

Set `SEREIN_SCREEN_WIREGUARD_CONFIG` to an existing, private WireGuard configuration
before starting the new Serein build. On macOS, the launcher uses the standard locally
packaged application:

```sh
chmod 600 /path/to/proton.conf
sh scripts/screen-share-vpn.sh /path/to/proton.conf
```

An explicit executable and its arguments can follow the configuration path. Quit an
already running Serein before launching; it cannot inherit the new environment. The
application must contain this implementation; the launcher cannot add VPN support to
an older binary. Build with the pinned toolchain and `cargo xtask package`.
Keep the Proton application disconnected when other traffic should remain direct.
Existing system VPNs/proxies still determine ordinary connections' routes.

Only the outgoing screen-share UDP connection (video, optional shared audio, discovery,
feedback and keepalives) uses the tunnel. Call audio, camera, watching other streams,
REST, gateway and stream WebSocket signaling retain their existing system routes. This
does not conceal the normal connection's address from Discord. No OS interface, route,
DNS setting, privileged helper or local listening proxy is installed. Missing opt-in
retains ordinary media routing. An unreadable/invalid configured file, unsupported media
address or failed tunnel stops sharing; there is no direct fallback.

The file is read off the UI/audio threads only when establishing an outgoing share.
Serein never copies or persists the configuration, key or path. It caps the file at 16 KiB,
requires a regular file and rejects group/other permissions on Unix. Keep the file private
on other platforms using native ACLs. File contents and decoded private keys use zeroizing
memory; errors contain neither keys nor file contents. Deleting the file prevents future
tunnel creation; stop an existing share to release its tunnel and keys.

The supported subset has one `[Interface]`, one `[Peer]`, base64 private/public keys,
an optional preshared key, one IPv4 `/32` interface address, IPv4 default `AllowedIPs`,
a numeric endpoint and optional persistent keepalive. Proton's extra IPv6 `/128` address
and default range are accepted but unused. `DNS` is ignored. Hooks, multiple peers and
unknown options fail visibly. Only IPv4 Discord media endpoints are supported; the VPN
endpoint can use either family. Each share uses a random inner UDP port. Use a dedicated
configuration/key for Serein rather than activating the same key in another VPN client.

The single-flow adapter checks inner IPv4/UDP lengths, checksums and both address/port
pairs, rejecting fragments and other protocols/flows. Each direction queues at most 64
datagrams of 4,096 bytes (256 KiB payload). BoringTun's rekey queue holds at most 256 inner
packets of 4,124 bytes. Scratch buffers are fixed; full media queues drop datagrams.
Initial handshake waits at most 12 seconds; no successful rekey in 180 seconds closes the
session. Dropping the share aborts the worker. Discord DAVE and transport encryption remain
inside WireGuard.

## Verification

`cargo test --locked -p screen-tunnel` uses a synthetic localhost WireGuard peer. It checks
authenticated round trips, rejection of another inner flow, cancellation, queue/packet
bounds, malformed configurations and absence of direct fallback. These fixtures do not
establish working Discord screen sharing.

To check only the VPN peer (no Discord connection, capture or inner IP traffic):

```sh
cargo run --locked -p screen-tunnel --example handshake -- /path/to/proton.conf
```

Proton configuration export and standard WireGuard compatibility are
[documented by Proton](https://protonvpn.com/support/wireguard-configurations).
The application-specific adapter is Serein behavior, not a Proton integration guarantee.
Live Discord interoperability remains unverified and requires the owner's explicit
developer-session gate and control of the private conversation.
