# Outbounds

One complete Xray **outbound object** per file, used verbatim by the gateway.

`*.example.json` are committed templates. Everything else here is gitignored,
because these files hold your server credentials.

```bash
cp outbounds/main.example.json outbounds/main.json
$EDITOR outbounds/main.json          # or let `gw init` write it from a link
chmod 600 outbounds/main.json
```

Reference them from `gateway.toml`:

```toml
[xray.outbound]
file = "outbounds/main.json"

[[upstream]]
name = "work"
file = "outbounds/work.json"
```

Paths are resolved relative to `gateway.toml`.

The gateway overrides exactly two fields on whatever you put here:

- `tag` — routing rules reference outbounds by name
- `streamSettings.sockopt.mark` — the loop guard. Without it Xray's own packets
  are eligible for TPROXY and the box deadlocks as soon as interception starts.
  Don't set it yourself; a value that disagrees with `xray.outbound_mark` is
  rejected at load.

Anything else is yours: any protocol, transport, TLS/Reality settings, or a
chained outbound. If a config works in Xray, it works here — you can test one in
isolation with a minimal config and a SOCKS inbound before wiring it in.
