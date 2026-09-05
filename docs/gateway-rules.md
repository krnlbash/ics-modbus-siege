# Level 2 — Access Control Gateway Policy

`gateway/modbus_gateway.cpp` sits between clients and `track_sim`, enforcing
the rules below on every request. See `simulator/track_sim.cpp` and
`docs/register-map.md` for what the addresses mean.

## The policy

| Rule | Detail |
|------|--------|
| Reads | Function codes 1–4 (read coils/discrete inputs/holding regs/input regs) are allowed from **any** source IP. |
| Writes — who | Function codes 5, 6, 15, 16 (writes) are allowed **only** from `127.0.0.2`, standing in for a trusted operator console. Any other source gets an `ILLEGAL FUNCTION` exception, regardless of what address it's targeting. |
| Writes — where | Even the trusted console may only write within: holding registers **0–15** (track kinematic data) and coils **0–3**, **8–11** (track-active / IFF flags). Anything outside those ranges — including `SYSTEM_MODE` (100), `WATCHDOG_COUNTER` (101), `OPERATOR_LOCKOUT` (16), `ALARM_SILENCED` (17) — gets an `ILLEGAL DATA ADDRESS` exception even from the trusted IP. |

Trust and range-checking are two independent gates. A request has to clear
both to be forwarded to the backend.

## Why this specific split

- **IP-based trust** mirrors a real, common ICS mitigation: a Modbus-aware
  firewall or gateway restricting which hosts may issue writes at all — the
  first thing most ICS security guidance recommends for unauthenticated
  protocols.
- **Address-range limits independent of trust** models something often
  missed in real deployments: even a legitimate operator console shouldn't
  necessarily be able to touch safety-interlock or system-mode registers
  through the same interface it uses for routine track updates. Trusting
  a source doesn't mean granting it unlimited scope.

## What an attacker learns from the exception codes

The gateway returns real, distinct Modbus exception codes rather than
silently dropping requests:

- `ILLEGAL FUNCTION` (0x01) — sent for untrusted-IP denials and for
  genuinely unrecognized function codes
- `ILLEGAL DATA ADDRESS` (0x02) — sent for range violations, including from
  the trusted IP

This is realistic (a production Modbus gateway typically does respond, not
silently swallow the request) but it also leaks information: `probe-acl`
mode in `modbus_toolkit` uses exactly this distinction to map out the
boundary of the policy from the outside — "these all come back as illegal
function, so I'm probably not a trusted source at all" vs. "some of my
writes succeed and others come back illegal-address, so I'm trusted but
capped." That reconnaissance capability, without ever bypassing the
policy, is the "attacker adapts" half of Level 2 — and it's also exactly
the kind of signal a stealthier gateway (Level 4's anomaly detection) would
need to notice and respond to.

## Running the three-tier setup

```bash
./build/track_sim 127.0.0.1 15020                       # backend PLC
./build/modbus_gateway 127.0.0.1 15021 127.0.0.1 15020   # gateway: listens on 15021, forwards to 15020
```

Attacker (default, untrusted):
```bash
./build/modbus_toolkit 127.0.0.1 15021 probe-acl
```

Trusted console:
```bash
./build/modbus_toolkit --bind-ip 127.0.0.2 127.0.0.1 15021 probe-acl
```
