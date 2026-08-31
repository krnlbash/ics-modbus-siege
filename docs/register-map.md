# Track-Management PLC — Modbus Register/Coil Map

This defines the simulated industrial target: a stand-in for a PLC that would sit
between a radar/sensor feed and an HMI in a simplified track-management system
(inspired by generic air-defense/ATC track-management architectures — this is
**not** a real system, protocol, or product; it is a Modbus TCP teaching target).

## Coils (read/write, 1-bit) — base address 0

| Addr | Name              | Meaning                                      |
|------|-------------------|-----------------------------------------------|
| 0    | TRACK1_ACTIVE     | Track 1 present/active                        |
| 1    | TRACK2_ACTIVE     | Track 2 present/active                        |
| 2    | TRACK3_ACTIVE     | Track 3 present/active                        |
| 3    | TRACK4_ACTIVE     | Track 4 present/active                        |
| 8    | IFF_TRACK1_FRIEND | IFF resolved friendly for track 1 (0=unknown/hostile, 1=friend) |
| 9    | IFF_TRACK2_FRIEND | IFF resolved friendly for track 2             |
| 10   | IFF_TRACK3_FRIEND | IFF resolved friendly for track 3             |
| 11   | IFF_TRACK4_FRIEND | IFF resolved friendly for track 4             |
| 16   | OPERATOR_LOCKOUT  | Console lockout engaged (safety/HMI interlock) |
| 17   | ALARM_SILENCED    | Audible alarm silenced                        |

## Holding Registers (read/write, 16-bit) — base address 0

Each track occupies a 4-register block: `[bearing_deg, range_x10_nm, altitude_ft/10, speed_kts]`

| Addr | Name                  | Units / Notes                          |
|------|------------------------|-----------------------------------------|
| 0    | TRACK1_BEARING         | degrees, 0-359                          |
| 1    | TRACK1_RANGE           | nautical miles × 10                     |
| 2    | TRACK1_ALTITUDE        | feet / 10                               |
| 3    | TRACK1_SPEED           | knots                                   |
| 4-7  | TRACK2_* (same layout) |                                          |
| 8-11 | TRACK3_*               |                                          |
| 12-15| TRACK4_*               |                                          |
| 100  | SYSTEM_MODE            | 0=standby, 1=track, 2=maintenance       |
| 101  | WATCHDOG_COUNTER       | incremented by PLC each scan cycle      |

## Input Registers (read-only, 16-bit) — base address 0

| Addr | Name         | Notes                                    |
|------|--------------|-------------------------------------------|
| 0    | SENSOR_HEALTH| bitfield: bit0=radar OK, bit1=IFF interrogator OK |
| 1    | SCAN_RATE_RPM| simulated antenna scan rate               |

## Threat model this maps to

- No authentication on Modbus TCP (matches real-world Modbus, which has none natively)
- Writable coils/registers mean any client that can reach the port can:
  - Spoof a track into existence or erase a real one (coil flip)
  - Flip IFF resolution (friend/hostile mislabeling — the highest-impact spoof)
  - Overwrite bearing/range/altitude/speed of a live track (false data injection)
  - Force OPERATOR_LOCKOUT or ALARM_SILENCED (denial of alerting)
- This is the same class of exposure documented in real ICS/SCADA advisories for
  unauthenticated Modbus deployments — the scenario is illustrative, not fictional physics.
