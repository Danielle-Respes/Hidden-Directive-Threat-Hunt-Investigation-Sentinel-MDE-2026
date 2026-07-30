# Artifact Analysis — GF-INC-2026-0704

## `aggregatorhost.exe` (system32, signed Microsoft Windows)

- **SHA1:** `afccdb1e4960076a55a778036765e0ca1bdcb37a`
- **SHA256:** `31220c37981ab267d3b455c660d21206475420ebb57a17ee6426e7ec41266912`
- **VirusTotal:** 0/69 — clean/signed binary, living-off-the-land (LOLBin) usage
- **Process chain:** `services.exe → svchost.exe (-k utcsvc -p) → aggregatorhost.exe`
- **Execution context:** Token elevation Standard → Integrity level System, run as `NT AUTHORITY\SYSTEM`
- **Action observed:** `RegistryValueSet` on `HKLM\SYSTEM\ControlSet001\Control\CI\WhqlOnlyEvaluation`, value `SystemUptimeTimestamp` changed `432382340000 → 450302340000`
- **Timeline correlation:** 2026-07-08 22:00:55 PM — outside the core 4 Jul incident window; flagged for follow-up (possible anti-forensic timestamp/uptime manipulation, or unrelated background telemetry — needs scoping against C01 window)
- **KQL confirming execution:** pending — add query against `WindowsRegistry_CL` scoped to this key/host once correlated to in-scope timeframe

## `keepass.zip` (GF-WS01)

- **Type:** Archive, staged post credential-harvesting
- **Timeline correlation:** Created shortly after `cmdkey /list` enumeration (C07, ~11:57 AM+)
- **Status:** Staging confirmed; exfiltration mechanics deferred to C11

*Binary strings/imports analysis and additional artifacts to be appended as recovered.*
