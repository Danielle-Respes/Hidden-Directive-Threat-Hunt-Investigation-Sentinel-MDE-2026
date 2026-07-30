# Remediation Notes — GF-INC-2026-0704

**DETECTION GAP:** Azure Run Command executed by a Service Principal outside CI/CD pipelines went unalerted.
→ **Recommendation:** Alert on `RUNCOMMAND/ACTION` from Service Principals; enforce JIT/least-privilege for Contributor-role SPs.

**DETECTION GAP:** PowerShell execution-policy bypass (`-ExecutionPolicy Unrestricted`) not flagged.
→ **Recommendation:** Detection rule on execution-policy-bypass flags in any process command line.

**DETECTION GAP:** Local admin account creation (`sancadmin`) not alerted.
→ **Recommendation:** Sentinel rule on `net user /add` + `net localgroup administrators /add` chained within seconds.

**DETECTION GAP:** Token theft (`ProcessPrimaryTokenModification`) only visible in MDE, not SIEM.
→ **Recommendation:** Onboard token-manipulation events into Sentinel via Defender XDR connector.

**DETECTION GAP:** Named-pipe stdin shell execution (`CmdExecutionWithStdInNamedPipe`) not flagged.
→ **Recommendation:** Alert on this pattern — strong indicator of remote tooling vs. interactive use.

**DETECTION GAP:** Credential-store enumeration (`cmdkey /list`) and KeePass vault access not alerted.
→ **Recommendation:** Rule on password-manager launch + archive creation (`keepass.zip`) in short sequence.

**DETECTION GAP:** AD service-account reconnaissance (`Get-ADUser svc_backup -Properties ServicePrincipalNames`) not detected.
→ **Recommendation:** Rule on SPN-property queries against service accounts — Kerberoasting precursor.

**DETECTION GAP:** LSASS-dump prep (`tasklist | findstr lsass`) not flagged.
→ **Recommendation:** Alert on LSASS PID enumeration preceding known dumping tool execution.

**DETECTION GAP:** Pass-the-Hash / Overpass-the-Hash lateral movement not alerted in real time.
→ **Recommendation:** Rule on machine-account auth combined with anomalous TGT/TGS patterns (4768/4769); correlate repeated 4771 failures preceding a success.

**DETECTION GAP:** No baseline for Kerberos ticket volume through GF-DC01.
→ **Recommendation:** Baseline per-host/IP ticket volume; alert on deviation now that GF-DC01 is confirmed as the operation's authentication pivot.
