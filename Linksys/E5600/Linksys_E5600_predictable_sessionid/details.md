# Linksys E5600 — Predictable Admin Session ID → Admin Session Hijack

## Summary

The web management interface of the Linksys E5600 router (firmware **1.1.0.26**) generates the administrator session ID by concatenating the **client IP address** with the **current Unix timestamp**, with **no cryptographic randomness**. An unauthenticated, network-adjacent attacker who knows the administrator's IP can predict the session ID of an active admin session and hijack it **from any source IP**, obtaining administrative control of the router.

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | Linksys |
| Device | E5600 Dual-Band AC1200 Wi-Fi Router |
| Firmware | 1.1.0.26 (`FW_E5600_1.1.0.26_prod.img`) |
| Architecture | MIPS 32-bit little-endian |
| Component | Web management session (`login.cgi` / `mod_session.so`) |

## Vulnerability

In `login.cgi`, when a request has no `HSESSIONID` cookie, the session ID is built with the format string `"%s%lli"`:

```
sessionid = <REMOTE_ADDR with dots removed> + <gettimeofday().tv_sec>
```

No random source is used (no `/dev/urandom`, no `getrandom`, no `rand`). The value is stored in `/tmp/httpd_session` and issued as:

```
Set-Cookie: HSESSIONID=<sessionid>; path=/; HttpOnly; SameSite=Strict
```

`mod_session.so` validates the `HSESSIONID` cookie only by matching the stored session and a 600-second sliding timeout — it **never checks the requester's source IP against the session**, so a hijacked session works from any IP.

## Impact

- **Confidentiality**: read Wi-Fi passwords, PPPoE credentials, full config
- **Integrity**: modify DNS, firewall, port forwarding; reflash firmware
- **Availability**: disconnect / reboot the device

## CVSS 3.1

**9.8 (CRITICAL)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (LAN-only exposure → `AV:A`, 8.8 HIGH)

## CWE

[CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

## Proof of Concept

```bash
pip install requests
python exp.py --target http://192.168.1.1 --victim-ip 192.168.1.2
```

- Brute-forces the ≤600-second session window (one candidate per second).
- Known login time → exact match in a single request (`--login-time <eexph>`).
- Success: `/system-status.html` returns the full admin page (7702 bytes) instead of the 55-byte unauthenticated redirect.
- Verified cross-IP: attacker at a different source IP hijacks the admin session.

## Remediation

1. Generate session IDs with a CSPRNG (`/dev/urandom` / `getrandom()`), ≥128 bits.
2. Bind the session to the client IP and validate it on every request.
3. Do not issue a session on failed login; add brute-force protection.

## Timeline

| Date | Event |
|------|-------|
| 2026-08-14 | Vulnerability identified (static analysis) |
| 2026-08-27 | Reproduced and validated in emulated firmware; exp written |
| 2026-08-27 | Disclosed / CVE requested |
