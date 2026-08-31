# CVE-2026-82555 Predictable Session Token in TOTOLINK N600R V4.3.0cu.7866

## Summary

TOTOLINK N600R firmware **V4.3.0cu.7866_B20220506** generates the administrative session token via `md5(time(NULL))`, where `time(NULL)` returns the Unix timestamp at the moment of login. An unauthenticated attacker can brute-force the token within a narrow time window and hijack an active admin session, gaining full control of the router.

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | TOTOLINK |
| Device | N600R |
| Firmware | V4.3.0cu.7866_B20220506 |
| Build Date | 2022-05-06 |
| Architecture | MIPS 32-bit big-endian |
| Vulnerable Binary | `/web_cste/cgi-bin/cstecgi.cgi` |

## Vulnerability

The `loginAuth` handler in `cstecgi.cgi` (function `sub_415A38`) generates the session token by computing the MD5 hash of the current Unix timestamp:

```c
v10 = time(0);
sprintf(cmd, "echo -n \"%ld\" | md5sum | awk '{ print $1 }'", v10);
getCmdStr(cmd, token, 128);
f_write("/tmp/cookie_key", token, ...);   // session token
f_write("/tmp/token_uptime", timestamp, ...);  // raw timestamp leaked to disk
```

The token is set as the `cookie_key` cookie and used to authenticate all subsequent admin requests. Since it is derived solely from `time(NULL)`, it is predictable within a practical search window.

For detailed technical analysis, see [details.md](details.md).

## Impact

- **Confidentiality**: Read Wi-Fi PSK, PPPoE credentials, device configuration
- **Integrity**: Modify DNS, firewall rules, port forwarding, flash firmware
- **Availability**: Disconnect network, reboot device, deny service

## CVSS 3.1

**Score: 8.8 (HIGH)** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

## CWE

[CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

## Proof of Concept

```bash
pip install -r requirements.txt
python poc.py --target 192.168.0.1
```

A valid session can be guessed in minutes.

## Timeline

| Date | Event |
|------|-------|
| 2026-07-15 | Vulnerability discovered |
| 2026-07-15 | Submitted to VulDB |
| 2026-08-30 | CVE assigned |

## Directory Structure

```
├── README.md           # This file
├── details.md          # Detailed technical analysis with IDA evidence
├── poc.py              # Proof-of-concept exploit
├── requirements.txt    # Python dependencies
├── pics/               # Screenshots and diagrams
├── binaries/           # Vulnerable binary (cstecgi.cgi)
└── firmware/           # Affected firmware file
```
