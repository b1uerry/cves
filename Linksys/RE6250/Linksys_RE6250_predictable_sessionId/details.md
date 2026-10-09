# Linksys RE6250 — Predictable Admin Session ID → Admin Session Hijack

## Summary

The web management interface of the Linksys RE6250 range extender (firmware **v1.0.04.001**) generates the administrator session ID with the C library PRNG seeded **only by the current wall-clock second**:

```c
srand(time(0) + srv[141]);                  /* srv[141] is always 0 — see §2 */
session_id[i] = token_char[rand() % 62];    /* 32 characters */
```

No CSPRNG is involved (no `/dev/urandom`, no `getrandom`). The resulting 32-character value is handed to the client as the `session_id` cookie and is later validated by a bare `strcmp()` — with **no source-IP binding**. An unauthenticated attacker who knows (or can narrow down) the second in which the administrator logged in can compute the session ID **offline** and hijack the active admin session, obtaining full administrative control of the device.

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | Linksys (Belkin International) |
| Device | RE6250 Wi-Fi Range Extender ("Range Extender" per firmware `rcS` / nvram) |
| Firmware | v1.0.04.001, build 2021-10-28 (`FW_RE6250_v1.0.04.001_20211028.gpg.bin`) |
| Build tag | `RE6350_RE6250_v1.0.04_build1` / `RE6350_RE6250_v1.0.04.build_1_disable_console` |
| Architecture | MIPS 32-bit little-endian (kernel 2.6.36, uClibc 0.9.33.2, lighttpd 1.4.29) |
| Components | `usr/local/lib/mod_ssi.so` (`gen_random_char`), `usr/local/lib/mod_form.so` (`webLogin`), `usr/local/lib/mod_auth.so` (session validation), `bin/lighttpd` (cookie parsing) |
| Possibly affected | Sibling models sharing the same build (RE6350, RE6700 strings are present) — **not verified** |

## Vulnerability

### 1. Session ID generation — non-cryptographic PRNG, time-only seed

`POST /goform/webLogin` (handler `sub_36EF0`, `usr/local/lib/mod_form.so`) calls `gen_random_char()` from `usr/local/lib/mod_ssi.so`:

```c
int gen_random_char(int srv, int out, int n)
{
    ...
    v8 = time(0);                      /* seed: current second        */
    v9 = *(_DWORD *)(srv + 564);       /* srv[141]: token counter     */
    srand(v8 + v9);                    /* uClibc srand() -> srandom_r */
    do {
        v11 = rand();                  /* uClibc rand() == random()   */
        *v12 = token_char[v11 % 0x3E]; /* 62-char alphabet            */
    } while (n2_1 != n);
    strcpy(out, v13);
}
```

`token_char = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"`, `n = 32`.

The value is written to `/tmp/session_id` and issued to the client:

```c
gen_random_char(a1, a1 + 732, 32);
doSystem("echo %s > /tmp/session_id", (const char *)(a1 + 732));
...
buffer_copy_string(v15, "session_id=");
buffer_append_string(v15, a1 + 732);
response_header_append(a1, a2, "Set-Cookie", 10, *v15, v18);
```

The PRNG is the standard additive-feedback generator of uClibc 0.9.33.2 (`TYPE_3`, implemented as `random_r`), and it is seeded **only** with the epoch second. Its entire output is therefore a pure function of that second.

### 2. The seed is exactly `time(0)` — no other entropy

The seed expression is `time(0) + srv[141]`. `srv[141]` is a token counter, but it is **never written in practice**:

- Its only incrementing writer, `addToken()` (`mod_ssi.so`), is called only by `genToken()`, which is reachable only through the SSI tag `#genToken` — **no file in the firmware uses that tag**.
- `delToken()` (`mod_ssi.so`, `mod_form.so`) and `checkToken()` (`mod_form.so`) have **no callers** (unreachable).

Therefore `srv+564` stays in its zero-initialised BSS state for the whole process lifetime, and the seed is simply `time(0)`.

### 3. Validation is a bare `strcmp()` — no IP binding, no HMAC

`mod_auth.so` (`sub_1BBC`) protects every `*.shtml` page and `/goform/*` endpoint. For requests carrying a cookie it performs:

```c
if ( *(_BYTE *)(con + 588) )                 /* cookie present?            */
{
    if ( strcmp(srv + 732, con + 588) )      /* plain string compare       */
        goto LABEL_115;                      /* -> unauthenticated (307)   */
    v72 = atoi(nvram_get("AuthTimeout")) + srv[772] < uptime;   /* expiry    */
}
```

- The comparison is a plain `strcmp()` against the stored 32-character string — there is **no HMAC, no server-side salt, no per-session secret**.
- Nothing in the check compares the requester's source address with the session, so the cookie is **transferable across hosts**.
- The only lifetime control is `AuthTimeout` (nvram) evaluated against *device uptime*; it does not mitigate prediction of a currently-valid ID.

`bin/lighttpd` (1.4.29) extracts the value by locating the literal `session_id=` inside the `Cookie` header and copies up to 32 bytes into the connection state consumed above.

Consequently, the effective entropy of the credential is **the uncertainty of the admin's login second** — typically a few thousand candidates, all computable offline.

## Impact

- **Confidentiality**: read Wi-Fi passphrases, WPS PIN, PPPoE/DDNS credentials and the full device configuration.
- **Integrity**: change the admin password, DNS servers, SSID/security, port forwarding; upload/install firmware.
- **Availability**: reboot or reset the device, disable the network.

The attack requires no credentials and no user interaction; a single login-time estimate is sufficient.

## CVSS 3.1

**8.8 (HIGH)** — `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

*(The management interface is normally reachable only from the adjacent network. If the web UI is exposed beyond the LAN, the vector becomes `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 CRITICAL**.)*

## CWE

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html) (primary)
- [CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

## Proof of Concept

A self-contained PoC (`re6250_session_id_exp.py`, Python 3 + `requests`) reproduces the generator and walks backwards from the current time, one candidate per second:

```bash
pip install requests
python3 re6250_session_id_exp.py 192.168.154.128:8080
```

- Success criterion: the protected page returns **HTTP 200** (e.g. `/admin/management.shtml`, 19,378 bytes) instead of the **307** redirect to `/redirect.shtml?url=/login.shtml` that unauthenticated requests receive.
- Known admin login time (`T`) → the session ID is obtained in a single request, since `session_id = gen_random_char(T)`.

The generator is a bit-exact re-implementation of the firmware's PRNG (`TYPE_3` additive-feedback; `srand()` seed 0 → 1; first 310 outputs discarded; `result = (*fptr += *rptr) >> 1`), and was validated against the glibc canonical sequence for `srand(1)`.

A stronger demonstration — the attacker never sees the `Set-Cookie` value — was also run: the attacker is given **only the login second** and blindly tries candidates.

## Evidence (verified against the vendor firmware under QEMU emulation)

| Step | Result |
|------|--------|
| Offline calibration of four real session IDs | Every observed `session_id` was recovered from its seed (e.g. seed `1791512338` → `ALxZ3O3EtRxX2pnaoFtJh7GshosqFXoN`, with `srv[141] = 0`), confirming the PRNG model and the seed formula |
| Login-prediction | Login at epoch `1791512267`; device returned `Set-Cookie: session_id=GNotkVmAbDBIL4oYFEF3Q7wSxiHvUk9k`; reproduced exactly by the PoC generator from that second |
| **Blind attack** (no access to `Set-Cookie`) | Given only the login second `1791512355`, the predicted value `dmW1QAeg7JCN7EADGnGBUXKoafMrJcjw` matched the device's value **on the 2nd request (0.7 s)** |
| Access with the predicted cookie | `/wireless/wireless_basic.shtml` → **HTTP 200** (413,297 bytes); `/admin/management.shtml` → **HTTP 200** (19,378 bytes) |
| Access without the cookie | HTTP **307** redirect to `/redirect.shtml?url=/login.shtml` |

## Remediation

1. Generate session IDs with a CSPRNG (`getrandom()` / `/dev/urandom`), at least 128 bits, and never derive them from time or any other predictable value.
2. Bind each session to its originating client (e.g. address and/or a random per-session secret) and validate on every request.
3. Store only a hash of the session ID server-side.
4. Do not create a session on failed authentication; add rate limiting on the login endpoint.
5. Do not persist the session ID in a world-readable file such as `/tmp/session_id`.


## Timeline

| Date | Event |
|------|-------|
| 2026-10-08 | Vulnerability identified by static analysis of the firmware image |
| 2026-10-09 | Reproduced and validated on the vendor firmware under emulation; PoC written and blind attack confirmed |
| 2026-10-09 | CVE ID requested |
