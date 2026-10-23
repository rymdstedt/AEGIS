#!/usr/bin/env python3
"""Loopback-only Naabu stand-in for the packaged discovery acceptance test.

This file is never installed as an AEGIS scanner. The acceptance runner puts a
temporary symlink named ``naabu`` first on the backend child's PATH.
"""

import json
import os
import sys
import time


def main() -> int:
    args = sys.argv[1:]
    try:
        target = args[args.index("-host") + 1]
    except (ValueError, IndexError):
        return 2
    if target != "127.0.0.1":
        print("Refusing a non-loopback target", file=sys.stderr)
        return 2

    state_path = os.environ["AEGIS_RECOVERY_TEST_CALLS"]
    listener_port = int(os.environ["AEGIS_RECOVERY_TEST_PORT"])
    scenario = os.environ["AEGIS_RECOVERY_TEST_SCENARIO"]
    if scenario not in {"retry", "partial"}:
        return 2

    if "-top-ports" in args and args[args.index("-top-ports") + 1] == "full":
        call = "full"
    elif "-p" in args:
        call = args[args.index("-p") + 1]
    else:
        return 2
    try:
        with open(state_path, encoding="ascii") as file:
            previous = file.read().splitlines()
    except FileNotFoundError:
        previous = []
    with open(state_path, "a", encoding="ascii") as file:
        file.write(call + "\n")

    if call == "full":
        print(json.dumps({"ip": target, "port": listener_port, "protocol": "tcp"}), flush=True)
        # The real packaged tool deadline is intentionally exercised. Its
        # subprocess group is terminated by ToolExecutor after 90 seconds.
        time.sleep(120)
        return 0

    start, end = map(int, call.split("-"))
    if not 1 <= start <= end <= 65_535 or end - start >= 16_384:
        return 2
    if start == 1 and (scenario == "partial" or previous.count(call) == 0):
        return 2
    if start <= listener_port <= end:
        print(json.dumps({"ip": target, "port": listener_port, "protocol": "tcp"}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
