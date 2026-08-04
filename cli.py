"""Guided, single-command local_key extraction.

Wraps check_env.py + get_local_key.py into one interactive flow.

Order matters here: we get a *stable attached frida session* first, fully
automatically (retrying quietly, no human interaction, since retrying
doesn't actually need a human - the app was observed to occasionally
crash-loop for a few cycles on its own before settling down, unrelated to
anything the human does). Only once we're solidly attached do we ask the
human to open the gateway card - once - and then scan on that same
session, so the scan itself never has to re-attach.
"""

from __future__ import annotations

import argparse
import sys
import time

import adb_util
import check_env
import get_local_key as glk

APP_ACTIVITY = "com.danfoss.ally/com.smart.ThingSplashActivity"


def app_is_running(adb: str) -> bool:
    rc, out = adb_util.run(adb, ["shell", "su -c 'ps -A'"])
    return any(line.strip().endswith("com.danfoss.ally") for line in out.splitlines())


def relaunch_app(adb: str) -> None:
    print("[*] (re)launching the Danfoss Ally app...")
    adb_util.run(adb, ["shell", "am", "start", "-n", APP_ACTIVITY])
    time.sleep(5)


def get_stable_session(adb: str, timeout: int, max_attempts: int, retry_delay: float):
    """Keeps attaching (relaunching the app if it died) until a session
    sticks, with no human interaction - the app was observed to settle
    down after a few automatic cycles on its own."""
    for attempt in range(1, max_attempts + 1):
        try:
            session = glk.attach_to_app(timeout)
            if attempt > 1:
                print(f"[*] attached cleanly on attempt {attempt}/{max_attempts}")
            return session
        except glk.AttachFailed as e:
            print(f"[!] attach attempt {attempt}/{max_attempts} failed: {e}")
            if attempt == max_attempts:
                return None
            if not app_is_running(adb):
                relaunch_app(adb)
            else:
                time.sleep(retry_delay)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", required=True, help="Gateway's LAN IP address (for the credentials.py snippet)")
    parser.add_argument("--out", help="Write the credentials.py snippet to this path")
    parser.add_argument("--timeout", type=int, default=5, help="frida USB device discovery timeout (seconds)")
    parser.add_argument("--attach-attempts", type=int, default=20, help="automatic attach attempts before giving up")
    parser.add_argument("--attach-retry-delay", type=float, default=3.0, help="seconds between automatic attach retries")
    parser.add_argument("--skip-env-check", action="store_true", help="skip the environment prerequisite check")
    parser.add_argument(
        "--auto", action="store_true", help="don't pause for Enter - assume the gateway card is already open"
    )
    args = parser.parse_args()

    def pause(message: str) -> None:
        if args.auto:
            print(message.rstrip() + " (--auto: continuing without waiting)")
        else:
            input(message)

    if not args.skip_env_check:
        print("=" * 70)
        print("Step 1/4: checking environment (adb, root, frida-server, ...)")
        print("=" * 70)
        if check_env.main() != 0:
            print("\nFix the issue(s) above, then run this again.")
            return 1

    adb = adb_util.find_adb()
    if adb is None:
        print("[!] adb not found - see check_env.py output above (or run it without --skip-env-check).")
        return 1

    print("\n" + "=" * 70)
    print("Step 2/4: getting a stable connection to the app")
    print("=" * 70)
    if not app_is_running(adb):
        relaunch_app(adb)
    print("[*] attaching (this retries automatically - no need to do anything)...")
    session = get_stable_session(adb, args.timeout, args.attach_attempts, args.attach_retry_delay)
    if session is None:
        print(
            f"\nGave up after {args.attach_attempts} automatic attach attempts. The app seems to be\n"
            "crash-looping persistently - try closing it completely and re-running this script\n"
            "after a minute, or reboot the emulator/device."
        )
        return 1

    print("\n" + "=" * 70)
    print("Step 3/4: open the app")
    print("=" * 70)
    print(
        "Now, in the app, tap into the GATEWAY's device card (just view it -\n"
        "nothing to press inside). This is what loads its local_key into memory."
    )
    pause("Press Enter once the gateway card is open on screen... ")

    print("\n" + "=" * 70)
    print("Step 4/4: scanning")
    print("=" * 70)
    try:
        records = glk.run_scan(session)
    finally:
        session.detach()

    snippet = glk.report_and_build_snippet(records, args.ip, args.out)
    if snippet is None:
        print(
            "\nIf nothing useful was found, the gateway card likely wasn't open yet -\n"
            "just re-run the script, Step 2 will re-attach quickly since the app is warm now."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
