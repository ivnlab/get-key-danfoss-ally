"""Environment check for the local_key extraction tool.

Run this first. It does not touch the phone beyond read-only `adb`/`pm`/`ps`
queries - no push, no install, no key extraction. It just tells you what's
missing before you run get_local_key.py.
"""

from __future__ import annotations

import sys

import adb_util

APP_PACKAGE = "com.danfoss.ally"

# frida-server asset naming: github.com/frida/frida releases use these
# short arch names, which don't match Android's own ro.product.cpu.abi values.
ABI_TO_FRIDA_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


def ok(label: str, detail: str = "") -> None:
    print(f"[OK]   {label}" + (f" - {detail}" if detail else ""))


def fail(label: str, detail: str = "") -> None:
    print(f"[MISS] {label}" + (f" - {detail}" if detail else ""))


def main() -> int:
    problems = 0

    # 1. locate adb - on PATH, bundled next to this script, or a known install location
    adb = adb_util.find_adb()
    if adb is None:
        fail("adb", "not found on PATH, next to this script, or in any known install location")
        problems += 1
        print(
            "\nCan't check anything else without adb. Either put adb.exe next to this\n"
            "script, or install Android platform-tools:\n"
            "  https://dl.google.com/android/repository/platform-tools-latest-windows.zip\n"
            "Stopping here."
        )
        return 1
    ok("adb found", adb)

    def adb_shell(args: str) -> tuple[int, str]:
        return adb_util.run(adb, ["shell", args])

    # 2. device connected and authorized
    rc, out = adb_util.run(adb, ["devices"])
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("List of")]
    devices = [l.split()[0] for l in lines if l.split() and l.split()[1] == "device"]
    unauthorized = [l for l in lines if "unauthorized" in l]
    if unauthorized:
        fail("device authorization", "device connected but unauthorized - accept the RSA prompt on the phone screen")
        problems += 1
    if not devices:
        fail("device connection", "no authorized device in `adb devices` - check USB cable/debugging toggle, or that the emulator is running")
        problems += 1
        print("\nCan't check anything device-side without a connected device. Stopping here.")
        return 1
    ok("device connected", devices[0])

    # 3. root access
    rc, out = adb_shell("su -c id")
    if "uid=0" in out:
        ok("root access", "su -c works")
    else:
        fail("root access", f"`adb shell su -c id` did not return uid=0 (got: {out!r})")
        problems += 1

    # 4. CPU ABI (needed to pick the right frida-server build)
    rc, abi = adb_shell("getprop ro.product.cpu.abi")
    abi = abi.strip()
    frida_arch = ABI_TO_FRIDA_ARCH.get(abi)
    if frida_arch:
        ok("device ABI", f"{abi} -> frida-server arch '{frida_arch}'")
    else:
        fail("device ABI", f"unrecognized value {abi!r}")
        problems += 1

    # 5. Danfoss Ally app installed
    rc, out = adb_shell(f"pm list packages {APP_PACKAGE}")
    if APP_PACKAGE in out:
        ok("Danfoss Ally app installed")
    else:
        fail("Danfoss Ally app", f"package {APP_PACKAGE} not found on device")
        problems += 1

    # 6. frida-server binary present on device
    rc, out = adb_shell("su -c 'ls -la /data/local/tmp/frida-server 2>/dev/null'")
    server_present = "frida-server" in out and "No such file" not in out
    if server_present:
        ok("frida-server binary present", "/data/local/tmp/frida-server")
    else:
        fail("frida-server binary", "not found at /data/local/tmp/frida-server")
        problems += 1

    # 7. frida-server currently running
    rc, out = adb_shell("su -c 'ps -A' | grep frida-server")
    if "frida-server" in out:
        ok("frida-server running")
    else:
        fail("frida-server running", "not in process list - start it (see README)")
        problems += 1

    # 8. frida python package + version, for matching frida-server build
    try:
        import frida  # noqa: PLC0415

        ok("frida python package", f"version {frida.__version__}")
        if frida_arch and not server_present:
            print(
                "\nDownload the matching frida-server for this device:\n"
                f"  https://github.com/frida/frida/releases/download/"
                f"{frida.__version__}/frida-server-{frida.__version__}-android-{frida_arch}.xz\n"
                "  Unpack it (Windows needs 7-Zip for .xz), then:\n"
                f'    "{adb}" push frida-server /data/local/tmp/frida-server\n'
                f"    \"{adb}\" shell su -c 'chmod 755 /data/local/tmp/frida-server'\n"
                f"    \"{adb}\" shell su -c '/data/local/tmp/frida-server &'\n"
                "  The frida-server version MUST match the frida pip package version above."
            )
    except ImportError:
        fail("frida python package", "not installed - run: pip install frida")
        problems += 1

    print()
    if problems:
        print(f"{problems} issue(s) found - fix them, then re-run this check.")
        return 1
    print("Environment looks ready. You can run get_local_key.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
