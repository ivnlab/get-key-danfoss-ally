"""Extract a Danfoss Ally gateway's Tuya local_key (and its sub-devices'
cid/nodeId table) from the running Android app's process memory.

Generalized version of the original ad hoc mem_scan.py: it does not need any
device_id known ahead of time. It scans the whole process for the literal
JSON key patterns `"localKey":"` and `"nodeId":"`, then pulls the sibling
fields (devId, name, parentDevId) out of the text immediately around each
hit. This is the same manual grep-around-the-match process from
docs/LOCAL_KEY_EXTRACTION_METHOD.md, automated.

Prerequisites (see check_env.py and the README in this folder):
  - adb, connected + authorized device, root (su) access
  - frida-server running on the device, matching the local `frida` pip version
  - Danfoss Ally app open, logged in, device list loaded
  - the target device's card opened at least once (local_key is loaded lazily
    per-card; nodeId/deviceTopo usually comes with the device list already)

Usage:
    python get_local_key.py --ip 192.168.1.50
    python get_local_key.py --ip 192.168.1.50 --out credentials_snippet.py
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field

import frida

PROCESS_NAME = "Ally"  # confirmed process name is "Ally", not "com.danfoss.ally"

NEEDLES = [
    '"localKey":"',
    '"nodeId":"',
]

WINDOW_BEFORE = 2000
WINDOW_AFTER = 2000
FIELD_SEARCH_RADIUS = 1200

# minified schema/type definitions in the app bundle contain literal strings
# like {"devId":"devId","localKey":"localKey",...} - field name used as its
# own value. Real device records never do this, so these are safe to discard.
SCHEMA_LOOKALIKE_VALUES = {"devId", "name", "customName", "localKey", "nodeId", "parentDevId"}

FIELD_PATTERNS = {
    "devId": re.compile(r'"devId"\s*:\s*"([^"]*)"'),
    "name": re.compile(r'"(?:customName|name)"\s*:\s*"([^"]*)"'),
    "localKey": re.compile(r'"localKey"\s*:\s*"([^"]*)"'),
    "nodeId": re.compile(r'"nodeId"\s*:\s*"([^"]*)"'),
    "parentDevId": re.compile(r'"parentDevId"\s*:\s*"([^"]*)"'),
}

JS_SCAN_SCRIPT = r"""
const NEEDLES = __NEEDLES__;
const WINDOW_BEFORE = __WINDOW_BEFORE__;
const WINDOW_AFTER = __WINDOW_AFTER__;

function toHexPattern(str) {
    let bytes = [];
    for (let i = 0; i < str.length; i++) bytes.push(str.charCodeAt(i));
    return bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
}

function bufToHex(buf) {
    const arr = new Uint8Array(buf);
    let out = '';
    for (let i = 0; i < arr.length; i++) out += arr[i].toString(16).padStart(2, '0');
    return out;
}

rpc.exports = {
    scan: function () {
        const results = [];
        let ranges = [];
        try {
            ranges = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
        } catch (e) {}
        const seenRange = new Set();
        for (const r of ranges) {
            const key = r.base.toString() + '_' + r.size;
            if (seenRange.has(key)) continue;
            seenRange.add(key);
            for (const needle of NEEDLES) {
                const pattern = toHexPattern(needle);
                try {
                    const matches = Memory.scanSync(r.base, r.size, pattern);
                    for (const m of matches) {
                        const start = m.address.sub(WINDOW_BEFORE);
                        const len = WINDOW_BEFORE + WINDOW_AFTER;
                        try {
                            const buf = start.readByteArray(len);
                            results.push({
                                needle: needle,
                                addr: m.address.toString(),
                                hex: bufToHex(buf),
                            });
                        } catch (e) {
                            // window straddled an unmapped page edge - skip
                        }
                    }
                } catch (e) {}
            }
        }
        return results;
    }
};
""".replace("__NEEDLES__", str(NEEDLES)).replace(
    "__WINDOW_BEFORE__", str(WINDOW_BEFORE)
).replace("__WINDOW_AFTER__", str(WINDOW_AFTER))


@dataclass
class DeviceRecord:
    dev_id: str
    name: str | None = None
    local_key: str | None = None
    node_id: str | None = None
    parent_dev_id: str | None = None
    sources: list[str] = field(default_factory=list)

    def merge(self, other: "DeviceRecord", source: str) -> None:
        self.name = self.name or other.name
        self.local_key = self.local_key or other.local_key
        self.node_id = self.node_id or other.node_id
        self.parent_dev_id = self.parent_dev_id or other.parent_dev_id
        self.sources.append(source)


class AttachFailed(Exception):
    """Raised when the app process isn't found, or dies between listing and attach.

    Both are expected flakes (see docs/LOCAL_KEY_EXTRACTION_METHOD.md) - callers
    should catch this and retry rather than treat it as fatal.
    """


def attach_to_app(timeout: int) -> frida.core.Session:
    device = frida.get_usb_device(timeout=timeout)
    procs = device.enumerate_processes()
    target = next((p for p in procs if p.name == PROCESS_NAME), None)
    if target is None:
        candidates = [p.name for p in procs if "ally" in p.name.lower() or "danfoss" in p.name.lower()]
        hint = f"similarly named processes running: {candidates}" if candidates else "is the app open in the foreground?"
        raise AttachFailed(f"process '{PROCESS_NAME}' not found - {hint}")
    print(f"[*] attaching to {target.name} (pid {target.pid})")
    try:
        return device.attach(target.pid)
    except (frida.ProcessNotFoundError, frida.NotSupportedError) as e:
        raise AttachFailed(f"attach failed ({e}) - the app process likely died/respawned between listing and attach")


def find_field_near(text: str, pattern: re.Pattern, anchor: int, radius: int, direction: str) -> str | None:
    """direction='before': last match ending <= anchor. 'after': first match starting >= anchor."""
    lo = max(0, anchor - radius)
    hi = min(len(text), anchor + radius)
    window = text[lo:hi]
    local_anchor = anchor - lo
    matches = list(pattern.finditer(window))
    if not matches:
        return None
    if direction == "before":
        before = [m for m in matches if m.end() <= local_anchor]
        return before[-1].group(1) if before else None
    after = [m for m in matches if m.start() >= local_anchor]
    return after[0].group(1) if after else None


def parse_hits(raw_hits: list[dict]) -> dict[str, DeviceRecord]:
    records: dict[str, DeviceRecord] = {}
    unparsed = 0

    for hit in raw_hits:
        try:
            raw = bytes.fromhex(hit["hex"])
        except ValueError:
            unparsed += 1
            continue
        text = raw.decode("latin-1")
        anchor = WINDOW_BEFORE  # match starts approximately here

        needle = hit["needle"]
        m = FIELD_PATTERNS["localKey" if needle.startswith('"localKey"') else "nodeId"].search(
            text[anchor - 5 : anchor + 200]
        )
        direct_value = m.group(1) if m else None

        dev_id = find_field_near(text, FIELD_PATTERNS["devId"], anchor, FIELD_SEARCH_RADIUS, "before")
        if dev_id is None:
            dev_id = find_field_near(text, FIELD_PATTERNS["devId"], anchor, FIELD_SEARCH_RADIUS, "after")
        if dev_id is None:
            unparsed += 1
            continue
        if dev_id in SCHEMA_LOOKALIKE_VALUES or (direct_value and direct_value in SCHEMA_LOOKALIKE_VALUES):
            # matched a minified JSON-schema/type definition (e.g. {"devId":"devId",...}),
            # not an actual device record - discard
            unparsed += 1
            continue

        name = find_field_near(text, FIELD_PATTERNS["name"], anchor, FIELD_SEARCH_RADIUS, "before")
        parent_dev_id = find_field_near(text, FIELD_PATTERNS["parentDevId"], anchor, FIELD_SEARCH_RADIUS, "before")

        rec = DeviceRecord(dev_id=dev_id)
        if needle.startswith('"localKey"'):
            rec.local_key = direct_value or None
        else:
            rec.node_id = direct_value or None
        rec.name = name
        rec.parent_dev_id = parent_dev_id

        source = f"{needle}@{hit['addr']}"
        if dev_id in records:
            records[dev_id].merge(rec, source)
        else:
            rec.sources.append(source)
            records[dev_id] = rec

    if unparsed:
        print(f"[!] {unparsed} hit(s) could not be parsed (devId not found nearby) - ignored")

    return records


def print_report(records: dict[str, DeviceRecord]) -> list[DeviceRecord]:
    gateways = [r for r in records.values() if r.local_key]
    subs = [r for r in records.values() if r.node_id and not r.local_key]

    print("\n" + "=" * 70)
    print(f"{len(records)} distinct device_id(s) found in memory")
    print("=" * 70)

    if not gateways:
        print(
            "\n[!] No non-empty localKey found yet.\n"
            "    Open the gateway's device card in the app (just view it,\n"
            "    no need to press anything), then re-run this script."
        )
    for g in gateways:
        print(f"\nGATEWAY  devId={g.dev_id}  name={g.name!r}")
        print(f"         local_key={g.local_key}")

    if subs:
        print(f"\n{len(subs)} sub-device(s) (nodeId = device_cid):")
        print(f"{'devId':<26} {'nodeId (cid)':<20} {'parentDevId':<26} name")
        for s in sorted(subs, key=lambda r: r.name or r.dev_id):
            print(f"{s.dev_id:<26} {s.node_id or '-':<20} {s.parent_dev_id or '-':<26} {s.name}")
    else:
        print(
            "\nNo sub-devices with a nodeId found yet.\n"
            "Open the device list (and ideally each RT's card once) in the app, then re-run."
        )

    return gateways


def build_credentials_snippet(ip: str, gateway: DeviceRecord, subs: list[DeviceRecord]) -> str:
    lines = [
        "from __future__ import annotations",
        "",
        f'GATEWAY_ID = "{gateway.dev_id}"',
        f'GATEWAY_HOST = "{ip}"',
        f'GATEWAY_LOCAL_KEY = "{gateway.local_key}"',
        "",
        "RT_DEVICES: list[tuple[str, str, str]] = [",
    ]
    own_children = [s for s in subs if s.parent_dev_id == gateway.dev_id or s.parent_dev_id is None]
    for s in sorted(own_children, key=lambda r: r.name or r.dev_id):
        name = s.name or s.dev_id
        lines.append(f'    ("{s.dev_id}", "{s.node_id}", "{name}"),')
    lines.append("]")
    return "\n".join(lines)


def run_scan(session: frida.core.Session) -> dict[str, DeviceRecord]:
    """Runs the memory scan on an already-attached session and parses the hits."""
    script = session.create_script(JS_SCAN_SCRIPT)
    script.load()
    print("[*] scanning process memory (this can take a minute)...")
    raw_hits = script.exports_sync.scan()
    print(f"[*] {len(raw_hits)} raw pattern hit(s)")
    return parse_hits(raw_hits)


def scan_once(timeout: int) -> dict[str, DeviceRecord]:
    """Attach, scan, parse. Raises AttachFailed on the known flaky-attach case."""
    session = attach_to_app(timeout)
    try:
        return run_scan(session)
    finally:
        session.detach()


def report_and_build_snippet(records: dict[str, DeviceRecord], ip: str, out: str | None) -> str | None:
    """Prints the device table, and if exactly one gateway was found, the
    credentials.py snippet (writing it to `out` too, if given). Returns the
    snippet text, or None if zero/multiple gateways were found."""
    gateways = print_report(records)

    if len(gateways) == 1:
        gateway = gateways[0]
        subs = [r for r in records.values() if r.node_id]
        snippet = build_credentials_snippet(ip, gateway, subs)
        print("\n" + "=" * 70)
        print("credentials.py snippet:")
        print("=" * 70)
        print(snippet)
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(snippet + "\n")
            print(f"\n[*] written to {out}")
        return snippet

    if len(gateways) > 1:
        print(
            f"\n[!] {len(gateways)} devices with a non-empty localKey found - "
            "can't auto-pick one. Review the list above and build the snippet by hand."
        )
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", required=True, help="Gateway's LAN IP address (for the credentials.py snippet)")
    parser.add_argument("--timeout", type=int, default=5, help="frida USB device discovery timeout (seconds)")
    parser.add_argument("--out", help="Write the credentials.py snippet to this path in addition to stdout")
    args = parser.parse_args()

    try:
        records = scan_once(args.timeout)
    except AttachFailed as e:
        print(f"[!] {e}.\n    This is a known flake, not a real error - just run the script again.", file=sys.stderr)
        return 1

    report_and_build_snippet(records, args.ip, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
