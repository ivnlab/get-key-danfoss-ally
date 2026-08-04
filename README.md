# get_local_key - Tuya local_key extraction tool

*[Русская версия](README.ru.md)*

> **Disclaimer:** this is provided **as-is**, with no warranty of any kind.
> It's a dirty hack built around scanning an Android app's live process
> memory - it works reliably in the environment it was developed and tested
> on (Windows + LDPlayer emulator), but the exact failure mode described
> under [Known instability](#known-instability-attach-sometimes-kills-the-app)
> below was never fully root-caused, and other environments (real phones,
> other emulators, other OS/frida versions) may behave differently or not
> work at all. If it doesn't work for you, please open a GitHub issue and
> describe your environment (OS, phone/emulator model, Android version,
> `frida`/`frida-server` version) and exactly what you ran and what
> happened - that's the only way this gets more robust over time.

Extracts a Danfoss Ally gateway's Tuya `local_key` (and the `nodeId`/`cid`
table for its RT sub-devices) from the Danfoss Ally Android app's own
process memory, without needing to already know any device_id.

This automates the manual procedure described in
[`docs/LOCAL_KEY_EXTRACTION_METHOD.md`](docs/LOCAL_KEY_EXTRACTION_METHOD.md).
Read that file for *why* this works (in short: the app keeps its Tuya
device cache, `local_key` included, as plain JSON in memory once you've
opened a device's card - the key is never written to disk unencrypted).

## What it does NOT do

- It does not root your phone or bypass anything - it needs root you already
  have (see prerequisites).
- It does not touch the Danfoss/Tuya cloud. Everything happens against your
  own phone's RAM over a local `adb`/`frida` connection.
- It does not send your `local_key` anywhere. Output goes to your terminal
  (and optionally a local file via `--out`) only.

## Prerequisites

- A rooted Android device (physical phone or emulator) with the Danfoss
  Ally app (`com.danfoss.ally`) installed and logged in. **Root must be
  explicitly enabled** - on an emulator this is virtually never on by
  default, it's a setting you have to turn on yourself (see below).
- `adb` on your computer, with the device connected and authorized.
- `frida-server` running on the device (must match your local `frida` pip
  package version and the device's CPU architecture).
- `pip install frida` on your computer.

Tested on: Windows 11 (build 10.0.26100), [LDPlayer](https://www.ldplayer.net/)
14.0.18.0. Other Windows versions/emulators/real phones may work but
haven't been verified - see the disclaimer above.

### Enabling root on LDPlayer

Root is **off by default** and must be turned on manually, or `adb shell
su` will fail even though the emulator itself is running fine:

1. Open the emulator's own settings (gear icon in the side toolbar of the
   emulator window itself, not Android's settings inside it).
2. Under the **Basic settings** tab, find **Root permission** (or similarly
   worded - toggle names vary slightly by LDPlayer version) and turn it on.
3. Restart the emulator instance for it to take effect.

Verify with `python check_env.py` - it checks `adb shell su -c id` for you.

Run [`check_env.py`](check_env.py) first - it verifies all of the above
read-only (no writes to the device) and tells you exactly what's missing
and, if `frida-server` isn't running yet, the exact download URL and adb
commands to fix it:

```bash
python check_env.py
```

## Usage

The easiest way is the guided CLI - it runs the environment check, tells
you exactly when to open the app, and automatically retries through the
flaky-attach issue (relaunching the app via adb if it died):

```bash
python cli.py --ip 192.168.1.50
```

It first tries to get a stable connection to the app fully automatically
(up to 20 attempts, relaunching the app if it died - see Known instability
below). Only once that's solid does it pause once with an Enter prompt,
after you've opened the **gateway's** device card (that's what loads
`local_key` into memory). Pass `--auto` to skip that pause (only useful if
you already know the card is open, e.g. for a quick re-run).

Output is the same either way: a table of every device found in memory
(`devId`, `name`, `nodeId`/cid, `parentDevId`), the one with a non-empty
`local_key` highlighted as the gateway, and a ready-to-paste Python
snippet (`GATEWAY_ID` / `GATEWAY_HOST` / `GATEWAY_LOCAL_KEY` /
`RT_DEVICES`) matching the format used by the
[`danfoss-ally-local`](https://github.com/ivnlab/danfoss-ally-local)
Home Assistant integration's `credentials.py`. Add `--out credentials.py`
to write the snippet straight to a file.

### Manual, step by step

If you'd rather run the two pieces separately (e.g. to re-scan without
redoing the environment check each time):

1. Open the Danfoss Ally app, make sure you're logged in and the device
   list has loaded with live data.
2. Open the **gateway's** device card at least once (tap the tile - no
   need to press anything inside). Opening each RT's card too is not
   required for `nodeId` (that comes with the device list) but doesn't
   hurt.
3. Run the scanner directly:

   ```bash
   python get_local_key.py --ip 192.168.1.50
   ```

If it hits the flaky-attach error (see below), it just exits - `cli.py`
is the one that retries automatically.

## If it finds nothing

- **No `localKey` hits with a non-empty value**: the gateway's card
  probably hasn't been opened this app session. Open it, then re-run.
- **App process not found**: the app must be in the foreground (or at
  least recently opened) - Android can evict a backgrounded process,
  which drops the cached data from memory.
- **Attach fails / app process dies**: see [Known instability](#known-instability-attach-sometimes-kills-the-app)
  below - `cli.py` retries this automatically, `get_local_key.py` run
  directly does not.
- **Sub-devices missing from the table**: open the device list itself (not
  just the gateway) so `deviceTopo`/`nodeId` for each RT gets fetched.

## Known instability: attach sometimes kills the app

On the LDPlayer setup this was built and tested on, `frida`'s `attach()`
call kills the target app's process roughly 1 time in 3-4, consistently
reproducible. Investigated directly (see commit history / issue tracker
for the session notes):

- Not an ARM-on-x86 emulation issue - confirmed via Frida itself
  (`realm='emulated'` errors with "process is not using emulation" on this
  setup), so it's not about instrumenting translated code.
- Not a longer boot-delay issue - retested with the app given significantly
  more time to settle before attaching, failures still occurred at the
  same rate.
- No crash signature in `logcat` at all when it happens - no native fatal
  signal, no tombstone, no uncaught Java exception. The process just
  silently disappears from ActivityManager's view ~2 seconds after attach
  is attempted, which looks more like an external kill than an actual
  crash, but the actual trigger was never identified.

`cli.py` works around this with an automatic, silent retry loop (up to 20
attempts) *before* ever asking you to interact with the app - in practice
it takes at most one retry to get a stable session. If your environment
hits this far more than "usually succeeds within 1-2 tries," that's exactly
the kind of thing worth an issue report.

## Files

- `cli.py` - guided entry point: runs the two scripts below in sequence,
  with automatic retry/relaunch through the flaky-attach issue.
- `check_env.py` - read-only environment/prerequisite check.
- `get_local_key.py` - the memory scanner + credentials.py generator.
