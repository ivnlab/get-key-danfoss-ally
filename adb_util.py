"""Locates the adb binary without requiring the user to put it on PATH.

adb often already exists on disk (bundled inside LDPlayer/NoxPlayer, or
installed as part of Android Studio) but isn't on PATH. Rather than making
every user hunt it down and edit PATH by hand, check the obvious places
first and only ask if none of them pan out.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from pathlib import Path

_CANDIDATE_GLOBS = [
    str(Path(__file__).resolve().parent / "adb.exe"),
    r"C:\LDPlayer\LDPlayer*\adb.exe",
    r"C:\Program Files\LDPlayer\LDPlayer*\adb.exe",
    r"C:\Program Files (x86)\LDPlayer\LDPlayer*\adb.exe",
    r"C:\platform-tools\adb.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
    os.path.expandvars(r"%ANDROID_HOME%\platform-tools\adb.exe"),
    os.path.expandvars(r"%ANDROID_SDK_ROOT%\platform-tools\adb.exe"),
]


def find_adb() -> str | None:
    """Returns a runnable adb path, or None if nothing was found anywhere."""
    on_path = shutil.which("adb")
    if on_path:
        return on_path
    for pattern in _CANDIDATE_GLOBS:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def run(adb_path: str, args: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        proc = subprocess.run([adb_path, *args], capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, "timed out"
