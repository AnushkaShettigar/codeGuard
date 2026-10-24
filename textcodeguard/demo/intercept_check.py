from __future__ import annotations

from pathlib import Path

from textcodeguard.guard import GuardBlocked, guarded


@guarded
def safe_marker() -> None:
    Path("marker_safe.txt").write_text("safe", encoding="utf-8")


@guarded
def unsafe_marker() -> None:
    _dangerous = "os.system('rm -rf /tmp/fake')"
    Path("marker_unsafe.txt").write_text(_dangerous, encoding="utf-8")


if __name__ == "__main__":
    marker_safe = Path("marker_safe.txt")
    marker_unsafe = Path("marker_unsafe.txt")
    if marker_safe.exists():
        marker_safe.unlink()
    if marker_unsafe.exists():
        marker_unsafe.unlink()

    safe_marker()
    try:
        unsafe_marker()
    except GuardBlocked:
        pass
    else:
        print("FAIL: unsafe marker executed")
        raise SystemExit(1)

    if marker_safe.exists() and not marker_unsafe.exists():
        print("PASS")
    else:
        print("FAIL")
        raise SystemExit(1)
