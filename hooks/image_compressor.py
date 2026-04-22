#!/usr/bin/env python3
"""
redmem image compressor — transparently downscale large images before they
reach Claude's vision API, saving tokens on every session (not just autopilot).

Mechanism
─────────
Claude Code's PreToolUse hook lets us rewrite tool_input via
`hookSpecificOutput.updatedInput`. When Claude tries to Read a large image
file, this module:

  1. Checks if the file is an image (.png/.jpg/.jpeg/.webp/.heic)
  2. Checks file size and dimensions (fast path: small → pass through)
  3. Invokes `sips -Z <max_dim>` (macOS built-in — no Python deps) to
     produce a downscaled copy in `/tmp/redmem-img-cache/`, keyed by
     path-hash + mtime so later edits invalidate the cache automatically
  4. Returns `updatedInput` pointing at the cached copy

Claude sees the smaller image; the original file on disk is untouched.

Opt-out
───────
Three layers, in order of scope:

  - `REDMEM_NO_IMAGE_COMPRESS=1` env var — whole-host kill switch
  - `<cwd>/.redmem-no-compress` file    — per-project kill switch
  - `.orig.` or `.nocompress.` in the filename — per-image escape hatch

Failure modes (all fail-open → original path unchanged)
──────────────────────────────────────────────────────
  - `sips` not on PATH (non-macOS) → log once, pass through
  - File can't be read / is a symlink loop → pass through
  - Cache dir can't be created → pass through
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys

IMAGE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".heic", ".heif"})

# Thresholds: only touch images that are BOTH bigger than `SIZE_THRESHOLD`
# AND longer than `DIM_THRESHOLD_PX` on their longest side.
SIZE_THRESHOLD_BYTES = 500 * 1024       # 500 KB
DIM_THRESHOLD_PX = 1920                 # longest side cap after compression

CACHE_DIR = os.environ.get(
    "REDMEM_IMG_CACHE_DIR", "/tmp/redmem-img-cache"
)
OPT_OUT_ENV = "REDMEM_NO_IMAGE_COMPRESS"
OPT_OUT_FILE = ".redmem-no-compress"
OPT_OUT_FILENAME_MARKERS = (".orig.", ".nocompress.")

LOG_PREFIX = "[redmem-imgc]"


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"{LOG_PREFIX} {msg}\n")
    except Exception:
        pass


def is_image_path(file_path: str) -> bool:
    if not file_path:
        return False
    ext = os.path.splitext(file_path.lower())[1]
    return ext in IMAGE_EXTS


def opt_out_active(file_path: str, cwd: str) -> bool:
    """Any of the three opt-out layers active?"""
    if os.environ.get(OPT_OUT_ENV):
        return True
    if file_path:
        base = os.path.basename(file_path).lower()
        for marker in OPT_OUT_FILENAME_MARKERS:
            if marker in base:
                return True
    if cwd:
        try:
            if os.path.isfile(os.path.join(cwd, OPT_OUT_FILE)):
                return True
        except OSError:
            pass
    return False


def get_image_dims(file_path: str) -> tuple[int, int]:
    """Return (width, height) via sips. (0, 0) on any failure."""
    try:
        r = subprocess.run(
            ["sips", "-g", "pixelWidth", "-g", "pixelHeight", file_path],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return 0, 0
        w = h = 0
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("pixelWidth:"):
                try:
                    w = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("pixelHeight:"):
                try:
                    h = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        return w, h
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 0, 0


def cache_path_for(file_path: str) -> str:
    """Deterministic cache path that invalidates when source mtime changes.

    Using mtime in the filename means we never serve stale compressed
    images after the user edits / replaces the original.
    """
    try:
        mt = int(os.path.getmtime(file_path))
    except OSError:
        mt = 0
    key = hashlib.sha1(os.path.abspath(file_path).encode("utf-8", "replace"))
    h = key.hexdigest()[:12]
    ext = os.path.splitext(file_path)[1].lower() or ".png"
    return os.path.join(CACHE_DIR, f"{h}-{mt}{ext}")


def compress_to_cache(file_path: str, max_dim: int = DIM_THRESHOLD_PX) -> str | None:
    """Downscale longest side to `max_dim`. Returns the cache path on
    success, None on any failure. Idempotent — second call hits cache."""
    out = cache_path_for(file_path)
    if os.path.isfile(out):
        return out
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        r = subprocess.run(
            ["sips", "-Z", str(max_dim), file_path, "-o", out],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and os.path.isfile(out):
            return out
        _log(f"sips rc={r.returncode}: {r.stderr.strip()[:120]}")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log(f"compress failed: {e.__class__.__name__}: {e}")
    return None


def maybe_compress_read(data: dict) -> dict | None:
    """
    PreToolUse helper. Returns a hook response dict that rewrites
    `tool_input.file_path` to a compressed version, or None to pass
    through unchanged. Fail-open on any error.
    """
    try:
        if data.get("tool_name") != "Read":
            return None
        tool_input = data.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            return None
        file_path = tool_input.get("file_path", "")
        if not file_path or not is_image_path(file_path):
            return None
        if not os.path.isfile(file_path):
            return None  # leave Read's own error handling in place
        cwd = data.get("cwd", "") or ""
        if opt_out_active(file_path, cwd):
            return None

        try:
            size = os.path.getsize(file_path)
        except OSError:
            return None
        if size < SIZE_THRESHOLD_BYTES:
            return None

        w, h = get_image_dims(file_path)
        if max(w, h) < DIM_THRESHOLD_PX:
            return None

        compressed = compress_to_cache(file_path)
        if not compressed:
            return None

        _log(
            f"compressed {file_path} ({w}x{h}, {size // 1024}KB) "
            f"-> {compressed}"
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {**tool_input, "file_path": compressed},
            }
        }
    except Exception as e:
        _log(f"unexpected error: {e.__class__.__name__}: {e}")
        return None


# Allow running the module standalone for diagnostics:
#   echo '{"tool_name":"Read","tool_input":{"file_path":"/path.png"}}' | \
#       python3 image_compressor.py
if __name__ == "__main__":
    import json as _json
    try:
        raw = sys.stdin.read()
        data = _json.loads(raw) if raw.strip() else {}
    except _json.JSONDecodeError:
        sys.exit(0)
    resp = maybe_compress_read(data)
    if resp:
        sys.stdout.write(_json.dumps(resp))
    sys.exit(0)
