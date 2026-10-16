#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
pt_runtime_verify.py -- load a `.pkt` into a real Packet Tracer under Xvfb and
collect runtime evidence.

Covers four catalogue entries in ``docs/ENTERPRISE_PROBLEMS.md``:

* **15** -- STP / link convergence time at scale (recorded by sampling the
  amber link-light fraction over time);
* **24** -- end-to-end traffic (the harness opens a device CLI in PT, issues
  ``ping`` across tiers and captures the CLI text);
* **25** -- tier-by-tier visual inspection (a screenshot per tier plus a full
  scroll sweep so no device goes unrendered);
* **26** -- PT acceptance across releases (the exact executable, version and
  digest that accepted the file are recorded in the evidence).

Design
------
Everything is staged, and every stage writes evidence before it can fail, so a
run that stops half way still says precisely what was and was not observed.  A
stage that cannot proceed raises :class:`StageFailure` with a machine-readable
``blocker`` -- the tool never reports success it did not see.

GUI automation is done with ``xdotool``; pixels are read with ImageMagick
(``import`` + ``convert ... txt:-``); CLI text is read with ``tesseract`` when
it is installed.  Every external dependency is probed up front and reported.

Usage
-----
    python3 tools/pt_runtime_verify.py --artifact /tmp/lab.pkt \\
        --outdir build/pt_runtime

    # faster: skip the traffic stage
    python3 tools/pt_runtime_verify.py --artifact lab.pkt --no-traffic

    # point at a specific Packet Tracer
    PT_BIN=/opt/pt/packettracer python3 tools/pt_runtime_verify.py ...
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO = Path(__file__).resolve().parent.parent
for _p in (str(REPO / "src"), str(REPO), str(REPO / "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

__all__ = ["main", "StageFailure", "Toolchain", "PacketTracer", "Screen"]


# =========================================================================== #
# 0. Small utilities
# =========================================================================== #


class StageFailure(RuntimeError):
    """A stage could not complete.  Carries a machine-readable blocker."""

    def __init__(self, stage: str, blocker: str, detail: str = "") -> None:
        super().__init__(f"[{stage}] {blocker}: {detail}" if detail else f"[{stage}] {blocker}")
        self.stage = stage
        self.blocker = blocker
        self.detail = detail


def run(cmd: Sequence[str], *, timeout: float = 30.0, env: dict[str, str] | None = None,
        check: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(list(cmd), capture_output=True, text=True,
                          timeout=timeout, env=env)
    if check and proc.returncode != 0:
        raise StageFailure("exec", "command-failed",
                           f"{' '.join(cmd[:3])}... rc={proc.returncode}: {proc.stderr[:200]}")
    return proc


def have(binary: str) -> str | None:
    return shutil.which(binary)


def free_display(start: int = 90, end: int = 130) -> int:
    """Lowest display number with no X socket and no Xvfb already on it."""
    for n in range(start, end):
        if Path(f"/tmp/.X11-unix/X{n}").exists():
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.15)
            if s.connect_ex(("127.0.0.1", 6000 + n)) == 0:
                continue
        return n
    raise StageFailure("display", "no-free-display",
                       f"tried :{start}..:{end - 1}")


def file_sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# =========================================================================== #
# 1. Toolchain probe
# =========================================================================== #

PT_CANDIDATES = (
    "/usr/local/bin/packettracer",
    "/opt/pt/packettracer",
    "/opt/pt/bin/PacketTracer",
    "/usr/bin/packettracer",
)


@dataclass
class Toolchain:
    """What is installed, and what that means for each stage."""

    xvfb: str | None = None
    xdotool: str | None = None
    screenshot: str | None = None       # `import` or `scrot`
    screenshot_kind: str = ""
    magick: str | None = None           # `convert` / `magick`
    tesseract: str | None = None
    pt_bin: str | None = None
    pt_source: str = ""
    xvfb_error: str = ""

    @classmethod
    def probe(cls, pt_override: str | None = None) -> "Toolchain":
        tc = cls()
        tc.xvfb = have("Xvfb")
        tc.xdotool = have("xdotool")
        if have("import"):
            tc.screenshot, tc.screenshot_kind = have("import"), "imagemagick"
        elif have("scrot"):
            tc.screenshot, tc.screenshot_kind = have("scrot"), "scrot"
        tc.magick = have("convert") or have("magick")
        tc.tesseract = have("tesseract")

        if pt_override:
            if Path(pt_override).exists():
                tc.pt_bin, tc.pt_source = pt_override, "argument"
        if tc.pt_bin is None and os.environ.get("PT_BIN"):
            cand = os.environ["PT_BIN"]
            if Path(cand).exists():
                tc.pt_bin, tc.pt_source = cand, "PT_BIN"
        if tc.pt_bin is None:
            for cand in PT_CANDIDATES:
                if Path(cand).exists():
                    tc.pt_bin, tc.pt_source = cand, "well-known-path"
                    break
        return tc

    def required_missing(self) -> list[str]:
        missing = []
        if not self.xvfb:
            missing.append("Xvfb (apt-get install -y xvfb)")
        if not self.xdotool:
            missing.append("xdotool (apt-get install -y xdotool)")
        if not self.screenshot:
            missing.append("import|scrot (apt-get install -y imagemagick | scrot)")
        if not self.pt_bin:
            missing.append("Packet Tracer (set PT_BIN=/path/to/packettracer)")
        return missing

    def as_dict(self) -> dict[str, Any]:
        return {
            "xvfb": self.xvfb, "xdotool": self.xdotool,
            "screenshot": self.screenshot, "screenshot_kind": self.screenshot_kind,
            "imagemagick": self.magick, "tesseract": self.tesseract,
            "packet_tracer": self.pt_bin, "packet_tracer_source": self.pt_source,
            "ocr_available": bool(self.tesseract),
        }


# =========================================================================== #
# 2. X server + screen
# =========================================================================== #


class XServer:
    """An Xvfb display owned by this run."""

    def __init__(self, toolchain: Toolchain, size: tuple[int, int], display: int | None = None):
        self.tc = toolchain
        self.size = size
        self.display = display if display is not None else free_display()
        self.proc: subprocess.Popen[bytes] | None = None
        self.log = Path("/tmp") / f"pt_runtime_xvfb_{self.display}.log"

    @property
    def env_display(self) -> str:
        return f":{self.display}"

    def start(self) -> None:
        if not self.tc.xvfb:
            raise StageFailure("xvfb", "xvfb-not-installed",
                               "install with: apt-get install -y xvfb")
        with self.log.open("wb") as fh:
            self.proc = subprocess.Popen(
                [self.tc.xvfb, self.env_display,
                 "-screen", "0", f"{self.size[0]}x{self.size[1]}x24",
                 "-nolisten", "tcp"],
                stdout=fh, stderr=subprocess.STDOUT,
            )
        deadline = time.time() + 15
        sock = Path(f"/tmp/.X11-unix/X{self.display}")
        while time.time() < deadline:
            if sock.exists():
                time.sleep(0.5)
                return
            if self.proc.poll() is not None:
                raise StageFailure("xvfb", "xvfb-exited",
                                   self.log.read_text(errors="replace")[-400:])
            time.sleep(0.2)
        raise StageFailure("xvfb", "xvfb-timeout", f"no {sock} after 15s")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.proc.kill()


class Screen:
    """Screenshot + pixel statistics through ImageMagick."""

    def __init__(self, tc: Toolchain, display: str, outdir: Path):
        self.tc = tc
        self.display = display
        self.outdir = outdir
        self.outdir.mkdir(parents=True, exist_ok=True)
        self._env = {**os.environ, "DISPLAY": display}

    def capture(self, name: str) -> Path:
        path = self.outdir / name
        if self.tc.screenshot_kind == "imagemagick":
            proc = run([self.tc.screenshot or "import", "-window", "root", str(path)],
                       env=self._env, timeout=60)
        else:
            proc = run([self.tc.screenshot or "scrot", "-o", str(path)],
                       env=self._env, timeout=60)
        if proc.returncode != 0 or not path.exists():
            raise StageFailure("screenshot", "capture-failed",
                               proc.stderr.strip()[:300])
        return path

    def histogram(self, path: Path, region: tuple[int, int, int, int] | None = None,
                  sample: int = 4) -> Counter[tuple[int, int, int]]:
        """Exact colour histogram of (a region of) a PNG, point-sampled.

        `-sample` keeps the original pixel values (no interpolation), so link
        light colours stay exactly what PT drew.
        """
        magick = self.tc.magick
        if not magick:
            raise StageFailure("pixels", "imagemagick-missing",
                               "apt-get install -y imagemagick")
        cmd = [magick, str(path)]
        if region:
            x, y, w, h = region
            cmd += ["-crop", f"{w}x{h}+{x}+{y}", "+repage"]
        if sample > 1:
            cmd += ["-sample", f"{100 // sample}%"]
        cmd += ["txt:-"]
        proc = run(cmd, timeout=180)
        if proc.returncode != 0:
            raise StageFailure("pixels", "convert-failed", proc.stderr[:300])
        counts: Counter[tuple[int, int, int]] = Counter()
        for line in proc.stdout.splitlines():
            # `0,0: (255,255,255)  #FFFFFF  white`
            if not line or line.startswith("#"):
                continue
            m = re.search(r"\((\d+),(\d+),(\d+)", line)
            if m:
                counts[(int(m.group(1)), int(m.group(2)), int(m.group(3)))] += 1
        return counts

    def ocr(self, path: Path, region: tuple[int, int, int, int] | None = None) -> str:
        if not self.tc.tesseract:
            return ""
        magick = self.tc.magick
        tmp = path.with_name(path.stem + "_ocr.png")
        cmd = [magick or "convert", str(path)]
        if region:
            x, y, w, h = region
            cmd += ["-crop", f"{w}x{h}+{x}+{y}", "+repage"]
        cmd += ["-colorspace", "Gray", "-negate", "-resize", "200%", str(tmp)]
        run(cmd, timeout=60)
        proc = run([self.tc.tesseract, str(tmp), "stdout", "--psm", "6"], timeout=90)
        return proc.stdout


# =========================================================================== #
# 3. Packet Tracer process + window driving
# =========================================================================== #


class Xdo:
    """Thin xdotool wrapper bound to one DISPLAY."""

    def __init__(self, tc: Toolchain, display: str):
        if not tc.xdotool:
            raise StageFailure("xdotool", "xdotool-not-installed",
                               "apt-get install -y xdotool")
        self.bin = tc.xdotool
        self.env = {**os.environ, "DISPLAY": display}

    def __call__(self, *args: str, timeout: float = 15.0) -> str:
        proc = run([self.bin, *args], env=self.env, timeout=timeout)
        return proc.stdout

    # -- windows -------------------------------------------------------- #
    def windows(self, name_pattern: str = ".", pid: int | None = None) -> list[int]:
        """Window ids matching a name regex.

        `--pid` is used whenever the owning process is known: walking every
        window on a bare Xvfb display with `--onlyvisible` alone is measurably
        slow once Packet Tracer has opened a few device windows.
        """
        args = ["search"]
        if pid:
            args += ["--pid", str(pid)]
        args += ["--onlyvisible", "--name", name_pattern]
        try:
            out = self(*args, timeout=60.0)
        except subprocess.TimeoutExpired:
            if not pid:
                raise
            out = self("search", "--onlyvisible", "--name", name_pattern,
                       timeout=60.0)
        return [int(x) for x in out.split() if x.strip().isdigit()]

    def window_name(self, wid: int) -> str:
        return self("getwindowname", str(wid)).strip()

    def geometry(self, wid: int) -> tuple[int, int, int, int]:
        out = self("getwindowgeometry", "--shell", str(wid))
        vals: dict[str, int] = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                try:
                    vals[k] = int(v)
                except ValueError:
                    pass
        return (vals.get("X", 0), vals.get("Y", 0),
                vals.get("WIDTH", 0), vals.get("HEIGHT", 0))

    def move_resize(self, wid: int, x: int, y: int, w: int, h: int) -> None:
        self("windowmove", str(wid), str(x), str(y))
        self("windowsize", str(wid), str(w), str(h))
        time.sleep(0.4)

    def activate(self, wid: int) -> None:
        self("windowactivate", "--sync", str(wid), timeout=20)

    # -- input ---------------------------------------------------------- #
    def click(self, x: int, y: int, button: int = 1, repeat: int = 1) -> None:
        self("mousemove", str(x), str(y))
        time.sleep(0.15)
        self("click", "--repeat", str(repeat), "--delay", "120", str(button))

    def drag(self, x1: int, y1: int, x2: int, y2: int, button: int = 1) -> None:
        self("mousemove", "--sync", str(x1), str(y1))
        self("mousedown", str(button))
        time.sleep(0.2)
        # two intermediate moves so the toolkit sees a real drag
        for frac in (0.4, 0.8, 1.0):
            self("mousemove", "--sync",
                 str(int(x1 + (x2 - x1) * frac)), str(int(y1 + (y2 - y1) * frac)))
            time.sleep(0.12)
        self("mouseup", str(button))

    def type(self, text: str, delay_ms: int = 40) -> None:
        self("type", "--delay", str(delay_ms), text, timeout=60)

    def key(self, *keys: str) -> None:
        self("key", "--clearmodifiers", *keys)


@dataclass
class PtProcess:
    """A launched Packet Tracer instance."""

    popen: subprocess.Popen[bytes]
    window: int
    geometry: tuple[int, int, int, int]
    log: Path
    launch_seconds: float
    argv: list[str] = field(default_factory=list)


class PacketTracer:
    """Launch, wait for, and drive one Packet Tracer GUI session."""

    # `^Cisco Packet Tracer` deliberately excludes Qt's internal helpers
    # ("Qt Selection Owner for PacketTracer", "PacketTracer"), which are also
    # owned by the same pid but are 1x1 / 3x3 windows.
    TITLE_RE = re.compile(r"^Cisco\s+Packet\s+Tracer", re.IGNORECASE)
    MIN_WINDOW = (500, 350)
    # PT needs a while to draw 200+ device icons
    DEFAULT_LOAD_TIMEOUT = 300.0

    def __init__(self, tc: Toolchain, xdo: Xdo, screen: Screen, display: str):
        self.tc = tc
        self.xdo = xdo
        self.screen = screen
        self.display = display
        self.env = {**os.environ, "DISPLAY": display}
        self.log = Path("/tmp") / "pt_runtime_packettracer.log"
        self.pid: int | None = None
        self._main: int | None = None

    # -- launch --------------------------------------------------------- #
    def version(self) -> dict[str, Any]:
        info: dict[str, Any] = {"binary": self.tc.pt_bin, "source": self.tc.pt_source}
        if not self.tc.pt_bin:
            return info
        p = Path(self.tc.pt_bin)
        try:
            info["resolved"] = str(p.resolve())
            info["sha256"] = file_sha256(p.resolve())
            info["bytes"] = p.resolve().stat().st_size
        except OSError:
            pass
        # the AppImage payload carries the real version string
        for cand in ("/tmp/ptx/squashfs-root/opt/pt/bin/PT.conf",
                     "/opt/pt/bin/PT.conf"):
            if Path(cand).exists():
                info["pt_conf"] = cand
        log = Path("/opt/pt/packettracer.AppImage-log.txt")
        if log.exists():
            text = log.read_text(errors="replace")
            m = re.search(r"Cisco Packet Tracer (\d+\.\d+\.\d+(?:\.\d+)?)", text)
            if m:
                info["version"] = m.group(1)
        return info

    def launch(self, artifact: Path, extra_args: Sequence[str] = ()) -> PtProcess:
        if not self.tc.pt_bin:
            raise StageFailure(
                "launch", "packet-tracer-not-found",
                "no Packet Tracer executable; looked at " + ", ".join(PT_CANDIDATES)
                + " and $PT_BIN")
        argv = [self.tc.pt_bin, str(artifact), *extra_args]
        started = time.time()
        with self.log.open("wb") as fh:
            popen = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                     env=self.env, cwd="/tmp",
                                     start_new_session=True)
        self.pid = popen.pid
        wid = self.wait_for_window(timeout=self.DEFAULT_LOAD_TIMEOUT,
                                   popen=popen)
        self._main = wid
        return PtProcess(popen=popen, window=wid, geometry=self.xdo.geometry(wid),
                         log=self.log, launch_seconds=round(time.time() - started, 2),
                         argv=argv)

    def wait_for_window(self, timeout: float, popen: subprocess.Popen[bytes] | None = None) -> int:
        deadline = time.time() + timeout
        seen: list[str] = []
        while time.time() < deadline:
            if popen is not None and popen.poll() is not None:
                raise StageFailure(
                    "launch", "packet-tracer-exited",
                    f"exit code {popen.returncode}; log tail: "
                    f"{self.log.read_text(errors='replace')[-500:]}")
            for wid in self.xdo.windows(".", pid=self.pid):
                name = self.xdo.window_name(wid)
                if name and name not in seen:
                    seen.append(name)
                if not self.TITLE_RE.search(name or ""):
                    continue
                _x, _y, w, h = self.xdo.geometry(wid)
                if w < self.MIN_WINDOW[0] or h < self.MIN_WINDOW[1]:
                    continue
                return wid
            time.sleep(1.0)
        raise StageFailure("launch", "main-window-timeout",
                           f"after {timeout:.0f}s; windows seen: {seen[-8:]}")

    # -- load completion ------------------------------------------------ #
    def wait_for_load(self, artifact_name: str, timeout: float) -> dict[str, Any]:
        """Wait until PT has actually finished opening the file.

        PT creates its main window before the file is parsed, and it restores
        its own saved window geometry when loading finishes -- resizing before
        that point is silently undone.  The progress dialog
        (`Please wait. Opening file...`) is the reliable completion signal, and
        the main window title carries the opened path.
        """
        deadline = time.time() + timeout
        started = time.time()
        seen_progress = False
        while time.time() < deadline:
            names = [n for _w, n in self.other_windows_any()]
            if any(re.search(r"opening file|please wait", n, re.I) for n in names):
                seen_progress = True
                time.sleep(1.0)
                continue
            title = self.xdo.window_name(self._main) if self._main else ""
            if not title:
                for wid, nm in self.other_windows_any():
                    if self.TITLE_RE.search(nm):
                        self._main = wid
                        title = nm
                        break
            if artifact_name in title and (seen_progress or time.time() - started > 5):
                return {"load_seconds": round(time.time() - started, 2),
                        "title": title, "progress_dialog_seen": seen_progress}
            time.sleep(1.0)
        raise StageFailure("load", "load-timeout",
                           f"{artifact_name} not confirmed loaded after "
                           f"{timeout:.0f}s; windows: "
                           f"{[n for _w, n in self.other_windows_any()][:6]}")

    def other_windows_any(self) -> list[tuple[int, str]]:
        return [(w, self.xdo.window_name(w)) for w in self.xdo.windows(".", pid=self.pid)
                if self.xdo.window_name(w)]

    # -- helpers -------------------------------------------------------- #
    def other_windows(self, main: int) -> list[tuple[int, str]]:
        out = []
        for wid in self.xdo.windows(".", pid=self.pid):
            if wid == main:
                continue
            name = self.xdo.window_name(wid)
            if name:
                out.append((wid, name))
        return out

    def wait_for_new_window(self, main: int, timeout: float = 8.0) -> tuple[int, str] | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for wid, name in self.other_windows(main):
                if wid != main:
                    return wid, name
            time.sleep(0.4)
        return None


# =========================================================================== #
# 4. Canvas geometry, scrollbars and link-colour statistics
# =========================================================================== #


@dataclass
class Canvas:
    """The logical-workspace rectangle inside the PT window."""

    x: int
    y: int
    w: int
    h: int

    def region(self) -> tuple[int, int, int, int]:
        return (self.x, self.y, self.w, self.h)

    def as_dict(self) -> dict[str, int]:
        return {"x": self.x, "y": self.y, "width": self.w, "height": self.h}


def detect_canvas(screen: Screen, shot: Path, window: tuple[int, int, int, int],
                  hist: Counter[tuple[int, int, int]] | None = None) -> Canvas:
    """Locate the big near-white logical workspace inside the PT window.

    The canvas is by far the largest light region in the window, so a coarse
    row/column profile of "light" pixels finds it without any template.
    """
    wx, wy, ww, wh = window
    hist = hist or screen.histogram(shot, region=None, sample=4)

    # Re-scan at full resolution but in strips: cheap (a few hundred rows).
    magick = screen.tc.magick or "convert"
    proc = run([magick, str(shot), "-crop", f"{ww}x{wh}+{wx}+{wy}", "+repage",
                "-sample", "8%", "txt:-"], timeout=180)
    rows: Counter[int] = Counter()
    cols: Counter[int] = Counter()
    for line in proc.stdout.splitlines():
        m = re.match(r"(\d+),(\d+): \((\d+),(\d+),(\d+)", line)
        if not m:
            continue
        x, y, r, g, b = (int(m.group(i)) for i in range(1, 6))
        # Only the logical workspace is pure white; the menu bar, toolbars and
        # docked panels are light grey (~240) and must not join the band.
        if r > 248 and g > 248 and b > 248:
            rows[y] += 1
            cols[x] += 1
    if not rows:
        raise StageFailure("canvas", "no-light-region",
                           "could not find the logical workspace; is PT showing "
                           "a dialog?")
    # The menu/toolbar rows contain a few light pixels too, so take the longest
    # *contiguous* band of rows/columns that are mostly light -- that is the
    # workspace and nothing else.
    def band(counter: Counter[int], _limit: int) -> tuple[int, int] | None:
        """Longest canvas band, grown outwards from the whitest rows/columns.

        A single fixed threshold cannot work: an empty canvas row is 100% white
        while a row crossing a dense cable bundle in a 290-device lab is not,
        so the band is anchored on the strong rows and then extended while the
        row is still at least a quarter white, tolerating two-sample gaps.
        """
        if not counter:
            return None
        peak = max(counter.values())
        strong = sorted(i for i, n in counter.items() if n >= 0.9 * peak)
        if not strong:
            return None
        # largest contiguous run of strong indices, then extend
        start = prev = strong[0]
        seed = (start, prev)
        for i in strong[1:]:
            if i == prev + 1:
                prev = i
                continue
            if prev - start > seed[1] - seed[0]:
                seed = (start, prev)
            start = prev = i
        if prev - start > seed[1] - seed[0]:
            seed = (start, prev)

        lo, hi = seed
        misses = 0
        i = lo - 1
        while i >= 0:
            if counter.get(i, 0) >= 0.25 * peak:
                lo, misses = i, 0
            else:
                misses += 1
                if misses > 2:
                    break
            i -= 1
        misses = 0
        i = hi + 1
        while i <= max(counter):
            if counter.get(i, 0) >= 0.25 * peak:
                hi, misses = i, 0
            else:
                misses += 1
                if misses > 2:
                    break
            i += 1
        return (lo, hi)

    def seed_band(counter: Counter[int]) -> tuple[int, int] | None:
        """Largest contiguous run of rows/columns that are >=90% white."""
        if not counter:
            return None
        peak = max(counter.values())
        strong = sorted(i for i, n in counter.items() if n >= 0.9 * peak)
        if not strong:
            return None
        best = (strong[0], strong[0])
        start = prev = strong[0]
        for i in strong[1:]:
            if i == prev + 1:
                prev = i
                continue
            if prev - start > best[1] - best[0]:
                best = (start, prev)
            start = prev = i
        if prev - start > best[1] - best[0]:
            best = (start, prev)
        return best

    # row index -> how many light samples in that row (out of ~ww/8 columns)
    row_band = band(rows, max(1, ww // 8))
    col_band = band(cols, max(1, wh // 8))
    if row_band is None or col_band is None:
        raise StageFailure("canvas", "no-light-region",
                           "no contiguous light band found in the PT window")
    y0, y1 = row_band
    seed = seed_band(rows)
    # The top edge comes from the *strong* band: whatever else is white, the
    # menu bar and toolbar are not a full-width run of pure white, and the
    # weak extension above it is unreliable.
    top = seed[0] if seed else y0
    # The logical workspace always fills the window width in Packet Tracer, so
    # the right edge is the window edge minus its scrollbar; the pixel band is
    # unreliable there because a dense lab paints cables over most columns.
    x0 = col_band[0]
    left = wx + x0 * 8
    right = wx + ww - 20
    return Canvas(x=left, y=wy + top * 8,
                  w=max(8, right - left),
                  h=max(8, (y1 - top + 1) * 8))


def content_extent(shot: Path, magick: str | None) -> tuple[int, int]:
    """Bounding box of the non-black area of a screenshot.

    Xvfb leaves unpainted root pixels black, so this is how the harness proves
    Packet Tracer really did resize instead of trusting `xdotool`'s report.
    """
    proc = run([magick or "convert", str(shot), "-sample", "10%",
                "-threshold", "5%", "-format", "%[fx:w] %[fx:h]", "info:"],
               timeout=120)
    # `-trim` on a black background gives the painted extent directly
    proc = run([magick or "convert", str(shot), "-sample", "10%",
                "-bordercolor", "black", "-border", "1",
                "-trim", "-format", "%w %h", "info:"], timeout=120)
    try:
        w, h = (int(x) for x in proc.stdout.split())
    except ValueError:
        return (0, 0)
    return (w * 10, h * 10)


def ensure_window_size(xdo: Xdo, screen: Screen, wid: int,
                       target: tuple[int, int], *, tries: int = 3) -> dict[str, Any]:
    """Resize PT to fill the screen and verify it from pixels, not from xdotool."""
    info: dict[str, Any] = {"target": list(target), "attempts": []}
    for attempt in range(1, tries + 1):
        xdo.move_resize(wid, 0, 0, target[0], target[1])
        time.sleep(4.0)
        shot = screen.capture(f"01_resize_attempt{attempt}.png")
        w, h = content_extent(shot, screen.tc.magick)
        info["attempts"].append({"attempt": attempt,
                                 "geometry": list(xdo.geometry(wid)),
                                 "painted": [w, h]})
        if w >= int(target[0] * 0.9) and h >= int(target[1] * 0.9):
            info["resize_ok"] = True
            info["painted"] = [w, h]
            return info
    info["resize_ok"] = False
    return info


class Scrollbars:
    """Locate and drag the PT logical-workspace scrollbars.

    Thumbs are found by pixel profile, never by hard-coded coordinates, so the
    harness survives a different window size or PT theme.
    """

    def __init__(self, xdo: Xdo, screen: Screen):
        self.xdo = xdo
        self.screen = screen

    def _thumb(self, shot: Path, *, horizontal: bool, canvas: Canvas) -> tuple[int, int, int]:
        """Return (start, end, cross) of the thumb along the scrollbar."""
        magick = self.screen.tc.magick or "convert"
        if horizontal:
            y = canvas.y + canvas.h + 4
            crop = f"{canvas.w}x8+{canvas.x}+{y}"
            length = canvas.w
            origin = canvas.x
        else:
            x = canvas.x + canvas.w + 4
            crop = f"8x{canvas.h}+{x}+{canvas.y}"
            length = canvas.h
            origin = canvas.y
        proc = run([magick, str(shot), "-crop", crop, "+repage", "txt:-"], timeout=120)
        # background of a scrollbar trough is a flat grey; the thumb is lighter
        vals: dict[int, tuple[int, int, int]] = {}
        for line in proc.stdout.splitlines():
            m = re.match(r"(\d+),(\d+): \((\d+),(\d+),(\d+)", line)
            if not m:
                continue
            a, b = int(m.group(1)), int(m.group(2))
            idx = a if horizontal else b
            vals.setdefault(idx, (int(m.group(3)), int(m.group(4)), int(m.group(5))))
        if not vals:
            raise StageFailure("scrollbar", "no-scrollbar-pixels", crop)
        trough = Counter(vals.values()).most_common(1)[0][0]
        thumb = [i for i, c in sorted(vals.items())
                 if abs(c[0] - trough[0]) + abs(c[1] - trough[1]) + abs(c[2] - trough[2]) > 30]
        if not thumb:
            raise StageFailure("scrollbar", "no-thumb-found",
                               f"horizontal={horizontal} trough={trough}")
        return origin + min(thumb), origin + max(thumb), (y if horizontal else x)

    def thumb_span(self, shot: Path, canvas: Canvas, horizontal: bool) -> tuple[int, int, int]:
        return self._thumb(shot, horizontal=horizontal, canvas=canvas)

    # Dragging the scrollbar thumbs was measured *not* to move the workspace on
    # a bare Xvfb display (no window manager, so the toolkit's scrollbar
    # hit-testing is unreliable).  The mouse wheel does move it, so scrolling is
    # done incrementally: rewind to the origin, then advance by a known number
    # of wheel clicks.
    WHEEL_CLICKS_FULL_TRAVEL = 40

    def _wheel(self, canvas: Canvas, clicks: int, *, horizontal: bool) -> None:
        if clicks == 0:
            return
        self.xdo("mousemove", str(canvas.x + canvas.w // 2),
                 str(canvas.y + canvas.h // 2))
        time.sleep(0.2)
        button = "4" if horizontal else "5"   # 4 = left/up, 5 = right/down
        if clicks < 0:
            button = "6" if horizontal else "4"   # 6/7 are horizontal on X11
            clicks = -clicks
        if clicks:
            self.xdo("click", "--repeat", str(clicks), "--delay", "60", button,
                     timeout=120)
        time.sleep(0.4)

    def scroll_to(self, shot: Path, canvas: Canvas, fx: float, fy: float) -> None:
        """Move the logical view to the given 0..1 fractions of the workspace."""
        n = self.WHEEL_CLICKS_FULL_TRAVEL
        self._wheel(canvas, -n, horizontal=False)     # rewind vertically
        self._scroll_horizontal(canvas, -n)
        self._wheel(canvas, int(round(max(0.0, min(1.0, fy)) * n)), horizontal=False)
        self._scroll_horizontal(canvas, int(round(max(0.0, min(1.0, fx)) * n)))
        time.sleep(0.6)

    def _scroll_horizontal(self, canvas: Canvas, clicks: int) -> None:
        """Shift+wheel scrolls the PT workspace horizontally."""
        if clicks == 0:
            return
        self.xdo("mousemove", str(canvas.x + canvas.w // 2),
                 str(canvas.y + canvas.h // 2))
        time.sleep(0.2)
        self.xdo("keydown", "shift")
        try:
            button = "4" if clicks < 0 else "5"
            self.xdo("click", "--repeat", str(abs(clicks)), "--delay", "60", button,
                     timeout=120)
        finally:
            self.xdo("keyup", "shift")
        time.sleep(0.4)


# --- link-light colour classification ------------------------------------- #

AMBER_RANGE = ((150, 90, 0), (255, 210, 90))
GREEN_RANGE = ((0, 120, 0), (140, 255, 140))


def _in_range(c: tuple[int, int, int], lo: tuple[int, int, int],
              hi: tuple[int, int, int]) -> bool:
    return all(lo[i] <= c[i] <= hi[i] for i in range(3))


def count_link_colours(hist: Counter[tuple[int, int, int]]) -> dict[str, int]:
    """Count link-light pixels by colour family.

    Amber = spanning-tree blocking/learning, green = forwarding.  The ranges are
    deliberately wide: PT anti-aliases the small triangles against both the
    white canvas and the device icon.
    """
    out = {"amber": 0, "green": 0, "red": 0, "dark": 0, "total": 0}
    for colour, n in hist.items():
        out["total"] += n
        r, g, b = colour
        if _in_range(colour, *AMBER_RANGE):
            out["amber"] += n
        elif _in_range(colour, *GREEN_RANGE):
            out["green"] += n
        elif r > 170 and g < 90 and b < 90:
            out["red"] += n
        elif r < 90 and g < 90 and b < 90:
            out["dark"] += n
    return out


# =========================================================================== #
# 5. The artefact model (tiers, endpoints)
# =========================================================================== #

DEFAULT_TIERS: dict[str, tuple[str, ...]] = {
    "airborne": ("E767", "E2D", "E2C", "RC2", "MISSION", "DATALINK", "LINK16",
                 "TRACK", "SATCOM", "TDL"),
    "radar": ("RDR", "RADAR"),
    "airbase": ("AB", "CRC", "ADC", "NOSC", "AIR", "COP", "MGMT"),
    "datacentre": ("JADGE", "CORE", "WAN", "REG", "FW", "DNS", "DHCP", "NTP",
                   "SYSLOG", "AAA", "TFTP", "MAIL", "PKI", "NETFLOW", "DATA",
                   "BACKUP", "CYBER", "PARTNER", "COALITION"),
}


@dataclass
class DeviceInfo:
    name: str
    kind: str
    model: str
    x: float
    y: float
    tier: str
    ips: list[str] = field(default_factory=list)
    ios: bool = False                 # carries an IOS RUNNINGCONFIG
    console_locked: bool = False      # console/vty demands a login PT can check

    @property
    def cli_kind(self) -> str:
        """`ios` (CLI tab) or `desktop` (PC/Server Desktop tab)."""
        return "ios" if self.ios else "desktop"

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "model": self.model,
                "x": self.x, "y": self.y, "tier": self.tier, "ips": self.ips,
                "ios": self.ios, "console_locked": self.console_locked}


def tier_of(name: str, tiers: dict[str, tuple[str, ...]]) -> str:
    head = re.split(r"[-_]", name, maxsplit=1)[0].upper()
    for tier, prefixes in tiers.items():
        if head in prefixes:
            return tier
    return "other"


IOS_KINDS = frozenset({"router", "multilayerswitch", "switch", "asa",
                       "wirelessrouter", "router-pt", "l3switch"})

_LOGIN_LINE_RE = re.compile(r"^\s*(login|login\s+local|login\s+authentication\b.*)$")


def console_requires_login(lines: Sequence[str]) -> bool:
    """True when a device's console/vty demands credentials PT will verify.

    `line con 0` / `line vty 0 4` open a sub-mode; the commands indented under
    it decide.  `aaa new-model` plus `login authentication <list>` means PT asks
    for a username and checks it against the stored (hashed) secret.
    """
    inside = False
    needs = False
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped:
            inside = False
        if not inside and re.match(r"^line\s+(con|vty|aux)\b", stripped):
            inside = True
            continue
        if inside and _LOGIN_LINE_RE.match(stripped):
            needs = True
    return needs


def load_artifact_model(path: Path, tiers: dict[str, tuple[str, ...]]) -> list[DeviceInfo]:
    """Read device names, canvas coordinates, interface IPs and console policy."""
    from pkt_core import decode
    from pkt_core.models import Lab

    sys.path.insert(0, str(REPO / "tools"))
    try:
        import audit_ios_commands as _cfg  # reuse the config-line walker
        configs = {name: lines for name, lines in _cfg._iter_running_configs(
            decode(str(path)).xml)}
    except Exception:  # noqa: BLE001 - config analysis is advisory
        configs = {}

    container = decode(str(path))
    lab = Lab.from_bytes(container.xml)
    out: list[DeviceInfo] = []
    for dev in lab.devices:
        pos = dev.position or (0.0, 0.0)
        ips: list[str] = []
        engine = dev.engine
        if engine is not None:
            # Ports are nested (ENGINE -> MODULE -> SLOT -> MODULE -> PORT), so
            # a direct-child search finds nothing on real routers.
            for node_el in engine.iter_elements():
                if node_el.tag != "PORT":
                    continue
                node = node_el.find("IP")
                if node is None:
                    continue
                value = node.text.strip()
                if value and value != "0.0.0.0":
                    ips.append(value)
        lines = configs.get(dev.name, [])
        # Server/PC appliances also carry a short RUNNINGCONFIG stub; only a
        # real IOS platform exposes the CLI tab.
        has_ios = (dev.kind.lower() in IOS_KINDS and bool(lines)
                   and any(ln.strip() and not ln.strip().startswith("!")
                           for ln in lines))
        out.append(DeviceInfo(
            name=dev.name, kind=dev.kind, model=dev.model,
            x=float(pos[0]), y=float(pos[1]),
            tier=tier_of(dev.name, tiers), ips=ips,
            ios=has_ios,
            console_locked=console_requires_login(lines),
        ))
    return out


def tier_boxes(devices: Sequence[DeviceInfo]) -> dict[str, dict[str, float]]:
    boxes: dict[str, dict[str, float]] = {}
    for tier in sorted({d.tier for d in devices}):
        group = [d for d in devices if d.tier == tier]
        if not group:
            continue
        xs = [d.x for d in group]
        ys = [d.y for d in group]
        boxes[tier] = {
            "x0": min(xs), "y0": min(ys), "x1": max(xs), "y1": max(ys),
            "cx": (min(xs) + max(xs)) / 2, "cy": (min(ys) + max(ys)) / 2,
            "devices": float(len(group)),
        }
    return boxes


def plan_ping_pairs(devices: Sequence[DeviceInfo],
                    max_pairs: int = 5) -> list[dict[str, str]]:
    """Cross-tier source/destination pairs a human can execute in minutes.

    Source: a router in the source tier (routers have a full IOS CLI).
    Destination: an interface address of a device in the destination tier.
    """
    by_tier: dict[str, list[DeviceInfo]] = {}
    for d in devices:
        by_tier.setdefault(d.tier, []).append(d)

    def pick_router(tier: str) -> DeviceInfo | None:
        """Prefer a CLI device PT will open without a password prompt."""
        cands = [d for d in by_tier.get(tier, []) if d.ios]
        if not cands:
            cands = [d for d in by_tier.get(tier, []) if d.ips]
        if not cands:
            return None
        unlocked = [d for d in cands if not d.console_locked]
        if unlocked:
            return sorted(unlocked, key=lambda d: d.name)[0]
        # Nothing in this tier can be reached without a password.  Prefer any
        # console-free IOS device anywhere, so the run still produces real
        # end-to-end evidence instead of only a manual procedure.
        global_free = sorted((d for d in devices if d.ios and not d.console_locked),
                             key=lambda d: d.name)
        if global_free:
            return global_free[0]
        return sorted(cands, key=lambda d: d.name)[0]

    def pick_target(tier: str, exclude: str) -> tuple[DeviceInfo, str] | None:
        cands = [d for d in by_tier.get(tier, []) if d.ips and d.name != exclude]
        for d in sorted(cands, key=lambda d: d.name):
            ip = sorted(d.ips, key=lambda s: tuple(int(o) for o in s.split(".")))[0]
            return d, ip
        return None

    order = ["airborne", "radar", "airbase", "datacentre"]
    pairs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for src_tier in order:
        src = pick_router(src_tier)
        if src is None:
            continue
        for dst_tier in order:
            if dst_tier == src_tier:
                continue
            tgt = pick_target(dst_tier, src.name)
            if tgt is None:
                continue
            dst, ip = tgt
            if (src.name, ip) in seen:
                continue
            seen.add((src.name, ip))
            pairs.append({
                "source_tier": src_tier, "source_device": src.name,
                "source_kind": src.kind, "source_cli": src.cli_kind,
                "console_locked": str(src.console_locked).lower(),
                "destination_tier": dst_tier, "destination_device": dst.name,
                "destination_ip": ip,
                "command": f"ping {ip}",
            })
            if len(pairs) >= max_pairs:
                return pairs
    # No tier offers an unlocked console: still try any device PT will open
    # without a password, so at least one real ping is attempted.
    unlocked = [d for d in devices if d.ios and not d.console_locked]
    for src in sorted(unlocked, key=lambda d: d.name):
        for dst_tier in order:
            if dst_tier == src.tier:
                continue
            tgt = pick_target(dst_tier, src.name)
            if tgt is None:
                continue
            dst, ip = tgt
            if (src.name, ip) in seen:
                continue
            seen.add((src.name, ip))
            pairs.append({
                "source_tier": src.tier, "source_device": src.name,
                "source_kind": src.kind, "source_cli": src.cli_kind,
                "console_locked": "false",
                "destination_tier": dst_tier, "destination_device": dst.name,
                "destination_ip": ip, "command": f"ping {ip}",
            })
            break
        if len(pairs) >= max_pairs:
            break
    return pairs


# =========================================================================== #
# 5b. Canvas <-> screen calibration and PT device-window driving
# =========================================================================== #

# Geometry of a PT device window, measured against Packet Tracer 9.0.1 at a
# 1:1 desktop: the device window is a fixed 700x680 frame whose tab strip sits
# 21 px below its top edge, and the CLI/Desktop text area starts 27 px in and
# 68 px down.  All of it is recorded in the evidence so a different PT build
# can be re-measured rather than silently mis-clicked.
DEVICE_WINDOW_TABS = {"clip": (158, 21)}
DEVICE_WINDOW_TEXT = (27, 68, 646, 520)
TAB_INDEX = {"Physical": 0, "Config": 1, "CLI": 2, "Desktop": 2, "Attributes": 3}


@dataclass
class Calibration:
    """Affine canvas -> screen mapping recovered from live PT clicks."""

    scale_x: float
    off_x: float
    scale_y: float
    off_y: float
    points: list[dict[str, Any]] = field(default_factory=list)

    def to_screen(self, x: float, y: float) -> tuple[int, int]:
        return (int(round(x * self.scale_x + self.off_x)),
                int(round(y * self.scale_y + self.off_y)))

    @property
    def ok(self) -> bool:
        return len(self.points) >= 2

    def as_dict(self) -> dict[str, Any]:
        return {"scale_x": self.scale_x, "off_x": self.off_x,
                "scale_y": self.scale_y, "off_y": self.off_y,
                "points": self.points, "method": "double-click probe"}


def _fit(pairs: list[tuple[float, float]]) -> tuple[float, float]:
    """Least-squares y = scale*x + off for (canvas, screen) pairs."""
    if len(pairs) == 1:
        return 1.0, pairs[0][1] - pairs[0][0]
    n = len(pairs)
    sx = sum(a for a, _ in pairs)
    sy = sum(b for _, b in pairs)
    sxx = sum(a * a for a, _ in pairs)
    sxy = sum(a * b for a, b in pairs)
    denom = n * sxx - sx * sx
    if abs(denom) < 1e-9:
        return 1.0, sy / n - sx / n
    scale = (n * sxy - sx * sy) / denom
    return scale, (sy - scale * sx) / n


# Packet Tracer draws router/switch icons in a steel blue; the toolbar navy is
# much darker (b~77) and the canvas is white, so this range isolates the icons.
_ICON_BLUE = ((100, 140, 150), (200, 220, 235))


def find_icon_candidates(screen: Screen, shot: Path, canvas: Canvas,
                         limit: int = 16, bin_px: int = 5,
                         min_hits: int = 6) -> list[tuple[int, int]]:
    """Screen points that look like device icons, densest first.

    Probe grids at random miss a 40x40 icon on a 1570x448 workspace, so the
    calibration probes are aimed at pixels that actually have icon colour.
    """
    x, y, w, h = canvas.region()
    proc = run([screen.tc.magick or "convert", str(shot),
                "-crop", f"{w}x{h}+{x}+{y}", "+repage", "-sample", "25%", "txt:-"],
               timeout=180)
    bins: Counter[tuple[int, int]] = Counter()
    for line in proc.stdout.splitlines():
        m = re.match(r"(\d+),(\d+): \((\d+),(\d+),(\d+)", line)
        if not m:
            continue
        bx, by = int(m.group(1)), int(m.group(2))
        r, g, b = int(m.group(3)), int(m.group(4)), int(m.group(5))
        if _ICON_BLUE[0][0] <= r <= _ICON_BLUE[1][0] and \
           _ICON_BLUE[0][1] <= g <= _ICON_BLUE[1][1] and \
           _ICON_BLUE[0][2] <= b <= _ICON_BLUE[1][2]:
            bins[(bx // bin_px, by // bin_px)] += 1
    points = []
    for (bx, by), hits in bins.most_common():
        if hits < min_hits:
            break
        points.append((canvas.x + (bx * bin_px + bin_px // 2) * 4,
                       canvas.y + (by * bin_px + bin_px // 2) * 4))
        if len(points) >= limit * 2:
            break
    return points[:limit]


def calibrate_view(pt: PacketTracer, xdo: Xdo, screen: Screen, canvas: Canvas,
                   devices: Sequence[DeviceInfo], main: int,
                   *, cols: int = 4, rows: int = 3,
                   max_hits: int = 4) -> Calibration:
    """Recover canvas -> screen by double-clicking device icons.

    Packet Tracer names a device window after the device, and this tool already
    knows every device's canvas coordinates from the file, so each successful
    double-click yields one exact (canvas, screen) correspondence.  Nothing is
    hard-coded to a particular window size or scroll position.
    """
    by_name = {d.name: d for d in devices}
    xs: list[tuple[float, float]] = []
    ys: list[tuple[float, float]] = []
    points: list[dict[str, Any]] = []
    shot = screen.capture("02_calibration_view.png")
    probes: list[tuple[int, int]] = []
    try:
        probes = find_icon_candidates(screen, shot, canvas, limit=cols * rows)
    except Exception:  # noqa: BLE001 - fall back to a plain grid
        probes = []
    if len(probes) < 3:
        probes = [(canvas.x + int(canvas.w * (ix + 0.5) / cols),
                   canvas.y + int(canvas.h * (iy + 0.5) / rows))
                  for iy in range(rows) for ix in range(cols)]
    for px, py in probes:
        if len(points) >= max_hits:
            break
        before = {w for w, _ in pt.other_windows(main)}
        xdo.click(px, py, repeat=2)
        time.sleep(2.5)
        fresh = [(w, n) for w, n in pt.other_windows(main) if w not in before]
        if not fresh:
            continue
        wid, name = fresh[-1]
        dev = by_name.get(name)
        if dev is None:
            continue
        xs.append((dev.x, float(px)))
        ys.append((dev.y, float(py)))
        points.append({"device": name, "canvas": [dev.x, dev.y],
                       "screen": [px, py], "window": wid})
        print(f"  calibration: {name} canvas=({dev.x:.0f},{dev.y:.0f}) "
              f"-> screen=({px},{py})")
    if len(points) < 2:
        raise StageFailure(
            "calibrate", "calibration-failed",
            f"only {len(points)} device icon(s) could be located by "
            f"double-click probing over a {cols}x{rows} grid; Packet Tracer's "
            f"logical view may not be showing the canvas")
    sx, ox = _fit(xs)
    sy, oy = _fit(ys)
    return Calibration(scale_x=sx, off_x=ox, scale_y=sy, off_y=oy, points=points)


def close_window(xdo: Xdo, wid: int) -> None:
    """Best effort: PT device windows have no WM decoration under bare Xvfb."""
    try:
        xdo("windowkill", str(wid), timeout=10)
    except Exception:  # noqa: BLE001
        pass


def scroll_to_device(sb: "Scrollbars", screen: Screen, canvas: Canvas,
                     calib: Calibration, dev: DeviceInfo,
                     workspace: tuple[float, float]) -> Calibration:
    """Scroll the logical workspace so *dev* is on screen, and re-derive the map.

    A scrollbar maps linearly onto the scrollable range, so once the mapping is
    known at one scroll position the offset at any other position follows
    analytically -- no second calibration pass is needed.
    """
    wx, wy = workspace
    span_x = max(0.0, wx - canvas.w)
    span_y = max(0.0, wy - canvas.h)
    fx = 0.0 if span_x <= 0 else max(0.0, min(1.0, (dev.x - canvas.w / 2) / span_x))
    fy = 0.0 if span_y <= 0 else max(0.0, min(1.0, (dev.y - canvas.h / 2) / span_y))
    shot = screen.capture("03_scroll_to_device.png")
    sb.scroll_to(shot, canvas, fx, fy)
    time.sleep(1.2)
    return Calibration(scale_x=calib.scale_x, off_x=canvas.x - fx * span_x,
                       scale_y=calib.scale_y, off_y=canvas.y - fy * span_y,
                       points=calib.points)


def open_device_window(pt: PacketTracer, xdo: Xdo, calib: Calibration,
                       dev: DeviceInfo, main: int,
                       timeout: float = 10.0) -> int:
    """Double-click a device icon and return its window id.

    The analytic screen position can be a few pixels out after scrolling, so a
    small spiral of offsets around it is tried before giving up.
    """
    px, py = calib.to_screen(dev.x, dev.y)
    offsets = [(0, 0), (0, -18), (0, 18), (-18, 0), (18, 0), (-18, -18), (18, 18)]
    for dx, dy in offsets:
        wid = _try_click(pt, xdo, main, dev.name, px + dx, py + dy, timeout)
        if wid is not None:
            return wid
    raise StageFailure("traffic", "device-window-not-opened",
                       f"{dev.name}: double-clicked near ({px},{py}) with "
                       f"{len(offsets)} offsets but no window titled "
                       f"'{dev.name}' appeared")


def _try_click(pt: PacketTracer, xdo: Xdo, main: int, name: str,
               px: int, py: int, timeout: float) -> int | None:
    before = {w for w, _ in pt.other_windows(main)}
    xdo.click(px, py, repeat=2)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for wid, wname in pt.other_windows(main):
            if wid not in before and wname == name:
                return wid
        time.sleep(0.4)
    for wid, wname in pt.other_windows(main):
        if wname == name:
            return wid
    return None


def _unused_open_device_window(pt: PacketTracer, xdo: Xdo, calib: Calibration,
                       dev: DeviceInfo, main: int,
                       timeout: float = 12.0) -> int:
    """Double-click a device icon and return its window id."""
    px, py = calib.to_screen(dev.x, dev.y)
    before = {w for w, _ in pt.other_windows(main)}
    xdo.click(px, py, repeat=2)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for wid, name in pt.other_windows(main):
            if wid not in before and name == dev.name:
                return wid
        time.sleep(0.4)
    # PT may have re-used an existing window with this exact title
    for wid, name in pt.other_windows(main):
        if name == dev.name:
            return wid
    raise StageFailure("traffic", "device-window-not-opened",
                       f"{dev.name}: double-clicked ({px},{py}) but no window "
                       f"titled '{dev.name}' appeared")


def device_tab(xdo: Xdo, wid: int, label: str,
               window: tuple[int, int, int, int]) -> None:
    """Click a device-window tab by its measured offset from the window origin."""
    wx, wy, _ww, _wh = window
    dx, dy = DEVICE_WINDOW_TABS["clip"]
    xdo.click(wx + dx, wy + dy)
    time.sleep(2.0)


def cli_region(window: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    wx, wy, _ww, _wh = window
    dx, dy, w, h = DEVICE_WINDOW_TEXT
    return (wx + dx, wy + dy, w, h)


def drive_ping(pt: PacketTracer, xdo: Xdo, screen: Screen, calib: Calibration,
               dev: DeviceInfo, main: int, command: str, shots_dir: Path,
               *, username: str = "", password: str = "",
               settle: float = 18.0, tag: str = "ping") -> dict[str, Any]:
    """Open a device CLI, optionally log in, run one command, read the output."""
    result: dict[str, Any] = {"command": command, "device": dev.name,
                              "status": "NOT-ATTEMPTED", "cli_text": ""}
    wid = open_device_window(pt, xdo, calib, dev, main)
    result["device_window"] = wid
    window = xdo.geometry(wid)
    result["device_window_geometry"] = f"{window[2]}x{window[3]}+{window[0]}+{window[1]}"
    tab = "CLI" if dev.cli_kind == "ios" else "Desktop"
    device_tab(xdo, wid, tab, window)
    time.sleep(1.5)

    pre = screen.capture(f"30_{tag}_cli_open.png")
    text = screen.ocr(pre, cli_region(window))
    result["initial_text"] = text[-800:]

    if "Username:" in text and username:
        xdo("type", "--window", str(wid), "--delay", "60", username, timeout=30)
        xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
        time.sleep(2.5)
        xdo("type", "--window", str(wid), "--delay", "60", password, timeout=30)
        xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
        time.sleep(6.0)
        pre = screen.capture(f"30_{tag}_after_login.png")
        text = screen.ocr(pre, cli_region(window))
        if "Login invalid" in text or "Username:" in text.split("Password:")[-1]:
            result["status"] = "LOGIN-FAILED"
            result["cli_text"] = text[-2000:]
            return result
    elif "Username:" in text:
        result["status"] = "LOGIN-REQUIRED"
        result["cli_text"] = text[-2000:]
        result["hint"] = ("pass --username/--password; the shipped secrets are "
                          "type-5 hashes, so the plaintext must come from the "
                          "generator, not from the file")
        return result

    for keystroke in ("Return",):
        xdo("key", "--window", str(wid), "--clearmodifiers", keystroke)
        time.sleep(0.6)
    # `terminal length 0` keeps the ping output on one screen
    xdo("type", "--window", str(wid), "--delay", "50", "terminal length 0", timeout=30)
    xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
    time.sleep(1.5)

    xdo("type", "--window", str(wid), "--delay", "50", command, timeout=30)
    xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
    time.sleep(settle)
    shot = screen.capture(f"31_{tag}_result.png")
    text = screen.ocr(shot, cli_region(window))
    result["cli_text"] = text[-4000:]
    result["screenshot"] = shot.name
    if re.search(r"(Success rate is \d+ percent|!!!!|\.{4})", text):
        m = re.search(r"Success rate is (\d+) percent", text)
        result["status"] = "REPLIED" if (not m or m.group(1) != "0") else "TIMEOUT"
        if m:
            result["success_rate"] = f"{m.group(1)}%"
    elif "Invalid input" in text or "% " in text:
        result["status"] = "CLI-ERROR"
    else:
        result["status"] = "UNPARSED"
    return result


# =========================================================================== #
# 6. Evidence collection
# =========================================================================== #


@dataclass
class Evidence:
    artifact: str = ""
    artifact_sha256: str = ""
    outdir: str = ""
    started: str = ""
    finished: str = ""
    toolchain: dict[str, Any] = field(default_factory=dict)
    packet_tracer: dict[str, Any] = field(default_factory=dict)
    stages: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    convergence: dict[str, Any] = field(default_factory=dict)
    tiers: dict[str, Any] = field(default_factory=dict)
    traffic: list[dict[str, Any]] = field(default_factory=list)
    blockers: list[dict[str, str]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def stage(self, name: str, ok: bool, seconds: float, **extra: Any) -> None:
        entry = {"stage": name, "ok": ok, "seconds": round(seconds, 2)}
        entry.update(extra)
        self.stages.append(entry)

    def block(self, exc: StageFailure) -> None:
        self.blockers.append({"stage": exc.stage, "blocker": exc.blocker,
                              "detail": exc.detail})

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "pkt-pt-runtime-verify/1",
            "artifact": self.artifact,
            "artifact_sha256": self.artifact_sha256,
            "outdir": self.outdir,
            "started": self.started,
            "finished": self.finished,
            "toolchain": self.toolchain,
            "packet_tracer": self.packet_tracer,
            "stages": self.stages,
            "screenshots": self.screenshots,
            "convergence": self.convergence,
            "tiers": self.tiers,
            "traffic": self.traffic,
            "blockers": self.blockers,
            "limitations": self.limitations,
        }


def render_markdown(ev: Evidence) -> str:
    d = ev.as_dict()
    out: list[str] = ["# Packet Tracer runtime verification", ""]
    out.append(f"* artefact: `{d['artifact']}`")
    out.append(f"* sha256: `{d['artifact_sha256']}`")
    out.append(f"* screenshots: `{d['outdir']}`")
    out.append(f"* started: {d['started']}  finished: {d['finished']}")
    out.append("")

    pt = d.get("packet_tracer") or {}
    if pt:
        out.append("## Packet Tracer used")
        out.append("")
        for k in ("binary", "version", "sha256", "source"):
            if pt.get(k):
                out.append(f"* {k}: `{pt[k]}`")
        out.append("")

    tc = d.get("toolchain") or {}
    out.append("## Toolchain")
    out.append("")
    out.append("| tool | path |")
    out.append("| --- | --- |")
    for k, v in tc.items():
        out.append(f"| {k} | `{v}` |")
    out.append("")

    out.append("## Stages")
    out.append("")
    out.append("| stage | ok | seconds | detail |")
    out.append("| --- | --- | ---: | --- |")
    for s in d["stages"]:
        detail = ", ".join(f"{k}={v}" for k, v in s.items()
                           if k not in ("stage", "ok", "seconds"))
        out.append(f"| {s['stage']} | {'yes' if s['ok'] else 'NO'} | {s['seconds']} | {detail[:220]} |")
    out.append("")

    conv = d.get("convergence") or {}
    if conv:
        out.append("## Link / STP convergence (problem 15)")
        out.append("")
        if conv.get("observed"):
            out.append(f"* samples: {conv.get('samples')} over {conv.get('window_s')}s")
            out.append(f"* amber at t0: {conv.get('amber_t0')} px, "
                       f"minimum: {conv.get('amber_min')} px")
            done = conv.get("converged_at_s")
            out.append(f"* amber stopped falling at: "
                       f"{'never within the window' if done is None else str(done) + ' s'}")
            out.append(f"* converged within {conv.get('bound_s')}s: "
                       f"**{conv.get('within_bound')}**")
        else:
            out.append(f"* not measured: {conv.get('reason', 'stage did not run')}")
        out.append("")

    tiers = d.get("tiers") or {}
    if tiers:
        out.append("## Tier coverage (problem 25)")
        out.append("")
        for tier, info in sorted(tiers.items()):
            out.append(f"* **{tier}** — {int(info.get('devices', 0))} devices, "
                       f"bbox ({info.get('x0'):.0f},{info.get('y0'):.0f})-"
                       f"({info.get('x1'):.0f},{info.get('y1'):.0f}), "
                       f"framed in `{info.get('screenshot', 'n/a')}`")
        out.append("")

    if d["screenshots"]:
        out.append("## Screenshots")
        out.append("")
        out.append("| file | scroll | amber px | green px |")
        out.append("| --- | --- | ---: | ---: |")
        for s in d["screenshots"]:
            out.append(f"| `{s['file']}` | fx={s.get('fx')} fy={s.get('fy')} | "
                       f"{s.get('amber', '')} | {s.get('green', '')} |")
        out.append("")

    if d["traffic"]:
        out.append("## End-to-end traffic (problem 24)")
        out.append("")
        for t in d["traffic"]:
            out.append(f"### {t.get('source_device')} -> {t.get('destination_ip')} "
                       f"({t.get('source_tier')} -> {t.get('destination_tier')})")
            out.append("")
            out.append(f"* status: **{t.get('status')}**")
            if t.get("cli_text"):
                out.append("")
                out.append("```")
                out.append(t["cli_text"].strip()[:4000])
                out.append("```")
            out.append("")

    if d["blockers"]:
        out.append("## Blockers")
        out.append("")
        out.append("| stage | blocker | detail |")
        out.append("| --- | --- | --- |")
        for b in d["blockers"]:
            out.append(f"| {b['stage']} | `{b['blocker']}` | {b['detail'][:300]} |")
        out.append("")

    if d["limitations"]:
        out.append("## Limitations")
        out.append("")
        for lim in d["limitations"]:
            out.append(f"* {lim}")
        out.append("")
    return "\n".join(out) + "\n"


# =========================================================================== #
# 7. CLI
# =========================================================================== #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pt_runtime_verify.py",
        description="Load a .pkt into a real Packet Tracer under Xvfb and "
                    "collect runtime evidence for problems 15/24/25/26.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--artifact", required=True, metavar="PATH",
                   help="the .pkt/.pka to open (a copy is used; never written to)")
    p.add_argument("--outdir", default=str(REPO / "build" / "pt_runtime"),
                   help="where screenshots and reports go")
    p.add_argument("--pt-bin", metavar="PATH", help="Packet Tracer executable")
    p.add_argument("--screen", default="1600x1000",
                   help="Xvfb screen geometry (default 1600x1000)")
    p.add_argument("--display", type=int, default=None,
                   help="X display number to use (default: first free)")
    p.add_argument("--load-timeout", type=float, default=300.0,
                   help="seconds to wait for PT's main window")
    p.add_argument("--render-wait", type=float, default=45.0,
                   help="seconds to let PT draw every device icon after load")
    p.add_argument("--sweep-cols", type=int, default=4)
    p.add_argument("--sweep-rows", type=int, default=4)
    p.add_argument("--convergence-window", type=float, default=120.0,
                   help="seconds to watch link lights for (problem 15)")
    p.add_argument("--convergence-bound", type=float, default=75.0,
                   help="the bound the catalogue says was exceeded")
    p.add_argument("--convergence-interval", type=float, default=3.0)
    p.add_argument("--no-traffic", action="store_true",
                   help="skip the ping stage")
    p.add_argument("--username", default="", help="CLI username for AAA devices")
    p.add_argument("--password", default="", help="CLI password for AAA devices")
    p.add_argument("--ping-settle", type=float, default=18.0,
                   help="seconds to wait for a ping to finish")
    p.add_argument("--calibration-cols", type=int, default=4)
    p.add_argument("--calibration-rows", type=int, default=3)
    p.add_argument("--calibration-hits", type=int, default=4)
    p.add_argument("--max-pings", type=int, default=4)
    p.add_argument("--keep-running", action="store_true",
                   help="leave Packet Tracer running after the run")
    p.add_argument("--json", metavar="PATH", help="report path (default <outdir>/report.json)")
    p.add_argument("--markdown", metavar="PATH",
                   help="markdown report (default <outdir>/report.md)")
    return p


# =========================================================================== #
# 8. Main
# =========================================================================== #


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    artifact = Path(args.artifact)
    if not artifact.is_file():
        print(f"error: artefact not found: {artifact}", file=sys.stderr)
        return 1

    outdir = Path(args.outdir)
    shots_dir = outdir / "screenshots"
    outdir.mkdir(parents=True, exist_ok=True)
    shots_dir.mkdir(parents=True, exist_ok=True)

    # Work on a private copy: the harness must never mutate the artefact.
    work = Path("/tmp") / f"pt_runtime_{os.getpid()}_{artifact.name}"
    shutil.copy2(artifact, work)

    ev = Evidence(
        artifact=str(artifact),
        artifact_sha256=file_sha256(artifact),
        outdir=str(outdir),
        started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    tc = Toolchain.probe(args.pt_bin)
    ev.toolchain = tc.as_dict()
    ev.packet_tracer = {"binary": tc.pt_bin, "source": tc.pt_source}

    missing = tc.required_missing()
    json_path = Path(args.json) if args.json else outdir / "report.json"
    md_path = Path(args.markdown) if args.markdown else outdir / "report.md"

    def finish(code: int) -> int:
        ev.finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(ev.as_dict(), indent=1) + "\n", encoding="utf-8")
        md_path.write_text(render_markdown(ev), encoding="utf-8")
        print(f"\nevidence json : {json_path}")
        print(f"evidence md   : {md_path}")
        if ev.blockers:
            print("\nBLOCKERS:")
            for b in ev.blockers:
                print(f"  [{b['stage']}] {b['blocker']}: {b['detail'][:200]}")
        return code

    if missing:
        ev.limitations.append("missing toolchain: " + "; ".join(missing))
        ev.blockers.append({"stage": "probe", "blocker": "toolchain-incomplete",
                            "detail": "; ".join(missing)})
        print("error: cannot run Packet Tracer headlessly:", file=sys.stderr)
        for m in missing:
            print(f"  missing: {m}", file=sys.stderr)
        return finish(3)

    size = tuple(int(x) for x in args.screen.lower().split("x"))  # type: ignore[assignment]
    xserver = XServer(tc, (size[0], size[1]), args.display)
    screen: Screen | None = None
    pt: PacketTracer | None = None
    session: PtProcess | None = None
    try:
        t0 = time.time()
        xserver.start()
        ev.stage("xvfb", True, time.time() - t0, display=xserver.env_display,
                 geometry=args.screen)
    except StageFailure as exc:
        ev.block(exc)
        ev.stage("xvfb", False, 0.0, blocker=exc.blocker)
        return finish(3)

    xdo = Xdo(tc, xserver.env_display)
    screen = Screen(tc, xserver.env_display, shots_dir)
    pt = PacketTracer(tc, xdo, screen, xserver.env_display)
    ev.packet_tracer = pt.version()

    try:
        # ---------------------------------------------------------------- #
        # stage: launch
        # ---------------------------------------------------------------- #
        t0 = time.time()
        session = pt.launch(work)
        wx, wy, ww, wh = session.geometry
        ev.stage("launch", True, time.time() - t0, window=session.window,
                 geometry=f"{ww}x{wh}+{wx}+{wy}",
                 launch_seconds=session.launch_seconds, argv=session.argv[1:])
        print(f"PT window {session.window} {ww}x{wh} after "
              f"{session.launch_seconds:.0f}s")

        # PT restores its own window geometry when the file finishes loading,
        # so anything done before this point is undone. Wait for the loader.
        t0 = time.time()
        load = pt.wait_for_load(work.name, timeout=args.load_timeout)
        ev.stage("file-open", True, time.time() - t0, **load)
        print(f"file opened: {load['title']} ({load['load_seconds']:.0f}s)")

        # Now fill the screen so a screenshot is (almost) the whole window,
        # and prove it from pixels rather than from xdotool's report.
        resize = ensure_window_size(xdo, screen, session.window,
                                    (size[0] - 10, size[1] - 10))
        ev.stage("resize", bool(resize.get("resize_ok")), 0.0, **resize)
        if not resize.get("resize_ok"):
            ev.limitations.append(
                "Packet Tracer refused to grow to the Xvfb screen size; "
                f"painted area {resize['attempts'][-1]['painted']} -- "
                "screenshots cover less of the logical workspace than intended")
        wx, wy, ww, wh = xdo.geometry(session.window)
        print(f"resize: {resize.get('resize_ok')} painted={resize['attempts'][-1]['painted']}")

        # ---------------------------------------------------------------- #
        # stage: load  (a rejected file shows a modal dialog, not a canvas)
        # ---------------------------------------------------------------- #
        t0 = time.time()
        time.sleep(max(0.0, args.render_wait))
        shot0 = screen.capture("00_after_load.png")
        hist0 = screen.histogram(shot0, region=(wx, wy, ww, wh), sample=4)
        canvas = detect_canvas(screen, shot0, (wx, wy, ww, wh), hist0)
        dialogs = pt.other_windows(session.window)
        ev.stage("load", True, time.time() - t0,
                 seconds_to_canvas=round(time.time() - t0, 1),
                 canvas=canvas.as_dict(),
                 modal_windows=[n for _w, n in dialogs][:5])
        ev.screenshots.append({"file": shot0.name, "fx": 0.0, "fy": 0.0,
                               "kind": "after-load"})
        if dialogs:
            ev.limitations.append(
                "extra top-level windows present after load: "
                + "; ".join(n for _w, n in dialogs[:5])
                + " (a modal error dialog would appear here)")
        print(f"canvas {canvas.w}x{canvas.h}+{canvas.x}+{canvas.y}; "
              f"other windows: {[n for _w, n in dialogs][:4]}")

        # ---------------------------------------------------------------- #
        # stage: artefact model + tier framing
        # ---------------------------------------------------------------- #
        t0 = time.time()
        try:
            devices = load_artifact_model(work, DEFAULT_TIERS)
            boxes = tier_boxes(devices)
            ev.tiers = {k: dict(v) for k, v in boxes.items()}
            ev.stage("model", True, time.time() - t0, devices=len(devices),
                     tiers={k: int(v["devices"]) for k, v in boxes.items()})
            print("tiers: " + ", ".join(
                f"{k}={int(v['devices'])}" for k, v in sorted(boxes.items())))
        except Exception as exc:  # noqa: BLE001 - model is advisory only
            devices, boxes = [], {}
            ev.stage("model", False, time.time() - t0, error=f"{type(exc).__name__}: {exc}")
            ev.limitations.append(f"could not read device coordinates: {exc}")

        # ---------------------------------------------------------------- #
        # stage: tier / sweep screenshots
        # ---------------------------------------------------------------- #
        t0 = time.time()
        sb = Scrollbars(xdo, screen)
        shots: list[tuple[Path, float, float]] = []
        fxs = [i / max(1, args.sweep_cols - 1) for i in range(args.sweep_cols)]
        fys = [i / max(1, args.sweep_rows - 1) for i in range(args.sweep_rows)]
        sweep_shot = shot0
        for iy, fy in enumerate(fys):
            for ix, fx in enumerate(fxs):
                if ix or iy:
                    sb.scroll_to(sweep_shot, canvas, fx, fy)
                    time.sleep(1.2)
                    sweep_shot = screen.capture(f"{10 + iy * len(fxs) + ix:02d}_sweep_"
                                                f"x{int(fx * 100):03d}_y{int(fy * 100):03d}.png")
                else:
                    sweep_shot = screen.capture("10_sweep_x000_y000.png")
                hist = screen.histogram(sweep_shot, canvas.region(), sample=4)
                colours = count_link_colours(hist)
                ev.screenshots.append({
                    "file": sweep_shot.name, "fx": round(fx, 3), "fy": round(fy, 3),
                    "kind": "sweep", "amber": colours["amber"],
                    "green": colours["green"], "red": colours["red"],
                })
                shots.append((sweep_shot, fx, fy))
        # assign each tier to the sweep frame nearest its normalised centroid
        all_x = [d.x for d in devices] or [0.0, 1.0]
        all_y = [d.y for d in devices] or [0.0, 1.0]
        for tier, box in ev.tiers.items():
            nx = (box["cx"] - min(all_x)) / max(1.0, max(all_x) - min(all_x))
            ny = (box["cy"] - min(all_y)) / max(1.0, max(all_y) - min(all_y))
            best = min(shots, key=lambda s: (s[1] - nx) ** 2 + (s[2] - ny) ** 2)
            box["screenshot"] = best[0].name
            box["norm_cx"] = round(nx, 3)
            box["norm_cy"] = round(ny, 3)
        ev.stage("screenshots", True, time.time() - t0, frames=len(shots),
                 tier_mapping="nearest-normalised-centroid")
        ev.limitations.append(
            "tier frames are chosen by nearest normalised centroid over a "
            "scroll sweep; the sweep itself is exhaustive, so no device goes "
            "unrendered, but the tier->frame label is an approximation")
        print(f"{len(shots)} sweep frames captured")

        # ---------------------------------------------------------------- #
        # stage: convergence  (problem 15)
        # ---------------------------------------------------------------- #
        t0 = time.time()
        sb.scroll_to(sweep_shot, canvas, 0.0, 0.0)
        time.sleep(1.0)
        samples: list[dict[str, Any]] = []
        started = time.time()
        conv_shot = screen.capture("20_convergence_t000.png")
        while time.time() - started <= args.convergence_window:
            conv_shot = screen.capture(
                f"20_convergence_t{int(time.time() - started):03d}.png")
            colours = count_link_colours(screen.histogram(conv_shot, canvas.region(), sample=4))
            samples.append({"t": round(time.time() - started, 2),
                            "amber": colours["amber"], "green": colours["green"],
                            "file": conv_shot.name})
            time.sleep(args.convergence_interval)
        amber0 = samples[0]["amber"] if samples else 0
        amber_min = min((s["amber"] for s in samples), default=0)
        converged_at = None
        for i, s in enumerate(samples):
            if s["amber"] <= max(1, int(amber0 * 0.05)):
                converged_at = s["t"]
                break
        ev.convergence = {
            "observed": bool(samples),
            "samples": len(samples),
            "window_s": args.convergence_window,
            "bound_s": args.convergence_bound,
            "interval_s": args.convergence_interval,
            "amber_t0": amber0,
            "amber_min": amber_min,
            "converged_at_s": converged_at,
            "within_bound": (converged_at is not None
                             and converged_at <= args.convergence_bound),
            "series": samples,
        }
        ev.stage("convergence", True, time.time() - t0, samples=len(samples),
                 amber_t0=amber0, amber_min=amber_min,
                 converged_at_s=converged_at)
        print(f"convergence: amber {amber0} -> {amber_min} px; "
              f"converged_at={converged_at}")

        # ---------------------------------------------------------------- #
        # stage: traffic  (problem 24)
        # ---------------------------------------------------------------- #
        if args.no_traffic:
            ev.limitations.append("traffic stage skipped (--no-traffic)")
            ev.traffic = [{
                "status": "SKIPPED",
                "command": p["command"],
                "source_device": p["source_device"],
                "destination_ip": p["destination_ip"],
                "source_tier": p["source_tier"],
                "destination_tier": p["destination_tier"],
            } for p in plan_ping_pairs(devices, args.max_pings)]
        else:
            t0 = time.time()
            plans = plan_ping_pairs(devices, args.max_pings)
            if not plans:
                ev.blockers.append({"stage": "traffic", "blocker": "no-ping-pairs",
                                    "detail": "no cross-tier endpoints found in the file"})
            for plan in plans:
                plan["status"] = "NOT-ATTEMPTED"
            ev.traffic = plans
            if plans:
                try:
                    cal = calibrate_view(
                        pt, xdo, screen, canvas, devices, session.window,
                        cols=args.calibration_cols, rows=args.calibration_rows,
                        max_hits=args.calibration_hits)
                    ev.packet_tracer["calibration"] = cal.as_dict()
                    print(f"calibration ok: scale=({cal.scale_x:.3f},"
                          f"{cal.scale_y:.3f}) from {len(cal.points)} points")
                    by_name = {d.name: d for d in devices}
                    for i, plan in enumerate(plans):
                        src = by_name.get(plan["source_device"])
                        if src is None:
                            plan["status"] = "NO-SOURCE"
                            continue
                        if src.cli_kind != "ios":
                            plan["status"] = "NEEDS-DESKTOP-CLI"
                            plan["hint"] = ("end-device CLI is reached through "
                                            "the Desktop tab; use the manual "
                                            "procedure below")
                            continue
                        if src.console_locked and not args.username:
                            plan["status"] = "LOGIN-REQUIRED"
                            plan["hint"] = ("device runs AAA login; pass "
                                            "--username/--password")
                            continue
                        print(f"ping {i + 1}/{len(plans)}: {plan['command']} "
                              f"from {src.name}")
                        cal = scroll_to_device(
                            sb, screen, canvas, cal, src,
                            (max(d.x for d in devices) + 200.0,
                             max(d.y for d in devices) + 200.0))
                        out = drive_ping(
                            pt, xdo, screen, cal, src, session.window,
                            plan["command"], shots_dir,
                            username=args.username, password=args.password,
                            settle=args.ping_settle, tag=f"ping{i + 1}")
                        plan.update({k: v for k, v in out.items()
                                     if k not in ("device", "command")})
                        plan["status"] = out["status"]
                        print(f"  -> {plan['status']}")
                except StageFailure as exc:
                    ev.block(exc)
                    for plan in plans:
                        if plan.get("status") == "NOT-ATTEMPTED":
                            plan["status"] = "BLOCKED"
                            plan["hint"] = f"{exc.blocker}: {exc.detail}"
                    ev.stage("traffic", False, time.time() - t0,
                             blocker=exc.blocker, detail=exc.detail[:300])
                    raise
            ev.stage("traffic", True, time.time() - t0, completed=sum(
                1 for p in ev.traffic if p.get("status") in ("REPLIED", "TIMEOUT")),
                attempted=len(ev.traffic))

    except StageFailure as exc:
        ev.block(exc)
        ev.stage(exc.stage, False, 0.0, blocker=exc.blocker, detail=exc.detail[:400])
        print(f"\nFAILED at stage '{exc.stage}': {exc.blocker} -- {exc.detail}",
              file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        ev.block(StageFailure("unexpected", type(exc).__name__, str(exc)[:400]))
        print(f"\nFAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        if session is not None and not args.keep_running:
            try:
                os.killpg(os.getpgid(session.popen.pid), signal.SIGTERM)
                session.popen.wait(timeout=15)
            except Exception:  # noqa: BLE001
                pass
        xserver.stop()

    ok = not ev.blockers and bool(ev.traffic)
    return finish(0 if not ev.blockers else 4)


if __name__ == "__main__":
    raise SystemExit(main())
