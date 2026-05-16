#!/usr/bin/env python3
"""
z2w — Windows DPI-bypass launcher.

Architecture:
    * UI: HTML/CSS/JS, rendered in a pywebview window (WebView2 on Win10/11).
    * Backend: this file. Exposes an `Api` class to JavaScript via pywebview.
    * Worker: winws2.exe spawned with args from BASE_ARGS + profiles.default.txt.
"""

from __future__ import annotations

import collections
import ctypes
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────

if getattr(sys, "frozen", False):
    SCRIPT_DIR = Path(sys.executable).resolve().parent
    RES_DIR    = Path(getattr(sys, "_MEIPASS", str(SCRIPT_DIR)))
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
    RES_DIR    = SCRIPT_DIR

WINWS_EXE        = SCRIPT_DIR / "winws2.exe"
PROFILES         = SCRIPT_DIR / "profiles.default.txt"
RKN_SILENT_FLAG  = SCRIPT_DIR / "cache" / "autocircular" / "rkn_silent_fallback.flag"
TG_PROXY_EXE     = SCRIPT_DIR / "tg-transparent.exe"
TG_ENABLED_FLAG  = SCRIPT_DIR / "cache" / "tg_enabled.flag"    # persists toggle across restarts
UI_INDEX         = RES_DIR / "ui" / "index.html"
WINWS_LOG_FILE   = SCRIPT_DIR / "z2w-winws.log"      # current session log
WINWS_LOG_OLD    = SCRIPT_DIR / "z2w-winws.log.1"    # previous rotation
WINWS_LOG_CAP    = 2 * 1024 * 1024                   # 2 MB per file
TG_LOG_FILE      = SCRIPT_DIR / "z2w-tg.log"
TG_LOG_OLD       = SCRIPT_DIR / "z2w-tg.log.1"

# How many trailing stderr lines to keep in RAM for crash-report popup.
STDERR_TAIL_LINES = 80

# ─── Telegram tunnel constants (mirroring z2k tg-tunnel-watchdog.sh) ──────────
TG_CRASH_GRACE_SEC      = 1.5    # if proc dies < this after spawn → fatal
TG_WATCHDOG_INTERVAL    = 60     # seconds between health checks
TG_PROBE_HOST           = "core.telegram.org"
TG_PROBE_IP             = "149.154.167.99"   # Telegram CDN, pinned to bypass DNS variance
TG_PROBE_PORT           = 443
TG_PROBE_TIMEOUT        = 8
TG_PROBE_FAILS_FOR_RESTART = 3   # consecutive failures (~3min) → restart
TG_RESTART_MIN_INTERVAL = 30     # seconds; never restart faster than this
TG_RESTART_BUDGET       = 5      # max restarts...
TG_RESTART_BUDGET_WIN   = 300    # ...within this many seconds
TG_STDERR_FAIL_MARKERS  = (
    "WinDivertOpen:", "WinDivertRecv:", "WinDivertSend:",
    "fatal error:", "panic:",
)

VERSION = "1.4.1"

_UNBLOCK_NAMES = [
    "winws2.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys",
    "tg-transparent.exe",
]

HOSTS_FILE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"

_INSTAGRAM_DNS = {
    "instagram.com":                "157.240.251.174",
    "www.instagram.com":            "157.240.9.174",
    "graph.instagram.com":          "157.240.0.63",
    "api.instagram.com":            "157.240.253.63",
    "instagram.c10r.instagram.com": "157.240.214.63",
    "static.cdninstagram.com":      "163.70.147.63",
    "scontent.cdninstagram.com":    "163.70.147.63",
}

BASE_ARGS = [
    "--wf-tcp-out=80,443,2053,2083,2087,2096,8443",
    "--rst-filter=on",
    "--lua-init=@lua/zapret-lib.lua",
    "--lua-init=@lua/zapret-antidpi.lua",
    "--lua-init=@lua/zapret-auto.lua",
    "--lua-init=@lua/z2k-detectors.lua",
    "--lua-init=@lua/z2k-fooling-ext.lua",
    "--lua-init=@lua/z2k-range-rand.lua",
    "--lua-init=@lua/z2k-autocircular.lua",
    "--lua-init=@lua/z2k-modern-core.lua",
    "--lua-init=@lua/z2k-http-strats.lua",
    "--lua-init=@lua/z2k-dynamic-strategy.lua",
    "--blob=quic_google:files/quic_initial_www_google_com.bin",
    "--blob=quic_rutracker:files/quic_initial_rutracker_org.bin",
    "--blob=quic_ozon_ru:files/quic_initial_ozon_ru.bin",
    "--blob=quic_dbankcloud:files/quic_initial_dbankcloud_ru.bin",
    "--blob=quic1:files/quic_1.bin",
    "--blob=quic4:files/quic_4.bin",
    "--blob=quic5:files/quic_5.bin",
    "--blob=quic6:files/quic_6.bin",
    "--blob=quic_test:files/quic_test_00.bin",
    "--blob=stun:files/stun.bin",
    "--blob=syn_packet:files/syn_packet.bin",
    "--blob=tls_max_ru:files/tls_clienthello_max_ru.bin",
    "--blob=tls_clienthello_14:files/tls_clienthello_14.bin",
    "--blob=tls_clienthello_4pda_to:files/tls_clienthello_4pda_to.bin",
    "--blob=tls_clienthello_vk_com:files/tls_clienthello_vk_com.bin",
    "--blob=tls_clienthello_www_google_com:files/tls_clienthello_www_google_com.bin",
    "--blob=tls_clienthello_activated:files/tls_clienthello_activated.bin",
    "--blob=tls_clienthello_gosuslugi_ru:files/tls_clienthello_gosuslugi_ru.bin",
    "--blob=tls_clienthello_www_onetrust_com:files/tls_clienthello_www_onetrust_com.bin",
    "--blob=tls_clienthello_ucoz_ru_tls13:files/tls_clienthello_ucoz_ru_tls13.bin",
    "--blob=t2:files/t2.bin",
    "--blob=zero_256:files/zero_256.bin",
    "--blob=http_iana:files/http_iana_org.bin",
    "--wf-raw-part=@windivert.filter/windivert_part.discord_media.txt",
    "--wf-raw-part=@windivert.filter/windivert_part.stun.txt",
    "--wf-raw-part=@windivert.filter/windivert_part.wireguard.txt",
    "--wf-raw-part=@windivert.filter/windivert_part.quic_initial_ietf.txt",
]

CREATE_NO_WINDOW = 0x08000000

# ─── UAC ──────────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate_and_exit() -> None:
    params = " ".join(f'"{a}"' for a in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, str(SCRIPT_DIR), 1,
    )
    sys.exit(0 if rc > 32 else 1)

# ─── Worker helpers ───────────────────────────────────────────────────────────

def _kill_tree(pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        pass

def _kill_stale(image: str) -> None:
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", image],
            capture_output=True, creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        pass

def _build_args() -> list[str]:
    """BASE_ARGS + one profile per non-comment line of profiles.default.txt.
    Comments (#-prefixed) and blank lines are skipped — profiles.default.txt
    is generator output (tools/build_profiles.py) and carries a header."""
    args = list(BASE_ARGS)
    with open(PROFILES, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            args.extend(line.split())
    return args

def _ensure_instagram_dns() -> None:
    try:
        content = HOSTS_FILE.read_text(encoding="utf-8")
    except OSError:
        return
    lower = content.lower()
    missing = [f"{ip}  {d}" for d, ip in _INSTAGRAM_DNS.items() if d.lower() not in lower]
    if not missing:
        return
    try:
        with HOSTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write("\n# z2w — Instagram DNS fix\n")
            for line in missing:
                fh.write(line + "\n")
    except OSError:
        pass

class _StderrDrain(threading.Thread):
    """
    Continuously read winws2's stderr.

    WHY: winws2 (bol-van zapret2) writes diagnostic lines to stderr via
    DLOG_ERR / DLOG_CONDUP regardless of --debug verbosity — nfqws.c
    alone has 154 such call-sites that fire on hostlist warnings, IP
    cache events, parse errors, OOM, etc. The default Windows pipe
    buffer is 4-64 KB; without continuous draining it fills within
    minutes of active traffic, and the next fwrite(stderr) inside
    winws2 BLOCKS — packet processing halts and users see the bypass
    "stop responding".

    Each instance:
      • Mirrors raw stderr bytes into a size-capped rotating log file
        (current → .1 → discard). Capped at WINWS_LOG_CAP per file, so
        long-running sessions stay bounded at ~2×CAP on disk total.
      • Keeps the last STDERR_TAIL_LINES decoded lines in memory so
        the crash callback can show recent context to the user.
    """

    def __init__(self, stream, log_path: Path | None,
                 log_path_old: Path | None = None,
                 size_cap: int = WINWS_LOG_CAP) -> None:
        super().__init__(daemon=True, name="winws2-stderr-drain")
        self.stream = stream
        self.log_path = log_path
        self.log_path_old = log_path_old
        self.size_cap = size_cap
        self.lines: collections.deque[str] = collections.deque(maxlen=STDERR_TAIL_LINES)

    def _open_log(self):
        if self.log_path is None:
            return None
        try:
            return self.log_path.open("wb")
        except OSError:
            return None

    def _rotate(self, log_fh):
        """Close current, move → .1 (overwriting), reopen fresh."""
        try:
            log_fh.close()
        except Exception:
            pass
        if self.log_path is None:
            return None
        if self.log_path_old is not None:
            try:
                if self.log_path_old.exists():
                    self.log_path_old.unlink()
            except OSError:
                pass
            try:
                self.log_path.replace(self.log_path_old)
            except OSError:
                # If rename failed, fall back to truncating in place.
                try:
                    self.log_path.unlink()
                except OSError:
                    pass
        return self._open_log()

    def run(self) -> None:
        log_fh = self._open_log()
        bytes_written = 0
        try:
            for raw in iter(self.stream.readline, b""):
                if not raw:
                    break
                if log_fh is not None:
                    try:
                        log_fh.write(raw)
                        log_fh.flush()
                        bytes_written += len(raw)
                        if bytes_written >= self.size_cap:
                            log_fh = self._rotate(log_fh)
                            bytes_written = 0
                    except Exception:
                        try:
                            log_fh.close()
                        except Exception:
                            pass
                        log_fh = None
                self.lines.append(raw.decode("utf-8", errors="replace").rstrip())
        except Exception:
            pass
        finally:
            if log_fh is not None:
                try:
                    log_fh.close()
                except Exception:
                    pass

    def tail(self, n: int = 12) -> str:
        if not self.lines:
            return ""
        return "\n".join(list(self.lines)[-n:])[-1500:]


def _unblock_files() -> None:
    for name in _UNBLOCK_NAMES:
        path = SCRIPT_DIR / name
        if path.exists():
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command",
                 f"Unblock-File -LiteralPath '{path}' -ErrorAction SilentlyContinue"],
                capture_output=True, creationflags=CREATE_NO_WINDOW,
            )

# ─── pywebview API (exposed to JavaScript) ────────────────────────────────────

class Api:
    """Bridge between the HTML/JS frontend and the Python worker."""

    def __init__(self) -> None:
        self.window = None
        self.process: subprocess.Popen | None = None
        self.stderr_drain: _StderrDrain | None = None

        # Telegram tunnel state (independent of winws2 power button — mirrors
        # z2k's S98tg-tunnel/cron-watchdog split where tg-tunnel lives outside
        # of nfqws2's lifecycle).
        self.tg_proc: subprocess.Popen | None = None
        self.tg_stderr_drain: _StderrDrain | None = None
        self.tg_enabled = TG_ENABLED_FLAG.exists()   # persisted across z2w restarts
        self.tg_want_running = False                  # tracks user intent for watchdog
        self.tg_watchdog_thread: threading.Thread | None = None
        self.tg_probe_failures = 0
        self._tg_restart_log: collections.deque = collections.deque(maxlen=TG_RESTART_BUDGET)
        self._tg_lock = threading.Lock()

    # called from main()
    def attach(self, window) -> None:
        self.window = window

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    # ── Public methods (called from JS) ──────────────────────

    def initial_state(self) -> dict:
        RKN_SILENT_FLAG.parent.mkdir(parents=True, exist_ok=True)
        TG_ENABLED_FLAG.parent.mkdir(parents=True, exist_ok=True)
        # If TG was enabled in a previous session, start it now (independent
        # of the winws2 power button). Mirrors S98tg-tunnel autostart that
        # respects TG_PROXY_USER_DISABLED=0 on boot.
        if self.tg_enabled and self.tg_proc is None and TG_PROXY_EXE.exists():
            threading.Thread(target=self._tg_start, daemon=True,
                             name="tg-autostart").start()
        return {
            "version":      VERSION,
            "running":      self.running,
            "tg_available": TG_PROXY_EXE.exists(),
            "tg_enabled":   self.tg_enabled,
            "tg_running":   self._tg_alive(),
            "rkn_silent":   RKN_SILENT_FLAG.exists(),
        }

    def start(self) -> dict:
        try:
            (SCRIPT_DIR / "cache" / "autocircular").mkdir(parents=True, exist_ok=True)
            _kill_stale("winws2.exe")
            _ensure_instagram_dns()
            _unblock_files()
            args = _build_args()
            self.process = subprocess.Popen(
                [str(WINWS_EXE), *args],
                cwd=str(SCRIPT_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                bufsize=0,  # we read line-by-line in the drain thread
                creationflags=CREATE_NO_WINDOW,
            )
        except FileNotFoundError as exc:
            return {"ok": False, "err": f"File not found: {Path(str(exc)).name}"}
        except Exception as exc:
            return {"ok": False, "err": str(exc)}

        # CRITICAL: drain stderr continuously so the OS pipe buffer never fills.
        # See _StderrDrain docstring for the failure mode this prevents.
        self.stderr_drain = _StderrDrain(
            self.process.stderr, WINWS_LOG_FILE, WINWS_LOG_OLD,
        )
        self.stderr_drain.start()

        # TG tunnel is INDEPENDENT of winws2 lifecycle (mirrors z2k's split
        # where S98tg-tunnel and S99zapret2 are separate init scripts).
        threading.Thread(target=self._watch, daemon=True).start()
        return {"ok": True}

    def stop(self) -> dict:
        proc = self.process
        if proc is not None:
            self.process = None  # mark stopped before kill so _watch ignores exit
            _kill_tree(proc.pid)
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        # Drain thread exits naturally on stderr EOF (after the kill above).
        self.stderr_drain = None
        _kill_stale("winws2.exe")
        # TG is independent — power-off must NOT kill the tunnel.
        return {"ok": True}

    def set_tg_enabled(self, enabled: bool) -> dict:
        """User toggled TG. Independent of winws2 power state."""
        want = bool(enabled)

        # Validate BEFORE mutating persistent state. If we wrote the flag
        # first and only then noticed the exe was missing, a later
        # exe-restore (re-download, Defender quarantine release) would
        # silently autostart TG on next z2w launch — user never asked for
        # that. Leave self.tg_enabled / TG_ENABLED_FLAG untouched on this
        # failure path so the user has to re-toggle explicitly once the
        # exe is back.
        if want and not TG_PROXY_EXE.exists():
            self._tg_emit("error", "tg-transparent.exe не найден рядом с z2w.exe")
            return {"ok": False, "err": "tg-transparent.exe не найден"}

        self.tg_enabled = want
        # Persist across z2w restarts (mirrors TG_PROXY_USER_DISABLED).
        try:
            TG_ENABLED_FLAG.parent.mkdir(parents=True, exist_ok=True)
            if want:
                TG_ENABLED_FLAG.write_text("1", encoding="utf-8")
            else:
                try:
                    TG_ENABLED_FLAG.unlink()
                except FileNotFoundError:
                    pass
        except OSError:
            pass

        if want:
            # Spawn in background — UI doesn't wait for crash-grace.
            threading.Thread(target=self._tg_start, daemon=True,
                             name="tg-start").start()
        else:
            threading.Thread(target=self._tg_stop, daemon=True,
                             name="tg-stop").start()
        return {"ok": True}

    def set_rkn_silent(self, enabled: bool) -> dict:
        RKN_SILENT_FLAG.parent.mkdir(parents=True, exist_ok=True)
        if enabled:
            RKN_SILENT_FLAG.write_text("1", encoding="utf-8")
        else:
            try:
                RKN_SILENT_FLAG.unlink()
            except FileNotFoundError:
                pass
        return {"ok": True}

    def minimize(self) -> None:
        if self.window is not None:
            try:
                self.window.minimize()
            except Exception:
                pass

    def close(self) -> None:
        self.stop()
        # On app exit, ALWAYS stop the tunnel (regardless of tg_enabled flag).
        # The flag remains set so next launch auto-starts.
        self._tg_stop(persist=False)
        if self.window is not None:
            try:
                self.window.destroy()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────────
    # ── Telegram tunnel: lifecycle + watchdog                ──
    # ──────────────────────────────────────────────────────────
    #
    # Mirrors z2k's tg-tunnel pipeline:
    #   - S98tg-tunnel    → _tg_start / _tg_stop
    #   - watchdog cron   → _tg_watchdog (daemon thread, 60s tick)
    #   - active probe    → _tg_probe (TLS to TG_PROBE_IP)
    #   - restart logic   → _tg_restart with rate-limit + budget
    #   - log mgmt        → _StderrDrain → z2w-tg.log (rolling, 2MB cap)
    # ──────────────────────────────────────────────────────────

    def _tg_alive(self) -> bool:
        return self.tg_proc is not None and self.tg_proc.poll() is None

    def _tg_emit(self, state: str, msg: str = "") -> None:
        """Push state update to JS. state ∈ {starting, running, error, stopped}."""
        if self.window is None:
            return
        try:
            self.window.evaluate_js(
                f"window.onTgState && window.onTgState({_js_string(state)}, {_js_string(msg)})"
            )
        except Exception:
            pass

    def _tg_give_up(self) -> None:
        """Persistent give-up: clear tg_enabled + remove flag + stop watchdog.
        Used on immediate crash and on restart-budget exhaustion. Without this,
        the next z2w launch reads the flag and autostarts a broken tunnel."""
        self.tg_enabled = False
        self.tg_want_running = False
        try:
            TG_ENABLED_FLAG.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _tg_start(self) -> None:
        """Spawn tg-transparent.exe + start drain + spawn watchdog.
        Re-checks self.tg_enabled under the lock to handle the on→off race
        when this fn is invoked via background thread from set_tg_enabled."""
        with self._tg_lock:
            # Race guard: user may have toggled off before this thread ran.
            # Both set_tg_enabled(False) (clears tg_enabled+flag) and an
            # explicit _tg_stop (clears tg_want_running) can happen between
            # the threading.Thread(...).start() and this lock acquisition.
            if not self.tg_enabled:
                return
            if self._tg_alive():
                return  # already running
            if not TG_PROXY_EXE.exists():
                # TOCTOU window: set_tg_enabled() checked exe and wrote the
                # flag, then this thread was scheduled, and meanwhile the exe
                # was quarantined/deleted. Clear persistent state under the
                # same lock so the next z2w launch doesn't blindly autostart.
                self._tg_give_up()
                self._tg_emit("error", "tg-transparent.exe не найден")
                return

            _unblock_files()
            _kill_stale("tg-transparent.exe")  # clean any orphan

            try:
                self.tg_proc = subprocess.Popen(
                    [str(TG_PROXY_EXE)],
                    cwd=str(SCRIPT_DIR),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                    creationflags=CREATE_NO_WINDOW,
                )
            except Exception as exc:
                self._tg_emit("error", f"Не удалось запустить tg-transparent: {exc}")
                return

            self.tg_stderr_drain = _StderrDrain(
                self.tg_proc.stderr, TG_LOG_FILE, TG_LOG_OLD,
            )
            self.tg_stderr_drain.start()
            self.tg_want_running = True
            self.tg_probe_failures = 0

        self._tg_emit("starting")

        # Crash-grace check — if the process dies within TG_CRASH_GRACE_SEC,
        # treat as fatal and surface the tail. Otherwise → running.
        threading.Thread(target=self._tg_crash_check, daemon=True,
                         name="tg-crash-check").start()

        # Start watchdog if not already running.
        if (self.tg_watchdog_thread is None
                or not self.tg_watchdog_thread.is_alive()):
            self.tg_watchdog_thread = threading.Thread(
                target=self._tg_watchdog, daemon=True, name="tg-watchdog",
            )
            self.tg_watchdog_thread.start()

    def _tg_kill_proc(self) -> None:
        """Silent kill of the current tg_proc + drain. NO UI emit, NO flag
        changes. Idempotent — no-op if no proc. Used both by user-stop
        (followed by 'stopped' emit) and by persistent-give-up paths
        (followed by 'error' emit — must NOT be clobbered with 'stopped')."""
        with self._tg_lock:
            proc = self.tg_proc
            self.tg_proc = None
            self.tg_stderr_drain = None
        if proc is not None:
            _kill_tree(proc.pid)
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _kill_stale("tg-transparent.exe")

    def _tg_stop(self, persist: bool = True) -> None:
        """User-initiated stop. Kills proc + emits 'stopped'.
        persist=True clears tg_want_running so watchdog exits;
        persist=False is app-exit cleanup (flag preserved on disk)."""
        if persist:
            with self._tg_lock:
                self.tg_want_running = False
        self._tg_kill_proc()
        self._tg_emit("stopped")

    def _tg_crash_check(self) -> None:
        """Detect immediate post-spawn crash and surface stderr tail."""
        time.sleep(TG_CRASH_GRACE_SEC)
        with self._tg_lock:
            proc = self.tg_proc
            drain = self.tg_stderr_drain
        if proc is None:
            return
        if proc.poll() is None:
            # alive — promote to "running"
            self._tg_emit("running")
            return
        # Crashed during grace window — fatal.
        if drain is not None:
            drain.join(timeout=0.5)
        tail = drain.tail(12) if drain else ""
        # Process has already exited (poll != None above), but _tg_kill_proc
        # also nulls tg_proc/drain refs and calls _kill_stale for safety.
        self._tg_kill_proc()
        with self._tg_lock:
            # Don't loop-restart on immediate crash AND don't autostart next
            # session — UI now shows error+unchecked, backend must match.
            self._tg_give_up()
        msg = f"tg-transparent умер сразу после старта: {tail}" if tail \
              else "tg-transparent умер сразу после старта (см. z2w-tg.log)"
        self._tg_emit("error", msg)

    def _tg_watchdog(self) -> None:
        """Periodic health check. Identical contract to z2k-tg-watchdog.sh:
           - process must be alive
           - active TLS probe to Telegram must succeed (after 3 fails → restart)
           - rate-limited restarts; budget exhausted → give up + report"""
        while True:
            time.sleep(TG_WATCHDOG_INTERVAL)
            if not self.tg_want_running:
                return  # user has stopped; watchdog exits

            # 1. Process alive?
            if not self._tg_alive():
                self._tg_restart("process not running")
                continue

            # 2. CONNECT_FAIL / WinDivertOpen storm in stderr tail?
            drain = self.tg_stderr_drain
            if drain is not None:
                tail = drain.tail(40)
                hits = sum(1 for line in tail.splitlines()
                           if any(m in line for m in TG_STDERR_FAIL_MARKERS))
                if hits >= 10:
                    self._tg_restart(f"stderr storm: {hits} fail markers in last 40 lines")
                    continue

            # 3. Active probe.
            if self._tg_probe():
                self.tg_probe_failures = 0
                self._tg_emit("running")
            else:
                self.tg_probe_failures += 1
                if self.tg_probe_failures >= TG_PROBE_FAILS_FOR_RESTART:
                    self._tg_restart(
                        f"active probe failed {self.tg_probe_failures}x in a row"
                    )
                    self.tg_probe_failures = 0

    def _tg_probe(self) -> bool:
        """TLS handshake to Telegram (TG_PROBE_HOST resolved to TG_PROBE_IP).
        If WinDivert+tg-transparent are healthy, TG IP traffic goes through
        the tunnel and succeeds. Failure = tunnel broken."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                    (TG_PROBE_IP, TG_PROBE_PORT),
                    timeout=TG_PROBE_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=TG_PROBE_HOST) as tls:
                    tls.do_handshake()
                    return True
        except Exception:
            return False

    def _tg_restart(self, reason: str) -> None:
        """Rate-limited restart. Mirrors z2k-tg-watchdog.sh restart_tunnel()."""
        now = time.time()
        # Budget check: max TG_RESTART_BUDGET restarts within TG_RESTART_BUDGET_WIN.
        while self._tg_restart_log and now - self._tg_restart_log[0] > TG_RESTART_BUDGET_WIN:
            self._tg_restart_log.popleft()
        if len(self._tg_restart_log) >= TG_RESTART_BUDGET:
            # CRITICAL: kill the broken proc BEFORE emitting error. stderr-storm
            # and probe-fail branches reach here with a live tg-transparent.exe
            # still holding its WinDivert handle — without this kill it leaks
            # past give-up and continues intercepting TG traffic with no logic
            # behind it. Silent kill (no 'stopped' emit) so the final 'error'
            # state in UI isn't clobbered.
            self._tg_kill_proc()
            with self._tg_lock:
                # Same persistent give-up as immediate crash — backend state,
                # disk flag, and UI checkbox must agree across z2w restarts.
                self._tg_give_up()
            self._tg_emit("error",
                          f"tg-transparent: {TG_RESTART_BUDGET} рестартов за "
                          f"{TG_RESTART_BUDGET_WIN}с — даю отбой. См. z2w-tg.log")
            return

        if self._tg_restart_log and now - self._tg_restart_log[-1] < TG_RESTART_MIN_INTERVAL:
            return  # too soon since last restart, skip this tick

        self._tg_restart_log.append(now)
        self._tg_emit("error", f"рестарт: {reason}")
        # Tear down current proc cleanly; preserve tg_want_running.
        self._tg_stop(persist=False)
        # Brief settle, then bring up again. tg_want_running guards
        # against starting after a user stop that raced with the watchdog.
        time.sleep(1.0)
        if self.tg_enabled:
            self.tg_want_running = True
            self._tg_start()

    def _watch(self) -> None:
        """Wait for winws2 to exit; if it crashed, push a JS notification."""
        proc = self.process
        drain = self.stderr_drain
        if proc is None:
            return
        try:
            proc.wait()
        except Exception:
            return
        if self.process is not proc:
            return  # superseded by stop()

        # Give the drain thread a brief window to flush the final lines.
        if drain is not None:
            drain.join(timeout=0.5)

        msg = drain.tail(12) if drain is not None else ""

        self.process = None
        self.stderr_drain = None
        if self.window is not None:
            try:
                self.window.evaluate_js(f"window.onWinwsCrash({_js_string(msg)})")
            except Exception:
                pass


def _js_string(s: str) -> str:
    if not s:
        return "''"
    return ("'" + s.replace("\\", "\\\\").replace("'", "\\'")
                  .replace("\n", "\\n").replace("\r", "") + "'")

# ─── Win11 chrome polish (Mica + dark titlebar + rounded corners) ─────────────

def _apply_win11_chrome(window) -> None:
    """Apply Mica + dark titlebar + rounded corners. Win10 fails silently."""
    try:
        import win32gui  # noqa: F401 (pywin32, bundled with pywebview)
    except Exception:
        win32gui = None

    hwnd = 0
    try:
        if win32gui is not None:
            hwnd = win32gui.FindWindow(None, window.title)
    except Exception:
        hwnd = 0
    if not hwnd:
        try:
            hwnd = ctypes.windll.user32.FindWindowW(None, window.title)
        except Exception:
            return

    DWMWA_USE_IMMERSIVE_DARK_MODE   = 20
    DWMWA_SYSTEMBACKDROP_TYPE       = 38   # Win11 22H2+: 2 = Mica, 4 = Mica Tabbed
    DWMWA_WINDOW_CORNER_PREFERENCE  = 33   # Win11: 1 default, 2 round, 3 small

    dwm = ctypes.windll.dwmapi
    int_one = ctypes.c_int(1)
    int_two = ctypes.c_int(2)

    try:
        dwm.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                                  ctypes.byref(int_one), ctypes.sizeof(int_one))
    except Exception:
        pass
    try:
        dwm.DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE,
                                  ctypes.byref(int_two), ctypes.sizeof(int_two))
    except Exception:
        pass
    try:
        dwm.DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE,
                                  ctypes.byref(int_two), ctypes.sizeof(int_two))
    except Exception:
        pass

# ─── Entry ────────────────────────────────────────────────────────────────────

def _show_fatal(msg: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(None, msg, "z2w", 0x10)
    except Exception:
        print(msg, file=sys.stderr)

def main() -> None:
    if not is_admin():
        elevate_and_exit()
        return

    try:
        import webview
    except ImportError as exc:
        _show_fatal(
            "Не найден компонент pywebview.\n\n"
            "Если ты собрал из исходников — выполни:\n"
            "    pip install pywebview pywin32\n\n"
            f"Подробности: {exc}"
        )
        sys.exit(1)

    api = Api()

    try:
        window = webview.create_window(
            title="z2w",
            url=str(UI_INDEX),
            js_api=api,
            width=400,
            height=620,
            min_size=(380, 580),
            resizable=False,
            frameless=True,
            easy_drag=False,  # only .pywebview-drag-region (titlebar) drags
            background_color="#0b0e15",
        )
    except Exception as exc:
        _show_fatal(
            "Не удалось создать окно.\n\n"
            "Возможно, не установлен Microsoft Edge WebView2 Runtime.\n"
            "Скачай его: https://go.microsoft.com/fwlink/p/?LinkId=2124703\n\n"
            f"Подробности: {exc}"
        )
        sys.exit(1)

    api.attach(window)

    def on_shown() -> None:
        _apply_win11_chrome(window)

    try:
        window.events.shown += on_shown
    except Exception:
        pass

    try:
        webview.start()
    except Exception as exc:
        _show_fatal(
            "Не удалось запустить webview.\n\n"
            "Проверь, что установлен Microsoft Edge WebView2 Runtime:\n"
            "https://go.microsoft.com/fwlink/p/?LinkId=2124703\n\n"
            f"Подробности: {exc}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
