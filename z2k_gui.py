#!/usr/bin/env python3
"""
z2w — Windows DPI-bypass launcher.

Architecture:
    * UI: HTML/CSS/JS, rendered in a pywebview window (WebView2 on Win10/11).
    * Backend: this file. Exposes an `Api` class to JavaScript via pywebview.
    * Worker: winws2.exe spawned with args from BASE_ARGS + profiles.default.txt.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
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
UI_INDEX         = RES_DIR / "ui" / "index.html"

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
    args = list(BASE_ARGS)
    with open(PROFILES, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
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
        self.tg_proxy_proc: subprocess.Popen | None = None
        self.tg_enabled = False

    # called from main()
    def attach(self, window) -> None:
        self.window = window

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    # ── Public methods (called from JS) ──────────────────────

    def initial_state(self) -> dict:
        RKN_SILENT_FLAG.parent.mkdir(parents=True, exist_ok=True)
        return {
            "version":      VERSION,
            "running":      self.running,
            "tg_available": TG_PROXY_EXE.exists(),
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
                creationflags=CREATE_NO_WINDOW,
            )
        except FileNotFoundError as exc:
            return {"ok": False, "err": f"File not found: {Path(str(exc)).name}"}
        except Exception as exc:
            return {"ok": False, "err": str(exc)}

        if self.tg_enabled:
            self._start_tg_proxy()
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
        _kill_stale("winws2.exe")
        self._stop_tg_proxy()
        return {"ok": True}

    def set_tg_enabled(self, enabled: bool) -> dict:
        self.tg_enabled = bool(enabled)
        if self.running:
            if self.tg_enabled and not self.tg_proxy_proc:
                self._start_tg_proxy()
            elif not self.tg_enabled and self.tg_proxy_proc:
                self._stop_tg_proxy()
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
        if self.window is not None:
            try:
                self.window.destroy()
            except Exception:
                pass

    # ── internals ────────────────────────────────────────────

    def _start_tg_proxy(self) -> None:
        if not TG_PROXY_EXE.exists():
            return
        try:
            self.tg_proxy_proc = subprocess.Popen(
                [str(TG_PROXY_EXE)],
                cwd=str(SCRIPT_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    def _stop_tg_proxy(self) -> None:
        if self.tg_proxy_proc is not None:
            try:
                self.tg_proxy_proc.terminate()
                self.tg_proxy_proc.wait(timeout=3)
            except Exception:
                try:
                    self.tg_proxy_proc.kill()
                except Exception:
                    pass
            self.tg_proxy_proc = None
        _kill_stale("tg-transparent.exe")

    def _watch(self) -> None:
        """Wait for winws2 to exit; if it crashed, push a JS notification."""
        proc = self.process
        if proc is None:
            return
        try:
            proc.wait()
        except Exception:
            return
        if self.process is not proc:
            return  # superseded by stop()
        msg = ""
        try:
            data = proc.stderr.read() if proc.stderr else b""
            if data:
                msg = data.decode("utf-8", errors="replace").strip()[-300:]
        except Exception:
            pass
        self.process = None
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
