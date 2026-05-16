#!/usr/bin/env python3
"""
z2w GUI — кнопка включения/выключения DPI-обхода.
Запускает winws2.exe с аргументами из profiles.default.txt.
Требует прав администратора (запрашивает UAC автоматически).
"""

import os
import sys
import math
import ctypes
import threading
import subprocess
import tkinter as tk
import tkinter.messagebox as msgbox

# ─── Пути ────────────────────────────────────────────────────────────────────

if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

WINWS_EXE       = os.path.join(SCRIPT_DIR, "winws2.exe")
PROFILES        = os.path.join(SCRIPT_DIR, "profiles.default.txt")
RKN_SILENT_FLAG = os.path.join(SCRIPT_DIR, "cache", "autocircular", "rkn_silent_fallback.flag")
TG_PROXY_EXE   = os.path.join(SCRIPT_DIR, "tg-transparent.exe")

_UNBLOCK_NAMES = ["winws2.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys",
                   "tg-transparent.exe"]

HOSTS_FILE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "drivers", "etc", "hosts")

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
    "--lua-init=@lua/zapret-lib.lua",
    "--lua-init=@lua/zapret-antidpi.lua",
    "--lua-init=@lua/zapret-auto.lua",
    "--lua-init=@lua/locked.lua",
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

VERSION = "1.4.1"

# ─── UAC ─────────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate_and_exit():
    params = " ".join(f'"{a}"' for a in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, SCRIPT_DIR, 1
    )
    sys.exit(0 if rc > 32 else 1)

# ─── Дизайн-система ─────────────────────────────────────────────────────────

class C:
    """Палитра цветов."""
    BG          = "#0a0a12"
    SURFACE     = "#10101e"
    SURFACE2    = "#16162a"
    BORDER      = "#1a1a32"
    BORDER_LT   = "#222244"
    MUTED       = "#2e2e50"
    TEXT_DIM    = "#4a4a78"
    TEXT        = "#7a7aaa"
    TEXT_BR     = "#9a9acc"
    ACCENT      = "#22ee88"
    ACCENT_DIM  = "#14bb5a"
    ACCENT_DARK = "#0a5530"
    RED         = "#ee4444"
    RING_FILL   = "#0e0e1c"
    BTN_OFF     = "#12122a"
    BTN_ON      = "#071a10"
    INSET_OFF   = "#0b0b1a"
    INSET_ON    = "#041210"
    ICON_OFF    = "#2a2a50"
    GLOW_ON     = "#12aa50"
    # Toggle switch
    TRK_OFF     = "#1c1c36"
    TRK_ON      = "#115533"
    THB_OFF     = "#3a3a60"
    THB_ON      = "#22ee88"

FONT      = "Segoe UI"
FONT_MONO = "Consolas"

def lerp(c1: str, c2: str, t: float) -> str:
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    clamp = lambda v: max(0, min(255, int(v)))
    return f"#{clamp(r1+(r2-r1)*t):02x}{clamp(g1+(g2-g1)*t):02x}{clamp(b1+(b2-b1)*t):02x}"

# ─── Toggle Switch (Canvas) ─────────────────────────────────────────────────

class ToggleSwitch(tk.Canvas):
    """iOS-style toggle switch."""
    W, H, R = 38, 20, 8  # width, height, thumb radius

    def __init__(self, master, variable=None, command=None, enabled=True, **kw):
        super().__init__(master, width=self.W, height=self.H,
                         bg=C.BG, highlightthickness=0, **kw)
        self._var = variable or tk.BooleanVar(value=False)
        self._cmd = command
        self._enabled = enabled
        self._anim_t = 1.0 if self._var.get() else 0.0
        self._draw()
        if enabled:
            self.bind("<Button-1>", self._on_click)
            self.bind("<Enter>", lambda e: self.config(cursor="hand2"))
            self.bind("<Leave>", lambda e: self.config(cursor=""))

    def _draw(self):
        self.delete("all")
        t = self._anim_t
        trk = lerp(C.TRK_OFF, C.TRK_ON, t)
        thb = lerp(C.THB_OFF, C.THB_ON, t)
        if not self._enabled:
            trk = C.SURFACE
            thb = C.MUTED
        # Track (pill shape)
        r = self.H // 2
        self.create_oval(1, 1, self.H-1, self.H-1, fill=trk, outline=C.BORDER, width=1)
        self.create_oval(self.W-self.H+1, 1, self.W-1, self.H-1, fill=trk, outline=C.BORDER, width=1)
        self.create_rectangle(r, 1, self.W-r, self.H-1, fill=trk, outline="", width=0)
        self.create_line(r, 1, self.W-r, 1, fill=C.BORDER)
        self.create_line(r, self.H-1, self.W-r, self.H-1, fill=C.BORDER)
        # Thumb
        cx = r + t * (self.W - self.H)
        cy = self.H / 2
        self.create_oval(cx-self.R, cy-self.R, cx+self.R, cy+self.R,
                         fill=thb, outline="")

    def _on_click(self, _e=None):
        self._var.set(not self._var.get())
        self._animate()
        if self._cmd:
            self._cmd()

    def _animate(self, step=0):
        target = 1.0 if self._var.get() else 0.0
        self._anim_t += (target - self._anim_t) * 0.35
        if abs(self._anim_t - target) < 0.02:
            self._anim_t = target
            self._draw()
            return
        self._draw()
        self.after(16, self._animate)

# ─── Приложение ──────────────────────────────────────────────────────────────

WIN_W, WIN_H = 320, 460
BTN_S = 210  # canvas size for power button
CX = CY = BTN_S // 2

class App:
    def __init__(self):
        self.running = False
        self.process = None
        self.tg_proxy_proc = None
        self._phase = 0.0

        root = tk.Tk()
        self.root = root
        root.title("z2w")
        root.geometry(f"{WIN_W}x{WIN_H}")
        root.configure(bg=C.BG)
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._center()
        self._build_ui()
        root.after(40, self._tick)

    def _center(self):
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"+{(sw-WIN_W)//2}+{(sh-WIN_H)//2}")

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        r = self.root

        # Header
        hdr = tk.Frame(r, bg=C.BG)
        hdr.pack(fill="x", pady=(24, 0))
        tk.Label(hdr, text="z2w", bg=C.BG, fg=C.TEXT_BR,
                 font=(FONT, 16, "bold")).pack()
        tk.Label(hdr, text="DPI bypass", bg=C.BG, fg=C.MUTED,
                 font=(FONT, 9)).pack(pady=(1, 0))

        # Power button canvas
        cv = tk.Canvas(r, width=BTN_S, height=BTN_S, bg=C.BG, highlightthickness=0)
        cv.pack(pady=(12, 0))
        self.cv = cv

        # Glow rings
        self.g3 = cv.create_oval(CX-102, CY-102, CX+102, CY+102,
                                  outline=C.SURFACE, width=1, fill="")
        self.g2 = cv.create_oval(CX-97, CY-97, CX+97, CY+97,
                                  outline=C.SURFACE, width=1, fill="")
        self.g1 = cv.create_oval(CX-91, CY-91, CX+91, CY+91,
                                  outline=C.BORDER, width=2, fill=C.RING_FILL)
        # Highlight arc
        cv.create_arc(CX-90, CY-90, CX+90, CY+90, start=110, extent=90,
                      outline="#1c1c38", width=1, style="arc")
        # Button body
        self.btn = cv.create_oval(CX-78, CY-78, CX+78, CY+78,
                                   outline=C.BORDER, width=1,
                                   fill=C.BTN_OFF, tags="btn")
        # Inset
        self.inset = cv.create_oval(CX-60, CY-60, CX+60, CY+60,
                                     outline="#08080f", width=2,
                                     fill=C.INSET_OFF, tags="btn")
        cv.create_arc(CX-59, CY-59, CX+59, CY+59, start=110, extent=100,
                      outline="#161630", width=1, style="arc", tags="btn")
        # Power icon
        R = 32
        self.pw_arc = cv.create_arc(CX-R, CY-R, CX+R, CY+R,
                                     start=54, extent=252,
                                     outline=C.ICON_OFF, width=3,
                                     style="arc", tags="btn")
        self.pw_line = cv.create_line(CX, CY-R-4, CX, CY-14,
                                       fill=C.ICON_OFF, width=3,
                                       capstyle="round", tags="btn")
        cv.bind("<Button-1>", self._toggle)
        cv.tag_bind("btn", "<Enter>", lambda e: cv.config(cursor="hand2"))
        cv.tag_bind("btn", "<Leave>", lambda e: cv.config(cursor=""))

        # Status
        self._status_var = tk.StringVar(value="DISCONNECTED")
        self._status_lbl = tk.Label(r, textvariable=self._status_var,
                                     bg=C.BG, fg=C.MUTED,
                                     font=(FONT, 10, "bold"))
        self._status_lbl.pack(pady=(6, 0))

        # Divider
        div = tk.Canvas(r, width=WIN_W-60, height=20, bg=C.BG, highlightthickness=0)
        div.pack(pady=(10, 0))
        div.create_line(0, 10, 80, 10, fill=C.BORDER)
        div.create_text(130, 10, text="OPTIONS", fill=C.MUTED,
                        font=(FONT, 7, "bold"), anchor="center")
        div.create_line(180, 10, 260, 10, fill=C.BORDER)

        # Settings rows
        settings = tk.Frame(r, bg=C.BG)
        settings.pack(fill="x", padx=36, pady=(6, 0))

        # Row: Telegram proxy
        tg_exists = os.path.isfile(TG_PROXY_EXE)
        self._tg_var = tk.BooleanVar(value=False)
        self._make_row(settings, "Telegram", self._tg_var, enabled=tg_exists)

        # Row: RKN silent fallback
        self._rkn_var = tk.BooleanVar(value=os.path.isfile(RKN_SILENT_FLAG))
        self._make_row(settings, "RKN silent fallback", self._rkn_var,
                       command=self._toggle_rkn_silent)

        # Error
        self._err_var = tk.StringVar()
        tk.Label(r, textvariable=self._err_var, bg=C.BG, fg=C.RED,
                 font=(FONT, 8), wraplength=270).pack(pady=(8, 0))

        # Footer
        tk.Label(r, text=f"v{VERSION}", bg=C.BG, fg=C.BORDER_LT,
                 font=(FONT_MONO, 7)).pack(side="bottom", pady=(0, 10))

    def _make_row(self, parent, label, variable, command=None, enabled=True):
        row = tk.Frame(parent, bg=C.BG)
        row.pack(fill="x", pady=4)
        fg = C.TEXT if enabled else C.MUTED
        tk.Label(row, text=label, bg=C.BG, fg=fg,
                 font=(FONT, 9), anchor="w").pack(side="left")
        sw = ToggleSwitch(row, variable=variable, command=command, enabled=enabled)
        sw.pack(side="right")

    # ── Logic ────────────────────────────────────────────────────────────────

    def _toggle(self, _event=None):
        if self.running:
            self._stop()
        else:
            self._start()

    def _toggle_rkn_silent(self):
        os.makedirs(os.path.dirname(RKN_SILENT_FLAG), exist_ok=True)
        if self._rkn_var.get():
            with open(RKN_SILENT_FLAG, "w") as f:
                f.write("1")
        else:
            try:
                os.remove(RKN_SILENT_FLAG)
            except FileNotFoundError:
                pass

    def _start_tg_proxy(self):
        if not os.path.isfile(TG_PROXY_EXE):
            return
        try:
            self.tg_proxy_proc = subprocess.Popen(
                [TG_PROXY_EXE], cwd=SCRIPT_DIR,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    def _stop_tg_proxy(self):
        if self.tg_proxy_proc:
            try:
                self.tg_proxy_proc.terminate()
                self.tg_proxy_proc.wait(timeout=3)
            except Exception:
                try:
                    self.tg_proxy_proc.kill()
                except Exception:
                    pass
            self.tg_proxy_proc = None
        try:
            subprocess.run(["taskkill", "/F", "/IM", "tg-transparent.exe"],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    @staticmethod
    def _ensure_instagram_dns():
        try:
            with open(HOSTS_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return
        lower = content.lower()
        missing = [f"{ip}  {d}" for d, ip in _INSTAGRAM_DNS.items()
                   if d.lower() not in lower]
        if not missing:
            return
        try:
            with open(HOSTS_FILE, "a", encoding="utf-8") as f:
                f.write("\n# z2w — Instagram DNS fix\n")
                for line in missing:
                    f.write(line + "\n")
        except OSError:
            pass

    def _unblock_files(self):
        for name in _UNBLOCK_NAMES:
            path = os.path.join(SCRIPT_DIR, name)
            if os.path.exists(path):
                subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                     "-Command",
                     f"Unblock-File -LiteralPath '{path}' -ErrorAction SilentlyContinue"],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def _build_args(self) -> list:
        args = list(BASE_ARGS)
        with open(PROFILES, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    args.extend(line.split())
        return args

    def _start(self):
        self._err_var.set("")
        try:
            os.makedirs(os.path.join(SCRIPT_DIR, "cache", "autocircular"), exist_ok=True)
            self._kill_stale_winws()
            self._ensure_instagram_dns()
            self._unblock_files()
            args = self._build_args()
            self.process = subprocess.Popen(
                [WINWS_EXE] + args, cwd=SCRIPT_DIR,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except FileNotFoundError as e:
            self._err_var.set(f"File not found: {os.path.basename(str(e))}")
            return
        except Exception as e:
            self._err_var.set(str(e))
            return

        self.running = True
        self._phase = 0.0
        if self._tg_var.get():
            self._start_tg_proxy()
        self._refresh_visuals()
        threading.Thread(target=self._watch_process, daemon=True).start()

    @staticmethod
    def _kill_tree(pid: int):
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    @staticmethod
    def _kill_stale_winws():
        try:
            subprocess.run(["taskkill", "/F", "/IM", "winws2.exe"],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    def _stop(self):
        if self.process:
            self._kill_tree(self.process.pid)
            try:
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
        self._kill_stale_winws()
        self._stop_tg_proxy()
        self.running = False
        self._refresh_visuals()

    def _watch_process(self):
        proc = self.process
        if proc:
            proc.wait()
            stderr_data = b""
            try:
                stderr_data = proc.stderr.read()
            except Exception:
                pass
            if self.running:
                self.running = False
                self.process = None
                msg = stderr_data.decode("utf-8", errors="replace").strip()[-300:] if stderr_data else ""
                self.root.after(0, lambda m=msg: self._on_crash(m))

    def _on_crash(self, msg: str):
        self._refresh_visuals()
        self._err_var.set(f"winws2 crashed: {msg}" if msg else "winws2 stopped unexpectedly")

    # ── Visuals ──────────────────────────────────────────────────────────────

    def _refresh_visuals(self, glow_t: float = 0.0):
        cv = self.cv
        on = self.running
        cv.itemconfig(self.btn,     fill=C.BTN_ON   if on else C.BTN_OFF)
        cv.itemconfig(self.inset,   fill=C.INSET_ON if on else C.INSET_OFF)
        cv.itemconfig(self.pw_arc,  outline=C.ACCENT if on else C.ICON_OFF)
        cv.itemconfig(self.pw_line, fill=C.ACCENT    if on else C.ICON_OFF)
        if on:
            cv.itemconfig(self.g1, outline=lerp(C.BORDER, C.GLOW_ON, glow_t * 0.7))
            cv.itemconfig(self.g2, outline=lerp(C.SURFACE, C.GLOW_ON, glow_t * 0.4))
            cv.itemconfig(self.g3, outline=lerp(C.SURFACE, C.GLOW_ON, glow_t * 0.2))
        else:
            cv.itemconfig(self.g1, outline=C.BORDER)
            cv.itemconfig(self.g2, outline=C.SURFACE)
            cv.itemconfig(self.g3, outline=C.SURFACE)
        self._status_var.set("CONNECTED" if on else "DISCONNECTED")
        self._status_lbl.config(fg=C.ACCENT if on else C.MUTED)

    def _tick(self):
        if self.running:
            self._phase = (self._phase + 0.06) % (2 * math.pi)
            t = (math.sin(self._phase) + 1) / 2
            self._refresh_visuals(glow_t=0.3 + t * 0.7)
        self.root.after(40, self._tick)

    # ── Close ────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop()
        self.root.destroy()

    def mainloop(self):
        self.root.mainloop()

# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    if not is_admin():
        elevate_and_exit()
        root = tk.Tk()
        root.withdraw()
        msgbox.showerror("z2w", "z2w requires administrator privileges (WinDivert).\n"
                                "Run the application as administrator.")
        sys.exit(1)
    App().mainloop()

if __name__ == "__main__":
    main()
