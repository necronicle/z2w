#!/usr/bin/env python3
"""
z2k GUI — кнопка включения/выключения DPI-обхода.
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
    # PyInstaller exe: рядом с exe-файлом
    SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

WINWS_EXE   = os.path.join(SCRIPT_DIR, "winws2.exe")
PROFILES    = os.path.join(SCRIPT_DIR, "profiles.default.txt")

_UNBLOCK_NAMES = ["winws2.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys"]

BASE_ARGS = [
    "--wf-tcp-out=443,2053,2083,2087,2096,8443",
    "--lua-init=@lua/zapret-lib.lua",
    "--lua-init=@lua/zapret-antidpi.lua",
    "--lua-init=@lua/zapret-auto.lua",
    "--lua-init=@lua/locked.lua",
    "--lua-init=@lua/z2k-autocircular.lua",
    "--lua-init=@lua/z2k-modern-core.lua",
    "--blob=quic_google:files/quic_initial_www_google_com.bin",
    "--blob=quic1:files/quic_1.bin",
    "--blob=quic4:files/quic_4.bin",
    "--blob=quic5:files/quic_5.bin",
    "--blob=quic6:files/quic_6.bin",
    "--blob=stun:files/stun.bin",
    "--blob=syn_packet:files/syn_packet.bin",
    "--blob=tls_max_ru:files/tls_clienthello_max_ru.bin",
    "--blob=tls_clienthello_14:files/tls_clienthello_14.bin",
    "--blob=tls_clienthello_4pda_to:files/tls_clienthello_4pda_to.bin",
    "--blob=tls_clienthello_vk_com:files/tls_clienthello_vk_com.bin",
    "--blob=tls_clienthello_www_google_com:files/tls_clienthello_www_google_com.bin",
    "--wf-raw-part=@windivert.filter/windivert_part.discord_media.txt",
    "--wf-raw-part=@windivert.filter/windivert_part.stun.txt",
    "--wf-raw-part=@windivert.filter/windivert_part.wireguard.txt",
    "--wf-raw-part=@windivert.filter/windivert_part.quic_initial_ietf.txt",
]

# ─── UAC ─────────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate_and_exit():
    """Перезапустить процесс с повышенными правами через UAC."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, SCRIPT_DIR, 1
    )
    sys.exit(0 if rc > 32 else 1)

# ─── Цвета ───────────────────────────────────────────────────────────────────

BG         = "#0d0d14"
RING_FILL  = "#111120"
BTN_OFF    = "#14142a"
BTN_ON     = "#07180f"
INSET_OFF  = "#0c0c1e"
INSET_ON   = "#051210"
ICON_OFF   = "#303058"
ICON_ON    = "#22ee88"
GLOW_OFF   = "#111120"
GLOW_ON    = "#14bb5a"
STATUS_OFF = "#35355a"
STATUS_ON  = "#22ee88"
TITLE_CLR  = "#44447a"
SUB_CLR    = "#1e1e38"

def lerp_color(c1: str, c2: str, t: float) -> str:
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    r = max(0, min(255, int(r1 + (r2 - r1) * t)))
    g = max(0, min(255, int(g1 + (g2 - g1) * t)))
    b = max(0, min(255, int(b1 + (b2 - b1) * t)))
    return f"#{r:02x}{g:02x}{b:02x}"

# ─── Приложение ──────────────────────────────────────────────────────────────

WIN_W, WIN_H = 300, 360
CV_S = 230        # квадратный холст
CX = CY = CV_S // 2

class App:
    def __init__(self):
        self.running = False
        self.process = None
        self._phase  = 0.0

        root = tk.Tk()
        self.root = root
        root.title("z2k")
        root.geometry(f"{WIN_W}x{WIN_H}")
        root.configure(bg=BG)
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._center()
        self._build_ui()
        root.after(40, self._tick)

    def _center(self):
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"+{(sw - WIN_W) // 2}+{(sh - WIN_H) // 2}")

    # ── Построение интерфейса ─────────────────────────────────────────────────

    def _build_ui(self):
        r = self.root

        tk.Label(r, text="z2k", bg=BG, fg=TITLE_CLR,
                 font=("Segoe UI", 13, "bold")).pack(pady=(20, 0))
        tk.Label(r, text="DPI bypass", bg=BG, fg=SUB_CLR,
                 font=("Segoe UI", 8)).pack(pady=(2, 0))

        cv = tk.Canvas(r, width=CV_S, height=CV_S, bg=BG,
                       highlightthickness=0)
        cv.pack(pady=10)
        self.cv = cv

        # Внешние кольца свечения (3 слоя)
        self.g3 = cv.create_oval(CX-110, CY-110, CX+110, CY+110,
                                  outline=GLOW_OFF, width=1, fill="")
        self.g2 = cv.create_oval(CX-105, CY-105, CX+105, CY+105,
                                  outline=GLOW_OFF, width=1, fill="")
        self.g1 = cv.create_oval(CX-99,  CY-99,  CX+99,  CY+99,
                                  outline=GLOW_OFF, width=2, fill=RING_FILL)

        # Бликовая дуга (имитация глубины — светлее слева-сверху)
        cv.create_arc(CX-98, CY-98, CX+98, CY+98,
                      start=100, extent=100,
                      outline="#1a1a34", width=1, style="arc")

        # Основная кнопка
        self.btn = cv.create_oval(CX-85, CY-85, CX+85, CY+85,
                                   outline="#1a1a32", width=1,
                                   fill=BTN_OFF, tags="btn")

        # Внутренняя вдавленная область
        self.inset = cv.create_oval(CX-67, CY-67, CX+67, CY+67,
                                     outline="#090914", width=2,
                                     fill=INSET_OFF, tags="btn")

        # Блик на вдавленной области
        cv.create_arc(CX-66, CY-66, CX+66, CY+66,
                      start=100, extent=110,
                      outline="#181830", width=1, style="arc",
                      tags="btn")

        # Иконка питания: дуга с разрывом сверху
        R = 36
        self.pw_arc = cv.create_arc(
            CX-R, CY-R, CX+R, CY+R,
            start=54, extent=252,
            outline=ICON_OFF, width=3, style="arc", tags="btn"
        )
        # Иконка питания: вертикальная черта в разрыве
        self.pw_line = cv.create_line(
            CX, CY - R - 5,
            CX, CY - 16,
            fill=ICON_OFF, width=3, capstyle="round", tags="btn"
        )

        # Привязка событий
        cv.tag_bind("btn", "<Button-1>", self._toggle)
        cv.bind("<Button-1>", self._toggle)
        cv.tag_bind("btn", "<Enter>", lambda e: cv.config(cursor="hand2"))
        cv.tag_bind("btn", "<Leave>", lambda e: cv.config(cursor=""))

        # Статус
        self._status_var = tk.StringVar(value="ВЫКЛЮЧЕНО")
        self._status_lbl = tk.Label(
            r, textvariable=self._status_var,
            bg=BG, fg=STATUS_OFF,
            font=("Segoe UI", 10, "bold")
        )
        self._status_lbl.pack()

        # Ошибки
        self._err_var = tk.StringVar()
        tk.Label(r, textvariable=self._err_var,
                 bg=BG, fg="#cc3333",
                 font=("Segoe UI", 8), wraplength=260).pack(pady=(5, 0))

    # ── Логика ───────────────────────────────────────────────────────────────

    def _toggle(self, _event=None):
        if self.running:
            self._stop()
        else:
            self._start()

    def _unblock_files(self):
        for name in _UNBLOCK_NAMES:
            path = os.path.join(SCRIPT_DIR, name)
            if os.path.exists(path):
                subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                     "-Command",
                     f"Unblock-File -LiteralPath '{path}' -ErrorAction SilentlyContinue"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

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
            self._unblock_files()
            args = self._build_args()
            self.process = subprocess.Popen(
                [WINWS_EXE] + args,
                cwd=SCRIPT_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except FileNotFoundError as e:
            self._err_var.set(f"Файл не найден: {os.path.basename(str(e))}")
            return
        except Exception as e:
            self._err_var.set(str(e))
            return

        self.running = True
        self._phase = 0.0
        self._refresh_visuals()
        threading.Thread(target=self._watch_process, daemon=True).start()

    def _stop(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
        self.running = False
        self._refresh_visuals()

    def _watch_process(self):
        """Фоновый поток: следит за неожиданным завершением winws2."""
        if self.process:
            self.process.wait()
        if self.running:
            self.running = False
            self.process = None
            self.root.after(0, self._refresh_visuals)

    # ── Визуализация ─────────────────────────────────────────────────────────

    def _refresh_visuals(self, glow_t: float = 0.0):
        cv = self.cv
        on = self.running

        cv.itemconfig(self.btn,     fill=BTN_ON    if on else BTN_OFF)
        cv.itemconfig(self.inset,   fill=INSET_ON  if on else INSET_OFF)
        cv.itemconfig(self.pw_arc,  outline=ICON_ON if on else ICON_OFF)
        cv.itemconfig(self.pw_line, fill=ICON_ON   if on else ICON_OFF)

        if on:
            cv.itemconfig(self.g1, outline=lerp_color("#131320", GLOW_ON, glow_t * 0.7))
            cv.itemconfig(self.g2, outline=lerp_color(GLOW_OFF,  GLOW_ON, glow_t * 0.45))
            cv.itemconfig(self.g3, outline=lerp_color(GLOW_OFF,  GLOW_ON, glow_t * 0.22))
        else:
            cv.itemconfig(self.g1, outline=GLOW_OFF)
            cv.itemconfig(self.g2, outline=GLOW_OFF)
            cv.itemconfig(self.g3, outline=GLOW_OFF)

        self._status_var.set("ВКЛЮЧЕНО" if on else "ВЫКЛЮЧЕНО")
        self._status_lbl.config(fg=STATUS_ON if on else STATUS_OFF)

    def _tick(self):
        """Анимация пульсации свечения когда включено."""
        if self.running:
            self._phase = (self._phase + 0.07) % (2 * math.pi)
            t = (math.sin(self._phase) + 1) / 2   # плавно 0..1
            self._refresh_visuals(glow_t=0.35 + t * 0.65)
        self.root.after(40, self._tick)

    # ── Закрытие ─────────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop()
        self.root.destroy()

    def mainloop(self):
        self.root.mainloop()

# ─── Точка входа ─────────────────────────────────────────────────────────────

def main():
    if not is_admin():
        # Пробуем поднять права через UAC
        elevate_and_exit()
        # Если дошли сюда — UAC отклонён (elevate_and_exit вызывает sys.exit)
        root = tk.Tk()
        root.withdraw()
        msgbox.showerror(
            "z2k — ошибка",
            "z2k требует прав администратора (WinDivert).\n"
            "Запустите приложение от имени администратора."
        )
        sys.exit(1)

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
