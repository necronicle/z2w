// z2w — UI controller. Talks to Python backend via window.pywebview.api.

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const body         = document.body;
  const powerBtn     = $("power");
  const stateLbl     = $("state");
  const statusSub    = $("status-sub");
  const tgToggle     = $("tg-toggle");
  const tgSub        = $("tg-sub");
  const rknToggle    = $("rkn-toggle");
  const errorBox     = $("error");
  const verLabel     = $("ver");
  const wcMin        = $("wc-min");
  const wcClose      = $("wc-close");

  const tgRow  = tgToggle.closest(".row");
  const rknRow = rknToggle.closest(".row");

  let startedAt = null;
  let uptimeTimer = null;
  let busy = false;

  // ─── helpers ───────────────────────────────────────────────

  const fmtUptime = (ms) => {
    const s = Math.max(0, Math.floor(ms / 1000));
    const hh = String(Math.floor(s / 3600)).padStart(2, "0");
    const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
    const ss = String(s % 60).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
  };

  const showError = (msg) => {
    if (!msg) { errorBox.hidden = true; errorBox.textContent = ""; return; }
    errorBox.hidden = false;
    errorBox.textContent = msg;
  };

  const tickUptime = () => {
    if (!startedAt) return;
    statusSub.textContent = fmtUptime(Date.now() - startedAt);
  };

  const setBusy = (v) => {
    busy = v;
    powerBtn.disabled = v;
    powerBtn.style.opacity = v ? 0.85 : 1;
  };

  const setState = (s) => {
    body.classList.remove("is-on", "is-connecting");
    if (s === "on") {
      body.classList.add("is-on");
      powerBtn.setAttribute("aria-pressed", "true");
      stateLbl.textContent = "ВКЛЮЧЕНО";
      startedAt = startedAt || Date.now();
      tickUptime();
      if (!uptimeTimer) uptimeTimer = setInterval(tickUptime, 1000);
    } else if (s === "connecting") {
      body.classList.add("is-connecting");
      powerBtn.setAttribute("aria-pressed", "false");
      stateLbl.textContent = "ПОДКЛЮЧЕНИЕ";
      statusSub.textContent = "запуск winws2…";
    } else {
      powerBtn.setAttribute("aria-pressed", "false");
      stateLbl.textContent = "ОТКЛЮЧЕНО";
      statusSub.textContent = "Нажмите чтобы включить обход";
      startedAt = null;
      if (uptimeTimer) { clearInterval(uptimeTimer); uptimeTimer = null; }
    }
  };

  // ─── pywebview bridge ──────────────────────────────────────

  const apiReady = () =>
    new Promise((resolve) => {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.initial_state) return resolve();
      window.addEventListener("pywebviewready", () => resolve(), { once: true });
      // Fallback poll for environments where event doesn't fire.
      const t = setInterval(() => {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.initial_state) {
          clearInterval(t); resolve();
        }
      }, 60);
    });

  const call = async (name, ...args) => {
    try {
      const fn = window.pywebview.api[name];
      return await fn(...args);
    } catch (err) {
      return { ok: false, err: String(err) };
    }
  };

  // ─── handlers ──────────────────────────────────────────────

  powerBtn.addEventListener("click", async () => {
    if (busy) return;
    showError("");
    const isOn = body.classList.contains("is-on");
    setBusy(true);
    if (isOn) {
      setState("off");
      await call("stop");
    } else {
      setState("connecting");
      const res = await call("start");
      if (res && res.ok) {
        startedAt = Date.now();
        setState("on");
      } else {
        setState("off");
        showError((res && res.err) || "Не удалось запустить");
      }
    }
    setBusy(false);
  });

  // ── Telegram tunnel state ─────────────────────────────────
  // The backend drives this via window.onTgState(state, msg) where state ∈
  // {starting, running, error, stopped}. We just reflect it visually.
  const setTgState = (state, msg) => {
    tgRow.classList.remove("is-running", "is-connecting", "is-error");
    switch (state) {
      case "starting":
        tgRow.classList.add("is-connecting");
        tgSub.textContent = "запуск туннеля…";
        break;
      case "running":
        tgRow.classList.add("is-running");
        tgSub.textContent = "туннель активен";
        break;
      case "error":
        tgRow.classList.add("is-error");
        tgSub.textContent = msg || "ошибка туннеля";
        tgToggle.checked = false;  // reflect backend giving up
        break;
      case "stopped":
      default:
        tgSub.textContent = "Прозрачный прокси через VPS";
        break;
    }
  };

  window.onTgState = (state, msg) => setTgState(state, msg);

  tgToggle.addEventListener("change", async () => {
    const want = tgToggle.checked;
    setTgState(want ? "starting" : "stopped");
    const res = await call("set_tg_enabled", want);
    if (res && !res.ok) {
      tgToggle.checked = false;
      setTgState("error", res.err || "не удалось запустить");
    }
  });

  rknToggle.addEventListener("change", async () => {
    await call("set_rkn_silent", rknToggle.checked);
  });

  wcMin.addEventListener("click", () => call("minimize"));
  wcClose.addEventListener("click", () => call("close"));

  // Crash notifications come from Python (window.evaluate_js).
  window.onWinwsCrash = (msg) => {
    setState("off");
    showError(msg ? `winws2: ${msg}` : "winws2 неожиданно остановлен");
  };

  // ─── init ──────────────────────────────────────────────────

  (async () => {
    await apiReady();
    const st = await call("initial_state");
    if (st && st.version) verLabel.textContent = st.version;
    if (st && !st.tg_available) {
      tgRow.classList.add("is-disabled");
      tgSub.textContent = "tg-transparent.exe отсутствует";
      tgToggle.disabled = true;
    } else if (st) {
      tgToggle.checked = !!st.tg_enabled;
      if (st.tg_running) {
        setTgState("running");
      } else if (st.tg_enabled) {
        setTgState("starting");  // backend is autostarting
      } else {
        setTgState("stopped");
      }
    }
    if (st && st.rkn_silent) rknToggle.checked = true;
    if (st && st.running) {
      startedAt = Date.now();
      setState("on");
    } else {
      setState("off");
    }
    // Release CSS transition suppression.
    requestAnimationFrame(() => body.classList.remove("boot"));
  })();
})();
