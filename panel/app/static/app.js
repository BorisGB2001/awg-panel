// Сортировка и фильтр таблицы клиентов, автообновление главной (CSP: только свои скрипты).
(function () {
  const table = document.getElementById("clients");
  if (table) {
    const body = table.tBodies[0];
    const val = (td) => td.dataset.v !== undefined ? Number(td.dataset.v) : td.textContent.trim().toLowerCase();
    table.querySelectorAll("th").forEach((th, i) => {
      th.classList.add("sort");
      th.addEventListener("click", () => {
        const dir = th.dataset.dir === "asc" ? "desc" : "asc";
        table.querySelectorAll("th").forEach((x) => delete x.dataset.dir);
        th.dataset.dir = dir;
        const rows = Array.from(body.rows);
        rows.sort((a, b) => {
          const x = val(a.cells[i]), y = val(b.cells[i]);
          const r = typeof x === "number" ? x - y : String(x).localeCompare(String(y), "ru");
          return dir === "asc" ? r : -r;
        });
        rows.forEach((r) => body.appendChild(r));
      });
    });
    const q = document.getElementById("filter"), st = document.getElementById("status-filter");
    const apply = () => {
      const text = (q.value || "").toLowerCase(), s = st.value;
      Array.from(body.rows).forEach((r) => {
        r.hidden = !(r.textContent.toLowerCase().includes(text) && (!s || r.dataset.status === s));
      });
    };
    q.addEventListener("input", apply);
    st.addEventListener("change", apply);
    // автообновление раз в минуту, если пользователь ничего не делает на странице
    let busy = 0;
    ["input", "change", "click", "keydown"].forEach((e) => document.addEventListener(e, () => { busy = Date.now(); }));
    setInterval(() => {
      if (!document.hidden && Date.now() - busy > 60000 && !document.querySelector("details[open]")) location.reload();
    }, 60000);
  }
})();

// Списки-фильтры (группа и т. п.) применяются сразу при выборе — без встроенных обработчиков из-за CSP.
document.querySelectorAll("select[data-autosubmit]").forEach((s) => s.addEventListener("change", () => s.form.submit()));

// Топ по трафику: при наведении на клиента — карточка крупно (скачано/отдано и его график за период).
(function () {
  const rows = document.querySelectorAll(".tbars [data-tip]");
  if (!rows.length) return;
  const NS = "http://www.w3.org/2000/svg";
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  document.body.appendChild(tip);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  const svgEl = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };

  function chart(series) {
    const W = 300, H = 110, B = 16, n = series.length, bw = W / n;
    const top = Math.max(1, ...series.map((s) => s[1] + s[2]));
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "tip-chart" });
    series.forEach((s, i) => {
      const hd = (H - B) * s[1] / top, hu = (H - B) * s[2] / top, x = i * bw + 0.5, w = Math.max(bw - 1, 0.5);
      svg.appendChild(svgEl("rect", { class: "s1", x, y: H - B - hd, width: w, height: hd }));
      svg.appendChild(svgEl("rect", { class: "s2", x, y: H - B - hd - hu, width: w, height: hu }));
      if (i === 0 || i === n - 1 || i % Math.ceil(n / 6) === 0) {
        const t = svgEl("text", { class: "axis", x: x + w / 2, y: H - 3, "text-anchor": "middle" });
        t.textContent = s[0];
        svg.appendChild(t);
      }
    });
    return svg;
  }

  function show(a, ev) {
    const d = JSON.parse(a.getAttribute("data-tip"));
    const l = JSON.parse(a.closest("svg").getAttribute("data-labels") || "{}");
    tip.replaceChildren();
    tip.appendChild(el("div", "tip-name", d.name));
    const max = Math.max(1, d.d, d.u);
    for (const [cls, label, val, raw] of [["s1", l.down, d.down, d.d], ["s2", l.up, d.up, d.u]]) {
      const row = el("div", "tip-row");
      row.appendChild(el("span", "tip-label", label));
      const bar = el("span", "tip-bar");
      const fill = el("span", "tip-fill " + cls);
      fill.style.width = Math.max(1, 100 * raw / max) + "%";
      bar.appendChild(fill);
      row.appendChild(bar);
      row.appendChild(el("b", "", val));
      tip.appendChild(row);
    }
    tip.appendChild(el("div", "tip-total", `${l.total}: ${d.total}`));
    if (d.series && d.series.length > 1) {
      tip.appendChild(el("div", "tip-period", l.period));
      tip.appendChild(chart(d.series));
    }
    tip.hidden = false;
    move(ev);
  }

  function move(ev) {
    const pad = 16, r = tip.getBoundingClientRect();
    let x = ev.clientX + pad, y = ev.clientY + pad;
    if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - pad;
    if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - pad;
    tip.style.left = Math.max(8, x) + "px";
    tip.style.top = Math.max(8, y) + "px";
  }

  rows.forEach((a) => {
    a.addEventListener("mouseenter", (ev) => show(a, ev));
    a.addEventListener("mousemove", move);
    a.addEventListener("mouseleave", () => { tip.hidden = true; });
  });
})();

// Страница «Сервер», путь клиентов в интернет: сведения об адресе по кнопке, автообновление, пока идёт замер.
(function () {
  const box = document.getElementById("egress");
  if (!box) return;
  if (box.dataset.running) setTimeout(() => location.reload(), 5000);
  const L = JSON.parse(box.dataset.labels);
  const line = (name, text) => { const d = document.createElement("div"); const b = document.createElement("b"); b.textContent = name + ": "; d.append(b, text); return d; };
  const fields = (o) => Object.entries(o || {}).filter(([k, v]) => k !== "ip" && v !== null && v !== "").map(([k, v]) => `${k}: ${v}`).join(" · ");
  box.addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".ipcheck");
    if (!btn) return;
    const out = btn.nextElementSibling;
    if (!out.hidden) { out.hidden = true; return; }
    out.hidden = false;
    out.textContent = L.loading;
    try {
      const r = await fetch(`/server/ip/${encodeURIComponent(btn.dataset.ip)}`, { headers: { Accept: "application/json" } });
      const d = await r.json();
      out.textContent = "";
      if (d.private) { out.textContent = L.private; return; }
      out.append(line("DB-IP", fields(d.dbip) || "—"));
      out.append(line("ipinfo.io", d.ipinfo && d.ipinfo.error === "no key" ? L.nokey : (d.ipinfo && d.ipinfo.error) || fields(d.ipinfo) || "—"));
      out.append(line("Yandex", d.yandex ? fields(d.yandex) : L.yandex_na));
    } catch (e) {
      out.textContent = String(e);
    }
  });
})();

// Индикатор загрузки: полоса сверху при переходе по ссылке или отправке формы — страница могла «замереть» на
// десятки секунд (сборка бэкапа, замер) без признаков жизни. Кнопка с data-busy ещё и меняет надпись.
(function () {
  const bar = document.createElement("div");
  bar.className = "loadbar";
  bar.hidden = true;
  document.body.appendChild(bar);
  const show = () => { bar.hidden = false; };
  document.addEventListener("submit", (ev) => {
    if (ev.defaultPrevented) return;
    const btn = ev.submitter;
    show();
    if (btn && btn.dataset.busy) {
      const text = btn.textContent;
      btn.textContent = btn.dataset.busy;
      btn.classList.add("busy");
      // скачивание файла не уводит со страницы — вернуть кнопку, когда браузер начнёт загрузку
      if (btn.hasAttribute("data-busy-download")) {
        setTimeout(() => { btn.textContent = text; btn.classList.remove("busy"); bar.hidden = true; }, 60000);
        window.addEventListener("focus", () => { btn.textContent = text; btn.classList.remove("busy"); bar.hidden = true; }, { once: true });
      }
    }
  });
  document.addEventListener("click", (ev) => {
    const a = ev.target.closest && ev.target.closest("a[href]");
    if (!a || ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button !== 0 || a.target || a.hasAttribute("download")) return;
    const href = a.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("javascript:") || a.origin !== location.origin) return;
    show();
  });
  window.addEventListener("pageshow", () => { bar.hidden = true; });   // назад из кэша
  // страница с идущей в фоне работой обновляется сама
  const r = document.querySelector("[data-reload]");
  if (r) setTimeout(() => location.reload(), Number(r.dataset.reload) * 1000);
})();

// Уведомления: плашки в правом верхнем углу. Держатся несколько секунд (ошибки — дольше, при наведении — пока
// мышь над ними) и плавно исчезают; ✕ закрывает одну, «Закрыть все» — все, когда их больше одной.
(function () {
  const box = document.getElementById("toasts");
  if (!box) return;
  const all = document.createElement("button");
  all.type = "button";
  all.className = "toast-all";
  all.textContent = box.dataset.closeAll || "Close all";
  all.hidden = true;
  all.addEventListener("click", () => box.querySelectorAll(".toast").forEach((t) => hide(t)));
  box.appendChild(all);
  const refresh = () => { all.hidden = box.querySelectorAll(".toast:not(.leaving)").length < 2; };

  function hide(t) {
    if (t.classList.contains("leaving")) return;
    t.classList.add("leaving");
    refresh();
    setTimeout(() => { t.remove(); refresh(); }, 400);
  }

  function arm(t) {
    const x = document.createElement("button");
    x.type = "button";
    x.className = "toast-x";
    x.setAttribute("aria-label", box.dataset.close || "Close");
    x.textContent = "✕";
    x.addEventListener("click", () => hide(t));
    t.appendChild(x);
    let left = t.classList.contains("toast-error") ? 10000 : 5000, started = Date.now(), timer;
    const go = () => { started = Date.now(); timer = setTimeout(() => hide(t), left); };
    t.addEventListener("mouseenter", () => { clearTimeout(timer); left = Math.max(1500, left - (Date.now() - started)); });
    t.addEventListener("mouseleave", go);
    go();
  }

  box.querySelectorAll(".toast").forEach(arm);
  refresh();
  // для скриптов страницы: window.toast("Сохранено") / window.toast("Ошибка", "error")
  window.toast = (text, kind) => {
    const t = document.createElement("div");
    t.className = "toast toast-" + (kind || "ok");
    t.setAttribute("role", kind === "error" ? "alert" : "status");
    t.textContent = text;
    box.insertBefore(t, all);
    arm(t);
    refresh();
  };
})();
