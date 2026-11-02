"use strict";
// Night Tech Private AI: the chat page. Everything is built with DOM calls (never innerHTML), so nothing the AI
// writes can run as code in the browser.

const $ = (id) => document.getElementById(id);
const state = { me: null, chatId: null, controller: null, busy: false };

// ---------------- Talking to the server ----------------

async function api(path, options = {}) {
  const opts = { credentials: "same-origin", ...options, headers: { "X-NTAI": "1", ...(options.headers || {}) } };
  if (opts.json !== undefined) {
    opts.body = JSON.stringify(opts.json);
    opts.headers["Content-Type"] = "application/json";
    delete opts.json;
  }
  const res = await fetch(path, opts);
  if (res.status === 401 && path !== "/api/login" && path !== "/api/me/password") { await boot(); throw new Error("Please sign in again."); }
  let data = null;
  const type = res.headers.get("content-type") || "";
  if (type.includes("application/json")) data = await res.json();
  if (!res.ok) throw new Error((data && data.error) || `Something went wrong (${res.status}).`);
  return data;
}

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== false && v !== null && v !== undefined) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) if (c !== null && c !== undefined) n.append(c);
  return n;
}

function formData(form) {
  const o = {};
  for (const e of form.elements) {
    if (!e.name) continue;
    o[e.name] = e.type === "checkbox" ? e.checked : e.value;
  }
  return o;
}

function showError(form, message) {
  const p = form.querySelector(".form-error");
  if (p) p.textContent = message || "";
}

// ---------------- Start: signed in or not ----------------

async function boot() {
  let me;
  try { me = await (await fetch("/api/me", { credentials: "same-origin" })).json(); }
  catch { document.body.textContent = "Can't reach Private AI. Check that this computer is on the same network as the AI computer."; return; }
  state.me = me;
  document.title = `${me.company} · Private AI`;
  if (!me.signedIn) {
    $("app").hidden = true;
    $("gate").hidden = false;
    $("gate-company").textContent = me.company;
    $("login-form").hidden = me.needsSetup;
    $("setup-form").hidden = !(me.needsSetup && me.setupAllowed);
    $("setup-remote").hidden = !(me.needsSetup && !me.setupAllowed);
    $("port-hint").textContent = location.port || "80";
    const first = document.querySelector("#gate form:not([hidden]) input");
    if (first) first.focus();
    return;
  }
  $("gate").hidden = true;
  $("app").hidden = false;
  $("company").textContent = me.company;
  $("model-pill").textContent = me.model;
  $("version").textContent = "v" + me.version;
  $("open-settings").hidden = !me.isAdmin;
  $("upload-form").hidden = !me.isAdmin;
  updateDocs(me.documents);
  await loadChatList();
  newChat();
}

function updateDocs(count) {
  $("doc-count").textContent = count;
  $("docs-toggle").hidden = count === 0;
  const ex = document.querySelector(".docs-example");
  if (ex) ex.hidden = count === 0;
  if (count === 0) $("use-docs").checked = false;
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  showError(f, "");
  const btn = f.querySelector("button");
  btn.disabled = true;
  try { await api("/api/login", { method: "POST", json: formData(f) }); f.reset(); await boot(); }
  catch (err) { showError(f, err.message); }
  finally { btn.disabled = false; }
});

$("setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  showError(f, "");
  try { await api("/api/setup", { method: "POST", json: formData(f) }); await boot(); }
  catch (err) { showError(f, err.message); }
});

// ---------------- Chat list ----------------

function dayLabel(iso) {
  const d = new Date(iso), now = new Date();
  const days = Math.floor((new Date(now.toDateString()) - new Date(d.toDateString())) / 86400000);
  if (days <= 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return "This week";
  return d.toLocaleDateString(undefined, { month: "long", year: "numeric" });
}

async function loadChatList() {
  const list = await api("/api/chats");
  const nav = $("chat-list");
  nav.replaceChildren();
  let last = "";
  for (const c of list) {
    const label = dayLabel(c.updated);
    if (label !== last) { nav.append(el("p", { class: "chat-day", text: label })); last = label; }
    const item = el("div", { class: "chat-item" + (c.id === state.chatId ? " active" : "") },
      el("a", { href: "#", text: c.title, title: c.title, onclick: (e) => { e.preventDefault(); openChat(c.id); closeSide(); } }),
      el("button", { type: "button", "aria-label": `Delete chat: ${c.title}`, title: "Delete", text: "Delete",
        onclick: async () => {
          if (!confirm(`Delete "${c.title}"? This can't be undone.`)) return;
          await api(`/api/chats/${c.id}`, { method: "DELETE" });
          if (state.chatId === c.id) newChat();
          loadChatList();
        } }));
    nav.append(item);
  }
}

function newChat() {
  if (state.busy) return;
  state.chatId = null;
  $("chat-title").textContent = "New chat";
  const box = $("messages");
  box.replaceChildren($("empty") || buildEmpty());
  $("empty").hidden = false;
  const ex = document.querySelector(".docs-example");
  if (ex) ex.hidden = $("docs-toggle").hidden;
  $("question").value = "";
  autoGrow();
  $("question").focus();
  document.querySelectorAll(".chat-item.active").forEach((x) => x.classList.remove("active"));
}

let emptyTemplate = null;
function buildEmpty() { return emptyTemplate.cloneNode(true); }

async function openChat(id) {
  if (state.busy) return;
  const c = await api(`/api/chats/${id}`);
  state.chatId = c.id;
  $("chat-title").textContent = c.title;
  $("use-docs").checked = !!c.useDocuments && !$("docs-toggle").hidden;
  const box = $("messages");
  box.replaceChildren();
  for (const m of c.messages) {
    if (m.role === "user") box.append(el("div", { class: "msg you", text: m.content }));
    else {
      const b = el("div", { class: "msg bot" });
      renderMarkdown(b, m.content);
      addSources(b, m.sources);
      box.append(b);
    }
  }
  box.scrollTop = box.scrollHeight;
  loadChatList();
}

// ---------------- Asking ----------------

function autoGrow() {
  const t = $("question");
  t.style.height = "auto";
  t.style.height = Math.min(220, t.scrollHeight + 2) + "px";
}

$("question").addEventListener("input", autoGrow);
$("question").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); $("composer").requestSubmit(); }
});

$("composer").addEventListener("submit", (e) => { e.preventDefault(); ask(); });
$("new-chat").addEventListener("click", () => { newChat(); closeSide(); });
$("stop").addEventListener("click", () => { if (state.controller) state.controller.abort(); });

function setBusy(b) {
  state.busy = b;
  $("send").hidden = b;
  $("stop").hidden = !b;
  $("new-chat").disabled = b;
}

async function ask(text) {
  const q = (text ?? $("question").value).trim();
  if (!q || state.busy) return;
  const box = $("messages");
  if ($("empty")) $("empty").remove();
  box.append(el("div", { class: "msg you", text: q }));
  const bot = el("div", { class: "msg bot" }, el("span", { class: "thinking", "aria-label": "Thinking" }, el("i"), el("i"), el("i")));
  box.append(bot);
  box.scrollTop = box.scrollHeight;
  $("question").value = "";
  autoGrow();
  setBusy(true);
  state.controller = new AbortController();
  let answer = "", sources = [], gotText = false;
  try {
    const res = await fetch("/api/chat", {
      method: "POST", credentials: "same-origin", signal: state.controller.signal,
      headers: { "Content-Type": "application/json", "X-NTAI": "1" },
      body: JSON.stringify({ chatId: state.chatId, message: q, useDocs: $("use-docs").checked }),
    });
    if (!res.ok) {
      let msg = `Something went wrong (${res.status}).`;
      try { msg = (await res.json()).error || msg; } catch { }
      if (res.status === 401) { await boot(); return; }
      throw new Error(msg);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.type === "meta") { state.chatId = ev.chatId; sources = ev.sources || []; }
        else if (ev.type === "text") {
          answer += ev.text;
          gotText = true;
          renderMarkdown(bot, answer);
          if (box.scrollHeight - box.scrollTop - box.clientHeight < 160) box.scrollTop = box.scrollHeight;
        }
        else if (ev.type === "notice") box.insertBefore(el("div", { class: "msg notice", text: ev.message }), bot);
        else if (ev.type === "error") throw new Error(ev.message);
        else if (ev.type === "done") $("chat-title").textContent = ev.title;
      }
    }
    if (!gotText) renderMarkdown(bot, "_(No answer came back. Try asking again.)_");
    addSources(bot, sources);
  } catch (err) {
    if (err.name === "AbortError") {
      if (gotText) { renderMarkdown(bot, answer + "\n\n_(Stopped.)_"); addSources(bot, sources); }
      else bot.remove();
    } else {
      if (!gotText) bot.remove();
      box.append(el("div", { class: "msg error", text: err.message }));
    }
  } finally {
    setBusy(false);
    state.controller = null;
    box.scrollTop = box.scrollHeight;
    loadChatList().catch(() => { });
    $("question").focus();
  }
}

function addSources(bot, sources) {
  if (!sources || sources.length === 0) return;
  const wrap = el("div", { class: "sources" });
  sources.forEach((s, i) => wrap.append(el("span", { class: "source", text: `[${i + 1}] ${s.fileName}${s.page ? ", page " + s.page : ""}` })));
  bot.append(wrap);
}

// ---------------- A small, safe Markdown renderer ----------------

function inline(parent, text) {
  // **bold**, *italic*, `code`, _italic_ and [1] citations. Everything else stays plain text.
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[\d{1,2}\]|(?<![\w*])\*[^*\s][^*]*\*(?!\w)|(?<!\w)_[^_\s][^_]*_(?!\w))/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) parent.append(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith("**")) parent.append(el("strong", { text: t.slice(2, -2) }));
    else if (t.startsWith("`")) parent.append(el("code", { text: t.slice(1, -1) }));
    else if (t.startsWith("[")) parent.append(el("span", { class: "cite", text: t }));
    else parent.append(el("em", { text: t.slice(1, -1) }));
    last = m.index + t.length;
  }
  if (last < text.length) parent.append(text.slice(last));
}

function renderMarkdown(target, md) {
  const out = document.createDocumentFragment();
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  let para = [], list = null, listType = "";
  const flushPara = () => { if (para.length) { const p = el("p"); para.forEach((l, i) => { if (i) p.append(el("br")); inline(p, l); }); out.append(p); para = []; } };
  const flushList = () => { if (list) { out.append(list); list = null; listType = ""; } };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("```")) {
      flushPara(); flushList();
      const code = [];
      for (i++; i < lines.length && !lines[i].startsWith("```"); i++) code.push(lines[i]);
      out.append(el("pre", {}, el("code", { text: code.join("\n") })));
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    const ul = /^\s*[-*•]\s+(.*)$/.exec(line);
    const ol = /^\s*(\d+)[.)]\s+(.*)$/.exec(line);
    if (h) { flushPara(); flushList(); const n = el(h[1].length <= 2 ? "h3" : "h4"); inline(n, h[2]); out.append(n); }
    else if (ul || ol) {
      flushPara();
      const type = ul ? "ul" : "ol";
      if (listType !== type) { flushList(); list = el(type); listType = type; if (ol && ol[1] !== "1") list.setAttribute("start", ol[1]); }
      const li = el("li"); inline(li, ul ? ul[1] : ol[2]); list.append(li);
    }
    else if (line.trim() === "") { flushPara(); flushList(); }
    else { flushList(); para.push(line); }
  }
  flushPara(); flushList();
  target.replaceChildren(out);
}

// ---------------- Panels ----------------

document.querySelectorAll("dialog [data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

function closeSide() { $("side").classList.remove("open"); }
$("open-side").addEventListener("click", () => $("side").classList.add("open"));
$("close-side").addEventListener("click", closeSide);

$("open-docs").addEventListener("click", async () => { closeSide(); await loadDocs(); $("docs-dialog").showModal(); });

async function loadDocs() {
  const docs = await api("/api/docs");
  updateDocs(docs.length);
  const rows = $("doc-rows");
  rows.replaceChildren();
  if (docs.length === 0) rows.append(el("tr", {}, el("td", { colspan: "4", text: "No documents yet." + (state.me.isAdmin ? " Add your handbook, price list or policies to get started." : "") })));
  for (const d of docs) {
    rows.append(el("tr", {},
      el("td", { text: d.fileName }),
      el("td", { text: String(d.passages) }),
      el("td", { text: new Date(d.added).toLocaleDateString() }),
      el("td", { class: "actions" }, state.me.isAdmin ? el("button", { class: "btn small", type: "button", text: "Remove",
        onclick: async () => {
          if (!confirm(`Remove "${d.fileName}" from the library?`)) return;
          await api(`/api/admin/docs/${d.id}`, { method: "DELETE" });
          loadDocs();
        } }) : null)));
  }
}

$("upload-input").addEventListener("change", async (e) => {
  const files = [...e.target.files];
  e.target.value = "";
  if (files.length === 0) return;
  const status = $("upload-status");
  status.replaceChildren(el("p", { text: `Reading ${files.length} document(s). Large documents can take a few minutes...` }));
  const fd = new FormData();
  files.forEach((f) => fd.append("files", f, f.name));
  try {
    const res = await api("/api/admin/docs", { method: "POST", body: fd });
    status.replaceChildren(...res.results.map((r) => el("p", { class: r.ok ? "ok" : "bad", text: `${r.fileName}: ${r.message}` })));
  } catch (err) {
    status.replaceChildren(el("p", { class: "bad", text: err.message }));
  }
  loadDocs();
});

// Settings (administrators)
$("open-settings").addEventListener("click", async () => { closeSide(); await loadSettings(); $("settings-dialog").showModal(); });

async function loadSettings() {
  const s = await api("/api/admin/settings");
  const f = $("settings-form");
  f.companyName.value = s.companyName;
  f.extraInstructions.value = s.extraInstructions || "";
  f.contextTokens.value = String(s.contextTokens);
  if (![...f.contextTokens.options].some((o) => o.value === String(s.contextTokens)))
    f.contextTokens.append(el("option", { value: String(s.contextTokens), text: `${s.contextTokens} (custom)` })), f.contextTokens.value = String(s.contextTokens);
  const sel = $("model-select");
  sel.replaceChildren();
  const names = s.models.map((m) => m.name.replace(/:latest$/, ""));
  if (!names.includes(s.chatModel)) sel.append(el("option", { value: s.chatModel, text: `${s.chatModel} (not installed)` }));
  for (const m of s.models) {
    const name = m.name.replace(/:latest$/, "");
    sel.append(el("option", { value: name, text: `${m.known || name} · ${m.sizeGb} GB` }));
  }
  sel.value = s.chatModel;
  const st = $("engine-status");
  if (!s.engine) { st.className = "status-row bad"; st.textContent = "The AI engine isn't running. It normally restarts on its own within a minute. If it doesn't, restart this computer."; }
  else {
    st.className = "status-row " + (s.chatModelInstalled ? "ok" : "bad");
    st.textContent = `AI engine running (version ${s.engine.version}). ` +
      (s.chatModelInstalled ? `Model ${s.chatModel} is ready.` : `Model ${s.chatModel} isn't installed; pick an installed one below.`) +
      (s.searchModelInstalled ? "" : " The document search model isn't installed, so documents can't be added.") +
      ` Library: ${s.documents} document(s), ${s.passages} passages.`;
  }
  $("data-folder").textContent = `Private AI ${s.version} · port ${s.port} · data kept in ${s.dataFolder}`;
  await loadUsers();
}

$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  showError(f, "");
  const d = formData(f);
  d.contextTokens = parseInt(d.contextTokens, 10);
  try {
    await api("/api/admin/settings", { method: "POST", json: d });
    state.me.company = d.companyName;
    $("company").textContent = d.companyName;
    $("model-pill").textContent = d.chatModel;
    showError(f, "");
    f.querySelector("button[type=submit]").textContent = "Saved";
    setTimeout(() => (f.querySelector("button[type=submit]").textContent = "Save settings"), 1500);
  } catch (err) { showError(f, err.message); }
});

async function loadUsers() {
  const users = await api("/api/admin/users");
  const rows = $("user-rows");
  rows.replaceChildren();
  for (const u of users) {
    const me = u.name.toLowerCase() === state.me.name.toLowerCase();
    rows.append(el("tr", {},
      el("td", { text: u.name }),
      el("td", { text: u.displayName }),
      el("td", {}, el("input", { type: "checkbox", checked: u.isAdmin, "aria-label": `${u.name} is an administrator`, disabled: me,
        onchange: async (e) => {
          try { await api(`/api/admin/users/${encodeURIComponent(u.name)}/admin`, { method: "POST", json: { isAdmin: e.target.checked } }); }
          catch (err) { alert(err.message); e.target.checked = !e.target.checked; }
        } })),
      el("td", { class: "actions" },
        el("button", { class: "btn small", type: "button", text: "Reset password",
          onclick: async () => {
            const pw = prompt(`New password for ${u.name} (8 or more characters). Give it to them in person or by phone.`);
            if (!pw) return;
            try { await api(`/api/admin/users/${encodeURIComponent(u.name)}/password`, { method: "POST", json: { password: pw } }); alert("Password changed."); }
            catch (err) { alert(err.message); }
          } }),
        " ",
        me ? null : el("button", { class: "btn small", type: "button", text: "Remove",
          onclick: async () => {
            if (!confirm(`Remove ${u.name}? Their chats are deleted too.`)) return;
            try { await api(`/api/admin/users/${encodeURIComponent(u.name)}`, { method: "DELETE" }); loadUsers(); }
            catch (err) { alert(err.message); }
          } }))));
  }
}

$("add-user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  showError(f, "");
  try { await api("/api/admin/users", { method: "POST", json: formData(f) }); f.reset(); loadUsers(); }
  catch (err) { showError(f, err.message); }
});

// My account
$("open-account").addEventListener("click", () => {
  closeSide();
  $("account-who").textContent = `Signed in as ${state.me.displayName} (${state.me.name})${state.me.isAdmin ? ", administrator" : ""}.`;
  $("account-dialog").showModal();
});

$("password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  showError(f, "");
  try { await api("/api/me/password", { method: "POST", json: formData(f) }); f.reset(); showError(f, ""); alert("Password changed."); }
  catch (err) { showError(f, err.message); }
});

$("sign-out").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  $("account-dialog").close();
  boot();
});

// Example prompts fill the box (and send the docs one with documents on).
document.addEventListener("click", (e) => {
  const b = e.target.closest(".example");
  if (!b) return;
  if (b.classList.contains("docs-example")) $("use-docs").checked = true;
  if (b.textContent.includes("(paste it here)")) { $("question").value = b.textContent.replace("(paste it here)", "\n\n"); $("question").focus(); autoGrow(); return; }
  ask(b.textContent);
});

emptyTemplate = $("empty").cloneNode(true);
boot();
