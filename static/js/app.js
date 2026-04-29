// ASCII Cipher Vault — main controller.
// Wires up every view and owns the in-memory state. The vault key never
// touches localStorage or the network; it lives only in `state.vaultKey`
// for the lifetime of the page.

import {
  encryptText, decryptToken,
  deriveAuthAndVault, deriveGroupAuth,
  sealJson, openJson, sealString, openString,
  sealBytes, openBytes,
  generatePassphrase, passwordStrength,
  bytesToHex,
} from "./crypto.js";
import { api } from "./api.js";

// ─── DOM helpers ───────────────────────────────────────────────
const $  = (id)  => document.getElementById(id);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const toastEl = $("toasts");
function toast(body, kind = "info", title = null, ttl = 2400) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `${title ? `<div class="t-title"></div>` : ""}<div class="t-body"></div>`;
  if (title) el.querySelector(".t-title").textContent = title;
  el.querySelector(".t-body").textContent = body;
  toastEl.appendChild(el);
  setTimeout(() => {
    el.classList.add("fade-out");
    el.addEventListener("animationend", () => el.remove(), { once: true });
  }, ttl);
}

const busyEl = $("busy");
const busyText = $("busy-text");
function busy(msg = "Working…") { busyText.textContent = msg; busyEl.classList.remove("hidden"); }
function unbusy() { busyEl.classList.add("hidden"); }

function confirmDialog({ title, body, okText = "Confirm", danger = true }) {
  return new Promise((resolve) => {
    const m = $("confirm-modal");
    $("cm-title").textContent = title;
    $("cm-body").textContent = body;
    const ok = $("cm-ok"), cancel = $("cm-cancel");
    ok.textContent = okText;
    ok.className = "btn " + (danger ? "danger" : "primary");
    const close = (v) => {
      m.classList.add("hidden");
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      resolve(v);
    };
    const onOk = () => close(true);
    const onCancel = () => close(false);
    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    m.classList.remove("hidden");
  });
}

function fmtTime(unix) {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  const now = Date.now();
  const diff = (now - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  if (diff < 86400 * 14) return `${Math.floor(diff / 86400)} d ago`;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ─── State ─────────────────────────────────────────────────────
const state = {
  user: null,           // { id, email, authSalt, iterations }
  vaultKey: null,       // Uint8Array(32) — never persisted
  vaultItems: [],       // decrypted: [{id, label, key, notes, tags, pinned, createdAt, updatedAt}]
  history: [],          // decrypted: [{id, op, preview, createdAt}]
  threads: [],          // [{peerId, peerEmail, unread, lastAt}]
  groups: [],           // [{id, name, salt, wrappedKey, key (hex), unread, lastAt}]
  messages: [],         // raw messages for active thread
  activeThread: null,   // {kind:'dm', peerId, peerEmail} | {kind:'group', groupId, name, key}
  threadKeyCache: {},   // peerId → vault item used last to decrypt (DM only)
  route: "cipher",
  cipherMode: "encrypt",
  showKey: false,
};

function setView(name) {
  for (const v of ["auth", "unlock", "app"]) {
    $(`view-${v}`).classList.toggle("hidden", v !== name);
  }
}
function setRoute(r) {
  state.route = r;
  for (const t of $$("#main-tabs .tab")) t.classList.toggle("active", t.dataset.route === r);
  for (const p of ["cipher", "vault", "messages", "history", "settings"]) {
    $(`tab-${p}`).classList.toggle("hidden", p !== r);
    $(`tab-${p}`).classList.toggle("active", p === r);
  }
  if (r === "vault")    renderVault();
  if (r === "history")  loadHistory();
  if (r === "settings") loadSettings();
  if (r === "messages") loadThreads();
  location.hash = r;
}

// ─── Auth view ─────────────────────────────────────────────────
const authForm = $("auth-form");
let authMode = "login";

function setAuthMode(m) {
  authMode = m;
  for (const t of $$("[data-auth-tab]")) t.classList.toggle("active", t.dataset.authTab === m);
  $("auth-confirm-field").classList.toggle("hidden", m !== "register");
  $("auth-token-field").classList.toggle("hidden", m !== "register");
  $("auth-warning").classList.toggle("hidden", m !== "register");
  $("auth-strength").classList.toggle("hidden", m !== "register");
  $("auth-submit").textContent = m === "register" ? "Create account" : "Sign in";
  $("auth-password").autocomplete = m === "register" ? "new-password" : "current-password";
  $("auth-error").classList.add("hidden");
}

for (const t of $$("[data-auth-tab]")) {
  t.addEventListener("click", () => setAuthMode(t.dataset.authTab));
}

$("auth-toggle").addEventListener("click", () => {
  const i = $("auth-password");
  i.type = i.type === "password" ? "text" : "password";
});

$("auth-password").addEventListener("input", () => {
  if (authMode !== "register") return;
  const s = passwordStrength($("auth-password").value);
  $("auth-strength-fill").style.width = s.pct + "%";
  $("auth-strength-fill").className = "strength-fill " + s.klass;
  $("auth-strength-text").textContent = s.bits ? `${s.label} · ${s.bits.toFixed(0)} bits` : "—";
});

function authError(msg) {
  const el = $("auth-error");
  el.textContent = msg;
  el.classList.remove("hidden");
}

authForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  $("auth-error").classList.add("hidden");
  const email = $("auth-email").value.trim().toLowerCase();
  const password = $("auth-password").value;
  if (!email || !password) return authError("Email and password required");

  if (authMode === "register") {
    if (password.length < 8) return authError("Password must be at least 8 characters");
    if (password !== $("auth-confirm").value) return authError("Passwords don't match");
    const s = passwordStrength(password);
    if (s.bits < 40) return authError("Password is too weak — aim for 40+ bits of entropy");
  }

  try {
    busy(authMode === "register" ? "Creating account…" : "Signing in…");
    if (authMode === "register") {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const saltHex = bytesToHex(saltBytes);
      const { authHash, vaultKey } = await deriveAuthAndVault(password, saltHex);
      const tokenInput = $("auth-token").value.trim();
      await api.post("/api/auth/register", {
        email,
        authSalt: saltHex,
        authHash,
        registrationToken: tokenInput || undefined,
      });
      state.vaultKey = vaultKey;
    } else {
      const pre = await api.post("/api/auth/preflight", { email });
      const { authHash, vaultKey } = await deriveAuthAndVault(password, pre.authSalt, pre.iterations);
      await api.post("/api/auth/login", { email, authHash });
      state.vaultKey = vaultKey;
    }
    await loadUser();
    await loadVault();
    setView("app");
    setRoute(window.location.hash.slice(1) || "cipher");
    refreshKeySource();
    updateUnreadBadge();
    startMessagePolling();
    toast("Welcome", "info", "✓");
  } catch (err) {
    authError(err.message || String(err));
  } finally { unbusy(); }
});

// ─── Unlock view ───────────────────────────────────────────────
$("unlock-toggle").addEventListener("click", () => {
  const i = $("unlock-password");
  i.type = i.type === "password" ? "text" : "password";
});
$("unlock-logout").addEventListener("click", logout);

$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("unlock-error").classList.add("hidden");
  const password = $("unlock-password").value;
  if (!password) return;
  try {
    busy("Unlocking…");
    const { authHash, vaultKey } = await deriveAuthAndVault(password, state.user.authSalt, state.user.iterations);
    await api.post("/api/auth/verify", { email: state.user.email, authHash });
    state.vaultKey = vaultKey;
    await loadVault();
    setView("app");
    setRoute(window.location.hash.slice(1) || "cipher");
    refreshKeySource();
    updateUnreadBadge();
    startMessagePolling();
    $("unlock-password").value = "";
  } catch (err) {
    const el = $("unlock-error");
    el.textContent = err.status === 401 ? "Wrong password" : (err.message || "Could not unlock");
    el.classList.remove("hidden");
  } finally { unbusy(); }
});

// ─── User loading / logout ─────────────────────────────────────
async function loadUser() {
  state.user = await api.get("/api/auth/me");
  $("user-email").textContent = state.user.email;
}

async function logout() {
  try { await api.post("/api/auth/logout"); } catch {}
  stopMessagePolling();
  hardLock();
  setView("auth");
}
$("logout-btn").addEventListener("click", logout);
$("lock-btn").addEventListener("click", () => {
  state.vaultKey = null;
  state.vaultItems = [];
  $("unlock-email").textContent = state.user.email;
  setView("unlock");
});

function hardLock() {
  state.user = null;
  state.vaultKey = null;
  state.vaultItems = [];
  state.history = [];
  state.threads = [];
  state.groups = [];
  state.messages = [];
  state.activeThread = null;
  state.threadKeyCache = {};
  for (const id of ["auth-email","auth-password","auth-confirm","auth-token","unlock-password"]) {
    const el = $(id); if (el) el.value = "";
  }
}

// ─── Cipher tab ────────────────────────────────────────────────
const cipherEls = {
  keySource: $("key-source"),
  key: $("key"),
  showKey: $("show-key"),
  copyKey: $("copy-key"),
  genKey: $("gen-key"),
  saveKey: $("save-key"),
  strengthFill: $("strength-fill"),
  strengthText: $("strength-text"),
  input: $("input"),
  inputTag: $("input-tag"),
  inputStats: $("input-stats"),
  output: $("output"),
  outputStats: $("output-stats"),
  outMeta: $("out-meta"),
  run: $("run"),
  runLabel: $("run-label"),
  swap: $("swap"),
  paste: $("paste"),
  clear: $("clear"),
  copyOut: $("copy-out"),
  downloadOut: $("download-out"),
};

function setCipherMode(m) {
  state.cipherMode = m;
  for (const b of $$(".mode-btn")) b.classList.toggle("active", b.dataset.mode === m);
  cipherEls.runLabel.textContent = m === "encrypt" ? "Encrypt" : "Decrypt";
  cipherEls.run.classList.toggle("primary", m === "encrypt");
  cipherEls.run.classList.toggle("success", m === "decrypt");
}
for (const b of $$(".mode-btn")) b.addEventListener("click", () => setCipherMode(b.dataset.mode));

function updateCipherStrength() {
  const s = passwordStrength(cipherEls.key.value);
  cipherEls.strengthFill.style.width = s.pct + "%";
  cipherEls.strengthFill.className = "strength-fill " + s.klass;
  cipherEls.strengthText.textContent = s.bits ? `${s.label} · ${s.bits.toFixed(0)} bits` : "—";
}
cipherEls.key.addEventListener("input", () => {
  cipherEls.keySource.value = "custom";
  updateCipherStrength();
});

cipherEls.showKey.addEventListener("click", () => {
  state.showKey = !state.showKey;
  cipherEls.key.type = state.showKey ? "text" : "password";
});
cipherEls.copyKey.addEventListener("click", async () => {
  if (!cipherEls.key.value) return toast("No key to copy", "error");
  await navigator.clipboard.writeText(cipherEls.key.value);
  toast("Key copied", "info", "✓");
});
cipherEls.genKey.addEventListener("click", () => {
  cipherEls.key.value = generatePassphrase(24);
  cipherEls.key.type = "text";
  state.showKey = true;
  cipherEls.keySource.value = "custom";
  updateCipherStrength();
  toast("Generated 24-char passphrase", "info");
});

cipherEls.keySource.addEventListener("change", () => {
  const v = cipherEls.keySource.value;
  if (v === "custom") {
    cipherEls.key.value = "";
    cipherEls.key.placeholder = "Enter passphrase…";
  } else {
    const item = state.vaultItems.find(it => String(it.id) === v);
    if (item) {
      cipherEls.key.value = item.key;
      cipherEls.key.placeholder = "";
    }
  }
  updateCipherStrength();
});

function refreshKeySource() {
  const sel = cipherEls.keySource;
  const cur = sel.value;
  sel.innerHTML = '<option value="custom">Custom key…</option>';
  for (const it of state.vaultItems) {
    const opt = document.createElement("option");
    opt.value = String(it.id);
    opt.textContent = (it.pinned ? "★ " : "") + it.label;
    sel.appendChild(opt);
  }
  sel.value = cur && (cur === "custom" || state.vaultItems.some(i => String(i.id) === cur)) ? cur : "custom";
  $("vault-count").textContent = state.vaultItems.length;
}

cipherEls.saveKey.addEventListener("click", async () => {
  const k = cipherEls.key.value;
  if (!k) return toast("No key to save", "error");
  openVaultModal({ key: k });
});

const TOKEN_RE = /^[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$/;
function detectInput() {
  const v = cipherEls.input.value.trim();
  const looksLikeToken = TOKEN_RE.test(v) && v.split(":")[0].length === 32;
  cipherEls.inputTag.classList.toggle("hidden", !looksLikeToken);
  cipherEls.inputStats.textContent = `${cipherEls.input.value.length.toLocaleString()} chars`;
  return looksLikeToken;
}
cipherEls.input.addEventListener("input", () => {
  const looksLikeToken = detectInput();
  if (looksLikeToken && state.cipherMode === "encrypt") setCipherMode("decrypt");
  else if (!looksLikeToken && cipherEls.input.value.trim().length > 0 && state.cipherMode === "decrypt") setCipherMode("encrypt");
});

let cipherBusy = false;
async function runCipher() {
  if (cipherBusy) return;
  const key = cipherEls.key.value;
  if (!key) { toast("Enter a key first", "error"); cipherEls.key.focus(); return; }
  const text = cipherEls.input.value;
  if (!text) { toast("Nothing to process", "error"); cipherEls.input.focus(); return; }
  cipherBusy = true;
  cipherEls.run.disabled = true;
  cipherEls.runLabel.textContent = state.cipherMode === "encrypt" ? "Encrypting…" : "Decrypting…";

  const t0 = performance.now();
  let opOk = false, previewSrc = "";
  try {
    if (state.cipherMode === "encrypt") {
      const out = await encryptText(text, key);
      cipherEls.output.value = out;
      const dt = (performance.now() - t0).toFixed(0);
      const inB = new TextEncoder().encode(text).length;
      cipherEls.outMeta.innerHTML = `<span><b>${inB}</b> B in</span><span><b>${out.length}</b> chars out</span><span><b>${dt}</b> ms</span>`;
      previewSrc = text.slice(0, 80);
      opOk = true;
    } else {
      const res = await decryptToken(text, key);
      if (!res.ok) {
        cipherEls.output.value = "";
        cipherEls.outMeta.innerHTML = "";
        toast(res.err === "wrong key or tampered" ? "Wrong key or message was tampered with" : `Decrypt failed (${res.err})`, "error");
      } else {
        cipherEls.output.value = res.text;
        const dt = (performance.now() - t0).toFixed(0);
        cipherEls.outMeta.innerHTML = `<span><b>${res.text.length}</b> chars out</span><span><b>${dt}</b> ms</span>`;
        previewSrc = res.text.slice(0, 80);
        opOk = true;
      }
    }
  } catch (e) { toast(String(e?.message || e), "error"); }
  cipherEls.run.disabled = false;
  cipherEls.runLabel.textContent = state.cipherMode === "encrypt" ? "Encrypt" : "Decrypt";
  cipherEls.outputStats.textContent = cipherEls.output.value ? `${cipherEls.output.value.length.toLocaleString()} chars` : "empty";
  cipherBusy = false;

  if (opOk && state.user && state.vaultKey) {
    try {
      const previewCt = await sealString(previewSrc, state.vaultKey);
      await api.post("/api/history", { op: state.cipherMode, previewCt });
    } catch {}
  }
}
cipherEls.run.addEventListener("click", runCipher);
cipherEls.swap.addEventListener("click", () => {
  const i = cipherEls.input.value, o = cipherEls.output.value;
  cipherEls.input.value = o;
  cipherEls.output.value = i;
  detectInput();
  cipherEls.outMeta.innerHTML = "";
});
cipherEls.paste.addEventListener("click", async () => {
  try {
    cipherEls.input.value = await navigator.clipboard.readText();
    detectInput();
  } catch { toast("Clipboard access denied", "error"); }
});
cipherEls.clear.addEventListener("click", () => {
  cipherEls.input.value = ""; cipherEls.output.value = "";
  cipherEls.outMeta.innerHTML = "";
  detectInput();
  cipherEls.outputStats.textContent = "empty";
});
cipherEls.copyOut.addEventListener("click", async () => {
  if (!cipherEls.output.value) return toast("Nothing to copy", "error");
  await navigator.clipboard.writeText(cipherEls.output.value);
  toast("Output copied", "info", "✓");
});
cipherEls.downloadOut.addEventListener("click", () => {
  if (!cipherEls.output.value) return toast("Nothing to download", "error");
  const blob = new Blob([cipherEls.output.value], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = state.cipherMode === "encrypt" ? "cipher.txt" : "plaintext.txt";
  a.click();
  URL.revokeObjectURL(url);
});

cipherEls.input.addEventListener("dragover", (e) => { e.preventDefault(); cipherEls.input.classList.add("drop"); });
cipherEls.input.addEventListener("dragleave", () => cipherEls.input.classList.remove("drop"));
cipherEls.input.addEventListener("drop", async (e) => {
  e.preventDefault();
  cipherEls.input.classList.remove("drop");
  const f = e.dataTransfer?.files?.[0];
  if (!f) return;
  if (f.size > 5 * 1024 * 1024) return toast("File too large (5 MB max)", "error");
  cipherEls.input.value = await f.text();
  detectInput();
  toast(`Loaded ${f.name}`, "info");
});

// ─── Vault tab ─────────────────────────────────────────────────
async function loadVault() {
  if (!state.vaultKey) return;
  const items = await api.get("/api/vault");
  const decrypted = [];
  for (const r of items) {
    try {
      const label = await openString(r.labelCt, state.vaultKey);
      const payload = await openJson(r.payloadCt, state.vaultKey);
      decrypted.push({
        id: r.id,
        label,
        key: payload.key || "",
        notes: payload.notes || "",
        tags: payload.tags || [],
        pinned: r.pinned,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
      });
    } catch { /* skip undecryptable */ }
  }
  state.vaultItems = decrypted;
  refreshKeySource();
}

const vaultEls = {
  search: $("vault-search"),
  sort: $("vault-sort"),
  list: $("vault-list"),
  empty: $("vault-empty"),
  add: $("vault-add"),
};

vaultEls.search.addEventListener("input", renderVault);
vaultEls.sort.addEventListener("change", renderVault);
vaultEls.add.addEventListener("click", () => openVaultModal({}));

function renderVault() {
  const q = vaultEls.search.value.trim().toLowerCase();
  const sortBy = vaultEls.sort.value;
  let items = state.vaultItems.slice();
  if (q) {
    items = items.filter(it =>
      it.label.toLowerCase().includes(q) ||
      (it.notes || "").toLowerCase().includes(q) ||
      (it.tags || []).some(t => t.toLowerCase().includes(q))
    );
  }
  items.sort((a, b) => {
    if (a.pinned !== b.pinned) return b.pinned - a.pinned;
    if (sortBy === "label") return a.label.localeCompare(b.label);
    if (sortBy === "created") return b.createdAt - a.createdAt;
    return b.updatedAt - a.updatedAt;
  });
  vaultEls.empty.classList.toggle("hidden", items.length > 0);
  vaultEls.list.innerHTML = items.map(it => `
    <article class="vault-item ${it.pinned ? "pinned" : ""}" data-id="${it.id}">
      <div>
        <div class="vi-head">
          <div class="vi-label">${escapeHtml(it.label)}</div>
          ${it.pinned ? '<span class="vi-pin">pinned</span>' : ""}
          <div class="vi-tags">${(it.tags || []).map(t => `<span class="vi-tag">${escapeHtml(t)}</span>`).join("")}</div>
        </div>
        ${it.notes ? `<div class="vi-notes">${escapeHtml(it.notes)}</div>` : ""}
        <div class="vi-meta">updated ${fmtTime(it.updatedAt)} · added ${fmtTime(it.createdAt)}</div>
      </div>
      <div class="vi-actions">
        <button class="icon-btn" data-act="use">use</button>
        <button class="icon-btn" data-act="copy">copy</button>
        <button class="icon-btn" data-act="pin">${it.pinned ? "unpin" : "pin"}</button>
        <button class="icon-btn" data-act="edit">edit</button>
        <button class="icon-btn" data-act="del">delete</button>
      </div>
    </article>
  `).join("");
  for (const el of $$(".vault-item")) {
    const id = Number(el.dataset.id);
    el.querySelector('[data-act="use"]').addEventListener("click", () => {
      cipherEls.keySource.value = String(id);
      cipherEls.keySource.dispatchEvent(new Event("change"));
      setRoute("cipher");
      toast("Key loaded", "info");
    });
    el.querySelector('[data-act="copy"]').addEventListener("click", async () => {
      const it = state.vaultItems.find(x => x.id === id);
      if (it) { await navigator.clipboard.writeText(it.key); toast("Key copied", "info", "✓"); }
    });
    el.querySelector('[data-act="pin"]').addEventListener("click", async () => {
      const it = state.vaultItems.find(x => x.id === id);
      if (!it) return;
      try {
        const labelCt = await sealString(it.label, state.vaultKey);
        const payloadCt = await sealJson({ key: it.key, notes: it.notes, tags: it.tags }, state.vaultKey);
        const r = await api.put(`/api/vault/${id}`, { labelCt, payloadCt, pinned: !it.pinned });
        it.pinned = !it.pinned;
        it.updatedAt = r.updatedAt;
        renderVault();
        refreshKeySource();
        toast(it.pinned ? "Pinned" : "Unpinned", "info");
      } catch (err) { toast(err.message || "Could not update", "error"); }
    });
    el.querySelector('[data-act="edit"]').addEventListener("click", () => {
      const it = state.vaultItems.find(x => x.id === id);
      if (it) openVaultModal(it);
    });
    el.querySelector('[data-act="del"]').addEventListener("click", async () => {
      const it = state.vaultItems.find(x => x.id === id);
      if (!it) return;
      const ok = await confirmDialog({
        title: "Delete vault entry?",
        body: `"${it.label}" will be permanently removed. Existing ciphertexts encrypted with this key will need the raw passphrase to be decrypted.`,
        okText: "Delete",
      });
      if (!ok) return;
      await api.del(`/api/vault/${id}`);
      state.vaultItems = state.vaultItems.filter(x => x.id !== id);
      renderVault();
      refreshKeySource();
      toast("Deleted", "info");
    });
  }
}

// ─── Vault modal (create / edit) ───────────────────────────────
const vmEls = {
  modal: $("vault-modal"),
  title: $("vm-title"),
  label: $("vm-label"),
  key: $("vm-key"),
  keyGen: $("vm-key-gen"),
  keyShow: $("vm-key-show"),
  tags: $("vm-tags"),
  notes: $("vm-notes"),
  pinned: $("vm-pinned"),
  err: $("vm-error"),
  cancel: $("vm-cancel"),
  close: $("vm-close"),
  form: $("vm-form"),
};
let editingId = null;

function openVaultModal(item) {
  editingId = item?.id || null;
  vmEls.title.textContent = editingId ? "Edit vault entry" : "New vault entry";
  vmEls.label.value = item?.label || "";
  vmEls.key.value = item?.key || "";
  vmEls.tags.value = (item?.tags || []).join(", ");
  vmEls.notes.value = item?.notes || "";
  vmEls.pinned.checked = !!item?.pinned;
  vmEls.err.classList.add("hidden");
  vmEls.key.type = "password";
  vmEls.modal.classList.remove("hidden");
  setTimeout(() => vmEls.label.focus(), 30);
}
function closeVaultModal() { vmEls.modal.classList.add("hidden"); editingId = null; }
vmEls.cancel.addEventListener("click", closeVaultModal);
vmEls.close.addEventListener("click", closeVaultModal);
vmEls.modal.addEventListener("click", (e) => { if (e.target === vmEls.modal) closeVaultModal(); });
vmEls.keyGen.addEventListener("click", () => { vmEls.key.value = generatePassphrase(24); vmEls.key.type = "text"; });
vmEls.keyShow.addEventListener("click", () => { vmEls.key.type = vmEls.key.type === "password" ? "text" : "password"; });

vmEls.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  vmEls.err.classList.add("hidden");
  const label = vmEls.label.value.trim();
  const key = vmEls.key.value;
  if (!label) { vmEls.err.textContent = "Label is required"; vmEls.err.classList.remove("hidden"); return; }
  if (!key) { vmEls.err.textContent = "Key is required"; vmEls.err.classList.remove("hidden"); return; }
  const tags = vmEls.tags.value.split(",").map(s => s.trim()).filter(Boolean).slice(0, 12);
  const notes = vmEls.notes.value;
  const pinned = vmEls.pinned.checked;
  try {
    busy(editingId ? "Saving…" : "Adding…");
    const labelCt = await sealString(label, state.vaultKey);
    const payloadCt = await sealJson({ key, notes, tags }, state.vaultKey);
    if (editingId) {
      const r = await api.put(`/api/vault/${editingId}`, { labelCt, payloadCt, pinned });
      const idx = state.vaultItems.findIndex(x => x.id === editingId);
      if (idx >= 0) state.vaultItems[idx] = { id: editingId, label, key, notes, tags, pinned, createdAt: state.vaultItems[idx].createdAt, updatedAt: r.updatedAt };
    } else {
      const r = await api.post("/api/vault", { labelCt, payloadCt, pinned });
      state.vaultItems.unshift({ id: r.id, label, key, notes, tags, pinned, createdAt: r.createdAt, updatedAt: r.updatedAt });
    }
    closeVaultModal();
    renderVault();
    refreshKeySource();
    toast(editingId ? "Updated" : "Saved", "info", "✓");
  } catch (err) {
    vmEls.err.textContent = err.message || String(err);
    vmEls.err.classList.remove("hidden");
  } finally { unbusy(); }
});

// ─── History tab ───────────────────────────────────────────────
async function loadHistory() {
  if (!state.vaultKey) return;
  const list = $("history-list");
  list.innerHTML = '<p class="muted small">Loading…</p>';
  try {
    const items = await api.get("/api/history?limit=200");
    const decrypted = [];
    for (const r of items) {
      try {
        const preview = await openString(r.previewCt, state.vaultKey);
        decrypted.push({ id: r.id, op: r.op, preview, createdAt: r.createdAt });
      } catch {}
    }
    state.history = decrypted;
    $("history-empty").classList.toggle("hidden", decrypted.length > 0);
    list.innerHTML = decrypted.map(h => `
      <div class="history-item" data-id="${h.id}">
        <span class="h-op ${h.op}">${h.op}</span>
        <div class="h-preview">${escapeHtml(h.preview) || '<span class="muted">(empty)</span>'}</div>
        <span class="h-time">${fmtTime(h.createdAt)}</span>
        <button class="icon-btn" data-act="del">×</button>
      </div>
    `).join("") || "";
    for (const el of list.querySelectorAll(".history-item")) {
      el.querySelector('[data-act="del"]').addEventListener("click", async () => {
        const id = Number(el.dataset.id);
        await api.del(`/api/history/${id}`);
        state.history = state.history.filter(h => h.id !== id);
        loadHistory();
      });
    }
  } catch (e) { list.innerHTML = `<p class="form-error">${escapeHtml(e.message)}</p>`; }
}
$("history-refresh").addEventListener("click", loadHistory);
$("history-clear").addEventListener("click", async () => {
  const ok = await confirmDialog({ title: "Clear history?", body: "All operation previews will be permanently deleted.", okText: "Clear" });
  if (!ok) return;
  await api.del("/api/history");
  state.history = [];
  loadHistory();
  toast("History cleared", "info");
});

// ─── Settings tab ──────────────────────────────────────────────
async function loadSettings() {
  $("set-email").textContent = state.user.email;
  $("set-created").textContent = fmtTime(state.user.createdAt);
  $("set-last").textContent = fmtTime(state.user.lastLoginAt);
  await loadSessions();
}

async function loadSessions() {
  const list = $("sessions-list");
  list.innerHTML = '<p class="muted small">Loading…</p>';
  try {
    const sessions = await api.get("/api/sessions");
    list.innerHTML = sessions.map(s => `
      <div class="session-item ${s.current ? "current" : ""}" data-id="${s.id}">
        <div class="si-info">
          <div class="si-ua">${escapeHtml(s.userAgent || "Unknown device")}</div>
          <div class="si-meta">${escapeHtml(s.ip || "—")} · started ${fmtTime(s.createdAt)} · expires ${fmtTime(s.expiresAt)}</div>
        </div>
        ${s.current ? '<span class="si-current-tag">this device</span>' : '<button class="icon-btn" data-act="revoke">revoke</button>'}
      </div>
    `).join("");
    for (const el of list.querySelectorAll(".session-item")) {
      el.querySelector('[data-act="revoke"]')?.addEventListener("click", async () => {
        await api.del(`/api/sessions/${el.dataset.id}`);
        loadSessions();
        toast("Session revoked", "info");
      });
    }
  } catch (e) { list.innerHTML = `<p class="form-error">${escapeHtml(e.message)}</p>`; }
}

$("change-pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const cur = $("cp-current").value;
  const next = $("cp-new").value;
  const conf = $("cp-confirm").value;
  if (next.length < 8) return toast("New password too short", "error");
  if (next !== conf) return toast("Passwords don't match", "error");
  if (passwordStrength(next).bits < 40) return toast("New password is too weak", "error");

  try {
    busy("Re-encrypting vault…");
    const cur_ = await deriveAuthAndVault(cur, state.user.authSalt, state.user.iterations);
    if (state.vaultKey && bytesToHex(state.vaultKey) !== bytesToHex(cur_.vaultKey)) {
      throw new Error("Current password verification failed");
    }
    const newSaltBytes = crypto.getRandomValues(new Uint8Array(16));
    const newSaltHex = bytesToHex(newSaltBytes);
    const next_ = await deriveAuthAndVault(next, newSaltHex, state.user.iterations);

    const rewrapped = [];
    for (const it of state.vaultItems) {
      const labelCt = await sealString(it.label, next_.vaultKey);
      const payloadCt = await sealJson({ key: it.key, notes: it.notes, tags: it.tags }, next_.vaultKey);
      rewrapped.push({ id: it.id, labelCt, payloadCt });
    }
    await api.post("/api/auth/change-password", {
      currentAuthHash: cur_.authHash,
      newAuthSalt: newSaltHex,
      newAuthHash: next_.authHash,
      rewrappedItems: rewrapped,
    });
    state.vaultKey = next_.vaultKey;
    state.user.authSalt = newSaltHex;
    $("cp-current").value = $("cp-new").value = $("cp-confirm").value = "";
    toast("Password changed — other sessions signed out", "info", "✓", 4000);
    await loadSessions();
  } catch (err) {
    toast(err.message || "Could not change password", "error");
  } finally { unbusy(); }
});

$("export-vault").addEventListener("click", async () => {
  const items = await api.get("/api/vault");
  const data = {
    schema: "ascii-cipher-vault.v1",
    exportedAt: Date.now(),
    email: state.user.email,
    authSalt: state.user.authSalt,
    iterations: state.user.iterations,
    items: items.map(r => ({
      labelCt: r.labelCt, payloadCt: r.payloadCt,
      pinned: r.pinned, createdAt: r.createdAt, updatedAt: r.updatedAt,
    })),
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cipher-vault-${state.user.email}-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast("Vault exported (encrypted)", "info");
});

$("import-vault").addEventListener("click", () => $("import-file").click());
$("import-file").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  if (!f) return;
  try {
    const data = JSON.parse(await f.text());
    if (data.schema !== "ascii-cipher-vault.v1") throw new Error("Unrecognised export format");
    if (data.authSalt !== state.user.authSalt) {
      const ok = await confirmDialog({
        title: "Different vault key",
        body: "This export was created with a different password. Items will only be readable if you re-encrypt them — proceed only if you understand the risks.",
        okText: "Import anyway", danger: true,
      });
      if (!ok) return;
    }
    const ok = await confirmDialog({
      title: "Import vault?",
      body: `Adds ${data.items.length} items to your vault. Existing items are kept.`,
      okText: "Import", danger: false,
    });
    if (!ok) return;
    busy("Importing…");
    let added = 0;
    for (const it of data.items) {
      try {
        await api.post("/api/vault", { labelCt: it.labelCt, payloadCt: it.payloadCt, pinned: !!it.pinned });
        added++;
      } catch {}
    }
    await loadVault();
    renderVault();
    toast(`Imported ${added} item${added === 1 ? "" : "s"}`, "info", "✓");
  } catch (err) { toast(err.message || "Import failed", "error"); }
  finally { unbusy(); e.target.value = ""; }
});

$("delete-account-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const password = $("da-password").value;
  if (!password) return;
  const ok = await confirmDialog({
    title: "Delete account?",
    body: "This permanently deletes your account, all vault entries, and all history. There is no undo.",
    okText: "Delete forever",
  });
  if (!ok) return;
  try {
    busy("Deleting…");
    const { authHash } = await deriveAuthAndVault(password, state.user.authSalt, state.user.iterations);
    await api.post("/api/auth/delete-account", { authHash });
    hardLock();
    setView("auth");
    toast("Account deleted", "info");
  } catch (err) { toast(err.message || "Could not delete", "error"); }
  finally { unbusy(); }
});

// ─── Routing ───────────────────────────────────────────────────
for (const t of $$("#main-tabs .tab")) t.addEventListener("click", () => setRoute(t.dataset.route));
window.addEventListener("hashchange", () => {
  const r = location.hash.slice(1);
  if (["cipher","vault","messages","history","settings"].includes(r)) setRoute(r);
});

// ─── Keyboard shortcuts ────────────────────────────────────────
document.addEventListener("keydown", (e) => {
  if ($("view-app").classList.contains("hidden")) return;
  if (state.route !== "cipher") return;
  const ctrl = e.ctrlKey || e.metaKey;
  if (!ctrl) return;
  switch (e.key.toLowerCase()) {
    case "enter": e.preventDefault(); runCipher(); break;
    case "s":     e.preventDefault(); cipherEls.swap.click(); break;
    case "l":     e.preventDefault(); cipherEls.clear.click(); break;
    case "g":     e.preventDefault(); cipherEls.genKey.click(); break;
  }
});

// ─── Boot ──────────────────────────────────────────────────────
// ─── Messages tab ──────────────────────────────────────────────
const msgEls = {
  threads: $("msg-threads"),
  threadsEmpty: $("msg-threads-empty"),
  groups: $("msg-groups"),
  groupsEmpty: $("msg-groups-empty"),
  header: $("msg-header"),
  list: $("msg-list"),
  compose: $("msg-compose"),
  body: $("msg-body"),
  key: $("msg-key"),
  keySource: $("msg-key-source"),
  keyShow: $("msg-key-show"),
  keyRow: document.querySelector(".msg-compose-keyrow"),
  hint: $("msg-hint"),
  unreadBadge: $("msg-unread"),
  newBtn: $("msg-new"),
  modal: $("new-msg-modal"),
};

async function loadThreads() {
  if (!state.vaultKey) return;
  try {
    const [threads, groups] = await Promise.all([
      api.get("/api/messages/threads"),
      api.get("/api/groups"),
    ]);
    state.threads = threads;
    state.groups = [];
    for (const g of groups) {
      let key = null, passcode = null;
      try {
        const raw = await openBytes(g.wrappedKey, state.vaultKey);
        try {
          const obj = JSON.parse(new TextDecoder().decode(raw));
          if (obj && typeof obj === "object" && obj.key) {
            key = obj.key;
            passcode = obj.passcode || null;
          }
        } catch {
          if (raw.length === 32) key = bytesToHex(raw);
        }
      } catch {}
      state.groups.push({ ...g, key, passcode });
    }
    renderThreads();
    renderGroups();
    updateUnreadBadge();
  } catch (e) { toast(e.message || "Failed to load conversations", "error"); }
}

function renderThreads() {
  const active = state.activeThread;
  const isActive = (peerId) => active?.kind === "dm" && active.peerId === peerId;
  msgEls.threadsEmpty.classList.toggle("hidden", state.threads.length > 0);
  msgEls.threads.innerHTML = state.threads.map(t => `
    <div class="msg-thread ${isActive(t.peerId) ? 'active' : ''}" data-peer="${t.peerId}">
      <div class="t-row">
        <span class="t-email">${escapeHtml(t.peerEmail)}</span>
        ${t.unread > 0 ? `<span class="t-unread">${t.unread}</span>` : ""}
      </div>
      <div class="t-row"><span class="t-time">${t.lastAt ? fmtTime(t.lastAt) : "—"}</span></div>
    </div>
  `).join("");
  for (const el of msgEls.threads.querySelectorAll(".msg-thread")) {
    el.addEventListener("click", () => openDmThread(Number(el.dataset.peer)));
  }
}

function renderGroups() {
  const active = state.activeThread;
  const isActive = (id) => active?.kind === "group" && active.groupId === id;
  msgEls.groupsEmpty.classList.toggle("hidden", state.groups.length > 0);
  msgEls.groups.innerHTML = state.groups.map(g => `
    <div class="msg-thread ${isActive(g.id) ? 'active' : ''}" data-group="${g.id}">
      <div class="t-row">
        <span class="t-email">⌘ ${escapeHtml(g.name)}</span>
        ${g.unread > 0 ? `<span class="t-unread">${g.unread}</span>` : ""}
      </div>
      <div class="t-row"><span class="t-time">${g.lastAt ? fmtTime(g.lastAt) : "—"}</span></div>
    </div>
  `).join("");
  for (const el of msgEls.groups.querySelectorAll(".msg-thread")) {
    el.addEventListener("click", () => openGroupThread(Number(el.dataset.group)));
  }
}

async function openDmThread(peerId) {
  const t = state.threads.find(x => x.peerId === peerId);
  const peerEmail = t?.peerEmail || state.activeThread?.peerEmail || "";
  state.activeThread = { kind: "dm", peerId, peerEmail };
  msgEls.header.innerHTML = `
    <div>
      <div class="h-email">${escapeHtml(peerEmail)}</div>
      <div class="h-meta">direct · end-to-end · key never leaves your browser</div>
    </div>
    <button class="icon-btn" id="msg-refresh" type="button">refresh</button>
  `;
  $("msg-refresh").addEventListener("click", () => loadDmMessages(peerId));
  msgEls.compose.classList.remove("hidden");
  msgEls.keyRow.classList.remove("hidden");
  refreshMsgKeySource();
  renderThreads();
  renderGroups();
  await loadDmMessages(peerId);
  setTimeout(() => msgEls.body.focus(), 50);
}

async function openGroupThread(groupId) {
  const g = state.groups.find(x => x.id === groupId);
  if (!g) return;
  if (!g.key) { toast("Could not unwrap this group's key — re-join with the code.", "error"); return; }
  state.activeThread = { kind: "group", groupId, name: g.name, key: g.key };
  msgEls.header.innerHTML = `
    <div>
      <div class="h-email">⌘ ${escapeHtml(g.name)}</div>
      <div class="h-meta">group · encrypted with shared join code</div>
    </div>
    <div style="display:flex;gap:6px;">
      <button class="icon-btn" id="msg-refresh" type="button">refresh</button>
      <button class="icon-btn" id="msg-share-code" type="button">share code</button>
      <button class="icon-btn" id="msg-leave-group" type="button">leave</button>
    </div>
  `;
  $("msg-refresh").addEventListener("click", () => loadGroupMessages(groupId));
  $("msg-share-code").addEventListener("click", async () => {
    if (!g.passcode) {
      toast("Original passcode unavailable for this group — recreate it to share a join code.", "error", null, 5000);
      return;
    }
    const code = `${groupId}:${g.passcode}`;
    try { await navigator.clipboard.writeText(code); toast("Join code copied", "info", "✓"); }
    catch { toast(code, "info", "Join code", 6000); }
  });
  $("msg-leave-group").addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "Leave group?",
      body: `You will lose access to "${g.name}". You can rejoin later if you still have the join code.`,
      okText: "Leave",
    });
    if (!ok) return;
    try {
      await api.post(`/api/groups/${groupId}/leave`);
      state.groups = state.groups.filter(x => x.id !== groupId);
      state.activeThread = null;
      msgEls.header.innerHTML = `<div class="muted small">Pick a conversation or start a new one.</div>`;
      msgEls.compose.classList.add("hidden");
      msgEls.list.innerHTML = `<div class="empty" style="padding:60px 20px;"><p>No conversation selected</p></div>`;
      renderGroups();
      toast("Left group", "info");
    } catch (err) { toast(err.message || "Failed to leave", "error"); }
  });
  msgEls.compose.classList.remove("hidden");
  msgEls.keyRow.classList.add("hidden"); // group key is fixed
  renderThreads();
  renderGroups();
  await loadGroupMessages(groupId);
  setTimeout(() => msgEls.body.focus(), 50);
}

async function loadDmMessages(peerId) {
  try {
    state.messages = await api.get(`/api/messages?peer=${peerId}&limit=200`);
    await renderDmMessages();
    for (const m of state.messages) {
      if (!m.fromMe && !m.readAt) {
        try { await api.post(`/api/messages/${m.id}/read`); } catch {}
      }
    }
    state.threads = await api.get("/api/messages/threads");
    renderThreads();
    updateUnreadBadge();
  } catch (e) {
    msgEls.list.innerHTML = `<p class="form-error" style="margin:20px;">${escapeHtml(e.message)}</p>`;
  }
}

async function loadGroupMessages(groupId) {
  try {
    state.messages = await api.get(`/api/groups/${groupId}/messages?limit=200`);
    await renderGroupMessages();
    try { await api.post(`/api/groups/${groupId}/read`); } catch {}
    const g = state.groups.find(x => x.id === groupId);
    if (g) g.unread = 0;
    renderGroups();
    updateUnreadBadge();
  } catch (e) {
    msgEls.list.innerHTML = `<p class="form-error" style="margin:20px;">${escapeHtml(e.message)}</p>`;
  }
}

async function tryDecryptDm(ciphertext, peerId) {
  const cached = state.threadKeyCache[peerId];
  if (cached) {
    const r = await decryptToken(ciphertext, cached.key);
    if (r.ok) return { ok: true, text: r.text, keyLabel: cached.label };
  }
  for (const k of state.vaultItems) {
    if (cached && k.id === cached.id) continue;
    const r = await decryptToken(ciphertext, k.key);
    if (r.ok) {
      state.threadKeyCache[peerId] = k;
      return { ok: true, text: r.text, keyLabel: k.label };
    }
  }
  const liveKey = msgEls.key.value;
  if (liveKey) {
    const r = await decryptToken(ciphertext, liveKey);
    if (r.ok) return { ok: true, text: r.text, keyLabel: "(custom)" };
  }
  return { ok: false };
}

function renderBubble(m, decrypted, side, opts = {}) {
  const meta = decrypted.ok
    ? `<span>${escapeHtml(opts.label || decrypted.keyLabel || "key")}</span><span>·</span><span>${fmtTime(m.createdAt)}</span>`
    : `<span>can't decrypt</span><span>·</span><span>${fmtTime(m.createdAt)}</span>`;
  const sender = opts.sender ? `<div class="b-hint">${escapeHtml(opts.sender)}</div>` : "";
  const hint = m.hint ? `<div class="b-hint">hint: ${escapeHtml(m.hint)}</div>` : "";
  const body = decrypted.ok
    ? `<div>${escapeHtml(decrypted.text)}</div>`
    : `<div>🔒 ${escapeHtml(m.ciphertext.slice(0, 80))}…</div>`;
  return `
    <div class="msg-bubble ${side} ${decrypted.ok ? "" : "encrypted"}" data-id="${m.id}">
      ${sender}${hint}${body}
      <div class="b-meta">${meta}</div>
      <div class="b-actions"><button data-act="del">delete</button></div>
    </div>`;
}

async function renderDmMessages() {
  if (state.messages.length === 0) {
    msgEls.list.innerHTML = `<div class="empty" style="padding:40px 20px;"><p>No messages yet</p><p class="muted small">Send the first one ↓</p></div>`;
    return;
  }
  const ordered = state.messages.slice().reverse();
  const html = [];
  for (const m of ordered) {
    const r = await tryDecryptDm(m.ciphertext, state.activeThread.peerId);
    html.push(renderBubble(m, r, m.fromMe ? "from-me" : "from-them", { label: r.ok ? `★ ${r.keyLabel}` : "" }));
  }
  msgEls.list.innerHTML = html.join("");
  bindBubbleDelete((id) => api.del(`/api/messages/${id}`));
  msgEls.list.scrollTop = msgEls.list.scrollHeight;
}

async function renderGroupMessages() {
  if (state.messages.length === 0) {
    msgEls.list.innerHTML = `<div class="empty" style="padding:40px 20px;"><p>No messages yet</p><p class="muted small">Send the first one ↓</p></div>`;
    return;
  }
  const groupKey = state.activeThread.key;
  const ordered = state.messages.slice().reverse();
  const html = [];
  for (const m of ordered) {
    const r = await decryptToken(m.ciphertext, groupKey);
    html.push(renderBubble(m, r,
      m.fromMe ? "from-me" : "from-them",
      { sender: m.fromMe ? null : (m.senderEmail || "(unknown)") }));
  }
  msgEls.list.innerHTML = html.join("");
  const groupId = state.activeThread.groupId;
  bindBubbleDelete((id) => api.del(`/api/groups/${groupId}/messages/${id}`));
  msgEls.list.scrollTop = msgEls.list.scrollHeight;
}

function bindBubbleDelete(deleteFn) {
  for (const el of msgEls.list.querySelectorAll(".msg-bubble")) {
    el.querySelector('[data-act="del"]')?.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = Number(el.dataset.id);
      try {
        await deleteFn(id);
        state.messages = state.messages.filter(x => x.id !== id);
        if (state.activeThread.kind === "dm") await renderDmMessages();
        else await renderGroupMessages();
      } catch (err) { toast(err.message, "error"); }
    });
  }
}

function refreshMsgKeySource() {
  const sel = msgEls.keySource;
  const cur = sel.value;
  sel.innerHTML = '<option value="custom">Custom key…</option>';
  for (const it of state.vaultItems) {
    const opt = document.createElement("option");
    opt.value = String(it.id);
    opt.textContent = (it.pinned ? "★ " : "") + it.label;
    sel.appendChild(opt);
  }
  const peerId = state.activeThread?.kind === "dm" ? state.activeThread.peerId : null;
  const cached = peerId != null ? state.threadKeyCache[peerId] : null;
  if (cached && state.vaultItems.some(v => v.id === cached.id)) {
    sel.value = String(cached.id);
    msgEls.key.value = cached.key;
  } else if (cur && (cur === "custom" || state.vaultItems.some(v => String(v.id) === cur))) {
    sel.value = cur;
  } else {
    sel.value = "custom";
    msgEls.key.value = "";
  }
}

msgEls.keySource.addEventListener("change", () => {
  const v = msgEls.keySource.value;
  if (v === "custom") {
    msgEls.key.value = "";
    msgEls.key.placeholder = "Encryption key (preshared)";
  } else {
    const it = state.vaultItems.find(x => String(x.id) === v);
    if (it) {
      msgEls.key.value = it.key;
      if (state.activeThread?.kind === "dm") {
        state.threadKeyCache[state.activeThread.peerId] = it;
        renderDmMessages();
      }
    }
  }
});
msgEls.keyShow.addEventListener("click", () => {
  msgEls.key.type = msgEls.key.type === "password" ? "text" : "password";
});

msgEls.compose.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.activeThread) return;
  const body = msgEls.body.value.trim();
  if (!body) return;
  const hint = msgEls.hint.value.trim();
  try {
    if (state.activeThread.kind === "dm") {
      const key = msgEls.key.value;
      if (!key) { toast("Pick a vault key or type one", "error"); msgEls.key.focus(); return; }
      const ciphertext = await encryptText(body, key);
      await api.post("/api/messages", {
        recipientId: state.activeThread.peerId,
        ciphertext,
        hint: hint || undefined,
      });
      const sel = msgEls.keySource.value;
      if (sel !== "custom") {
        const it = state.vaultItems.find(x => String(x.id) === sel);
        if (it) state.threadKeyCache[state.activeThread.peerId] = it;
      }
      msgEls.body.value = "";
      await loadDmMessages(state.activeThread.peerId);
    } else {
      const ciphertext = await encryptText(body, state.activeThread.key);
      await api.post(`/api/groups/${state.activeThread.groupId}/messages`, {
        ciphertext,
        hint: hint || undefined,
      });
      msgEls.body.value = "";
      await loadGroupMessages(state.activeThread.groupId);
    }
  } catch (err) { toast(err.message || "Send failed", "error"); }
});

msgEls.body.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault();
    msgEls.compose.requestSubmit();
  }
});

// ── New conversation modal (tabs: DM / Create group / Join group) ──
function nmCloseModal() {
  msgEls.modal.classList.add("hidden");
  for (const id of ["nm-dm-error","nm-create-error","nm-join-error"]) $(id).classList.add("hidden");
  $("nm-group-share").classList.add("hidden");
  $("nm-group-share").textContent = "";
}
function nmSetTab(name) {
  for (const t of $$("[data-nm-tab]")) t.classList.toggle("active", t.dataset.nmTab === name);
  for (const p of ["dm","create","join"]) $(`nm-pane-${p}`).classList.toggle("hidden", p !== name);
}
for (const t of $$("[data-nm-tab]")) t.addEventListener("click", () => nmSetTab(t.dataset.nmTab));
for (const b of $$("[data-nm-cancel]")) b.addEventListener("click", nmCloseModal);
$("nm-close").addEventListener("click", nmCloseModal);
msgEls.modal.addEventListener("click", (e) => { if (e.target === msgEls.modal) nmCloseModal(); });

msgEls.newBtn.addEventListener("click", () => {
  $("nm-email").value = "";
  $("nm-group-name").value = "";
  $("nm-group-pass").value = "";
  $("nm-join-code").value = "";
  nmSetTab("dm");
  msgEls.modal.classList.remove("hidden");
  setTimeout(() => $("nm-email").focus(), 30);
});

function nmShowErr(id, msg) { const el = $(id); el.textContent = msg; el.classList.remove("hidden"); }

$("nm-open-dm").addEventListener("click", async () => {
  $("nm-dm-error").classList.add("hidden");
  const email = $("nm-email").value.trim().toLowerCase();
  if (!email) return nmShowErr("nm-dm-error", "Enter an email address");
  try {
    busy("Looking up…");
    const peer = await api.post("/api/messages/lookup", { email });
    if (!state.threads.find(t => t.peerId === peer.id)) {
      state.threads.unshift({ peerId: peer.id, peerEmail: peer.email, unread: 0, lastAt: null });
    }
    nmCloseModal();
    await openDmThread(peer.id);
  } catch (err) {
    nmShowErr("nm-dm-error",
      err.status === 404 ? "No account with that email" : (err.message || "Lookup failed"));
  } finally { unbusy(); }
});

$("nm-group-gen").addEventListener("click", () => {
  $("nm-group-pass").value = generatePassphrase(24);
});

$("nm-create-go").addEventListener("click", async () => {
  $("nm-create-error").classList.add("hidden");
  const name = $("nm-group-name").value.trim();
  const passcode = $("nm-group-pass").value;
  if (!name) return nmShowErr("nm-create-error", "Group name required");
  if (!passcode || passcode.length < 8) return nmShowErr("nm-create-error", "Passcode must be at least 8 characters");
  try {
    busy("Creating group…");
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltHex = bytesToHex(saltBytes);
    const { authHash, vaultKey: groupKey } = await deriveGroupAuth(passcode, saltHex);
    const keyHex = bytesToHex(groupKey);
    const wrappedKey = await sealJson({ passcode, key: keyHex }, state.vaultKey);
    const r = await api.post("/api/groups", { name, salt: saltHex, authHash, wrappedKey });
    state.groups.unshift({
      id: r.id, name: r.name, salt: saltHex, wrappedKey,
      key: keyHex, passcode, unread: 0, lastAt: null,
    });
    renderGroups();
    const code = `${r.id}:${passcode}`;
    const share = $("nm-group-share");
    share.textContent = `Join code: ${code}  (also copied to clipboard)`;
    share.classList.remove("hidden");
    try { await navigator.clipboard.writeText(code); } catch {}
    toast("Group created — code copied", "info", "✓", 4000);
    setTimeout(() => { nmCloseModal(); openGroupThread(r.id); }, 1200);
  } catch (err) {
    nmShowErr("nm-create-error", err.message || "Create failed");
  } finally { unbusy(); }
});

$("nm-join-go").addEventListener("click", async () => {
  $("nm-join-error").classList.add("hidden");
  const raw = $("nm-join-code").value.trim();
  const idx = raw.indexOf(":");
  if (idx <= 0) return nmShowErr("nm-join-error", "Code must look like  id:passphrase");
  const groupId = Number(raw.slice(0, idx));
  const passcode = raw.slice(idx + 1);
  if (!Number.isFinite(groupId) || !passcode) return nmShowErr("nm-join-error", "Invalid code");
  try {
    busy("Joining…");
    const pre = await api.get(`/api/groups/${groupId}/preflight`);
    const { authHash, vaultKey: groupKey } = await deriveGroupAuth(passcode, pre.salt);
    const keyHex = bytesToHex(groupKey);
    const wrappedKey = await sealJson({ passcode, key: keyHex }, state.vaultKey);
    await api.post(`/api/groups/${groupId}/join`, { authHash, wrappedKey });
    const existing = state.groups.find(g => g.id === groupId);
    if (existing) {
      existing.key = keyHex;
      existing.passcode = passcode;
      existing.wrappedKey = wrappedKey;
    } else {
      state.groups.unshift({
        id: groupId, name: pre.name, salt: pre.salt, wrappedKey,
        key: keyHex, passcode, unread: 0, lastAt: null,
      });
    }
    renderGroups();
    nmCloseModal();
    await openGroupThread(groupId);
    toast(`Joined "${pre.name}"`, "info", "✓");
  } catch (err) {
    const msg = err.status === 403 ? "Wrong join code"
              : err.status === 404 ? "Group not found"
              : (err.message || "Join failed");
    nmShowErr("nm-join-error", msg);
  } finally { unbusy(); }
});

// ── Unread badge polling ──
async function updateUnreadBadge() {
  try {
    const r = await api.get("/api/messages/unread-count");
    const badge = msgEls.unreadBadge;
    if (r.unread > 0) {
      badge.textContent = r.unread > 99 ? "99+" : r.unread;
      badge.style.display = "";
    } else {
      badge.style.display = "none";
    }
  } catch {}
}

let _msgPoll = null;
function startMessagePolling() {
  if (_msgPoll) return;
  _msgPoll = setInterval(() => {
    if (!state.user || !state.vaultKey) return;
    updateUnreadBadge();
    if (state.route === "messages" && state.activeThread) {
      const at = state.activeThread;
      const p = at.kind === "dm" ? loadDmMessages(at.peerId) : loadGroupMessages(at.groupId);
      p.catch(() => {});
    } else if (state.route === "messages") {
      loadThreads().catch(() => {});
    }
  }, 15000);
}
function stopMessagePolling() {
  if (_msgPoll) { clearInterval(_msgPoll); _msgPoll = null; }
}

function ensureSecureContext() {
  if (window.isSecureContext && window.crypto?.subtle) return true;
  // Browsers refuse to expose Web Crypto over plain HTTP (except on localhost).
  // Replace every form with a clear message so the user knows what to do.
  const banner = `
    <div class="card" style="max-width:560px;margin:60px auto;text-align:center;">
      <div class="brand brand-lg"><div class="logo">!</div><h1>HTTPS required</h1></div>
      <p style="color:var(--fg);margin-bottom:10px;">
        Your browser blocks the cryptography this app depends on
        (<code>crypto.subtle</code>) over plain HTTP.
      </p>
      <p class="muted small" style="margin-bottom:14px;">
        Open this site over <b>https://</b> instead. In Nginx Proxy Manager:
        edit your proxy host → <b>SSL</b> tab → request a Let's Encrypt cert →
        enable <b>Force SSL</b>. Then reload.
      </p>
      <p class="muted small">
        Current origin: <code>${escapeHtml(location.origin)}</code><br>
        Secure context: <code>${window.isSecureContext}</code>
      </p>
    </div>`;
  document.body.innerHTML = banner;
  return false;
}

async function boot() {
  if (!ensureSecureContext()) return;
  setAuthMode("login");
  try {
    state.user = await api.get("/api/auth/me");
    $("user-email").textContent = state.user.email;
    $("unlock-email").textContent = state.user.email;
    setView("unlock");
    setTimeout(() => $("unlock-password").focus(), 60);
  } catch (err) {
    if (err.status === 401) {
      setView("auth");
      $("auth-email").focus();
    } else {
      setView("auth");
      toast(err.message || "Server error", "error");
    }
  }
}
boot();
