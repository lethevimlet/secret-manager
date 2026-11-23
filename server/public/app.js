// sm GUI. The admin token lives in sessionStorage (this tab only) and is sent
// as a bearer header; `smctl gui` passes it in the URL fragment, which never
// reaches the server.
const $ = (sel) => document.querySelector(sel);
const KEY = 'sm.adminToken';

let token = null;
let secrets = [];
let timer = null;

// ---------- helpers ----------
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) node.append(c);
  return node;
}

function ago(iso) {
  if (!iso) return 'never';
  const s = Math.round((Date.now() - new Date(iso)) / 1000);
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.round(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString();
}
const fullTime = (iso) => (iso ? new Date(iso).toLocaleString() : '');

let toastTimer;
function toast(msg, bad = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2600);
}

async function api(path, opts = {}) {
  const res = await fetch('/v1' + path, {
    method: opts.method || 'GET',
    headers: { 'X-SM-GUI': '1', ...((opts.token || token) ? { Authorization: `Bearer ${opts.token || token}` } : {}), ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  }).catch(() => {
    setStatus(false);
    throw new Error('server unreachable');
  });
  setStatus(true);
  if (res.status === 401 && !opts.token && !opts.probe) {
    showLogin('Your session ended, sign in again.');
    throw new Error('unauthorized');
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function setStatus(up) {
  const s = $('#status');
  s.classList.toggle('down', !up);
  s.lastElementChild.textContent = up ? 'connected' : 'offline';
}

function showError(id, msg) {
  const e = $(id);
  e.textContent = msg || '';
  e.hidden = !msg;
}

// ---------- auth ----------
function enterApp({ openMode = false } = {}) {
  $('#login').hidden = true;
  $('#app').hidden = false;
  showOpenMode(openMode);
  $('#change-password').hidden = openMode || Boolean(token);
  switchTab(['#activity', '#sync'].includes(location.hash) ? location.hash.slice(1) : 'secrets');
}

// Show the password form, or the first-time setup form.
async function showLogin(message) {
  hideAllValues();
  clearInterval(timer);
  $('#app').hidden = true;
  $('#login').hidden = false;
  let st = { passwordSet: true, setupNeedsCode: false, minPassword: 10 };
  try { st = await api('/auth/status', { probe: true }); } catch {}
  $('#login-form').hidden = !st.passwordSet;
  $('#setup-form').hidden = st.passwordSet;
  if (st.passwordSet) {
    showError('#login-error', message);
    $('#password').value = '';
    $('#password').focus();
  } else {
    $('#setup-code-field').hidden = !st.setupNeedsCode;
    $('#setup-code').required = st.setupNeedsCode;
    $('#setup-hint').textContent = `At least ${st.minPassword} characters.`;
    $('#setup-password').focus();
  }
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('#login-error');
  const btn = e.submitter;
  btn.disabled = true;
  try {
    await api('/auth/login', { method: 'POST', body: { password: $('#password').value }, probe: true });
    $('#password').value = '';
    enterApp();
  } catch (err) {
    showError('#login-error', err.message);
    $('#password').select();
  } finally {
    btn.disabled = false;
  }
});

$('#setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('#setup-error');
  if ($('#setup-password').value !== $('#setup-password2').value) return showError('#setup-error', 'The two passwords differ.');
  try {
    await api('/auth/setup', { method: 'POST', body: { password: $('#setup-password').value, code: $('#setup-code').value }, probe: true });
    $('#setup-form').reset();
    toast('Password set');
    enterApp();
  } catch (err) {
    showError('#setup-error', err.message);
  }
});

async function signOut() {
  hideAllValues();
  token = null;
  try { sessionStorage.removeItem(KEY); } catch {}
  try { await api('/auth/logout', { method: 'POST', probe: true }); } catch {}
  showLogin();
}
$('#logout').addEventListener('click', () => signOut());

// Change password
const passwordDialog = $('#password-dialog');
$('#change-password').addEventListener('click', () => {
  $('#password-form').reset();
  showError('#pw-error');
  passwordDialog.showModal();
  $('#pw-current').focus();
});
$('#password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if ($('#pw-new').value !== $('#pw-new2').value) return showError('#pw-error', 'The two new passwords differ.');
  try {
    await api('/auth/password', { method: 'PUT', body: { current: $('#pw-current').value, password: $('#pw-new').value }, probe: true });
    passwordDialog.close();
    toast('Password changed');
  } catch (err) {
    showError('#pw-error', err.message);
  }
});
passwordDialog.addEventListener('close', () => $('#password-form').reset());

// ---------- tabs ----------
function switchTab(name) {
  if (name !== 'secrets') hideAllValues();
  for (const b of document.querySelectorAll('[data-tab]')) b.setAttribute('aria-selected', String(b.dataset.tab === name));
  $('#tab-secrets').hidden = name !== 'secrets';
  $('#tab-activity').hidden = name !== 'activity';
  $('#tab-sync').hidden = name !== 'sync';
  history.replaceState(null, '', name === 'secrets' ? location.pathname : '#' + name);
  clearInterval(timer);
  if (name === 'secrets') {
    loadSecrets();
    timer = setInterval(loadSecrets, 10000);
  } else if (name === 'sync') {
    loadSync();
    timer = setInterval(loadSync, 5000);
  } else {
    loadActivity();
    timer = setInterval(() => $('#auto').checked && loadActivity(), 3000);
  }
}
for (const b of document.querySelectorAll('[data-tab]')) b.addEventListener('click', () => switchTab(b.dataset.tab));

// ---------- secrets ----------
const UNCAT = '\u0000uncategorized'; // chip key for secrets without a category
let categories = [];
let activeCategory = load('sm.category') ?? null; // null = all
const collapsed = new Set(JSON.parse(load('sm.collapsed') || '[]'));

function load(k) { try { return localStorage.getItem(k); } catch { return null; } }
function store(k, v) { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch {} }

// ---------- scopes ----------
// Each scope is a tab; '' = Default. Scopes exist on the server only while they
// hold a secret, so a new empty one is remembered in this browser until then.
const SCOPE_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
let serverScopes = [];
let scopesLoaded = false;
let extraScopes = JSON.parse(load('sm.extraScopes') || '[]').filter((x) => SCOPE_RE.test(x));
let activeScope = load('sm.scope') ?? '';
const scopeLabel = (scope) => scope || 'Default';
const allScopes = () => ['', ...[...new Set([...serverScopes, ...extraScopes])].sort()];
const inScope = () => secrets.filter((s) => s.scope === activeScope);
const sid = (s) => `${s.scope}/${s.name}`; // a secret's identity: scope + name
const secretPath = (s, suffix = '') => `/secrets/${encodeURIComponent(s.name)}${suffix}${s.scope ? `?scope=${encodeURIComponent(s.scope)}` : ''}`;
const named = (s) => (s.scope ? `${s.name} (${s.scope})` : s.name);

function setScope(scope) {
  if (scope === activeScope) return;
  hideAllValues();
  activeScope = scope;
  store('sm.scope', scope);
  activeCategory = null;
  store('sm.category', null);
  renderSecrets();
}

function renderScopes() {
  if (scopesLoaded && !allScopes().includes(activeScope)) activeScope = '';
  const counts = new Map();
  for (const s of secrets) counts.set(s.scope, (counts.get(s.scope) || 0) + 1);
  const tab = (scope) => {
    const n = counts.get(scope) || 0;
    return el('button', { class: 'scope-tab', role: 'tab', 'aria-selected': String(scope === activeScope), onclick: () => setScope(scope) },
      el('span', { class: scope ? '' : 'default' }, scopeLabel(scope)), el('span', { class: 'n' }, String(n)));
  };
  $('#scope-tabs').replaceChildren(
    ...allScopes().map(tab),
    el('button', { class: 'scope-tab new', onclick: openNewScope, title: 'Create a scope' }, '+ New scope'),
  );
  $('#scope-hint').replaceChildren(...(activeScope
    ? ['Only shells started with this scope get these: ', el('code', {}, `sm -s ${activeScope}`), ' (several: ', el('code', {}, `sm -s ${activeScope},other`), '). ',
      el('button', { class: 'link danger-text scope-delete', onclick: () => openScopeDelete(activeScope) }, 'Delete scope…')]
    : ['Plain ', el('code', {}, 'sm'), ' gets these. Add them to a scoped shell with ', el('code', {}, 'sm -s default,work'), '.']));
  $('#add-scope').textContent = scopeLabel(activeScope);
}

const scopeDialog = $('#scope-dialog');
function openNewScope() {
  $('#scope-form').reset();
  showError('#scope-error');
  scopeDialog.showModal();
  $('#scope-name').focus();
}
$('#scope-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const name = $('#scope-name').value.trim().toLowerCase();
  if (name === 'default') return showError('#scope-error', 'Default already exists: it is the first tab.');
  if (!SCOPE_RE.test(name)) return showError('#scope-error', 'Use lowercase letters, digits, _ and - (at most 32, starting with a letter or digit).');
  if (!allScopes().includes(name)) {
    extraScopes.push(name);
    store('sm.extraScopes', JSON.stringify(extraScopes));
  }
  scopeDialog.close();
  activeScope = null; // force the switch below to re-render
  setScope(name);
  addForm.hidden = false;
  $('#add-name').focus();
});

// Deleting a scope deletes its secrets too: never one click. An empty scope
// just needs a confirmation; one with secrets needs its name typed.
const scopeDeleteDialog = $('#scope-delete-dialog');
let scopeDeleteTarget = null;
const sdCount = () => secrets.filter((s) => s.scope === scopeDeleteTarget).length;
function sdUpdate() {
  $('#sd-submit').disabled = sdCount() > 0 && $('#sd-confirm').value.trim().toLowerCase() !== scopeDeleteTarget;
}
function openScopeDelete(scope) {
  scopeDeleteTarget = scope;
  const list = secrets.filter((s) => s.scope === scope).map((s) => s.name).sort();
  $('#scope-delete-form').reset();
  showError('#sd-error');
  $('#sd-name').textContent = scope;
  $('#sd-name2').textContent = scope;
  $('#sd-empty').hidden = list.length > 0;
  $('#sd-full').hidden = list.length === 0;
  $('#sd-count').textContent = `${list.length} secret${list.length === 1 ? '' : 's'}`;
  $('#sd-list').replaceChildren(...list.flatMap((n, i) => [i ? ', ' : '', el('code', {}, n)]));
  $('#sd-submit').textContent = list.length ? 'Delete scope and secrets' : 'Remove scope';
  sdUpdate();
  scopeDeleteDialog.showModal();
  (list.length ? $('#sd-confirm') : $('#scope-delete-form .ghost')).focus();
}
$('#sd-confirm').addEventListener('input', sdUpdate);
$('#scope-delete-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const scope = scopeDeleteTarget;
  try {
    if (sdCount()) {
      const r = await api(`/scopes/${encodeURIComponent(scope)}/delete`, { method: 'POST', body: { confirm: $('#sd-confirm').value } });
      hideAllValues();
      toast(`Scope ${scope} and ${r.names.length} secret${r.names.length === 1 ? '' : 's'} deleted`);
    } else toast(`Scope ${scope} removed`);
    extraScopes = extraScopes.filter((x) => x !== scope);
    store('sm.extraScopes', JSON.stringify(extraScopes));
    serverScopes = serverScopes.filter((x) => x !== scope);
    scopeDeleteDialog.close();
    setScope('');
    loadSecrets();
  } catch (err) {
    showError('#sd-error', err.message);
  }
});
scopeDeleteDialog.addEventListener('close', () => ($('#sd-confirm').value = ''));

async function loadSecrets() {
  try {
    const data = await api('/secrets');
    secrets = data.secrets.map((s) => ({ ...s, scope: s.scope || '' }));
    serverScopes = data.scopes || [];
    scopesLoaded = true;
    // A scope created here now exists on the server: no need to remember it.
    const before = extraScopes.length;
    extraScopes = extraScopes.filter((x) => !serverScopes.includes(x));
    if (extraScopes.length !== before) store('sm.extraScopes', JSON.stringify(extraScopes));
    $('#category-list').replaceChildren(...data.categories.map((c) => el('option', { value: c })));
    renderSecrets();
  } catch (err) {
    if (err.message !== 'unauthorized') toast(err.message, true);
  }
}

// Wrap case-insensitive matches of q in <mark>.
function highlight(text, q) {
  if (!q || !text) return text;
  const out = [];
  const lower = text.toLowerCase();
  let i = 0;
  for (let at = lower.indexOf(q); at !== -1; at = lower.indexOf(q, i)) {
    out.push(text.slice(i, at), el('mark', {}, text.slice(at, at + q.length)));
    i = at + q.length;
  }
  out.push(text.slice(i));
  return out;
}

const keyOf = (s) => s.category || UNCAT;
const matches = (s, q) => !q || s.name.toLowerCase().includes(q) || s.note.toLowerCase().includes(q) || s.category.toLowerCase().includes(q);

function renderChips(searched, base) {
  const counts = new Map();
  for (const s of searched) counts.set(keyOf(s), (counts.get(keyOf(s)) || 0) + 1);
  const keys = [...categories, ...(base.some((s) => !s.category) ? [UNCAT] : [])];
  if (activeCategory !== null && !keys.includes(activeCategory)) activeCategory = null;
  const chip = (key, label, n) =>
    el('button', {
      class: 'chip', role: 'tab', 'aria-selected': String(activeCategory === key),
      onclick: () => { activeCategory = activeCategory === key ? null : key; store('sm.category', activeCategory); renderSecrets(); },
    }, label, el('span', { class: 'n' }, String(n)));
  $('#categories').replaceChildren(
    ...(categories.length ? [
      chip(null, 'All', searched.length),
      ...keys.map((k) => chip(k, k === UNCAT ? 'Uncategorized' : k, counts.get(k) || 0)),
    ] : []),
  );
}

// ---------- viewing values ----------
const REVEAL_MS = 30000;
const revealed = new Map(); // sid (scope/name) -> { value, timer }

function hideValue(s) {
  const r = revealed.get(sid(s));
  if (!r) return;
  clearTimeout(r.timer);
  revealed.delete(sid(s));
  renderSecrets();
}
function hideAllValues() {
  for (const r of revealed.values()) clearTimeout(r.timer);
  if (revealed.size) {
    revealed.clear();
    renderSecrets();
  }
}
document.addEventListener('visibilitychange', () => document.hidden && hideAllValues());

// Show the current value (after rotating/generating), replacing an older one on screen.
async function revealFresh(s) {
  const r = revealed.get(sid(s));
  if (r) {
    clearTimeout(r.timer);
    revealed.delete(sid(s));
  }
  await showValue(s);
}

async function showValue(s) {
  if (revealed.has(sid(s))) return hideValue(s);
  try {
    const { value } = await api(secretPath(s, '/reveal'), { method: 'POST', probe: true });
    revealed.set(sid(s), { value, timer: setTimeout(() => hideValue(s), REVEAL_MS) });
    renderSecrets();
  } catch (err) {
    if (/admin token/.test(err.message)) return askAdminToken(() => showValue(s));
    toast(err.message, true);
  }
}

async function copyText(value, selectEl) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    getSelection().selectAllChildren(selectEl);
    toast('Copy blocked by the browser: the value is selected, press Ctrl+C');
    return false;
  }
}

function revealRow(s) {
  const { name } = s;
  const { value } = revealed.get(sid(s));
  const code = el('code', { class: 'secret-value' }, value);
  return el('tr', { class: 'reveal-row' },
    el('td', { colspan: '6' },
      el('div', { class: 'reveal-box' },
        code,
        el('div', { class: 'reveal-actions' },
          el('button', { class: 'small', onclick: async () => (await copyText(value, code)) && toast(`${name} copied`) }, 'Copy'),
          el('button', { class: 'small ghost', onclick: () => hideValue(s) }, 'Hide'),
          el('span', { class: 'muted' }, 'Hides after 30 s'),
        ),
      ),
    ),
  );
}

// Sign-in disabled mode: values still need the admin token, asked once per tab.
const tokenDialog = $('#token-dialog');
let afterToken = null;
function askAdminToken(then) {
  afterToken = then;
  $('#token-form').reset();
  showError('#token-error');
  tokenDialog.showModal();
  $('#admin-token').focus();
}
$('#token-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const candidate = $('#admin-token').value.trim();
  try {
    const who = await api('/whoami', { token: candidate });
    if (who.scope !== 'admin' || who.anonymous) throw new Error('That is not the admin token.');
    token = candidate;
    try { sessionStorage.setItem(KEY, token); } catch {}
    tokenDialog.close();
    afterToken?.();
  } catch (err) {
    showError('#token-error', err.message === 'missing or invalid token' ? 'That token is not valid for this server.' : err.message);
  }
});
tokenDialog.addEventListener('close', () => ($('#admin-token').value = ''));

function secretRow(s, q) {
  return el('tr', {},
    el('td', { class: 'name' }, highlight(s.name, q)),
    el('td', { class: 'note' }, el('button', { class: 'link', title: 'Edit scope, category and note', onclick: () => openEdit(s) }, s.note ? highlight(s.note, q) : '+ add note')),
    el('td', { class: 'when', title: fullTime(s.updatedAt) }, ago(s.updatedAt)),
    el('td', { class: 'when', title: fullTime(s.lastUsedAt) }, ago(s.lastUsedAt)),
    el('td', { class: 'num' }, String(s.uses)),
    el('td', { class: 'row-actions' },
      el('button', { class: 'link', 'aria-expanded': String(revealed.has(sid(s))), onclick: () => showValue(s) }, revealed.has(sid(s)) ? 'Hide' : 'Show'),
      el('button', { class: 'link', onclick: () => openEdit(s) }, 'Edit'),
      el('button', { class: 'link', title: 'Replace with a new random value', onclick: () => openRotate(s) }, 'Rotate'),
      el('button', { class: 'link', onclick: () => openReplace(s) }, 'Replace value'),
      el('button', { class: 'link danger-text', onclick: () => openDelete(s) }, 'Delete'),
    ),
  );
}

function renderSecrets() {
  renderScopes();
  const base = inScope();
  categories = [...new Set(base.map((s) => s.category).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  const q = $('#filter').value.trim().toLowerCase();
  const searched = base.filter((s) => matches(s, q));
  renderChips(searched, base);
  const shown = searched.filter((s) => activeCategory === null || keyOf(s) === activeCategory);

  $('#count').textContent = base.length ? `${shown.length} of ${base.length}` : '';
  $('#secrets-empty').hidden = base.length > 0;
  $('#secrets-empty-title').textContent = activeScope ? `No secrets in the scope ${activeScope} yet.` : 'No secrets yet.';
  $('#secrets-nomatch').hidden = !(base.length && !shown.length);
  $('#secrets-body').closest('table').hidden = !shown.length;

  // One section per category (named ones A-Z, Uncategorized last). With no
  // categories at all, a plain list.
  const groups = new Map();
  for (const s of shown) {
    if (!groups.has(keyOf(s))) groups.set(keyOf(s), []);
    groups.get(keyOf(s)).push(s);
  }
  const order = [...groups.keys()].sort((a, b) => (a === UNCAT) - (b === UNCAT) || a.localeCompare(b));
  const grouped = categories.length > 0;
  const rows = [];
  for (const key of order) {
    const list = groups.get(key);
    // A search opens collapsed groups so matches are never hidden.
    const closed = collapsed.has(key) && !q;
    if (grouped) {
      rows.push(el('tr', { class: 'group' + (closed ? ' collapsed' : '') },
        el('td', { colspan: '6' },
          el('button', {
            'aria-expanded': String(!closed),
            onclick: () => { collapsed.has(key) ? collapsed.delete(key) : collapsed.add(key); store('sm.collapsed', JSON.stringify([...collapsed])); renderSecrets(); },
          },
            el('span', { class: 'caret', 'aria-hidden': 'true' }, '▾'),
            key === UNCAT ? el('span', { class: 'uncat' }, 'Uncategorized') : highlight(key, q),
            el('span', { class: 'n' }, String(list.length)),
          ),
        ),
      ));
    }
    if (!closed) for (const s of list) rows.push(secretRow(s, q), ...(revealed.has(sid(s)) ? [revealRow(s)] : []));
  }
  $('#secrets-body').replaceChildren(...rows);
}
$('#filter').addEventListener('input', renderSecrets);
$('#clear-search').addEventListener('click', () => {
  $('#filter').value = '';
  activeCategory = null;
  store('sm.category', null);
  renderSecrets();
  $('#filter').focus();
});

// "/" focuses the search of the visible tab; Escape clears it.
document.addEventListener('keydown', (e) => {
  if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.target.closest('input, textarea, select, dialog[open]')) return;
  const input = $('#filter');
  if (!input.offsetParent) return; // Secrets tab only
  e.preventDefault();
  input.focus();
  input.select();
});
$('#filter').addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && e.target.value) {
    e.target.value = '';
    renderSecrets();
  }
});

// Edit category + note
const editDialog = $('#edit-dialog');
let editTarget = null;
function openEdit(s) {
  editTarget = s;
  $('#edit-name').textContent = s.name;
  $('#edit-scope').replaceChildren(...allScopes().map((x) => el('option', { value: x || 'default', selected: x === s.scope }, scopeLabel(x))));
  $('#edit-category').value = s.category;
  $('#edit-note').value = s.note;
  showError('#edit-error');
  editDialog.showModal();
  $('#edit-category').focus();
}
$('#edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const to = $('#edit-scope').value === 'default' ? '' : $('#edit-scope').value;
    const moved = to !== editTarget.scope;
    if (moved && secrets.some((x) => x.name === editTarget.name && x.scope === to)) return showError('#edit-error', `${editTarget.name} already exists in ${scopeLabel(to)}.`);
    // Send only what changed, so a move isn't also logged as an edit.
    const body = {
      ...($('#edit-category').value.trim() !== editTarget.category && { category: $('#edit-category').value }),
      ...($('#edit-note').value !== editTarget.note && { note: $('#edit-note').value }),
      ...(moved && { to: to || 'default' }),
    };
    if (!Object.keys(body).length) return editDialog.close();
    await api(secretPath(editTarget), { method: 'PATCH', body });
    editDialog.close();
    if (moved) hideValue(editTarget);
    toast(moved ? `${editTarget.name} moved to ${scopeLabel(to)}` : `${editTarget.name} updated`);
    loadSecrets();
  } catch (err) {
    showError('#edit-error', err.message);
  }
});

// Rotate: random value generated on the server.
const rotateDialog = $('#rotate-dialog');
let rotateTarget = null;
function openRotate(s) {
  rotateTarget = s;
  $('#rotate-name').textContent = named(s);
  showError('#rotate-error');
  $('#rotate-form').hidden = false;
  $('#rotate-result').hidden = true;
  $('#rotate-value').textContent = '';
  rotateDialog.showModal();
  $('#rotate-length').focus();
}
$('#rotate-copy').addEventListener('click', async () => {
  if (await copyText($('#rotate-value').textContent, $('#rotate-value'))) {
    $('#rotate-copy').textContent = 'Copied ✓';
    toast(`${rotateTarget.name} copied`);
  }
});
// Never leave the value in the page after the dialog closes.
rotateDialog.addEventListener('close', () => ($('#rotate-value').textContent = ''));

$('#rotate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const r = await api(secretPath(rotateTarget), {
      method: 'PUT', body: { generate: { length: Number($('#rotate-length').value), charset: $('#rotate-charset').value } },
    });
    // Switch the dialog to the new value with a Copy button (fetched like Show, so it's logged).
    const { value } = await api(secretPath(rotateTarget, '/reveal'), { method: 'POST', probe: true });
    if (revealed.has(sid(rotateTarget))) hideValue(rotateTarget); // an older value on screen is stale now
    $('#rotate-result-name').textContent = named(rotateTarget);
    $('#rotate-result-info').textContent = `${r.length} random characters`;
    $('#rotate-value').textContent = value;
    $('#rotate-form').hidden = true;
    $('#rotate-result').hidden = false;
    $('#rotate-copy').textContent = 'Copy';
    $('#rotate-copy').focus();
    loadSecrets();
  } catch (err) {
    showError('#rotate-error', err.message);
  }
});

// Add
const addForm = $('#add-form');
$('#add-generate').addEventListener('change', (e) => {
  const gen = e.target.checked;
  $('#add-gen').hidden = !gen;
  $('#add-value-row').hidden = gen;
  $('#add-value').required = !gen;
  $('#add-warn').hidden = true;
});
$('#add-toggle').addEventListener('click', () => {
  addForm.hidden = !addForm.hidden;
  if (!addForm.hidden) {
    // Pre-fill the category being viewed.
    if (activeCategory && activeCategory !== UNCAT && !$('#add-category').value) $('#add-category').value = activeCategory;
    $('#add-name').focus();
  }
});
$('#add-cancel').addEventListener('click', () => {
  addForm.reset();
  addForm.hidden = true;
  showError('#add-error');
});
$('#add-value').addEventListener('input', (e) => ($('#add-warn').hidden = !(e.target.value && e.target.value.length < 8)));
addForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('#add-error');
  const name = $('#add-name').value.trim();
  const target = { name, scope: activeScope };
  if (secrets.some((s) => s.name === name && s.scope === activeScope)) return showError('#add-error', `${name} already exists in ${scopeLabel(activeScope)}. Use "Replace value" in its row.`);
  try {
    const gen = $('#add-generate').checked;
    await api(secretPath(target), {
      method: 'PUT',
      body: {
        ...(gen ? { generate: { length: Number($('#add-length').value), charset: $('#add-charset').value } } : { value: $('#add-value').value }),
        note: $('#add-note').value, category: $('#add-category').value,
      },
    });
    addForm.reset();
    addForm.hidden = true;
    $('#add-warn').hidden = true;
    $('#add-generate').dispatchEvent(new Event('change'));
    if (gen) {
      toast(`${name} saved with a random value`);
      await loadSecrets();
      await revealFresh(target);
      return;
    }
    toast(`${name} saved`);
    loadSecrets();
  } catch (err) {
    showError('#add-error', err.message);
  }
});

// Show/hide value inputs
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-reveal]');
  if (!b) return;
  const input = document.getElementById(b.dataset.reveal);
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  b.textContent = show ? 'Hide' : 'Show';
});

// Replace
const replaceDialog = $('#replace-dialog');
let replaceTarget = null;
function openReplace(s) {
  replaceTarget = s;
  $('#replace-name').textContent = named(s);
  $('#replace-form').reset();
  $('#replace-value').type = 'password';
  showError('#replace-error');
  replaceDialog.showModal();
}
$('#replace-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api(secretPath(replaceTarget), { method: 'PUT', body: { value: $('#replace-value').value } });
    replaceDialog.close();
    toast(`${named(replaceTarget)} replaced`);
    loadSecrets();
  } catch (err) {
    showError('#replace-error', err.message);
  }
});

// Delete
const deleteDialog = $('#delete-dialog');
let deleteTarget = null;
function openDelete(s) {
  deleteTarget = s;
  $('#delete-name').textContent = named(s);
  deleteDialog.showModal();
}
$('#delete-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api(secretPath(deleteTarget), { method: 'DELETE' });
    deleteDialog.close();
    hideValue(deleteTarget);
    toast(`${named(deleteTarget)} deleted`);
    loadSecrets();
  } catch (err) {
    toast(err.message, true);
  }
});
for (const b of document.querySelectorAll('[data-close]')) b.addEventListener('click', () => b.closest('dialog').close());
// Wipe typed values when a dialog closes.
replaceDialog.addEventListener('close', () => ($('#replace-value').value = ''));

// ---------- activity ----------
// " (scope work)" after a secret's name, for non-default scopes.
const sc = (e) => (e.scope ? el('span', { class: 'scope-tag' }, e.scope) : null);
function describe(e) {
  switch (e.type) {
    case 'command':
      return [el('span', { class: 'badge command' }, e.mode === 'interactive' ? 'shell session' : 'command'),
        e.scopes?.length ? el('span', { class: 'scope-tag', title: 'Scopes this shell used' }, `-s ${e.scopes.join(',')}`) : null,
        e.mode === 'interactive' && (!e.command || e.command === '[]') ? el('span', { class: 'muted' }, 'interactive shell') : el('code', {}, e.command),
        e.cwd ? el('div', { class: 'muted' }, e.cwd) : null];
    case 'scope.delete': return [el('span', { class: 'badge delete' }, 'scope deleted'), el('span', { class: 'scope-tag' }, e.scope), el('span', { class: 'muted' }, e.names?.length ? ` ${e.names.length} deleted: ${e.names.join(', ')}` : ' empty')];
    case 'secret.move': return [el('span', { class: 'badge change' }, 'moved'), el('code', {}, e.name), el('span', { class: 'muted' }, ` ${scopeLabel(e.from)} → ${scopeLabel(e.to)}`)];
    case 'secret.create': return [el('span', { class: 'badge change' }, 'created'), el('code', {}, e.name), sc(e), e.by === 'client' ? el('span', { class: 'muted' }, ' by an agent (sm-add)') : null];
    case 'secret.update': return [el('span', { class: 'badge change' }, 'value replaced'), el('code', {}, e.name), sc(e)];
    case 'secret.rotate': return [el('span', { class: 'badge change' }, 'rotated'), el('code', {}, e.name), sc(e), e.generated ? el('span', { class: 'muted' }, ` → ${e.generated.length} random ${e.generated.charset} chars`) : null];
    case 'secret.note': return [el('span', { class: 'badge' }, 'note edited'), el('code', {}, e.name)];
    case 'secret.edit': return [el('span', { class: 'badge' }, 'details edited'), el('code', {}, e.name), sc(e), e.category !== undefined ? el('span', { class: 'muted' }, ` → ${e.category || 'Uncategorized'}`) : null];
    case 'secret.delete': return [el('span', { class: 'badge delete' }, 'deleted'), el('code', {}, e.name), sc(e)];
    case 'secret.reveal': return [el('span', { class: 'badge change' }, 'value viewed'), el('code', {}, e.name), sc(e), e.ip ? el('span', { class: 'muted' }, ` from ${e.ip.replace(/^::ffff:/, '')}`) : null];
    case 'auth.login': return [el('span', { class: 'badge' }, 'signed in'), el('span', { class: 'muted' }, `GUI from ${e.ip}`)];
    case 'auth.login-failed': return [el('span', { class: 'badge delete' }, 'wrong password'), el('span', { class: 'muted' }, `GUI from ${e.ip}`)];
    case 'auth.setup': return [el('span', { class: 'badge change' }, 'password set'), el('span', { class: 'muted' }, `first-time setup from ${e.ip}`)];
    case 'auth.setup-failed': return [el('span', { class: 'badge delete' }, 'setup refused'), el('span', { class: 'muted' }, `wrong setup code from ${e.ip}`)];
    case 'auth.password': return [el('span', { class: 'badge change' }, 'password changed'), el('span', { class: 'muted' }, `with the ${e.by} from ${e.ip}`)];
    case 'sync': return [el('span', { class: 'badge change' }, 'synced'), el('span', { class: 'muted' }, `${e.pulled} from the vault, ${e.pushed} to it (${e.reason})`)];
    case 'sync.conflict': return [el('span', { class: 'badge delete' }, 'sync conflict'), el('code', {}, e.name), el('span', { class: 'muted' }, ` changed on ${e.kept} and ${e.lost}; kept ${e.kept} (newer)`)];
    case 'sync.error': return [el('span', { class: 'badge delete' }, 'sync failed'), el('span', { class: 'muted' }, e.error)];
    case 'vault.init': return [el('span', { class: 'badge change' }, 'vault created'), el('code', {}, e.repo)];
    case 'vault.join': return [el('span', { class: 'badge change' }, 'joined vault'), el('code', {}, e.repo)];
    case 'vault.join-failed': return [el('span', { class: 'badge delete' }, 'vault join refused'), el('span', { class: 'muted' }, `wrong key file password from ${e.ip}`)];
    case 'resolve': return [el('span', { class: 'badge' }, 'values fetched'), el('span', { class: 'muted' }, `${e.count} secret${e.count === 1 ? '' : 's'} by ${e.by}` + (e.scopes ? `, scopes ${e.scopes.join(', ')}` : ''))];
    default: return [el('span', { class: 'badge' }, e.type)];
  }
}

const PAGE = 300;
let activityLimit = PAGE;

async function loadActivity() {
  try {
    const { entries, total, retention } = await api(`/audit?limit=${activityLimit}`);
    const keep = [retention.days ? `${retention.days} days` : null, retention.max ? `${retention.max.toLocaleString()} entries` : null].filter(Boolean).join(' or ');
    $('#activity-info').textContent = `Showing the latest ${entries.length.toLocaleString()} of ${total.toLocaleString()}.` + (keep ? ` Older activity is deleted after ${keep}, whichever comes first.` : '');
    $('#activity-more').hidden = entries.length >= total;
    const f = $('#activity-filter').value;
    const rows = entries.filter((e) => !f || e.type === f || e.type.startsWith(f + '.'));
    $('#activity-empty').hidden = rows.length > 0;
    $('#activity-empty').firstElementChild.textContent = entries.length ? 'Nothing of this kind.' : 'Nothing yet.';
    $('#activity-body').replaceChildren(
      ...rows.map((e) => {
        const red = Object.entries(e.redactions || {});
        const [badge, ...details] = describe(e);
        return el('tr', {},
          el('td', { class: 'when', title: fullTime(e.time) }, new Date(e.time).toLocaleTimeString()),
          el('td', {}, badge),
          el('td', { class: 'cmd' }, ...details),
          el('td', { class: 'num' }, red.length ? el('span', { class: 'redacted', title: red.map(([k, n]) => `${k}: ${n}`).join(', ') }, String(red.reduce((a, [, n]) => a + n, 0))) : ''),
          el('td', { class: 'num' + (e.exit ? ' exit-bad' : '') }, e.exit === null || e.exit === undefined ? '' : String(e.exit)),
        );
      }),
    );
  } catch (err) {
    if (err.message !== 'unauthorized') toast(err.message, true);
  }
}
$('#activity-filter').addEventListener('change', loadActivity);

$('#activity-more').addEventListener('click', () => {
  activityLimit += PAGE;
  loadActivity();
});

function showOpenMode(on) {
  $('#logout').hidden = on;
  $('#noauth').hidden = !on;
}

// ---------- start ----------
(async () => {
  // `smctl gui` passes the admin token in the URL fragment (never sent to the server).
  const fromHash = /(?:^#|&)token=([^&]+)/.exec(location.hash);
  if (fromHash) history.replaceState(null, '', location.pathname);
  let saved = null;
  try { saved = sessionStorage.getItem(KEY); } catch {}
  const candidate = fromHash ? decodeURIComponent(fromHash[1]) : saved;
  if (candidate) {
    try {
      const who = await api('/whoami', { token: candidate });
      if (who.scope === 'admin') {
        token = candidate;
        try { sessionStorage.setItem(KEY, token); } catch {}
        return enterApp();
      }
    } catch {}
    try { sessionStorage.removeItem(KEY); } catch {}
  }
  // Signed-in session cookie, or a server started with SM_NO_AUTH=1.
  try {
    const who = await api('/whoami', { probe: true });
    return enterApp({ openMode: who.anonymous });
  } catch {}
  showLogin();
})();

// ---------- sync (sm-vault) ----------
function downloadJson(obj, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2) + '\n'], { type: 'application/json' }));
  const a = el('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function inMinutes(iso) {
  const m = Math.round((Date.parse(iso) - Date.now()) / 60000);
  return m <= 0 ? 'in under a minute' : m === 1 ? 'in 1 minute' : `in ${m} minutes`;
}
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;

async function loadSync() {
  let st;
  try { st = await api('/vault'); } catch (err) { if (err.message !== 'unauthorized') toast(err.message, true); return; }
  $('#sync-on').hidden = !st.configured;
  $('#sync-off').hidden = st.configured;
  if (!st.configured) return;
  const r = st.lastResult;
  const known = r && r.vault !== undefined;
  const changedHere = known && st.local !== r.local;

  // Summary: one state and one sentence.
  let state, cls, headline;
  if (st.syncing) { state = '⟳ Syncing'; cls = 'busy'; headline = 'Comparing with the vault…'; }
  else if (st.lastError) { state = '✕ Sync failed'; cls = 'bad'; headline = 'The last sync did not complete (details below).'; }
  else if (!known) { state = '? Not checked'; cls = 'busy'; headline = 'Press Sync now to compare this server with the vault.'; }
  else if (changedHere) { state = '⟳ Changes pending'; cls = 'busy'; headline = `Secrets changed here since the last sync; they are uploaded within a few seconds.`; }
  else if (st.local === r.vault) { state = '✓ In sync'; cls = 'ok'; headline = st.local === 0 ? 'The vault and this server are both empty.' : `All ${plural(st.local, 'secret')} on this server are in the vault.`; }
  else { state = '! Not in sync'; cls = 'bad'; headline = `${st.local} here but ${r.vault} in the vault. Press Sync now; if it stays different, check Activity.`; }
  const sync = $('#sync-state');
  sync.textContent = state;
  sync.className = `sync-state ${cls}`;
  $('#sync-headline').textContent = headline;
  $('#sync-sub').textContent = [st.lastSync ? `Last sync ${ago(st.lastSync)}` : 'Never synced', st.nextSync ? `next ${inMinutes(st.nextSync)}` : null].filter(Boolean).join(' · ');

  $('#sync-local').textContent = String(st.local);
  $('#sync-vault').textContent = known ? `${r.vault}  (at the last sync)` : '—';
  $('#sync-last').textContent = !st.lastSync ? 'never'
    : `${new Date(st.lastSync).toLocaleString()} · ` + (r && (r.pulled || r.pushed)
      ? `${plural(r.pulled, 'change')} from the vault, ${plural(r.pushed, 'change')} to it${r.conflicts ? `, ${plural(r.conflicts, 'conflict')}` : ''}`
      : 'nothing needed changing');
  $('#sync-repo').textContent = st.repo;
  $('#sync-device').textContent = st.device;
  const mins = Math.round((st.intervalMs || 0) / 60000);
  $('#sync-how').textContent = `Syncs every ${plural(mins, 'minute')} and a few seconds after every change here. When the same secret changed on two servers, the newer change wins and Activity says so.`;
  showError('#sync-error', st.lastError ? `Last sync failed: ${st.lastError}` : '');
}

$('#sync-now').addEventListener('click', async (ev) => {
  ev.target.disabled = true;
  try {
    const { result } = await api('/vault/sync', { method: 'POST' });
    toast(result.pulled || result.pushed ? `Synced: ${result.pulled} from the vault, ${result.pushed} to it` : `Synced: already up to date (${result.vault} in the vault)`);
  } catch (err) { toast(err.message, true); }
  ev.target.disabled = false;
  loadSync();
});

$('#sync-show-key').addEventListener('click', async () => {
  try {
    const { publicKey } = await api('/vault/deploy-key');
    $('#sync-key').value = publicKey;
    $('#sync-key-box').hidden = false;
  } catch (err) { toast(err.message, true); }
});
$('#sync-copy-key').addEventListener('click', async () => { if (await copyText($('#sync-key').value, $('#sync-key'))) toast('Deploy key copied'); else $('#sync-key').select(); });

$('#sync-init-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter;
  btn.disabled = true;
  showError('#sync-init-error', '');
  try {
    const { keyFile } = await api('/vault/init', { method: 'POST', body: { repo: $('#sync-init-repo').value.trim(), password: $('#sync-init-pw').value } });
    $('#sync-init-pw').value = '';
    downloadJson(keyFile, 'sm-vault.key');
    toast('Vault created. Keep sm-vault.key safe (and one copy offline).');
    loadSync();
  } catch (err) { showError('#sync-init-error', err.message); }
  btn.disabled = false;
});

$('#sync-join-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter;
  btn.disabled = true;
  showError('#sync-join-error', '');
  try {
    const file = $('#sync-join-file').files[0];
    let keyFile;
    try { keyFile = JSON.parse(await file.text()); } catch { throw new Error('that is not an sm-vault key file'); }
    await api('/vault/join', { method: 'POST', body: { keyFile, password: $('#sync-join-pw').value } });
    $('#sync-join-pw').value = '';
    toast('Joined the vault');
    loadSync();
  } catch (err) { showError('#sync-join-error', err.message); }
  btn.disabled = false;
});

$('#sync-keyfile').addEventListener('click', () => {
  $('#kf-pw').value = '';
  showError('#kf-error', '');
  $('#keyfile-dialog').showModal();
});
$('#keyfile-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const { keyFile } = await api('/vault/key-file', { method: 'POST', body: { password: $('#kf-pw').value } });
    $('#kf-pw').value = '';
    downloadJson(keyFile, 'sm-vault.key');
    $('#keyfile-dialog').close();
  } catch (err) { showError('#kf-error', err.message); }
});
