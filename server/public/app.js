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
  switchTab(location.hash === '#activity' ? 'activity' : 'secrets');
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
  history.replaceState(null, '', name === 'activity' ? '#activity' : location.pathname);
  clearInterval(timer);
  if (name === 'secrets') {
    loadSecrets();
    timer = setInterval(loadSecrets, 10000);
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

async function loadSecrets() {
  try {
    const data = await api('/secrets');
    secrets = data.secrets;
    categories = data.categories;
    $('#category-list').replaceChildren(...categories.map((c) => el('option', { value: c })));
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

function renderChips(searched) {
  const counts = new Map();
  for (const s of searched) counts.set(keyOf(s), (counts.get(keyOf(s)) || 0) + 1);
  const keys = [...categories, ...(secrets.some((s) => !s.category) ? [UNCAT] : [])];
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
const revealed = new Map(); // name -> { value, timer }

function hideValue(name) {
  const r = revealed.get(name);
  if (!r) return;
  clearTimeout(r.timer);
  revealed.delete(name);
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

async function showValue(name) {
  if (revealed.has(name)) return hideValue(name);
  try {
    const { value } = await api(`/secrets/${encodeURIComponent(name)}/reveal`, { method: 'POST', probe: true });
    revealed.set(name, { value, timer: setTimeout(() => hideValue(name), REVEAL_MS) });
    renderSecrets();
  } catch (err) {
    if (/admin token/.test(err.message)) return askAdminToken(() => showValue(name));
    toast(err.message, true);
  }
}

function revealRow(name) {
  const { value } = revealed.get(name);
  const code = el('code', { class: 'secret-value' }, value);
  return el('tr', { class: 'reveal-row' },
    el('td', { colspan: '6' },
      el('div', { class: 'reveal-box' },
        code,
        el('div', { class: 'reveal-actions' },
          el('button', {
            class: 'small', onclick: async () => {
              try {
                await navigator.clipboard.writeText(value);
                toast(`${name} copied`);
              } catch {
                getSelection().selectAllChildren(code);
                toast('Copy blocked by the browser: the value is selected, press Ctrl+C');
              }
            },
          }, 'Copy'),
          el('button', { class: 'small ghost', onclick: () => hideValue(name) }, 'Hide'),
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
    el('td', { class: 'note' }, el('button', { class: 'link', title: 'Edit category and note', onclick: () => openEdit(s) }, s.note ? highlight(s.note, q) : '+ add note')),
    el('td', { class: 'when', title: fullTime(s.updatedAt) }, ago(s.updatedAt)),
    el('td', { class: 'when', title: fullTime(s.lastUsedAt) }, ago(s.lastUsedAt)),
    el('td', { class: 'num' }, String(s.uses)),
    el('td', { class: 'row-actions' },
      el('button', { class: 'link', 'aria-expanded': String(revealed.has(s.name)), onclick: () => showValue(s.name) }, revealed.has(s.name) ? 'Hide' : 'Show'),
      el('button', { class: 'link', onclick: () => openEdit(s) }, 'Edit'),
      el('button', { class: 'link', onclick: () => openReplace(s.name) }, 'Replace value'),
      el('button', { class: 'link danger-text', onclick: () => openDelete(s.name) }, 'Delete'),
    ),
  );
}

function renderSecrets() {
  const q = $('#filter').value.trim().toLowerCase();
  const searched = secrets.filter((s) => matches(s, q));
  renderChips(searched);
  const shown = searched.filter((s) => activeCategory === null || keyOf(s) === activeCategory);

  $('#count').textContent = secrets.length ? `${shown.length} of ${secrets.length}` : '';
  $('#secrets-empty').hidden = secrets.length > 0;
  $('#secrets-nomatch').hidden = !(secrets.length && !shown.length);
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
    if (!closed) for (const s of list) rows.push(secretRow(s, q), ...(revealed.has(s.name) ? [revealRow(s.name)] : []));
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
  editTarget = s.name;
  $('#edit-name').textContent = s.name;
  $('#edit-category').value = s.category;
  $('#edit-note').value = s.note;
  showError('#edit-error');
  editDialog.showModal();
  $('#edit-category').focus();
}
$('#edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api(`/secrets/${encodeURIComponent(editTarget)}`, { method: 'PATCH', body: { category: $('#edit-category').value, note: $('#edit-note').value } });
    editDialog.close();
    toast(`${editTarget} updated`);
    loadSecrets();
  } catch (err) {
    showError('#edit-error', err.message);
  }
});

// Add
const addForm = $('#add-form');
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
  if (secrets.some((s) => s.name === name)) return showError('#add-error', `${name} already exists. Use "Replace value" in its row.`);
  try {
    await api(`/secrets/${encodeURIComponent(name)}`, { method: 'PUT', body: { value: $('#add-value').value, note: $('#add-note').value, category: $('#add-category').value } });
    addForm.reset();
    addForm.hidden = true;
    $('#add-warn').hidden = true;
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
function openReplace(name) {
  replaceTarget = name;
  $('#replace-name').textContent = name;
  $('#replace-form').reset();
  $('#replace-value').type = 'password';
  showError('#replace-error');
  replaceDialog.showModal();
}
$('#replace-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api(`/secrets/${encodeURIComponent(replaceTarget)}`, { method: 'PUT', body: { value: $('#replace-value').value } });
    replaceDialog.close();
    toast(`${replaceTarget} replaced`);
    loadSecrets();
  } catch (err) {
    showError('#replace-error', err.message);
  }
});

// Delete
const deleteDialog = $('#delete-dialog');
let deleteTarget = null;
function openDelete(name) {
  deleteTarget = name;
  $('#delete-name').textContent = name;
  deleteDialog.showModal();
}
$('#delete-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api(`/secrets/${encodeURIComponent(deleteTarget)}`, { method: 'DELETE' });
    deleteDialog.close();
    toast(`${deleteTarget} deleted`);
    loadSecrets();
  } catch (err) {
    toast(err.message, true);
  }
});
for (const b of document.querySelectorAll('[data-close]')) b.addEventListener('click', () => b.closest('dialog').close());
// Wipe typed values when a dialog closes.
replaceDialog.addEventListener('close', () => ($('#replace-value').value = ''));

// ---------- activity ----------
function describe(e) {
  switch (e.type) {
    case 'command':
      return [el('span', { class: 'badge command' }, e.mode === 'interactive' ? 'shell session' : 'command'),
        e.mode === 'interactive' && (!e.command || e.command === '[]') ? el('span', { class: 'muted' }, 'interactive shell') : el('code', {}, e.command),
        e.cwd ? el('div', { class: 'muted' }, e.cwd) : null];
    case 'secret.create': return [el('span', { class: 'badge change' }, 'created'), el('code', {}, e.name), e.by === 'client' ? el('span', { class: 'muted' }, ' by an agent (sm-add)') : null];
    case 'secret.update': return [el('span', { class: 'badge change' }, 'value replaced'), el('code', {}, e.name)];
    case 'secret.note': return [el('span', { class: 'badge' }, 'note edited'), el('code', {}, e.name)];
    case 'secret.edit': return [el('span', { class: 'badge' }, 'details edited'), el('code', {}, e.name), e.category !== undefined ? el('span', { class: 'muted' }, ` → ${e.category || 'Uncategorized'}`) : null];
    case 'secret.delete': return [el('span', { class: 'badge delete' }, 'deleted'), el('code', {}, e.name)];
    case 'secret.reveal': return [el('span', { class: 'badge change' }, 'value viewed'), el('code', {}, e.name), e.ip ? el('span', { class: 'muted' }, ` from ${e.ip.replace(/^::ffff:/, '')}`) : null];
    case 'auth.login': return [el('span', { class: 'badge' }, 'signed in'), el('span', { class: 'muted' }, `GUI from ${e.ip}`)];
    case 'auth.login-failed': return [el('span', { class: 'badge delete' }, 'wrong password'), el('span', { class: 'muted' }, `GUI from ${e.ip}`)];
    case 'auth.setup': return [el('span', { class: 'badge change' }, 'password set'), el('span', { class: 'muted' }, `first-time setup from ${e.ip}`)];
    case 'auth.setup-failed': return [el('span', { class: 'badge delete' }, 'setup refused'), el('span', { class: 'muted' }, `wrong setup code from ${e.ip}`)];
    case 'auth.password': return [el('span', { class: 'badge change' }, 'password changed'), el('span', { class: 'muted' }, `with the ${e.by} from ${e.ip}`)];
    case 'resolve': return [el('span', { class: 'badge' }, 'values fetched'), el('span', { class: 'muted' }, `${e.count} secret${e.count === 1 ? '' : 's'} by ${e.by}`)];
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
