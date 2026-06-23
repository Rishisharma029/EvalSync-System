/* ══════════════════════════════════════════════════════════
   EVALSYNC — Application Engine v3.2.1
   Queue-Based Secure Submission Management System for CBSE
   ══════════════════════════════════════════════════════════ */

'use strict';

/* ─── CONSTANTS & CONFIG ──────────────────────────────────── */
const DEMO_USER = {
  email: 'evaluator@cbse.gov.in',
  password: 'CBSE@2024',
  name: 'Rajan Mehta',
  initials: 'RM',
  role: 'Senior Evaluator',
  id: 'EVL-DEL-0412-2024',
  subject: 'Mathematics (041)',
  center: 'DEL-0412',
};

const SUBJECTS = ['Mathematics', 'Physics', 'Chemistry', 'Biology', 'Computer Sc', 'English', 'Economics', 'History', 'Geography'];
const SUBJECT_CODES = { 'Mathematics': '041', 'Physics': '042', 'Chemistry': '043', 'Biology': '044', 'Computer Sc': '083', 'English': '301', 'Economics': '030', 'History': '027', 'Geography': '029' };
const SETS = ['A', 'B', 'C', 'D'];
const REGIONS = ['DEL', 'MUM', 'CHN', 'KOL', 'BLR', 'HYD', 'AHM', 'JDP', 'LKW'];
const WORKER_STAGES = ['IDLE', 'FETCHING', 'VALIDATING', 'HASHING', 'ENCRYPTING', 'SYNCING', 'DONE'];
const STAGE_LABELS = { 'IDLE': '—', 'FETCHING': 'Fetching item from queue', 'VALIDATING': 'Validating file integrity', 'HASHING': 'Computing SHA-256 hash', 'ENCRYPTING': 'AES-256-GCM encryption', 'SYNCING': 'Syncing to central DB', 'DONE': 'Task complete' };
const LOG_CONFIG = { maxTerminal: 200, maxFeed: 50, maxDbLog: 80, maxSecLog: 60, maxQueueCols: 8 };

/* ─── MY SUBMISSIONS (declared early so trackMySubmission works everywhere) ─ */
const mySubmissions = [];

let csrfToken = '';

async function fetchCsrfToken() {
  try {
    const response = await fetch('/api/csrf-token');
    if (response.ok) {
      const data = await response.json();
      csrfToken = data.csrfToken;
    }
  } catch (err) {
    console.warn('[EvalSync API] Could not fetch CSRF token.', err);
  }
}

/* ─── STATE ───────────────────────────────────────────────── */
const state = {
  user: null,
  isLoggedIn: false,
  currentView: 'dashboard',
  simulation: {
    running: true,
    paused: false,
    autoScale: true,
    retryEnabled: true,
    loggingEnabled: true,
    encryptEnforced: true,
    queueThreshold: 30,
    spikesCount: 0,
    sessionStart: null,
  },
  queue: {
    incoming: [],
    processing: [],
    completed: [],
    failed: [],
    retry: [],
  },
  workers: [],
  database: {
    totalRecords: 2476,
    todayRecords: 0,
    pendingSync: 0,
    dbSizeMB: 847.3,
    recentRecords: [],
  },
  stats: {
    totalSubmitted: 0,
    totalProcessed: 0,
    totalFailed: 0,
    totalRetried: 0,
    peakQueueDepth: 0,
    processTimes: [],
    throughputHistory: new Array(60).fill(0),
    processedHistory: new Array(60).fill(0),
    queueDepthHistory: new Array(60).fill(0),
    workerHistory: new Array(60).fill(0),
    subjectCounts: {},
    analyticsTimeline: [],
    submittedHistory: new Array(300).fill(0),
    successHistory: new Array(300).fill(0),
    failHistory: new Array(300).fill(0),
    dbSyncBatches: new Array(20).fill(0),
    nextBatch: 0,
  },
  submission: {
    step: 1,
    files: [],
    data: null,
    processing: false,
  },
  security: {
    recentIds: [],
    auditLog: [],
  },
  timers: {},
  sparkData: { total: [], queue: [], success: [], speed: [] },
  counter: 0,
};

/* ─── UTILITY HELPERS ─────────────────────────────────────── */
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randFloat(min, max) { return Math.random() * (max - min) + min; }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function pad(n, w = 2) { return String(n).padStart(w, '0'); }
function formatTime(d) { d = d || new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
function formatBytes(bytes) { if (bytes < 1024) return bytes + ' B'; if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'; return (bytes / (1024 * 1024)).toFixed(2) + ' MB'; }
function eid(id) { return document.getElementById(id); }
function shortHash(full) { return full.substring(0, 8) + '...' + full.substring(56); }
function setManagedInterval(key, fn, ms) {
  if (state.timers[key]) clearInterval(state.timers[key]);
  state.timers[key] = setInterval(fn, ms);
  return state.timers[key];
}
function clearManagedTimers() {
  Object.values(state.timers).forEach(timer => clearInterval(timer));
  state.timers = {};
}

function generateSHA256Like() {
  const chars = '0123456789abcdef';
  return Array.from({ length: 64 }, () => chars[rand(0, 15)]).join('');
}

function generateSubmissionId(subject, region) {
  const sub = (subject || 'MATH').toUpperCase().substring(0, 4).padEnd(4, 'X');
  const reg = region || pick(REGIONS);
  const ts = Date.now().toString().slice(-8);
  const rnd = Array.from({ length: 4 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[rand(0, 35)]).join('');
  return `CBSE-2024-${sub}-${reg}-${ts}-${rnd}`;
}

function generateAESKey() {
  return Array.from({ length: 64 }, () => '0123456789abcdef'[rand(0, 15)]).join('');
}

function generateIV() {
  return Array.from({ length: 24 }, () => '0123456789abcdef'[rand(0, 15)]).join('');
}

function generateTag() {
  return Array.from({ length: 32 }, () => '0123456789abcdef'[rand(0, 15)]).join('');
}

function generateRollNo() {
  return '2024' + Array.from({ length: 6 }, () => rand(0, 9)).join('');
}

function generateEncryptedPayload() {
  return Array.from({ length: rand(80, 120) }, () => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/='[rand(0, 63)]).join('');
}

function timeAgo(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60) return diff + 's ago';
  return Math.floor(diff / 60) + 'm ago';
}

/* ─── DOM HELPERS ─────────────────────────────────────────── */
function setText(id, val) { const el = eid(id); if (el) el.textContent = val; }
function setWidth(id, pct) { const el = eid(id); if (el) el.style.width = pct + '%'; }
function addClass(id, cls) { const el = eid(id); if (el) el.classList.add(cls); }
function removeClass(id, cls) { const el = eid(id); if (el) el.classList.remove(cls); }

/* ─── NOTIFICATION SYSTEM ─────────────────────────────────── */
function notify(title, msg, type = 'info', duration = 4000) {
  const icons = { success: '✅', warning: '⚠️', error: '❌', info: '💡', spike: '⚡' };
  const container = eid('notifications-container');
  const el = document.createElement('div');
  el.className = `notification ${type}`;
  el.innerHTML = `
    <span class="notif-icon">${icons[type] || icons.info}</span>
    <div class="notif-body">
      <span class="notif-title"></span>
      <span class="notif-msg"></span>
    </div>
    <button class="notif-close">✕</button>
  `;
  el.querySelector('.notif-title').textContent = title;
  el.querySelector('.notif-msg').textContent = msg;
  el.querySelector('.notif-close').onclick = function () { el.remove(); };
  container.appendChild(el);
  const dot = eid('notif-dot');
  if (dot) dot.classList.add('show');
  setTimeout(() => {
    el.classList.add('removing');
    setTimeout(() => el.remove(), 300);
  }, duration);
}

/* ─── CONFIRM MODAL ───────────────────────────────────────── */
function confirmAction(title, msg, icon, onConfirm) {
  eid('modal-icon').textContent = icon || '⚠️';
  eid('modal-title').textContent = title;
  eid('modal-msg').textContent = msg;
  eid('confirm-modal').classList.remove('hidden');
  const confirmBtn = eid('modal-confirm');
  const cancelBtn = eid('modal-cancel');
  const close = () => eid('confirm-modal').classList.add('hidden');
  confirmBtn.onclick = () => { close(); onConfirm(); };
  cancelBtn.onclick = close;
}

/* ─── TERMINAL LOG ────────────────────────────────────────── */
function termLog(level, msg) {
  if (!state.simulation.loggingEnabled) return;
  const terminal = eid('terminal');
  if (!terminal) return;
  const line = document.createElement('div');
  line.className = 'term-line';
  line.innerHTML = `<span class="tl-time">${formatTime()}</span><span class="tl-level ${level}">${level.padEnd(7)}</span><span class="tl-msg"></span>`;
  line.querySelector('.tl-msg').textContent = msg;
  terminal.appendChild(line);
  if (terminal.children.length > LOG_CONFIG.maxTerminal) terminal.firstChild.remove();
  terminal.scrollTop = terminal.scrollHeight;
}

/* ─── LIVE FEED ───────────────────────────────────────────── */
function feedLog(icon, text, type = 'info') {
  const feed = eid('live-feed');
  if (!feed) return;
  const item = document.createElement('div');
  item.className = `feed-item ${type}`;
  item.innerHTML = `<span class="fi-time">${formatTime()}</span><span class="fi-icon">${icon}</span><span class="fi-text">${text}</span>`;
  feed.insertBefore(item, feed.firstChild);
  if (feed.children.length > LOG_CONFIG.maxFeed) feed.lastChild.remove();
}

/* ─── DB LOG ──────────────────────────────────────────────── */
function dbLog(icon, text) {
  const log = eid('db-log');
  if (!log) return;
  const item = document.createElement('div');
  item.className = 'db-log-item';
  item.innerHTML = `<span class="dli-time">${formatTime()}</span><span class="dli-icon">${icon}</span><span class="dli-text">${text}</span>`;
  log.insertBefore(item, log.firstChild);
  if (log.children.length > LOG_CONFIG.maxDbLog) log.lastChild.remove();
}

/* ─── SECURITY LOG ────────────────────────────────────────── */
function secLog(icon, text, type = 'ok') {
  const log = eid('security-log');
  if (!log) return;
  const item = document.createElement('div');
  item.className = `sec-log-item ${type}`;
  item.innerHTML = `<span class="sli-time">${formatTime()}</span><span class="sli-icon">${icon}</span><span class="sli-text">${text}</span>`;
  log.insertBefore(item, log.firstChild);
  if (log.children.length > LOG_CONFIG.maxSecLog) log.lastChild.remove();
}

/* ─── NAVIGATION ──────────────────────────────────────────── */
function switchView(viewName) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const view = eid(`view-${viewName}`);
  if (view) view.classList.add('active');
  const navItem = eid(`nav-${viewName}`);
  if (navItem) navItem.classList.add('active');
  state.currentView = viewName;
  const labels = { dashboard: 'Dashboard', submit: 'Submit Script', queue: 'Queue Monitor', workers: 'Worker Pool', analytics: 'Analytics & Logs', security: 'Security Center', database: 'Database Sync', admin: 'Admin Control' };
  setText('bc-current', labels[viewName] || viewName);
  if (viewName === 'analytics') { setTimeout(() => { renderAnalyticsChart(); renderSubjectChart(); }, 100); }
  if (viewName === 'database') { setTimeout(() => renderDbSyncChart(), 100); }
}

/* ─── SUBMISSION WIZARD ───────────────────────────────────── */
window.nextStep = function (step) {
  if (step === 3) {
    const roll = eid('sub-roll') ? eid('sub-roll').value.trim() : '';
    const marks = eid('sub-marks') ? eid('sub-marks').value.trim() : '';
    if (!roll) { notify('Missing Field', 'Please enter a student roll number', 'warning'); return; }
    if (!marks) { notify('Missing Field', 'Please enter total marks awarded', 'warning'); return; }
  }
  if (step === 4 && state.submission.files.length === 0) {
    notify('No Files', 'Please upload at least one answer script file', 'warning');
    return;
  }

  // Mark previous steps complete
  for (let i = 1; i < step; i++) {
    const si = eid(`st-${i}`);
    if (si) { si.classList.remove('active'); si.classList.add('completed'); si.querySelector('.step-circle').textContent = '✓'; }
    const sl = eid(`sl-${i}`);
    if (sl) sl.classList.add('completed');
  }

  document.querySelectorAll('.step-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.step-item').forEach(s => s.classList.remove('active'));
  const panel = eid(`sp-${step}`);
  if (panel) panel.classList.add('active');
  const stepItem = eid(`st-${step}`);
  if (stepItem) { stepItem.classList.add('active'); stepItem.classList.remove('completed'); }
  state.submission.step = step;
};

window.startProcessing = function () {
  if (state.submission.files.length === 0) return;
  nextStep(4);
  runSubmissionProcessing();
};

window.resetSubmission = function () {
  state.submission.files = [];
  state.submission.step = 1;
  const uploaded = eid('uploaded-files');
  if (uploaded) uploaded.innerHTML = '';
  const btn = eid('btn-proceed-upload');
  if (btn) btn.disabled = true;

  document.querySelectorAll('.step-item').forEach(s => { s.classList.remove('active', 'completed'); s.querySelector('.step-circle').textContent = s.dataset.step; });
  document.querySelectorAll('.step-line').forEach(l => l.classList.remove('completed'));
  document.querySelectorAll('.step-panel').forEach(p => p.classList.remove('active'));
  const sp1 = eid('sp-1'); if (sp1) sp1.classList.add('active');
  const st1 = eid('st-1'); if (st1) st1.classList.add('active');
  state.submission.step = 1;

  // Reset proc steps
  ['validate', 'hash', 'encrypt', 'id', 'enqueue'].forEach(key => {
    const step = eid(`proc-${key}`);
    if (step) { step.classList.remove('active', 'done'); step.querySelector('.proc-icon').classList.remove('active', 'done'); step.querySelector('.proc-icon').classList.add('pending'); step.querySelector('.proc-icon').textContent = '⏳'; }
    const ps = eid(`ps-${key}`);
    if (ps) ps.textContent = 'Pending';
  });
  setWidth('proc-progress-fill', 0);
};

async function runSubmissionProcessing() {
  const steps = [
    { key: 'validate', icon: '📋', duration: 1000, label: 'Validated', detail: `File OK · ${state.submission.files.length} script(s) · ${formatBytes(state.submission.files.reduce((a, f) => a + f.size, 0))}` },
    { key: 'hash', icon: '#️⃣', duration: 1200, label: 'Hashed', detail: 'SHA-256: ' + generateSHA256Like().substring(0, 24) + '...' },
    { key: 'encrypt', icon: '🔐', duration: 1500, label: 'Encrypted', detail: 'AES-256-GCM · Key: ' + generateAESKey().substring(0, 16) + '...' },
    { key: 'id', icon: '🆔', duration: 800, label: 'Assigned', detail: '' },
    { key: 'enqueue', icon: '📦', duration: 600, label: 'Queued', detail: 'Added to processing queue' },
  ];

  const sid = generateSubmissionId('MATH', 'DEL');
  const hash = generateSHA256Like();
  steps[3].detail = `ID: ${sid}`;

  for (let i = 0; i < steps.length; i++) {
    const { key, icon, duration, label, detail } = steps[i];
    const stepEl = eid(`proc-${key}`);
    const psEl = eid(`ps-${key}`);
    const pdEl = eid(`pd-${key}`);
    const iconEl = stepEl ? stepEl.querySelector('.proc-icon') : null;

    if (stepEl) stepEl.classList.add('active');
    if (iconEl) { iconEl.classList.remove('pending'); iconEl.classList.add('active'); iconEl.textContent = '⚙️'; }
    if (psEl) psEl.textContent = 'Processing...';

    await new Promise(r => setTimeout(r, duration));

    if (stepEl) { stepEl.classList.remove('active'); stepEl.classList.add('done'); }
    if (iconEl) { iconEl.classList.remove('active'); iconEl.classList.add('done'); iconEl.textContent = icon; }
    if (psEl) psEl.textContent = label;
    if (pdEl && detail) pdEl.textContent = detail;

    setWidth('proc-progress-fill', ((i + 1) / steps.length) * 100);
    termLog('SUCCESS', `<span>[SUBMIT] Step ${i + 1}/${steps.length} — ${label}: ${detail.substring(0, 60)}</span>`);
  }

  // Enqueue in the sim
  const sub = createSubmission({ id: sid, hash, manual: true });
  state.queue.incoming.push(sub);
  state.stats.totalSubmitted++;

  // Track in My Submissions for the evaluator
  trackMySubmission(sub);

  // Show confirmation
  await new Promise(r => setTimeout(r, 400));
  nextStep(5);
  setText('cd-sid', sid);
  setText('cd-hash', hash.substring(0, 20) + '...' + hash.substring(44));
  setText('cd-pos', '#' + (state.queue.incoming.length + state.queue.processing.length));
  setText('cd-eta', `~${rand(15, 60)} seconds`);

  notify('Submission Accepted', `ID: ${sid.substring(0, 20)}...`, 'success');
  feedLog('📤', `<strong>Manual submission</strong> queued · ID: ${sid.substring(0, 16)}...`, 'enqueue');
  secLog('🔐', `<strong>AES-256</strong> encryption applied · Hash: ${hash.substring(0, 12)}...`, 'ok');
}

/* ─── UPLOAD ZONE ─────────────────────────────────────────── */
function initUploadZone() {
  const zone = eid('upload-zone');
  const input = eid('file-input');
  const btn = eid('btn-proceed-upload');
  if (!zone || !input) return;

  zone.onclick = () => input.click();

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.classList.remove('dragover');
    handleFiles(Array.from(e.dataTransfer.files));
  });

  input.addEventListener('change', () => { handleFiles(Array.from(input.files)); input.value = ''; });

  function handleFiles(files) {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'];
    const maxSize = 50 * 1024 * 1024;
    files.forEach(file => {
      if (!allowed.includes(file.type) && !file.name.match(/\.(pdf|jpg|jpeg|png|tif|tiff)$/i)) {
        notify('Invalid File', `${file.name} — unsupported format`, 'error'); return;
      }
      if (file.size > maxSize) { notify('File Too Large', `${file.name} exceeds 50MB limit`, 'error'); return; }
      state.submission.files.push(file);
      addFileCard(file);
      termLog('INFO', `<span>File loaded: <strong>${file.name}</strong> (${formatBytes(file.size)})</span>`);
    });
    if (btn) btn.disabled = state.submission.files.length === 0;
  }

  function addFileCard(file) {
    const container = eid('uploaded-files');
    if (!container) return;
    const ext = file.name.split('.').pop().toLowerCase();
    const icons = { pdf: '📄', jpg: '🖼️', jpeg: '🖼️', png: '🖼️', tif: '📑', tiff: '📑' };
    const card = document.createElement('div');
    card.className = 'uploaded-file';
    card.dataset.filename = file.name;
    card.innerHTML = `
      <span class="uf-icon">${icons[ext] || '📎'}</span>
      <div class="uf-info">
        <span class="uf-name"></span>
        <span class="uf-size"></span>
      </div>
      <button class="uf-remove" title="Remove">✕</button>
    `;
    card.querySelector('.uf-name').textContent = file.name;
    card.querySelector('.uf-size').textContent = `${formatBytes(file.size)} · ${ext.toUpperCase()}`;
    card.querySelector('.uf-remove').onclick = () => {
      state.submission.files = state.submission.files.filter(f => f.name !== file.name);
      card.remove();
      if (btn) btn.disabled = state.submission.files.length === 0;
    };
    container.appendChild(card);
  }
}

/* ─── WORKER SYSTEM ───────────────────────────────────────── */
function createWorker(id, isScaled = false) {
  return {
    id, isScaled,
    status: 'idle',
    stage: 'IDLE',
    progress: 0,
    currentTask: null,
    tasksCompleted: 0,
    totalProcessingTime: 0,
    errors: 0,
    startTime: Date.now(),
    stageProgress: 0,
    stageInterval: null,
  };
}

function initWorkers(count = 6) {
  state.workers = Array.from({ length: count }, (_, i) => createWorker(i + 1, false));
  renderWorkers();
}

function renderWorkers() {
  const grid = eid('workers-grid');
  if (!grid) return;
  grid.innerHTML = '';
  state.workers.forEach(w => {
    const card = document.createElement('div');
    card.className = `worker-card ${w.status === 'active' || w.status === 'processing' ? 'active-worker' : ''} ${w.isScaled ? 'scaled-worker' : ''}`;
    card.id = `wcard-${w.id}`;
    const avgTime = w.tasksCompleted > 0 ? Math.round(w.totalProcessingTime / w.tasksCompleted) : 0;
    const statusColor = { idle: 'idle', active: 'processing', processing: 'processing' };
    card.innerHTML = `
      <div class="wc-header">
        <div class="wc-title">
          <span class="wc-icon">⚙️</span>
          <span class="wc-name">Worker-${String(w.id).padStart(2, '0')}${w.isScaled ? ' <span style="color:var(--primary);font-size:.6rem">AUTO</span>' : ''}</span>
        </div>
        <span class="wc-status-badge ${statusColor[w.status] || 'idle'}">${w.status.toUpperCase()}</span>
      </div>
      <div class="wc-task">
        Stage: <span class="wc-task-name" id="wstage-${w.id}">${STAGE_LABELS[w.stage]}</span>
      </div>
      <div class="wc-progress">
        <div class="wcp-header">
          <span id="wctask-${w.id}">${w.currentTask ? w.currentTask.id.substring(0, 20) + '...' : 'No task'}</span>
          <span id="wcpct-${w.id}">${w.progress}%</span>
        </div>
        <div class="wcp-bar"><div class="wcp-fill" id="wcpfill-${w.id}" style="width:${w.progress}%"></div></div>
      </div>
      <div class="wc-stats">
        <div class="wcs"><span class="wcs-val text-success" id="wcc-${w.id}">${w.tasksCompleted}</span><span class="wcs-label">Done</span></div>
        <div class="wcs"><span class="wcs-val" id="wca-${w.id}">${avgTime}ms</span><span class="wcs-label">Avg Time</span></div>
        <div class="wcs"><span class="wcs-val text-danger" id="wce-${w.id}">${w.errors}</span><span class="wcs-label">Errors</span></div>
      </div>
    `;
    grid.appendChild(card);
  });
  updateWorkerBadges();
}

function updateWorkerCard(w) {
  const card = eid(`wcard-${w.id}`);
  if (!card) return;
  const statusColor = { idle: 'idle', active: 'processing', processing: 'processing' };
  const badge = card.querySelector('.wc-status-badge');
  if (badge) { badge.className = `wc-status-badge ${statusColor[w.status] || 'idle'}`; badge.textContent = w.status.toUpperCase(); }
  setText(`wstage-${w.id}`, STAGE_LABELS[w.stage] || w.stage);
  setText(`wctask-${w.id}`, w.currentTask ? w.currentTask.id.substring(0, 22) + '...' : 'No task');
  setText(`wcpct-${w.id}`, w.progress + '%');
  setWidth(`wcpfill-${w.id}`, w.progress);
  const avgTime = w.tasksCompleted > 0 ? Math.round(w.totalProcessingTime / w.tasksCompleted) : 0;
  setText(`wcc-${w.id}`, w.tasksCompleted);
  setText(`wca-${w.id}`, avgTime + 'ms');
  setText(`wce-${w.id}`, w.errors);
  card.className = `worker-card ${w.status === 'active' || w.status === 'processing' ? 'active-worker' : ''} ${w.isScaled ? 'scaled-worker' : ''}`;
}

function updateWorkerBadges() {
  const active = state.workers.filter(w => w.status === 'active' || w.status === 'processing').length;
  const idle = state.workers.filter(w => w.status === 'idle').length;
  const scaled = state.workers.filter(w => w.isScaled).length;
  setText('wsb-active', `${active} Active`);
  setText('wsb-idle', `${idle} Idle`);
  setText('wsb-scaled', `${scaled} Auto-Scaled`);
  setText('nb-workers', state.workers.length);

  // Mini worker grid on dashboard
  const mini = eid('mini-worker-grid');
  if (mini) {
    mini.innerHTML = '';
    state.workers.slice(0, 9).forEach(w => {
      const s = w.status === 'processing' || w.status === 'active' ? 'processing' : w.status;
      const c = document.createElement('div');
      c.className = 'mini-worker-card';
      c.innerHTML = `<span class="mwc-id">W-${String(w.id).padStart(2, '0')}</span><span class="mwc-status ${s}">${s.toUpperCase()}</span>`;
      mini.appendChild(c);
    });
  }
}

/* ─── SUBMISSION FACTORY ──────────────────────────────────── */
let subCounter = 10000;
function createSubmission(overrides = {}) {
  subCounter++;
  const subject = overrides.subject || pick(SUBJECTS);
  const region = overrides.region || pick(REGIONS);
  return {
    id: overrides.id || generateSubmissionId(subject, region),
    hash: overrides.hash || generateSHA256Like(),
    subject,
    subjectCode: SUBJECT_CODES[subject] || '000',
    set: pick(SETS),
    roll: overrides.roll || generateRollNo(),
    region,
    fileSize: rand(200000, 5000000),
    createdAt: Date.now(),
    priority: rand(1, 5),
    retryCount: overrides.retryCount || 0,
    status: 'incoming',
    processTime: null,
    manual: overrides.manual || false,
  };
}

/* ─── QUEUE MANAGEMENT ────────────────────────────────────── */
function enqueueSubmission(sub) {
  if (state.simulation.paused) return;
  sub.status = 'incoming';
  state.queue.incoming.push(sub);
  state.stats.totalSubmitted++;
  const subj = sub.subject;
  state.stats.subjectCounts[subj] = (state.stats.subjectCounts[subj] || 0) + 1;
  updateQueueStats();
  addQueueCard('incoming', sub);
  feedLog('📥', `Submission <strong>${sub.id.substring(0, 20)}...</strong> received`, 'info');
  termLog('INFO', `<span>ENQUEUE [${sub.subject}] ${sub.id.substring(0, 28)}... · Roll: ${sub.roll} · Size: ${formatBytes(sub.fileSize)}</span>`);
}

function addQueueCard(col, sub) {
  const container = eid(`qci-${col}`);
  if (!container) return;
  if (container.children.length >= LOG_CONFIG.maxQueueCols) {
    container.lastChild && container.lastChild.remove();
  }
  const card = document.createElement('div');
  card.className = `queue-item ${col !== 'incoming' ? col + '-item' : ''}`;
  card.id = `qi-${sub.id.substring(sub.id.length - 8)}`;
  card.innerHTML = `
    <span class="qi-id">${sub.id.substring(0, 26)}...</span>
    <span class="qi-sub">${sub.subject} · Roll: ${sub.roll}</span>
    <span class="qi-time">${formatTime()} · ${formatBytes(sub.fileSize)}</span>
    ${col === 'processing' ? '<div class="qi-progress"><div class="qi-progress-fill" style="width:0%"></div></div>' : ''}
  `;
  container.insertBefore(card, container.firstChild);
}

function updateQueueCard(sub, progress) {
  const key = sub.id.substring(sub.id.length - 8);
  const card = eid(`qi-${key}`);
  if (card) {
    const fill = card.querySelector('.qi-progress-fill');
    if (fill) fill.style.width = progress + '%';
  }
}

function moveQueueCard(sub, fromCol, toCol) {
  const key = sub.id.substring(sub.id.length - 8);
  const oldCard = eid(`qi-${key}`);
  if (oldCard) oldCard.remove();
  if (toCol) addQueueCard(toCol, sub);
}

function updateQueueStats() {
  const total = state.queue.incoming.length + state.queue.processing.length;
  const depth = total + state.queue.retry.length;
  setText('kv-queue', depth);
  setText('kc-queue', depth > 0 ? `${depth} items pending` : 'Queue clear');
  setText('nb-queue', depth);
  setText('qs-incoming', state.queue.incoming.length);
  setText('qs-processing', state.queue.processing.length);
  setText('qs-completed', state.queue.completed.length);
  setText('qs-failed', state.queue.failed.length);
  setText('qs-retry', state.queue.retry.length);
  setText('qcc-incoming', state.queue.incoming.length);
  setText('qcc-processing', state.queue.processing.length);
  setText('qcc-completed', state.queue.completed.length);
  setText('qcc-failed', state.queue.failed.length);

  if (depth > state.stats.peakQueueDepth) {
    state.stats.peakQueueDepth = depth;
    setText('stat-peak', depth);
  }

  // Alert if queue exceeds threshold
  if (depth > state.simulation.queueThreshold && !state.simulation._alertFired) {
    state.simulation._alertFired = true;
    notify('Queue Alert', `Queue depth ${depth} exceeds threshold of ${state.simulation.queueThreshold}`, 'warning');
    setTimeout(() => { state.simulation._alertFired = false; }, 10000);
  }

  // Pipeline visual
  const pctGateway = Math.min(state.stats.throughputHistory.slice(-1)[0] * 20, 100);
  const pctQueue = Math.min((depth / 50) * 100, 100);
  const pctWorkers = (state.workers.filter(w => w.status !== 'idle').length / state.workers.length) * 100;
  const pctDB = Math.min((state.database.todayRecords / 500) * 100, 100);
  setWidth('psf-gateway', pctGateway);
  setWidth('psf-queue', pctQueue);
  setWidth('psf-workers', pctWorkers);
  setWidth('psf-db', pctDB);

  const rate = state.stats.throughputHistory.slice(-5).reduce((a, b) => a + b, 0) / 5;
  setText('psc-gateway', rate.toFixed(1) + '/s');
  setText('psc-queue', depth + ' items');
  setText('psc-workers', state.workers.filter(w => w.status !== 'idle').length + ' busy');
  setText('psc-db', state.database.todayRecords + ' synced');
}

/* ─── WORKER PROCESSING ───────────────────────────────────── */
async function processWithWorker(worker) {
  if (state.simulation.paused) return;

  // Throttle expensive DOM updates inside stage loop
  // (worker stage changes are frequent; DOM work is the bottleneck)
  worker._uiLast = worker._uiLast || 0;
  worker._uiQueued = false;
  const scheduleUIFlush = () => {
    if (worker._uiQueued) return;
    worker._uiQueued = true;
    requestAnimationFrame(() => {
      worker._uiQueued = false;
      // Worker card
      updateWorkerCard(worker);
    });
  };

  let sub = state.queue.retry.shift();
  if (!sub) sub = state.queue.incoming.shift();
  if (!sub) { worker.status = 'idle'; worker.stage = 'IDLE'; worker.progress = 0; updateWorkerCard(worker); return; }

  worker.status = 'processing';
  worker.currentTask = sub;
  worker.stage = 'FETCHING';
  worker.progress = 0;
  sub.status = 'processing';
  state.queue.processing.push(sub);
  updateWorkerCard(worker);
  moveQueueCard(sub, 'incoming', 'processing');
  updateQueueStats();

  const startTime = Date.now();

  const stages = [
    { stage: 'FETCHING', pct: 15, duration: rand(200, 400) },
    { stage: 'VALIDATING', pct: 35, duration: rand(300, 600) },
    { stage: 'HASHING', pct: 60, duration: rand(400, 700) },
    { stage: 'ENCRYPTING', pct: 85, duration: rand(500, 800) },
    { stage: 'SYNCING', pct: 100, duration: rand(300, 500) },
  ];

  for (const { stage, pct, duration } of stages) {
    if (state.simulation.paused) { await new Promise(r => setTimeout(r, 500)); }
    worker.stage = stage;
    worker.progress = pct;

    // Only redraw queue/progress at a capped rate; keep final state exact.
    const now = performance && performance.now ? performance.now() : Date.now();
    if (now - worker._uiLast > 200) {
      worker._uiLast = now;
      // Worker card update (throttled to RAF)
      scheduleUIFlush();
      // Queue card update (cheap)
      updateQueueCard(sub, pct);
    } else {
      // Still update the queue progress occasionally (cheap) without redrawing worker card
      updateQueueCard(sub, pct);
    }

    termLog('INFO', `<span>W-${String(worker.id).padStart(2, '0')} [${stage}] ${sub.id.substring(0, 24)}...</span>`);
    await new Promise(r => setTimeout(r, duration));
  }

  const processTime = Date.now() - startTime;
  worker.totalProcessingTime += processTime;

  // ~8% failure rate
  const failed = Math.random() < 0.08 && sub.retryCount < 3;

  if (!failed) {
    worker.tasksCompleted++;
    worker.stage = 'DONE';
    sub.status = 'completed';
    sub.processTime = processTime;
    state.queue.processing = state.queue.processing.filter(s => s.id !== sub.id);
    state.queue.completed.push(sub);
    if (state.queue.completed.length > 30) state.queue.completed.shift();
    state.stats.totalProcessed++;
    state.stats.processTimes.push(processTime);
    if (state.stats.processTimes.length > 100) state.stats.processTimes.shift();

    moveQueueCard(sub, 'processing', 'completed');
    feedLog('✅', `<strong>${sub.subject}</strong> processed · ${processTime}ms · Roll: ${sub.roll}`, 'success');
    termLog('SUCCESS', `<span>COMPLETED ${sub.id.substring(0, 28)}... in ${processTime}ms</span>`);

    // DB sync
    syncToDatabase(sub);
    updateQueueStats();

  } else {
    worker.errors++;
    sub.retryCount++;
    sub.status = sub.retryCount >= 3 ? 'failed' : 'retry';
    state.queue.processing = state.queue.processing.filter(s => s.id !== sub.id);

    if (sub.retryCount < 3 && state.simulation.retryEnabled) {
      state.queue.retry.push(sub);
      state.stats.totalRetried++;
      moveQueueCard(sub, 'processing', 'failed');
      feedLog('🔄', `<strong>Retry ${sub.retryCount}/3</strong> — ${sub.id.substring(0, 18)}...`, 'warning');
      termLog('WARN', `<span>RETRY [${sub.retryCount}/3] ${sub.id.substring(0, 28)}... — Worker-${worker.id}</span>`);
    } else {
      state.queue.failed.push(sub);
      if (state.queue.failed.length > 20) state.queue.failed.shift();
      state.stats.totalFailed++;
      moveQueueCard(sub, 'processing', 'failed');
      feedLog('❌', `<strong>FAILED</strong> — ${sub.id.substring(0, 18)}... after ${sub.retryCount} retries`, 'error');
      termLog('ERROR', `<span>FAILED ${sub.id.substring(0, 28)}... after ${sub.retryCount} retries</span>`);
      secLog('⚠️', `<strong>Submission failed</strong> after ${sub.retryCount} retries — ID: ${sub.id.substring(0, 20)}...`, 'warn');
    }
  }

  worker.status = 'active';
  worker.stage = 'IDLE';
  worker.progress = 0;
  worker.currentTask = null;
  updateWorkerCard(worker);
  updateQueueStats();
  updateSessionStats();
}

/* ─── DATABASE SYNC ───────────────────────────────────────── */
function syncToDatabase(sub) {
  state.database.totalRecords++;
  state.database.todayRecords++;
  state.database.dbSizeMB += randFloat(0.05, 0.2);
  state.database.pendingSync = Math.max(0, state.database.pendingSync - 1);

  const record = {
    id: sub.id,
    subject: sub.subject,
    roll: sub.roll,
    hash: sub.hash,
    syncedAt: new Date(),
    status: 'synced',
  };
  state.database.recentRecords.unshift(record);
  if (state.database.recentRecords.length > 50) state.database.recentRecords.pop();

  // DB view updates
  setText('dbv-total', state.database.totalRecords.toLocaleString());
  setText('dbv-today', state.database.todayRecords.toLocaleString());
  setText('dbv-pending', state.database.pendingSync);
  setText('dbv-last', formatTime());
  setText('dbv-size', state.database.dbSizeMB.toFixed(1) + ' MB');

  dbLog('✅', `<strong>${sub.id.substring(0, 22)}...</strong> synced · ${sub.subject} · Roll: ${sub.roll}`);
  updateRecordsTable();

  // Batch stats
  const bi = state.stats.nextBatch % 20;
  state.stats.dbSyncBatches[bi] = (state.stats.dbSyncBatches[bi] || 0) + 1;
  state.stats.nextBatch++;
}

function updateRecordsTable() {
  const tbody = eid('records-tbody');
  if (!tbody) return;
  tbody.innerHTML = state.database.recentRecords.slice(0, 15).map(r => `
    <tr>
      <td><code>${r.id.substring(0, 24)}...</code></td>
      <td>${r.subject}</td>
      <td>${r.roll}</td>
      <td><code>${shortHash(r.hash)}</code></td>
      <td><span class="rt-status ${r.status}">${r.status.toUpperCase()}</span></td>
      <td>${r.syncedAt.toLocaleTimeString()}</td>
    </tr>
  `).join('');
}

/* ─── AUTO-SCALING ────────────────────────────────────────── */
function checkAutoScale() {
  if (!state.simulation.autoScale) return;
  const qDepth = state.queue.incoming.length + state.queue.retry.length;
  const maxWorkers = 20;

  if (qDepth > 15 && state.workers.length < maxWorkers) {
    const newId = state.workers.length + 1;
    const w = createWorker(newId, true);
    state.workers.push(w);
    const grid = eid('workers-grid');
    if (grid) {
      const card = document.createElement('div');
      card.id = `wcard-${w.id}`;
      card.className = 'worker-card scaled-worker';
      card.innerHTML = `<div class="wc-header"><div class="wc-title"><span class="wc-icon">⚙️</span><span class="wc-name">Worker-${String(w.id).padStart(2, '0')} <span style="color:var(--primary);font-size:.6rem">AUTO</span></span></div><span class="wc-status-badge idle">IDLE</span></div><div class="wc-task">Stage: <span class="wc-task-name" id="wstage-${w.id}">—</span></div><div class="wc-progress"><div class="wcp-header"><span id="wctask-${w.id}">No task</span><span id="wcpct-${w.id}">0%</span></div><div class="wcp-bar"><div class="wcp-fill" id="wcpfill-${w.id}" style="width:0%"></div></div></div><div class="wc-stats"><div class="wcs"><span class="wcs-val text-success" id="wcc-${w.id}">0</span><span class="wcs-label">Done</span></div><div class="wcs"><span class="wcs-val" id="wca-${w.id}">0ms</span><span class="wcs-label">Avg Time</span></div><div class="wcs"><span class="wcs-val text-danger" id="wce-${w.id}">0</span><span class="wcs-label">Errors</span></div></div>`;
      grid.appendChild(card);
    }
    const notice = eid('autoscale-notice');
    if (notice) { notice.style.display = 'flex'; setText('autoscale-msg', `Auto-scaled to ${state.workers.length} workers — Queue depth: ${qDepth}`); }
    notify('Auto-Scaling', `Spawned Worker-${newId} — Queue depth: ${qDepth}`, 'info', 3000);
    termLog('INFO', `<span>AUTO-SCALE: Spawned Worker-${newId} · Queue depth: ${qDepth}</span>`);
    secLog('⚡', `<strong>Auto-scale event</strong> — ${state.workers.length} workers deployed`, 'ok');
    updateWorkerBadges();
  } else if (qDepth <= 5 && state.workers.filter(w => w.isScaled && w.status === 'idle').length > 0) {
    const scaled = state.workers.filter(w => w.isScaled && w.status === 'idle');
    if (scaled.length > 0) {
      const w = scaled[scaled.length - 1];
      state.workers = state.workers.filter(x => x.id !== w.id);
      const card = eid(`wcard-${w.id}`);
      if (card) card.remove();
      const notice = eid('autoscale-notice');
      if (notice) notice.style.display = 'none';
      updateWorkerBadges();
    }
  }
}

/* ─── MAIN SIMULATION LOOP ────────────────────────────────── */
function startSimulation() {
  // Submission generator
  setManagedInterval('generator', () => {
    if (state.simulation.paused) return;
    const count = rand(0, 2);
    for (let i = 0; i < count; i++) {
      enqueueSubmission(createSubmission());
    }
  }, 1800);

  // Worker dispatcher
  setManagedInterval('dispatcher', () => {
    if (state.simulation.paused) return;
    state.workers.forEach(worker => {
      if (worker.status === 'idle' || worker.status === 'active') {
        const hasWork = state.queue.incoming.length > 0 || state.queue.retry.length > 0;
        if (hasWork) {
          worker.status = 'active';
          processWithWorker(worker);
        }
      }
    });
    checkAutoScale();
  }, 1000);

  // Stats updater
  setManagedInterval('stats', () => {
    updateThroughputHistory();
    updateKPIs();
    updateResourceMeters();
    updateSystemHealth();
  }, 1000);

  // Throughput chart updater
  setManagedInterval('chart', () => {
    if (state.currentView === 'dashboard') renderThroughputChart();
    if (state.currentView === 'queue') renderQueueDepthChart();
    if (state.currentView === 'workers') renderWorkerChart();
  }, 3500);

  // Clock
  setManagedInterval('clock', () => {
    setText('topbar-clock', formatTime());
  }, 1000);

  // Sparklines
  setManagedInterval('sparklines', () => {
    updateSparklines();
  }, 5000);

  // Particles
  startParticles();
}

/* ─── THROUGHPUT HISTORY ──────────────────────────────────── */
function updateThroughputHistory() {
  const rate = state.stats.totalSubmitted - (state.sparkData._lastTotal || 0);
  const processed = state.stats.totalProcessed - (state.sparkData._lastProcessed || 0);
  state.sparkData._lastTotal = state.stats.totalSubmitted;
  state.sparkData._lastProcessed = state.stats.totalProcessed;

  state.stats.throughputHistory.push(rate);
  state.stats.throughputHistory.shift();
  state.stats.processedHistory.push(processed);
  state.stats.processedHistory.shift();

  const qDepth = state.queue.incoming.length + state.queue.processing.length + state.queue.retry.length;
  state.stats.queueDepthHistory.push(qDepth);
  state.stats.queueDepthHistory.shift();
  state.stats.workerHistory.push(state.workers.filter(w => w.status !== 'idle').length);
  state.stats.workerHistory.shift();

  // Analytics timeline (5min window = 300 ticks at 1/s)
  state.stats.submittedHistory.push(rate);
  state.stats.submittedHistory.shift();
  state.stats.successHistory.push(processed);
  state.stats.successHistory.shift();
  const failed = state.stats.totalFailed - (state.sparkData._lastFailed || 0);
  state.sparkData._lastFailed = state.stats.totalFailed;
  state.stats.failHistory.push(failed);
  state.stats.failHistory.shift();
}

/* ─── KPI UPDATES ─────────────────────────────────────────── */
function updateKPIs() {
  setText('kv-total', state.stats.totalSubmitted.toLocaleString());
  setText('kv-total', state.stats.totalSubmitted.toLocaleString());

  const totalProcessed = state.stats.totalProcessed;
  const totalFailed = state.stats.totalFailed;
  const successRate = totalProcessed + totalFailed > 0
    ? ((totalProcessed / (totalProcessed + totalFailed)) * 100).toFixed(1) + '%'
    : '99.7%';
  setText('kv-success', successRate);

  const avgTime = state.stats.processTimes.length > 0
    ? Math.round(state.stats.processTimes.reduce((a, b) => a + b, 0) / state.stats.processTimes.length)
    : 142;
  setText('kv-speed', avgTime + 'ms');

  // Sparkline data
  const last = state.stats.throughputHistory.slice(-10);
  state.sparkData.total = last;
  state.sparkData.queue = state.stats.queueDepthHistory.slice(-10);
  const avg = state.stats.processTimes.slice(-10);
  state.sparkData.speed = avg.length > 0 ? [avg[avg.length - 1]] : [];

  // Session stats
  setText('stat-total', state.stats.totalSubmitted.toLocaleString());
  setText('stat-success', state.stats.totalProcessed.toLocaleString());
  setText('stat-failed', state.stats.totalFailed);
  setText('stat-retried', state.stats.totalRetried);
  setText('stat-workers', state.workers.length);
  setText('stat-spikes', state.simulation.spikesCount);
  if (state.stats.processTimes.length > 0) {
    const a = state.stats.processTimes;
    setText('stat-avgtime', Math.round(a.reduce((x, y) => x + y, 0) / a.length) + 'ms');
  }

  // Login screen total counter animation
  const lsTotal = eid('ls-total');
  if (lsTotal) {
    const base = 247836;
    lsTotal.textContent = (base + state.stats.totalSubmitted).toLocaleString();
  }

  // Sidebar health
  const health = calculateSystemHealth();
  setWidth('shm-fill', health);
  setText('shm-val', health + '%');
}

function updateSessionStats() {
  updateKPIs();
}

/* ─── RESOURCE METERS ─────────────────────────────────────── */
function updateResourceMeters() {
  const qDepth = state.queue.incoming.length + state.queue.processing.length + state.queue.retry.length;
  const activeWorkers = state.workers.filter(w => w.status !== 'idle').length;
  const totalWorkers = state.workers.length;

  const cpuBase = 30 + (activeWorkers / Math.max(totalWorkers, 1)) * 50 + rand(-5, 5);
  const memBase = 45 + (qDepth / 100) * 30 + rand(-3, 3);
  const queueLoad = Math.min((qDepth / 50) * 100, 99) + rand(-2, 2);
  const netBase = 20 + (activeWorkers / Math.max(totalWorkers, 1)) * 60 + rand(-10, 10);
  const netMB = (netBase * 0.4).toFixed(1);

  const cpu = Math.min(Math.max(cpuBase, 5), 98);
  const mem = Math.min(Math.max(memBase, 20), 92);
  const ql = Math.min(Math.max(queueLoad, 0), 99);
  const net = Math.min(Math.max(netBase, 0), 99);

  setText('rm-cpu', Math.round(cpu) + '%');
  setText('rm-mem', Math.round(mem) + '%');
  setText('rm-qload', Math.round(ql) + '%');
  setText('rm-net', netMB + ' MB/s');
  setWidth('rmf-cpu', cpu);
  setWidth('rmf-mem', mem);
  setWidth('rmf-qload', ql);
  setWidth('rmf-net', net);

  // System status
  const statusBar = eid('system-status-bar');
  const dot = statusBar ? statusBar.querySelector('.ssb-dot') : null;
  const text = eid('ssb-text') || (statusBar ? statusBar.querySelector('.ssb-text') : null);
  if (dot && text) {
    if (cpu > 90 || qDepth > 45) {
      dot.className = 'ssb-dot critical'; text.textContent = 'System Under Heavy Load';
    } else if (cpu > 75 || qDepth > 25) {
      dot.className = 'ssb-dot degraded'; text.textContent = 'Elevated Traffic — Monitoring';
    } else {
      dot.className = 'ssb-dot operational'; text.textContent = 'All Systems Operational';
    }
  }
}

function calculateSystemHealth() {
  const qDepth = state.queue.incoming.length + state.queue.processing.length + state.queue.retry.length;
  const failRate = state.stats.totalFailed / Math.max(state.stats.totalSubmitted, 1);
  let health = 100 - (qDepth / 100 * 30) - (failRate * 100 * 0.3) + rand(-2, 2);
  return Math.min(Math.max(Math.round(health), 60), 100);
}

function updateSystemHealth() {
  // already done in updateKPIs
}

/* ─── CANVAS CHARTS ───────────────────────────────────────── */
function drawLineChart(canvas, datasets, options = {}) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const pad = options.pad || { t: 10, r: 10, b: 20, l: 35 };
  const cW = W - pad.l - pad.r, cH = H - pad.t - pad.b;
  ctx.clearRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (cH / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + cW, y); ctx.stroke();
  }

  datasets.forEach(ds => {
    if (!ds.data || ds.data.length === 0) return;
    const max = options.max || Math.max(...datasets.flatMap(d => d.data), 1);
    const step = cW / (ds.data.length - 1 || 1);

    // Fill
    if (ds.fill) {
      ctx.beginPath();
      ds.data.forEach((v, i) => {
        const x = pad.l + i * step;
        const y = pad.t + cH - (v / max) * cH;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.lineTo(pad.l + (ds.data.length - 1) * step, pad.t + cH);
      ctx.lineTo(pad.l, pad.t + cH);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + cH);
      grad.addColorStop(0, ds.fillColor || 'rgba(124,58,237,0.15)');
      grad.addColorStop(1, 'transparent');
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // Line
    ctx.beginPath();
    ctx.strokeStyle = ds.color || '#7c3aed';
    ctx.lineWidth = ds.lineWidth || 2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ds.data.forEach((v, i) => {
      const x = pad.l + i * step;
      const y = pad.t + cH - (v / max) * cH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  });

  // Y labels
  if (options.yLabels !== false) {
    const max = options.max || Math.max(...datasets.flatMap(d => d.data), 1);
    ctx.fillStyle = 'rgba(148,163,184,0.7)';
    ctx.font = '9px Inter';
    for (let i = 0; i <= 4; i++) {
      const v = max - (max / 4) * i;
      const y = pad.t + (cH / 4) * i;
      ctx.fillText(Math.round(v), 0, y + 3);
    }
  }
}

function drawBarChart(canvas, data, colors, options = {}) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const pad = { t: 10, r: 10, b: 25, l: 40 };
  const cW = W - pad.l - pad.r, cH = H - pad.t - pad.b;
  ctx.clearRect(0, 0, W, H);

  const max = Math.max(...data, 1);
  const bW = (cW / data.length) * 0.6;
  const gap = (cW / data.length) * 0.4;

  data.forEach((v, i) => {
    const bH = (v / max) * cH;
    const x = pad.l + i * (bW + gap) + gap / 2;
    const y = pad.t + cH - bH;
    const grad = ctx.createLinearGradient(0, y, 0, y + bH);
    grad.addColorStop(0, colors[i % colors.length] || '#6366f1');
    grad.addColorStop(1, 'rgba(0,0,0,0.2)');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, y, bW, bH, [3, 3, 0, 0]) : ctx.rect(x, y, bW, bH);
    ctx.fill();

    if (options.labels) {
      ctx.fillStyle = 'rgba(148,163,184,0.7)';
      ctx.font = '8px Inter';
      ctx.textAlign = 'center';
      ctx.fillText(options.labels[i] || '', x + bW / 2, H - 5);
    }
  });
}

function renderThroughputChart() {
  const canvas = eid('throughput-chart');
  if (!canvas) return;
  const max = Math.max(...state.stats.throughputHistory, ...state.stats.processedHistory, 5);
  drawLineChart(canvas, [
    { data: state.stats.throughputHistory, color: '#7c3aed', fillColor: 'rgba(124,58,237,0.1)', fill: true, lineWidth: 2 },
    { data: state.stats.processedHistory, color: '#4ade80', fillColor: 'rgba(74,222,128,0.08)', fill: true, lineWidth: 2 },
  ], { max, pad: { t: 10, r: 10, b: 20, l: 35 } });
}

function renderQueueDepthChart() {
  const canvas = eid('queue-depth-chart');
  if (!canvas) return;
  drawLineChart(canvas, [
    { data: state.stats.queueDepthHistory, color: '#facc15', fillColor: 'rgba(250,204,21,0.12)', fill: true, lineWidth: 2.5 },
  ], { pad: { t: 10, r: 10, b: 20, l: 35 } });
}

function renderWorkerChart() {
  const canvas = eid('worker-chart');
  if (!canvas) return;
  drawLineChart(canvas, [
    { data: state.stats.workerHistory, color: '#7c3aed', fillColor: 'rgba(124,58,237,0.12)', fill: true, lineWidth: 2 },
  ], { pad: { t: 10, r: 10, b: 20, l: 35 } });
}

function renderAnalyticsChart() {
  const canvas = eid('analytics-main-chart');
  if (!canvas) return;
  const sub = state.stats.submittedHistory.slice(-120);
  const succ = state.stats.successHistory.slice(-120);
  const fail = state.stats.failHistory.slice(-120);
  const max = Math.max(...sub, ...succ, 5);
  drawLineChart(canvas, [
    { data: sub, color: '#7c3aed', fill: true, fillColor: 'rgba(124,58,237,0.08)', lineWidth: 2 },
    { data: succ, color: '#4ade80', fill: true, fillColor: 'rgba(74,222,128,0.08)', lineWidth: 2 },
    { data: fail, color: '#f87171', fill: true, fillColor: 'rgba(248,113,113,0.06)', lineWidth: 1.5 },
  ], { max, pad: { t: 10, r: 10, b: 20, l: 35 } });
}

function renderSubjectChart() {
  const canvas = eid('subject-chart');
  if (!canvas) return;
  const subjects = SUBJECTS;
  const counts = subjects.map(s => state.stats.subjectCounts[s] || 0);
  const colors = ['#7c3aed', '#a78bfa', '#4ade80', '#facc15', '#f87171', '#7c3aed', '#ec4899', '#14b8a6', '#f97316'];
  drawBarChart(canvas, counts, colors, { labels: subjects.map(s => s.substring(0, 4)) });
}

function renderDbSyncChart() {
  const canvas = eid('db-sync-chart');
  if (!canvas) return;
  const colors = Array(20).fill('#4ade80');
  drawBarChart(canvas, state.stats.dbSyncBatches, colors);
}

function updateSparklines() {
  const ids = ['total', 'queue', 'success', 'speed'];
  const datas = [
    state.stats.throughputHistory.slice(-15),
    state.stats.queueDepthHistory.slice(-15),
    state.stats.processedHistory.slice(-15),
    state.stats.processTimes.slice(-15).map(t => t / 10),
  ];
  const colors = ['#7c3aed', '#facc15', '#4ade80', '#a78bfa'];

  ids.forEach((id, idx) => {
    const canvas = eid(`spark-${id}`);
    if (!canvas) return;
    const data = datas[idx];
    if (!data || data.length === 0) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const max = Math.max(...data, 1);
    const step = W / (data.length - 1 || 1);
    ctx.beginPath();
    ctx.strokeStyle = colors[idx];
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    data.forEach((v, i) => {
      const x = i * step;
      const y = H - (v / max) * (H - 4) - 2;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Fill
    ctx.lineTo((data.length - 1) * step, H);
    ctx.lineTo(0, H);
    ctx.closePath();

    // Safe gradient fill (avoid expensive/buggy string transforms on each tick)
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, 'rgba(124,58,237,0.15)');
    grad.addColorStop(1, 'transparent');
    ctx.fillStyle = grad;
    ctx.fill();
  });
}

/* ─── PARTICLES ───────────────────────────────────────────── */
function startParticles() {
  const container = eid('pipeline-particles');
  if (!container) return;
  const colors = ['#7c3aed', '#a78bfa', '#4ade80', '#facc15', '#f87171'];
  let particleInterval = setInterval(() => {
    if (!eid('pipeline-particles')) { clearInterval(particleInterval); return; }
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.cssText = `animation-delay:${randFloat(0, 2)}s; animation-duration:${randFloat(2, 4)}s; background:${pick(colors)}; top:${rand(0, 2)}px`;
    container.appendChild(p);
    setTimeout(() => p.remove(), 5000);
  }, 800);
}

/* ─── TRAFFIC SPIKE ───────────────────────────────────────── */
function triggerSpike(count = 50) {
  const spikeFn = () => {
    for (let i = 0; i < count; i++) {
      setTimeout(() => enqueueSubmission(createSubmission()), i * 40);
    }
    state.simulation.spikesCount++;
    notify('⚡ Traffic Spike!', `${count} submissions injected — Queue absorbing load`, 'warning', 5000);
    feedLog('⚡', `<strong>TRAFFIC SPIKE</strong> — ${count} submissions injected simultaneously`, 'warning');
    termLog('WARN', `<span>TRAFFIC SPIKE: ${count} submissions injected — Queue management engaged</span>`);
    secLog('⚡', `<strong>Traffic spike detected</strong> — ${count} concurrent submissions`, 'warn');
    setText('stat-spikes', state.simulation.spikesCount);
  };
  confirmAction('Simulate Traffic Spike', `Inject ${count} submissions instantly to test system resilience?`, '⚡', spikeFn);
}

/* ─── SECURITY SIMULATOR ──────────────────────────────────── */
function initSecuritySimulator() {
  const btnEncrypt = eid('btn-encrypt');
  const btnHash = eid('btn-hash');
  const btnGenId = eid('btn-gen-id');

  if (btnEncrypt) {
    btnEncrypt.onclick = () => {
      const input = eid('enc-input') ? eid('enc-input').value : '';
      const key = generateAESKey();
      const iv = generateIV();
      const tag = generateTag();
      const cipher = generateEncryptedPayload();

      setText('eo-key', key);
      setText('eo-iv', iv);
      setText('eo-tag', tag);
      setText('eo-result', cipher);

      // Animate hash
      const anim = eid('hash-animation');
      if (anim) { animateHash(anim, cipher.substring(0, 60)); }

      secLog('🔐', `<strong>AES-256-GCM</strong> encryption successful · Key: ${key.substring(0, 12)}...`, 'ok');
      notify('Encrypted', 'AES-256-GCM encryption complete', 'success', 2000);
    };
  }

  if (btnHash) {
    btnHash.onclick = async () => {
      const input = eid('hash-input') ? eid('hash-input').value : '';
      const hash = generateSHA256Like();

      // Animate
      let anim = '';
      const hashRes = eid('hash-result');
      const interval = setInterval(() => {
        anim = Array.from({ length: 64 }, () => '0123456789abcdef'[rand(0, 15)]).join('');
        if (hashRes) hashRes.textContent = anim;
      }, 50);

      await new Promise(r => setTimeout(r, 800));
      clearInterval(interval);
      if (hashRes) hashRes.textContent = hash;

      setText('hash-status', '✅ Verified');
      eid('hash-status') && (eid('hash-status').className = 'status-ok');

      secLog('#️⃣', `<strong>SHA-256</strong> computed · Hash: ${hash.substring(0, 20)}...`, 'ok');
    };
  }

  if (btnGenId) {
    btnGenId.onclick = () => {
      const id = generateSubmissionId(pick(SUBJECTS).toUpperCase().substring(0, 4), pick(REGIONS));
      setText('cid-value', id);
      state.security.recentIds.unshift(id);
      if (state.security.recentIds.length > 5) state.security.recentIds.pop();
      updateRecentIds();
      secLog('🆔', `<strong>Submission ID</strong> generated: ${id}`, 'ok');
    };
  }

  // Initial security logs
  ['Evaluator session started · IP: 10.0.4.112', 'TLS 1.3 handshake successful', 'Token validated · Claims verified', 'Encryption module initialized', 'Audit trail enabled'].forEach(msg => {
    setTimeout(() => secLog('✅', `<strong>${msg}</strong>`, 'ok'), rand(100, 1000));
  });
}

async function animateHash(el, target) {
  const chars = '0123456789abcdef';
  for (let i = 0; i < 10; i++) {
    el.textContent = Array.from({ length: target.length }, () => chars[rand(0, 15)]).join('');
    await new Promise(r => setTimeout(r, 60));
  }
  el.textContent = target;
}

function updateRecentIds() {
  const list = eid('ri-list');
  if (!list) return;
  list.innerHTML = state.security.recentIds.map(id => `<div class="ri-item">${id}</div>`).join('');
}

/* ─── ADMIN CONTROLS ──────────────────────────────────────── */
function initAdminControls() {
  const spike = eid('btn-spike-big');
  if (spike) spike.onclick = () => triggerSpike(50);

  const topSpike = eid('btn-spike');
  if (topSpike) topSpike.onclick = () => triggerSpike(30);

  const moderate = eid('btn-moderate');
  if (moderate) moderate.onclick = () => triggerSpike(20);

  const resetQ = eid('btn-reset-queue');
  if (resetQ) resetQ.onclick = () => confirmAction('Reset Queue', 'Clear all pending queue items? Workers will finish their current tasks.', '🔄', () => {
    state.queue.incoming = [];
    state.queue.retry = [];
    ['incoming', 'retry'].forEach(col => { const c = eid(`qci-${col}`); if (c) c.innerHTML = ''; });
    updateQueueStats();
    notify('Queue Reset', 'All pending items cleared', 'info');
    termLog('WARN', '<span>QUEUE RESET: All pending items cleared by admin</span>');
    logAuditEvent('queue-reset', 'Pending queue items cleared by administrator');
  });

  const addWorker = eid('btn-add-worker');
  if (addWorker) addWorker.onclick = () => {
    const newId = state.workers.length + 1;
    const w = createWorker(newId, true);
    state.workers.push(w);
    renderWorkers();
    notify('Worker Added', `Worker-${String(newId).padStart(2, '0')} spawned`, 'success', 2000);
    termLog('INFO', `<span>MANUAL SPAWN: Worker-${newId} added by admin</span>`);
    logAuditEvent('scale-worker', `Manually spawned Worker-${newId}`);
  };

  const removeWorker = eid('btn-remove-worker');
  if (removeWorker) removeWorker.onclick = () => {
    const idle = state.workers.filter(w => w.status === 'idle');
    if (idle.length === 0) { notify('No Idle Workers', 'All workers are busy', 'warning'); return; }
    const w = idle[idle.length - 1];
    state.workers = state.workers.filter(x => x.id !== w.id);
    const card = eid(`wcard-${w.id}`);
    if (card) card.remove();
    notify('Worker Terminated', `Worker-${String(w.id).padStart(2, '0')} shut down`, 'info', 2000);
    updateWorkerBadges();
    logAuditEvent('scale-worker', `Manually terminated Worker-${w.id}`);
  };

  const slider = eid('worker-slider');
  if (slider) slider.addEventListener('input', () => {
    const target = parseInt(slider.value);
    setText('worker-count-label', target);
    const current = state.workers.length;
    if (target > current) {
      for (let i = current + 1; i <= target; i++) state.workers.push(createWorker(i, true));
      renderWorkers();
    } else if (target < current) {
      state.workers = state.workers.slice(0, target);
      renderWorkers();
    }
  });

  const pause = eid('btn-pause-queue');
  const resume = eid('btn-resume-queue');
  if (pause) pause.onclick = () => {
    state.simulation.paused = true;
    pause.disabled = true;
    if (resume) resume.disabled = false;
    eid('system-status-bar') && (eid('system-status-bar').querySelector('.ssb-dot').className = 'ssb-dot degraded');
    notify('Queue Paused', 'Processing halted — All workers suspended', 'warning', 8000);
    feedLog('⏸️', '<strong>Queue processing PAUSED</strong> by administrator', 'warning');
    termLog('WARN', '<span>ADMIN: Queue processing paused</span>');
    logAuditEvent('queue-control', 'Queue processing paused by administrator');
  };
  if (resume) resume.onclick = () => {
    state.simulation.paused = false;
    resume.disabled = true;
    if (pause) pause.disabled = false;
    notify('Queue Resumed', 'Processing restarted — Workers active', 'success', 3000);
    feedLog('▶️', '<strong>Queue processing RESUMED</strong> by administrator', 'success');
    termLog('SUCCESS', '<span>ADMIN: Queue processing resumed</span>');
    logAuditEvent('queue-control', 'Queue processing resumed by administrator');
  };

  const fullReset = eid('btn-full-reset');
  if (fullReset) fullReset.onclick = () => confirmAction('Full System Reset', 'This will reset ALL simulation data and restart the engine. Are you sure?', '🔃', () => {
    state.queue.incoming = []; state.queue.processing = []; state.queue.completed = []; state.queue.failed = []; state.queue.retry = [];
    state.stats.totalSubmitted = 0; state.stats.totalProcessed = 0; state.stats.totalFailed = 0; state.stats.totalRetried = 0;
    state.stats.peakQueueDepth = 0; state.stats.processTimes = [];
    state.stats.throughputHistory.fill(0); state.stats.processedHistory.fill(0);
    state.stats.queueDepthHistory.fill(0); state.stats.workerHistory.fill(0);
    state.database.todayRecords = 0; state.database.pendingSync = 0;
    state.database.recentRecords = [];
    state.simulation.paused = false; state.simulation.spikesCount = 0;
    initWorkers(6);
    ['incoming', 'processing', 'completed', 'failed'].forEach(col => { const c = eid(`qci-${col}`); if (c) c.innerHTML = ''; });
    updateQueueStats(); updateKPIs();
    notify('System Reset', 'All data cleared — Simulation restarted', 'info', 4000);
    termLog('WARN', '<span>FULL SYSTEM RESET performed by admin</span>');
    logAuditEvent('system-reset', 'Full simulation and stats data reset by administrator');
  });

  // Toggle switches
  const toggles = [
    ['toggle-autoscale', 'autoScale'],
    ['toggle-retry', 'retryEnabled'],
    ['toggle-logging', 'loggingEnabled'],
    ['toggle-encrypt', 'encryptEnforced'],
  ];
  toggles.forEach(([id, key]) => {
    const el = eid(id);
    if (el) el.addEventListener('change', () => {
      state.simulation[key] = el.checked;
      notify('Setting Updated', `${key} ${el.checked ? 'enabled' : 'disabled'}`, 'info', 2000);
      logAuditEvent('settings-change', `${key} toggle changed to ${el.checked}`);
    });
  });

  const thresholdInput = eid('queue-threshold');
  if (thresholdInput) thresholdInput.addEventListener('change', () => {
    state.simulation.queueThreshold = parseInt(thresholdInput.value) || 30;
    notify('Threshold Updated', `Queue alert at ${state.simulation.queueThreshold} items`, 'info', 2000);
    logAuditEvent('settings-change', `Queue alert threshold updated to ${state.simulation.queueThreshold}`);
  });
}

/* ─── LOGIN FLOW ──────────────────────────────────────────── */
function getSelectedRoleKey() {
  const selectedTab = document.querySelector('.role-tab.active');
  const selectedKey = selectedTab ? selectedTab.dataset.role : activeRole;
  return ROLES[selectedKey] ? selectedKey : 'evaluator';
}

function initLogin() {
  const form = eid('login-form');
  const demoBtn = eid('btn-demo-login');
  const togglePass = eid('toggle-pass');
  const passInput = eid('login-pass');

  if (togglePass && passInput) {
    togglePass.onclick = () => {
      passInput.type = passInput.type === 'password' ? 'text' : 'password';
    };
  }

  if (demoBtn) {
    demoBtn.onclick = () => {
      const selectedRoleKey = getSelectedRoleKey();
      const selectedRole = ROLES[selectedRoleKey] || ROLES.evaluator;
      const email = eid('login-email');
      const pass = eid('login-pass');
      if (email) email.value = selectedRole.email;
      if (pass) pass.value = selectedRole.pass;
      setTimeout(() => doLogin(selectedRole.email, selectedRole.pass, selectedRoleKey), 300);
    };
  }

  if (form) {
    form.onsubmit = (e) => {
      e.preventDefault();
      const email = eid('login-email') ? eid('login-email').value.trim() : '';
      const pass = eid('login-pass') ? eid('login-pass').value.trim() : '';
      let valid = true;

      const errEmail = eid('err-email');
      const errPass = eid('err-pass');
      if (errEmail) errEmail.textContent = '';
      if (errPass) errPass.textContent = '';

      if (!email || !email.includes('@')) { if (errEmail) errEmail.textContent = 'Please enter a valid email address'; valid = false; }
      if (!pass) { if (errPass) errPass.textContent = 'Password is required'; valid = false; }

      if (!valid) return;

      const spinner = eid('login-spinner');
      const btnText = eid('btn-login') ? eid('btn-login').querySelector('.btn-text') : null;
      const loginBtn = eid('btn-login');
      const demoBtn = eid('btn-demo-login');
      if (spinner) spinner.classList.remove('hidden');
      if (btnText) btnText.textContent = 'Authenticating...';
      if (loginBtn) loginBtn.disabled = true;
      if (demoBtn) demoBtn.disabled = true;

      // Try secure backend login first
      fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ email, password: pass })
      })
        .then(async response => {
          if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.error || 'Authentication failed');
          }
          return response.json();
        })
        .then(data => {
          if (spinner) spinner.classList.add('hidden');
          if (btnText) btnText.textContent = 'Sign In Securely';
          if (loginBtn) loginBtn.disabled = false;
          if (demoBtn) demoBtn.disabled = false;

          activeRole = data.user.roleKey;
          doLoginSuccess(data.user, data.user.roleKey);
        })
        .catch(err => {
          // If it's a validation/credentials failure from backend, show error
          if (err.message === 'Invalid credentials' || err.message === 'A valid email address is required' || err.message === 'Password is required') {
            if (spinner) spinner.classList.add('hidden');
            if (btnText) btnText.textContent = 'Sign In Securely';
            if (loginBtn) loginBtn.disabled = false;
            if (demoBtn) demoBtn.disabled = false;
            if (errEmail) errEmail.textContent = err.message;
            return;
          }

          // Otherwise (network error/404), fallback to local simulation
          console.warn('[EvalSync API] Backend offline/static environment. Falling back to local client simulation.', err);

          const matchedRoleKey = Object.keys(ROLES).find(key => {
            const r = ROLES[key];
            return r.email === email && r.pass === pass;
          });

          if (spinner) spinner.classList.add('hidden');
          if (btnText) btnText.textContent = 'Sign In Securely';
          if (loginBtn) loginBtn.disabled = false;
          if (demoBtn) demoBtn.disabled = false;

          if (!matchedRoleKey) {
            if (errEmail) errEmail.textContent = 'Invalid credentials. Use the demo credentials shown above.';
            return;
          }

          activeRole = matchedRoleKey;
          doLogin(email, pass, matchedRoleKey);
        });
    };
  }
}

function doLoginSuccess(loggedInUser, roleKey) {
  state.user = loggedInUser;
  state.isLoggedIn = true;
  state.simulation.sessionStart = new Date();
  setText('stat-start', new Date().toLocaleTimeString());

  // Setup user info
  setText('su-name', loggedInUser.name);
  setText('su-initials', loggedInUser.initials);
  setText('ta-initials', loggedInUser.initials);
  setText('ic-name', loggedInUser.name);
  setText('ic-id', loggedInUser.id);
  setText('ic-subject', loggedInUser.subject);

  // Animate login page out
  const lp = eid('login-page');
  const finishLogin = () => {
    if (lp) lp.classList.add('hidden');
    initApp(loggedInUser);
    applyRoleBadge(roleKey);
    startSessionTimer();
  };
  if (lp) {
    lp.style.transition = 'opacity 0.5s, transform 0.5s';
    lp.style.opacity = '0';
    lp.style.transform = 'scale(0.97)';
    setTimeout(finishLogin, 500);
  } else {
    finishLogin();
  }
}

function doLogin(email, pass, roleKey) {
  roleKey = ROLES[roleKey] ? roleKey : getSelectedRoleKey();
  const role = ROLES[roleKey] || ROLES.evaluator;
  activeRole = roleKey;
  const spinner = eid('login-spinner');
  const btnText = eid('btn-login') ? eid('btn-login').querySelector('.btn-text') : null;
  const loginBtn = eid('btn-login');
  const demoBtn = eid('btn-demo-login');
  if (spinner) spinner.classList.remove('hidden');
  if (btnText) btnText.textContent = 'Authenticating...';
  if (loginBtn) loginBtn.disabled = true;
  if (demoBtn) demoBtn.disabled = true;

  setTimeout(() => {
    const loggedInUser = {
      email: role.email,
      name: role.name,
      initials: role.initials,
      role: role.label,
      id: `${roleKey.toUpperCase()}-${pick(REGIONS)}-${rand(1000, 9999)}-2024`,
      subject: 'Mathematics (041)',
      center: `${pick(REGIONS)}-${rand(1000, 9999)}`,
    };

    if (spinner) spinner.classList.add('hidden');
    if (btnText) btnText.textContent = 'Sign In Securely';
    if (loginBtn) loginBtn.disabled = false;
    if (demoBtn) demoBtn.disabled = false;

    doLoginSuccess(loggedInUser, roleKey);
  }, 1200);
}

function doLogout() {
  fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'x-csrf-token': csrfToken }
  })
    .catch(err => console.warn('[EvalSync API] Backend offline during logout.', err))
    .finally(() => {
      state.isLoggedIn = false;
      clearManagedTimers();
      if (sessionTimerInterval) {
        clearInterval(sessionTimerInterval);
        sessionTimerInterval = null;
      }
      const lp = eid('login-page');
      const ma = eid('main-app');
      if (lp) {
        lp.classList.remove('hidden');
        lp.style.opacity = '1';
        lp.style.transform = 'scale(1)';
      }
      if (ma) ma.classList.add('hidden');
    });
}

// Bind to window so app.runtime.js and HTML triggers can reference them
window.doLogin = doLogin;
window.doLogout = doLogout;
window.doLoginSuccess = doLoginSuccess;

function logAuditEvent(action, details) {
  fetch('/api/audit/log', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken
    },
    body: JSON.stringify({ action, details })
  }).catch(err => {
    // Fallback to client-side audit table if API is unreachable
    if (typeof auditLog === 'function') {
      auditLog(action, details, activeRole, 'SYSTEM');
    }
  });
}
window.logAuditEvent = logAuditEvent;


/* ─── APP INIT ────────────────────────────────────────────── */
function initApp(loggedInUser) {
  const ma = eid('main-app');
  if (ma) ma.classList.remove('hidden');

  // Set date input default
  const datePicker = eid('sub-date');
  if (datePicker) datePicker.value = new Date().toISOString().split('T')[0];

  // Nav
  document.querySelectorAll('.nav-item').forEach(item => {
    item.onclick = (e) => {
      e.preventDefault();
      const view = item.dataset.view;
      if (view) switchView(view);
    };
  });

  // Sidebar collapse
  const collapseBtn = eid('sidebar-collapse');
  const sidebar = eid('sidebar');
  if (collapseBtn && sidebar) {
    collapseBtn.onclick = () => sidebar.classList.toggle('collapsed');
  }

  const menuBtn = eid('menu-btn');
  if (menuBtn && sidebar) {
    menuBtn.onclick = () => sidebar.classList.toggle('collapsed');
  }

  // Logout
  const logoutBtn = eid('btn-logout');
  if (logoutBtn) logoutBtn.onclick = () => confirmAction('Sign Out', 'Are you sure you want to sign out of EvalSync?', '\ud83d\udeaa', doLogout);

  // Notifications
  const notifBtn = eid('btn-notifications');
  if (notifBtn) notifBtn.onclick = () => {
    notify('Notifications', 'No new alerts \u2014 System running normally', 'info', 3000);
    const dot = eid('notif-dot');
    if (dot) dot.classList.remove('show');
  };

  initUploadZone();
  initSecuritySimulator();
  initAdminControls();
  initWorkers(6);
  startSimulation();

  const user = loggedInUser || state.user || DEMO_USER;
  // Initial notifications
  setTimeout(() => { notify('Welcome, ' + user.name, `EvalSync session started \u00b7 ${ROLES[activeRole]?.label || 'Evaluator'} access granted`, 'success', 5000); }, 1500);
  setTimeout(() => { notify('Queue Active', 'Simulation engine running \u2014 Live data streaming', 'info', 3000); }, 3000);
  termLog('SUCCESS', `<span>EvalSync v3.2.1 initialized \u00b7 ${ROLES[activeRole]?.label || 'Evaluator'} session started</span>`);
  termLog('INFO', `<span>User: ${user.name} \u00b7 Role: ${ROLES[activeRole]?.label} \u00b7 Center: ${user.center}</span>`);
  feedLog('\ud83d\ude80', '<strong>EvalSync</strong> simulation engine started', 'success');
  secLog('\ud83d\udd10', '<strong>TLS 1.3</strong> session established \u00b7 Certificate valid', 'ok');
  secLog('\u2705', `<strong>${user.name} authenticated</strong> \u00b7 Role: ${ROLES[activeRole]?.label}`, 'ok');
  dbLog('\ud83d\uddc4\ufe0f', '<strong>Database connection</strong> established \u00b7 3 replicas online');
  dbLog('\u2705', '<strong>Primary DB online</strong> \u00b7 Mumbai data center');

  // Sync DB initial state
  setText('dbv-total', state.database.totalRecords.toLocaleString());
  setText('dbv-today', '0');
  setText('dbv-pending', '0');
  setText('dbv-size', state.database.dbSizeMB.toFixed(1) + ' MB');

  // Bootstrap some initial submissions
  setTimeout(() => { for (let i = 0; i < 3; i++) enqueueSubmission(createSubmission()); }, 2000);
}

/* ─── BOOT ────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  initRoleSystem();

  // Set date input
  const datePicker = eid('sub-date');
  if (datePicker) datePicker.value = new Date().toISOString().split('T')[0];

  // Fetch CSRF token first, then restore session
  fetchCsrfToken().then(() => {
    fetch('/api/auth/session')
      .then(response => {
        if (response.ok) return response.json();
        throw new Error('No active session');
      })
      .then(data => {
        console.log('[EvalSync API] Session restored successfully for', data.user.name);
        doLoginSuccess(data.user, data.user.roleKey);
      })
      .catch(err => {
        // If no session, fallback to local remember-me check
        const savedLogin = localStorage.getItem('evalsync_session');
        if (savedLogin === 'demo') {
          const email = eid('login-email');
          const pass = eid('login-pass');
          if (email) email.value = DEMO_USER.email;
          if (pass) pass.value = DEMO_USER.password;
        }
      });
  });

  // Remember me
  const rememberCheckbox = eid('remember-me');
  const btnLogin = eid('btn-login');
  if (btnLogin) {
    btnLogin.addEventListener('click', () => {
      if (rememberCheckbox && rememberCheckbox.checked) {
        localStorage.setItem('evalsync_session', 'demo');
      }
    });
  }
});

/* ═══════════════════════════════════════════════════════════
   PHASE 2 — NEW SYSTEMS
   ═══════════════════════════════════════════════════════════ */

/* ─── ROLE SYSTEM ─────────────────────────────────────────── */
const ROLES = {
  // EVALUATOR — only Submit + personal Queue tracker
  evaluator: {
    label: '👨‍🏫 Evaluator', cls: 'evaluator',
    email: 'evaluator@cbse.gov.in', pass: 'CBSE@2024',
    name: 'Rajan Mehta', initials: 'RM',
    allowedViews: ['submit', 'queue', 'mysubmissions'],
    defaultView: 'submit', readOnly: false,
    description: 'Upload answer scripts & track your queue position',
  },
  // ADMIN — queue ops, DLQ recovery, DB sync monitoring, audit
  admin: {
    label: '🛡️ Admin', cls: 'admin',
    email: 'admin@cbse.gov.in', pass: 'Admin@2024',
    name: 'Priya Singh', initials: 'PS',
    allowedViews: ['dashboard', 'submit', 'queue', 'dlq', 'database', 'security', 'admin', 'audit'],
    defaultView: 'dashboard', readOnly: false,
    description: 'Queue control, DLQ recovery, DB sync & security audit',
  },
  // SUPER ADMIN — full unrestricted access
  superadmin: {
    label: '👑 Super Admin', cls: 'superadmin',
    email: 'superadmin@cbse.gov.in', pass: 'SuperAdmin@2024',
    name: 'Dr. Arvind Kumar', initials: 'AK',
    allowedViews: ['dashboard', 'submit', 'queue', 'workers', 'analytics', 'security', 'database', 'admin', 'health', 'dlq', 'audit', 'loadbalancer', 'prediction', 'metrics', 'testing', 'mysubmissions'],
    defaultView: 'dashboard', readOnly: false,
    description: 'Full system access — all modules unlocked',
  },
  // MONITOR — read-only view of all modules, no actions
  monitor: {
    label: '📡 Monitor', cls: 'monitor',
    email: 'monitor@cbse.gov.in', pass: 'Monitor@2024',
    name: 'Sanjay Patel', initials: 'SP',
    allowedViews: ['dashboard', 'queue', 'workers', 'analytics', 'health', 'loadbalancer', 'prediction', 'metrics', 'testing', 'database', 'dlq', 'audit', 'security'],
    defaultView: 'dashboard', readOnly: true,
    description: 'Read-only monitoring — all views, zero write access',
  },
};
let activeRole = 'evaluator';
let sessionSeconds = 1800;
let sessionTimerInterval = null;

function initRoleSystem() {
  document.querySelectorAll('.role-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.role-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeRole = tab.dataset.role;
      const role = ROLES[activeRole];
      const emailEl = eid('dc-email'), passEl = eid('dc-pass');
      const loginEmailEl = eid('login-email'), loginPassEl = eid('login-pass');
      if (emailEl) emailEl.textContent = role.email;
      if (passEl) passEl.textContent = role.pass;
      if (loginEmailEl) loginEmailEl.value = role.email;
      if (loginPassEl) loginPassEl.value = role.pass;
    });
  });
}

function applyRoleBadge(role) {
  const r = ROLES[role] || ROLES.evaluator;
  // Update topbar badge
  const badge = eid('role-badge-topbar');
  if (badge) { badge.textContent = r.label; badge.className = `role-badge-topbar ${r.cls}`; }
  // Hide/show nav items by allowedViews
  document.querySelectorAll('.nav-item[data-view]').forEach(nav => {
    nav.style.display = r.allowedViews.includes(nav.dataset.view) ? '' : 'none';
  });
  // Also hide nav section labels if their children are all hidden
  document.querySelectorAll('.nav-section-label').forEach(label => {
    let next = label.nextElementSibling;
    let hasVisible = false;
    while (next && !next.classList.contains('nav-section-label')) {
      if (next.style.display !== 'none') hasVisible = true;
      next = next.nextElementSibling;
    }
    label.style.display = hasVisible ? '' : 'none';
  });
  // Read-only overlay for Monitor role
  const roOverlay = eid('readonly-overlay');
  if (r.readOnly) {
    if (!roOverlay) {
      const overlay = document.createElement('div');
      overlay.id = 'readonly-overlay';
      overlay.className = 'readonly-banner';
      overlay.innerHTML = `<span>👁 READ-ONLY MODE — ${r.label} cannot modify system state</span>`;
      const mc = document.querySelector('.main-content');
      if (mc) mc.prepend(overlay);
    }
    // Disable all write buttons for monitor
    document.querySelectorAll('.chaos-btn, #btn-spike, #btn-dlq-retry-all, #btn-spawn-worker, #btn-pause, #btn-resume, #btn-reset').forEach(btn => {
      btn.disabled = true; btn.title = 'Read-only — Monitor cannot trigger actions';
    });
  } else {
    if (roOverlay) roOverlay.remove();
  }
  // Navigate to default view for this role
  if (r.defaultView && r.allowedViews.includes(r.defaultView)) {
    switchView(r.defaultView);
  }
  // Update user info in sidebar
  setText('su-name', r.name);
  setText('su-role', r.description || r.label);
}

function startSessionTimer() {
  sessionSeconds = 1800;
  if (sessionTimerInterval) clearInterval(sessionTimerInterval);
  sessionTimerInterval = setInterval(() => {
    sessionSeconds--;
    const m = Math.floor(sessionSeconds / 60), s = sessionSeconds % 60;
    const timerEl = eid('session-timer');
    if (timerEl) {
      timerEl.textContent = `⏱ ${pad(m)}:${pad(s)}`;
      timerEl.className = 'session-timer' + (sessionSeconds <= 300 ? ' warning' : '') + (sessionSeconds <= 60 ? ' critical' : '');
    }
    if (sessionSeconds <= 0) { clearInterval(sessionTimerInterval); notify('Session Expired', 'Please log in again', 'warning', 8000); }
  }, 1000);
}

/* ─── P2 STATE ────────────────────────────────────────────── */
const p2State = {
  dlq: [], dlqRetried: 0, dlqRecovered: 0,
  auditEntries: [], auditCounter: 0,
  healthLatencyHistory: { gateway: [], queue: [], workers: [], encrypt: [], db: [], replica: [] },
  predictionHistory: { actual: [], predicted: [], labels: [] },
  peakPrediction: null,
  scalingEvents: [],
  perfMetrics: { fast: 0, med: 0, slow: 0, peakThroughput: 0, waitTimes: [], p99: 0 },
  chaosActive: null, _lastWorkerCount: 6,
};
const FAKE_IPS = ['103.25.41.12', '49.248.17.5', '122.176.90.33', '59.91.18.4', '182.64.23.17', '115.97.40.2'];

/* ─── SMART ALERTS ────────────────────────────────────────── */
const alertState = { workerFail: false, queueOverload: false };
function checkSmartAlerts() {
  state.workers.filter(w => w.errors > 3 && !w._alertFired).forEach(w => {
    w._alertFired = true;
    notify('⚙️ Worker Alert', `Worker-${String(w.id).padStart(2, '0')} has ${w.errors} errors`, 'warning', 6000);
    addIncident('warning', `Worker-${w.id} error rate high`, 'WORKER');
  });
  const qDepth = state.queue.incoming.length + state.queue.processing.length;
  if (qDepth > 40 && !alertState.queueOverload) {
    alertState.queueOverload = true;
    notify('📦 Queue Overload', `Queue depth ${qDepth} — System under heavy load`, 'error', 7000);
    addIncident('critical', `Queue depth critical: ${qDepth} items`, 'QUEUE');
    setTimeout(() => { alertState.queueOverload = false; }, 30000);
  }
  setText('nb-dlq', p2State.dlq.length);
}
function addIncident(type, msg, src) {
  const list = eid('incidents-list');
  if (!list) return;
  const empty = list.querySelector('.incident-empty');
  if (empty) empty.remove();
  const item = document.createElement('div');
  item.className = `incident-item ${type}`;
  item.innerHTML = `<span class="ii-badge ${type}">${type.toUpperCase()}</span><span><strong>[${src}]</strong> ${msg}</span><span style="margin-left:auto;font-size:.65rem;color:var(--text-muted)">${formatTime()}</span>`;
  list.insertBefore(item, list.firstChild);
  if (list.children.length > 10) list.lastChild.remove();
}

/* ─── DEAD LETTER QUEUE ───────────────────────────────────── */
function moveToDLQ(sub) {
  const reasons = ['Hash mismatch', 'Encryption timeout', 'DB write failed', 'Validation error', 'Network timeout'];
  p2State.dlq.push({ ...sub, dlqEnteredAt: new Date(), failureReason: pick(reasons) });
  renderDLQ();
  notify('☠️ Dead Letter Queue', `${sub.id.substring(0, 18)}... sent to DLQ`, 'error', 5000);
}
function renderDLQ() {
  const tbody = eid('dlq-tbody');
  if (!tbody) return;
  tbody.innerHTML = p2State.dlq.length === 0
    ? `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:2rem">☠️ No items in Dead Letter Queue</td></tr>`
    : p2State.dlq.map((item, idx) => `<tr><td><code>${item.id.substring(0, 22)}...</code></td><td>${item.subject}</td><td>${item.roll}</td><td style="color:var(--danger);font-weight:700">${item.retryCount}/3</td><td style="color:var(--warning)">${item.failureReason}</td><td>${item.dlqEnteredAt.toLocaleTimeString()}</td><td><button class="dlq-action-btn retry" onclick="retryFromDLQ(${idx})">🔄 Retry</button><button class="dlq-action-btn delete" onclick="deleteFromDLQ(${idx})">🗑 Del</button></td></tr>`).join('');
  setText('dlqs-total', p2State.dlq.length); setText('dlqs-retried', p2State.dlqRetried); setText('nb-dlq', p2State.dlq.length);
  const badge = eid('dlq-count-badge'); if (badge) badge.textContent = p2State.dlq.length + ' items';
}
window.retryFromDLQ = (idx) => { const item = p2State.dlq[idx]; if (!item) return; item.retryCount = 0; state.queue.incoming.push(item); p2State.dlq.splice(idx, 1); p2State.dlqRetried++; renderDLQ(); notify('🔄 DLQ Retry', `Re-queued`, 'info', 3000); };
window.deleteFromDLQ = (idx) => { p2State.dlq.splice(idx, 1); renderDLQ(); };

/* ─── SYSTEM HEALTH ───────────────────────────────────────── */
function initSystemHealth() {
  buildUptimeBars();
  // Initialise healthStatus
  if (!p2State.healthStatus) p2State.healthStatus = { gateway: 'OPERATIONAL', queue: 'OPERATIONAL', workers: 'OPERATIONAL', encrypt: 'OPERATIONAL', db: 'OPERATIONAL', replica: 'OPERATIONAL' };
  setManagedInterval('systemHealth', () => { updateWorkerCPUGrid(); drawHealthLatencyChart(); updateSvcLatencies(); updateHealthCards(); }, 2000);
}

/* Called by chaos tests to immediately reflect failures in System Health cards */
function updateHealthCards() {
  if (!p2State.healthStatus) return;
  const statusText = { OPERATIONAL: 'OPERATIONAL', WARNING: 'DEGRADED', CRITICAL: 'CRITICAL', OFFLINE: 'OFFLINE' };
  const statusColor = { OPERATIONAL: 'var(--success)', WARNING: 'var(--warning)', CRITICAL: 'var(--danger)', OFFLINE: 'var(--danger)' };
  const cardBg = { OPERATIONAL: ['', ''], WARNING: ['rgba(245,158,11,0.5)', 'rgba(245,158,11,0.04)'], CRITICAL: ['rgba(244,63,94,0.6)', 'rgba(244,63,94,0.06)'], OFFLINE: ['rgba(244,63,94,0.6)', 'rgba(244,63,94,0.06)'] };

  const svcMap = { gateway: 'gateway', queue: 'queue', workers: 'workers', encrypt: 'encrypt', db: 'db', replica: 'replica' };

  Object.entries(svcMap).forEach(([svc, key]) => {
    const statusKey = p2State.healthStatus[svc] || 'OPERATIONAL';
    const card = eid(`svc-${svc}`);
    const statusEl = eid(`svcst-${svc}`);
    if (statusEl) {
      statusEl.textContent = statusText[statusKey] || statusKey;
      statusEl.style.color = statusColor[statusKey] || 'var(--success)';
      statusEl.className = `svc-status ${statusKey === 'OPERATIONAL' ? 'ok' : statusKey === 'WARNING' ? 'warn' : 'fail'}`;
    }
    if (card) {
      const [bc, bg] = cardBg[statusKey] || ['', ''];
      card.style.borderColor = bc; card.style.background = bg;
      // Pulse animation on critical
      if (statusKey === 'CRITICAL') { card.style.animation = 'pulse 1s infinite'; }
      else { card.style.animation = ''; }
    }
  });

  // Update DB replication visual on DB chaos
  const dbStatus = p2State.healthStatus.db || 'OPERATIONAL';
  const primaryEl = eid('repst-primary');
  const r1El = eid('repst-r1');
  const primaryNode = eid('rep-primary');
  if (dbStatus === 'CRITICAL') {
    if (primaryEl) { primaryEl.textContent = '● OFFLINE'; primaryEl.style.color = 'var(--danger)'; }
    if (r1El) { r1El.textContent = '● FAILOVER ACTIVE'; r1El.style.color = 'var(--warning)'; }
    if (primaryNode) { primaryNode.style.borderColor = 'rgba(244,63,94,0.6)'; primaryNode.style.background = 'rgba(244,63,94,0.08)'; }
  } else {
    if (primaryEl) { primaryEl.textContent = '● ONLINE'; primaryEl.style.color = 'var(--success)'; }
    if (r1El) { r1El.textContent = '● IN SYNC'; r1El.style.color = 'var(--success)'; }
    if (primaryNode) { primaryNode.style.borderColor = ''; primaryNode.style.background = ''; }
  }

  // Update latency values — colour-code by severity
  Object.entries(p2State.healthLatencyHistory).forEach(([svc, hist]) => {
    if (!hist || hist.length === 0) return;
    const latest = hist[hist.length - 1];
    const el = eid(`svcl-${svc}`); if (!el) return;
    el.textContent = latest > 999 ? (latest / 1000).toFixed(1) + 's' : latest + 'ms';
    el.style.color = latest > 1000 ? 'var(--danger)' : latest > 300 ? 'var(--warning)' : 'var(--success)';
    el.style.fontWeight = latest > 300 ? '700' : '';
  });

  // Health latency chart is already redrawn by the health interval.
  // (Avoid double redraws that cause jank during chaos/system health updates.)

  // Also add an incident card for active chaos
  if (p2State.chaosActive) {
    addIncident('critical', `[CHAOS] ${p2State.chaosActive.toUpperCase()} test active — System under stress`, 'CHAOS');
  }
}


function buildUptimeBars() {
  const row = eid('uptime-bar-row'); if (!row) return; row.innerHTML = '';
  for (let i = 0; i < 90; i++) { const r = Math.random(); const bar = document.createElement('div'); bar.className = `uptime-bar ${r > 0.02 ? 'up' : r > 0.01 ? 'partial' : 'down'}`; row.appendChild(bar); }
}
function updateSvcLatencies() {
  const base = { gateway: 12, queue: 8, workers: 2, encrypt: 3, db: 22, replica: 34 };
  Object.entries(base).forEach(([svc, v]) => {
    const lat = v + rand(-3, 8);
    setText(`svcl-${svc}`, lat + 'ms');
    p2State.healthLatencyHistory[svc] = p2State.healthLatencyHistory[svc] || [];
    p2State.healthLatencyHistory[svc].push(lat);
    if (p2State.healthLatencyHistory[svc].length > 30) p2State.healthLatencyHistory[svc].shift();
  });
  setText('repl-r1', rand(8, 20) + 'ms lag'); setText('repl-r2', rand(20, 45) + 'ms lag');
}
function updateWorkerCPUGrid() {
  const grid = eid('worker-cpu-grid'); if (!grid) return;
  grid.innerHTML = state.workers.slice(0, 12).map(w => {
    const cpu = w.status === 'idle' ? rand(2, 15) : rand(40, 90);
    const color = cpu > 70 ? 'var(--danger)' : cpu > 40 ? 'var(--warning)' : 'var(--success)';
    return `<div class="wcpu-card"><span class="wcpu-name">W-${String(w.id).padStart(2, '0')}</span><span class="wcpu-val" style="color:${color}">${cpu}%</span><div class="wcpu-bar"><div class="wcpu-fill" style="width:${cpu}%;background:${color}"></div></div></div>`;
  }).join('');
}
function drawHealthLatencyChart() {
  const canvas = eid('health-latency-chart'); if (!canvas) return;
  const ctx = canvas.getContext('2d'); const W = canvas.width, H = canvas.height; ctx.clearRect(0, 0, W, H);
  const colors = { gateway: '#7c3aed', queue: '#a78bfa', encrypt: '#4ade80', db: '#facc15', replica: '#7c3aed' };
  Object.entries(colors).forEach(([svc, color]) => {
    const hist = p2State.healthLatencyHistory[svc] || [];
    if (hist.length < 2) return;
    ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.globalAlpha = 0.8;
    hist.forEach((v, i) => { const x = (i / (hist.length - 1)) * W, y = H - (v / 60) * H; i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
    ctx.stroke(); ctx.globalAlpha = 1;
  });
}

/* ─── LOAD BALANCER ───────────────────────────────────────── */
function initLoadBalancer() { setManagedInterval('loadBalancer', () => { if (state.currentView === 'loadbalancer') updateLoadBalancerView(); }, 1500); }
function updateLoadBalancerView() {
  const qDepth = state.queue.incoming.length;
  const rps = state.stats.throughputHistory.slice(-3).reduce((a, b) => a + b, 0) / 3;
  setText('lb-rps', rps.toFixed(1) + ' req/s'); setText('lb-qdepth', qDepth + ' items'); setText('lb-dbrecs', state.database.totalRecords.toLocaleString() + ' records');
  setText('lbsr-workers', state.workers.length); setText('lbsr-rps', rps.toFixed(1)); setText('lbsr-resp', rand(80, 250) + 'ms');
  const workerRow = eid('lb-workers-row');
  if (workerRow) workerRow.innerHTML = state.workers.map(w => {
    const isOffline = w.status === 'OFFLINE';
    const cls = isOffline ? 'offline-lb' : (w.status === 'idle' || w.status === 'IDLE') ? '' : 'busy-lb';
    const load = isOffline ? 0 : (w.status === 'idle' || w.status === 'IDLE') ? rand(2, 15) : rand(45, 92);
    const color = isOffline ? 'var(--danger)' : load > 70 ? 'var(--warning)' : '';
    return `<div class="lb-worker-box ${cls}" style="${color ? 'border-color:' + color : ''}">W-${String(w.id).padStart(2, '0')}<span class="lb-worker-load" style="${color ? 'color:' + color : ''}">${isOffline ? 'DEAD' : load + '%'}</span></div>`;
  }).join('');

  if (state.workers.length !== p2State._lastWorkerCount) {
    const diff = state.workers.length - p2State._lastWorkerCount;
    const evt = document.createElement('div');
    evt.className = 'scale-event';
    const icon = diff > 0 ? '📈 AUTO-SCALE ↑' : '📉 SCALE-DOWN ↓';
    evt.innerHTML = `<span style="color:${diff > 0 ? 'var(--success)' : 'var(--warning)'}">${icon}</span> ${formatTime()} — Pool: ${p2State._lastWorkerCount} → <strong>${state.workers.length}</strong> workers`;
    const list = eid('scaling-events');
    if (list) { list.insertBefore(evt, list.firstChild); if (list.children.length > 20) list.lastChild.remove(); }
  }
  p2State._lastWorkerCount = state.workers.length;
  drawLBDistChart();
}

function drawLBDistChart() {
  const canvas = eid('lb-dist-chart'); if (!canvas) return;
  const ctx = canvas.getContext('2d'); const W = canvas.width, H = canvas.height; ctx.clearRect(0, 0, W, H);
  const workers = state.workers; if (!workers.length) return;
  const total = workers.reduce((a, w) => a + Math.max(w.tasksCompleted, 1), 0);
  const colors = ['#7c3aed', '#a78bfa', '#4ade80', '#facc15', '#7c3aed', '#f87171', '#3b82f6', '#ec4899'];
  const cx = W / 2, cy = H / 2, r = Math.min(W, H) * 0.35; let start = -Math.PI / 2;
  workers.slice(0, 8).forEach((w, i) => { const share = w.tasksCompleted / total; const angle = share * Math.PI * 2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, r, start, start + angle); ctx.closePath(); ctx.fillStyle = colors[i % colors.length]; ctx.globalAlpha = 0.8; ctx.fill(); ctx.globalAlpha = 1; start += angle; });
  ctx.fillStyle = 'rgba(255,255,255,0.8)'; ctx.font = 'bold 13px system-ui, sans-serif'; ctx.textAlign = 'center'; ctx.fillText(workers.length + ' Workers', cx, cy - 5);
  ctx.font = '10px system-ui, sans-serif'; ctx.fillStyle = 'rgba(255,255,255,0.4)'; ctx.fillText('Even Load', cx, cy + 12);
}

/* ─── AI PREDICTION ───────────────────────────────────────── */
function initAIPrediction() {
  if (p2State.predictionHistory.actual.length === 0) {
    for (let i = 0; i < 20; i++) { p2State.predictionHistory.actual.push(rand(2, 15)); p2State.predictionHistory.labels.push(`-${20 - i}m`); }
  }
  updateAIPrediction(); setManagedInterval('aiPrediction', updateAIPrediction, 5000);
}
function updateAIPrediction() {
  const qDepth = state.queue.incoming.length;
  const actual = qDepth + rand(0, 5);
  p2State.predictionHistory.actual.push(actual);
  if (p2State.predictionHistory.actual.length > 30) p2State.predictionHistory.actual.shift();
  const forecast = []; let base = actual;
  for (let i = 0; i < 30; i++) { base += (Math.random() - 0.4) * 5; base = Math.max(0, base); forecast.push(Math.round(base)); }
  p2State.predictionHistory.predicted = forecast;
  const peakIdx = forecast.indexOf(Math.max(...forecast)); const peakLoad = forecast[peakIdx]; const peakMins = peakIdx + 1;
  p2State.peakPrediction = { mins: peakMins, load: peakLoad, workers: Math.ceil(peakLoad / 3 + 2) };
  const isPeak = peakLoad > 30;
  const alertEl = eid('prediction-alert'); if (alertEl) alertEl.className = `prediction-alert ${isPeak ? 'alert' : peakLoad > 15 ? 'warning' : ''}`;
  setText('pa-icon', isPeak ? '🚨' : peakLoad > 15 ? '⚠️' : '🤖');
  setText('pa-title', isPeak ? `Peak load expected in ${peakMins} min!` : peakLoad > 15 ? `Moderate traffic in ${peakMins} min` : 'Traffic nominal — system stable');
  setText('pa-detail', `Confidence: ${rand(88, 97)}% · LSTM+ARIMA · Peak: ${peakLoad} req/s`);
  setText('pa-confidence', rand(88, 97) + '%');
  setText('pt-val', peakMins + ' min'); setText('psi-load', peakLoad + ' req/s');
  setText('psi-workers', p2State.peakPrediction.workers + ' recommended'); setText('psi-qdepth', Math.round(peakLoad * 2.5) + ' items'); setText('psi-confidence', rand(88, 97) + '%');
  const wOK = state.workers.length >= p2State.peakPrediction.workers;
  updateRecBadge('rec-workers-body', 'rec-workers-badge', wOK ? `${state.workers.length} workers sufficient` : `Need ${p2State.peakPrediction.workers} (have ${state.workers.length})`, wOK ? 'ok' : 'action', wOK ? '✅ OK' : `⬆ +${p2State.peakPrediction.workers - state.workers.length}`);
  updateRecBadge('rec-queue-body', 'rec-queue-badge', `Buffer: ${Math.round(peakLoad * 3)} item cap`, peakLoad > 20 ? 'warn' : 'ok', peakLoad > 20 ? '⚠ Monitor' : '✅ OK');
  updateRecBadge('rec-db-body', 'rec-db-badge', `${rand(15, 30)} DB connections needed`, 'ok', '✅ Ready');
  updateRecBadge('rec-scale-body', 'rec-scale-badge', peakMins <= 5 ? 'Scale NOW — peak imminent' : `Scale in ${peakMins - 2} min`, peakMins <= 5 ? 'action' : 'warn', peakMins <= 5 ? '🚨 Now' : `⏱ ${peakMins - 2}m`);
  drawPredictionChart();
}
function updateRecBadge(bodyId, badgeId, body, cls, text) {
  setText(bodyId, body);
  const el = eid(badgeId); if (!el) return; el.className = `rec-badge ${cls}`; el.textContent = text;
}
function drawPredictionChart() {
  const canvas = eid('prediction-chart'); if (!canvas) return;
  const ctx = canvas.getContext('2d'); const W = canvas.width, H = canvas.height; ctx.clearRect(0, 0, W, H);
  const actual = p2State.predictionHistory.actual; const predicted = p2State.predictionHistory.predicted;
  const allVals = [...actual, ...predicted]; const maxVal = Math.max(...allVals, 10);
  const total = actual.length + predicted.length;
  const toX = (i) => (i / (total - 1)) * W; const toY = (v) => H - 20 - (v / maxVal) * (H - 30);
  // Confidence band
  ctx.beginPath();
  predicted.forEach((v, i) => { const x = toX(actual.length + i), y = toY(v * 1.2); i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
  for (let i = predicted.length - 1; i >= 0; i--) ctx.lineTo(toX(actual.length + i), toY(predicted[i] * 0.8));
  ctx.closePath(); ctx.fillStyle = 'rgba(248,113,113,0.06)'; ctx.fill();
  // Actual
  ctx.beginPath(); ctx.strokeStyle = '#7c3aed'; ctx.lineWidth = 2;
  actual.forEach((v, i) => { const x = toX(i), y = toY(v); i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); }); ctx.stroke();
  // Predicted dashed
  ctx.beginPath(); ctx.strokeStyle = '#facc15'; ctx.lineWidth = 2; ctx.setLineDash([5, 3]);
  predicted.forEach((v, i) => { const x = toX(actual.length + i), y = toY(v); i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); }); ctx.stroke(); ctx.setLineDash([]);
  // Divider
  const divX = toX(actual.length - 1); ctx.beginPath(); ctx.strokeStyle = 'rgba(255,255,255,0.15)'; ctx.lineWidth = 1; ctx.setLineDash([3, 3]); ctx.moveTo(divX, 0); ctx.lineTo(divX, H); ctx.stroke(); ctx.setLineDash([]);
}

/* ─── AUDIT LOG ───────────────────────────────────────────── */
function auditLog(action, details, role, type = 'LOGIN') {
  p2State.auditCounter++;
  const entry = { index: p2State.auditCounter, timestamp: new Date(), user: (ROLES[role] || ROLES.evaluator).name, role, action: type, details, ip: pick(FAKE_IPS), hash: generateSHA256Like().substring(0, 16), status: 'success' };
  p2State.auditEntries.unshift(entry);
  if (p2State.auditEntries.length > 200) p2State.auditEntries.pop();
  renderAuditLog();
}
function renderAuditLog() {
  const tbody = eid('audit-tbody'); if (!tbody) return;
  const search = ((eid('audit-search') || {}).value || '').toLowerCase();
  const rf = (eid('audit-filter-role') || {}).value || '';
  const af = (eid('audit-filter-action') || {}).value || '';
  const filtered = p2State.auditEntries.filter(e => (!rf || e.role === rf) && (!af || e.action === af) && (!search || JSON.stringify(e).toLowerCase().includes(search)));
  setText('audit-count', filtered.length);
  tbody.innerHTML = filtered.slice(0, 50).map(e => `<tr><td style="color:var(--text-muted)">${e.index}</td><td><code>${e.timestamp.toLocaleTimeString()}</code></td><td>${e.user}</td><td><span class="role-pill ${e.role}">${e.role}</span></td><td>${e.action}</td><td style="max-width:180px;font-size:.72rem">${e.details}</td><td><code>${e.ip}</code></td><td><code>${e.hash}...</code></td><td><span class="status-badge ok">SUCCESS</span></td></tr>`).join('');
  // Login history
  const lhist = eid('login-history');
  if (lhist) {
    const logins = p2State.auditEntries.filter(e => e.action === 'LOGIN').slice(0, 8);
    lhist.innerHTML = logins.map(e => `<div class="lh-item"><span class="role-pill ${e.role}">${e.role}</span><span class="lh-info">${e.user} · ${e.ip}</span><span class="lh-time">${e.timestamp.toLocaleTimeString()}</span></div>`).join('') || '<div style="color:var(--text-muted);padding:.5rem;font-size:.75rem">No logins yet</div>';
  }
  // Active sessions
  const asess = eid('active-sessions');
  if (asess) asess.innerHTML = Object.entries(ROLES).slice(0, 3).map(([k, r]) => `<div class="as-item"><span class="as-dot"></span><span class="as-name">${r.name}</span><span class="role-pill ${k}">${k}</span><span class="as-ip">${pick(FAKE_IPS)}</span></div>`).join('');
}

/* ─── PERFORMANCE METRICS ─────────────────────────────────── */
function initPerformanceMetrics() { setManagedInterval('performanceMetrics', updatePerformanceMetrics, 3000); }
function updatePerformanceMetrics() {
  const total = state.stats.totalProcessed, failed = state.stats.totalFailed;
  const times = state.stats.processTimes;
  const successRate = total > 0 ? ((total / (total + failed)) * 100).toFixed(1) + '%' : '—';
  const retryRate = state.stats.totalRetried > 0 ? ((total / (total + state.stats.totalRetried)) * 100).toFixed(1) + '%' : '—';
  const avgWait = times.length > 0 ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : null;
  const sorted = [...times].sort((a, b) => a - b);
  const p99 = sorted.length > 0 ? (sorted[Math.floor(sorted.length * 0.99)] || sorted[sorted.length - 1]) : null;
  const rps = state.stats.throughputHistory.slice(-3).reduce((a, b) => a + b, 0) / 3;
  if (rps > p2State.perfMetrics.peakThroughput) p2State.perfMetrics.peakThroughput = rps;
  setText('mc-throughput', p2State.perfMetrics.peakThroughput.toFixed(1));
  setText('mc-avgwait', avgWait ? avgWait + 'ms' : '—'); setText('mc-success', successRate);
  setText('mc-retry', retryRate); setText('mc-p99', p99 ? p99 + 'ms' : '—');
  const fast = times.filter(t => t < 500).length, med = times.filter(t => t >= 500 && t <= 2000).length, slow = times.filter(t => t > 2000).length;
  setText('sla-total', total); setText('sla-fast', fast); setText('sla-med', med); setText('sla-slow', slow); setText('sla-recov', state.stats.totalRetried); setText('sla-failed', failed);
  if (total > 0) { setWidth('slaf-fast', (fast / total) * 100); setWidth('slaf-med', (med / total) * 100); setWidth('slaf-slow', (slow / total) * 100); setWidth('slaf-recov', (state.stats.totalRetried / total) * 100); setWidth('slaf-failed', (failed / Math.max(total, 1)) * 100); }
  drawMetricsLatencyChart(times);
}
function drawMetricsLatencyChart(times) {
  const canvas = eid('metrics-latency-chart'); if (!canvas) return;
  const ctx = canvas.getContext('2d'); const W = canvas.width, H = canvas.height; ctx.clearRect(0, 0, W, H);
  const buckets = new Array(10).fill(0);
  times.forEach(t => { buckets[Math.min(Math.floor(t / 500), 9)]++; });
  const maxB = Math.max(...buckets, 1); const bw = W / 10;
  const colors = ['#10b981', '#10b981', '#34d399', '#f59e0b', '#f59e0b', '#fb923c', '#f43f5e', '#f43f5e', '#f43f5e', '#f43f5e'];
  buckets.forEach((v, i) => { const bh = (v / maxB) * (H - 30); ctx.fillStyle = colors[i]; ctx.globalAlpha = 0.8; ctx.fillRect(i * bw + 2, H - bh - 20, bw - 4, bh); ctx.globalAlpha = 1; });
  ['<500ms', '1s', '1.5s', '2s', '2.5s', '3s', '3.5s', '4s', '4.5s', '5s+'].forEach((l, i) => { ctx.fillStyle = 'rgba(255,255,255,0.3)'; ctx.font = '9px Inter'; ctx.textAlign = 'center'; ctx.fillText(l, i * bw + bw / 2, H - 4); });
}

/* ─── RESILIENCE TESTING ──────────────────────────────────── */
function initResilienceTesting() {
  ['db', 'net', 'overload', 'workers', 'encrypt', 'queue'].forEach(t => {
    const btn = eid(`chaos-${t}`);
    if (btn) btn.addEventListener('click', () => runChaosTest(t));
  });
  chaosLog('💻 Chaos Engineering ready. Select a failure scenario to begin.');
  const dlqRetryAll = eid('btn-dlq-retry-all');
  if (dlqRetryAll) dlqRetryAll.addEventListener('click', () => { p2State.dlq.forEach(item => { item.retryCount = 0; state.queue.incoming.push(item); p2State.dlqRetried++; }); p2State.dlq = []; renderDLQ(); notify('🔄 DLQ Batch Retry', 'All items re-queued', 'success'); });
}
function chaosLog(msg, type = 'info') {
  const t = eid('chaos-terminal'); if (!t) return;
  const line = document.createElement('div'); line.className = 'term-line';
  const c = { info: '#94a3b8', success: '#10b981', warn: '#f59e0b', error: '#f43f5e' };
  line.innerHTML = `<span class="tl-time">${formatTime()}</span><span style="color:${c[type] || c.info}">${msg}</span>`;
  t.appendChild(line); if (t.children.length > 100) t.firstChild.remove(); t.scrollTop = t.scrollHeight;
}
async function runChaosTest(type) {
  if (p2State.chaosActive) { chaosLog('⚠️ Test already running — wait for current test to finish', 'warn'); return; }
  p2State.chaosActive = type;
  const btn = eid(`chaos-${type}`); if (btn) btn.disabled = true;
  const panel = eid('response-panel'); if (panel) panel.innerHTML = '';
  logAuditEvent('chaos-test', `Triggered Chaos Test: ${type.toUpperCase()}`);

  const step = (stype, msg, delayMs) => new Promise(r => {
    setTimeout(() => {
      addResponseItem(stype, msg);
      chaosLog(`[${type.toUpperCase()}] ${msg}`, stype);
      // Broadcast to live feed and terminal
      feedLog(stype === 'fail' ? '🔴' : stype === 'warn' ? '🟡' : '🟢', `<strong>[CHAOS-${type.toUpperCase()}]</strong> ${msg}`, stype === 'fail' ? 'error' : stype === 'warn' ? 'warning' : 'success');
      termLog(stype === 'fail' ? 'ERROR' : stype === 'warn' ? 'WARN' : 'SUCCESS', `<span>[CHAOS] ${msg}</span>`);
      r();
    }, delayMs);
  });

  // Update topbar status bar
  const ssb = eid('system-status-bar');
  const setStatus = (cls, text) => { if (ssb) ssb.innerHTML = `<span class="ssb-dot ${cls}"></span><span class="ssb-text">${text}</span>`; };

  addResponseItem('warn', `🔴 Initiating Chaos Test: ${type.toUpperCase()}`);
  chaosLog(`\n▶ Starting: ${type.toUpperCase()} test scenario`, 'warn');

  /* ─────────────────────────────────────────
     1. DB CRASH
     ───────────────────────────────────────── */
  if (type === 'db') {
    setStatus('critical', '🔴 CRITICAL — Primary DB Failure');
    // Mark DB as failed in health state
    p2State.healthStatus = { ...p2State.healthStatus, db: 'CRITICAL', replica: 'WARNING' };
    state.database.pendingSync = (state.database.pendingSync || 0) + 50;
    // Spike DB latency
    for (let i = 0; i < 20; i++) { p2State.healthLatencyHistory.db.push(rand(2000, 8000)); if (p2State.healthLatencyHistory.db.length > 30) p2State.healthLatencyHistory.db.shift(); }
    secLog('🔴', '<strong>PRIMARY DB FAILURE</strong> — All writes paused, failover initiated', 'fail');
    dbLog('💥', '<strong>PRIMARY DB CRASHED</strong> — Mumbai DC unresponsive');
    updateHealthCards();

    await step('fail', '💥 Primary DB (Mumbai) — Connection dropped!', 0);
    await step('fail', '🚨 Write pipeline HALTED — 50 submissions pending sync', 600);
    await step('warn', '🔄 Initiating failover to Replica 1 (Delhi)...', 1400);
    // Simulate failover — queue keeps buffering
    state.simulation.paused = true;
    await step('warn', '⏳ Replication lag: 847ms — Syncing WAL logs...', 2200);
    await step('warn', '📦 Queue absorbing load — No submissions lost', 3000);

    setTimeout(() => {
      // Recovery
      state.simulation.paused = false;
      p2State.healthStatus = { ...p2State.healthStatus, db: 'OPERATIONAL', replica: 'OPERATIONAL' };
      for (let i = 0; i < 10; i++) { p2State.healthLatencyHistory.db.push(rand(40, 120)); p2State.healthLatencyHistory.db.shift(); }
      state.database.pendingSync = 0;
      setStatus('operational', '✅ All Systems Operational — DB Recovered');
      updateHealthCards();
      dbLog('✅', '<strong>Replica promoted to Primary</strong> — Delhi DC now serving writes');
      secLog('✅', '<strong>DB Failover complete</strong> — Zero data loss confirmed', 'ok');
    }, 4500);
    await step('ok', '✅ Replica (Delhi) promoted to Primary DB', 4600);
    await step('ok', '✅ WAL replay complete — 0 rows lost', 5200);
    await step('ok', '🏆 DB recovered — All 50 pending submissions synced', 6000);
  }

  /* ─────────────────────────────────────────
     2. NETWORK PARTITION
     ───────────────────────────────────────── */
  else if (type === 'net') {
    setStatus('degraded', '🟡 DEGRADED — Network Partition Active');
    // Spike all latencies
    const spikeLatency = () => {
      ['gateway', 'queue', 'workers', 'encrypt', 'db', 'replica'].forEach(svc => {
        p2State.healthLatencyHistory[svc].push(rand(1500, 4000));
        if (p2State.healthLatencyHistory[svc].length > 30) p2State.healthLatencyHistory[svc].shift();
      });
    };
    spikeLatency();
    // Slow down workers artificially
    state.workers.forEach(w => { w._netDelay = true; });
    updateHealthCards();
    secLog('📡', '<strong>NETWORK PARTITION</strong> — 50% packet loss on inter-DC links', 'fail');

    await step('fail', '📡 Network partition detected — 50% packet loss', 0);
    await step('fail', '🌐 Inter-DC links degraded: Mumbai ↔ Delhi ↔ Chennai', 400);
    await step('warn', '⚙️ Workers entering retry-with-backoff mode', 900);
    await step('warn', '📦 Queue buffering — submissions held safely in memory', 1500);

    // Intermediate spike — add more latency
    setTimeout(() => { spikeLatency(); drawHealthLatencyChart(); }, 2000);
    await step('warn', '⚡ Throughput reduced 60% — System degraded but stable', 2200);
    await step('warn', '🔁 Retry storm: 1,247 in-flight retries', 3000);

    setTimeout(() => {
      // Partial recovery — latency normalises
      ['gateway', 'queue', 'workers', 'encrypt', 'db', 'replica'].forEach(svc => {
        p2State.healthLatencyHistory[svc].push(rand(80, 200));
        if (p2State.healthLatencyHistory[svc].length > 30) p2State.healthLatencyHistory[svc].shift();
      });
      state.workers.forEach(w => { delete w._netDelay; });
      setStatus('operational', '✅ All Systems Operational');
      updateHealthCards();
    }, 4200);
    await step('ok', '✅ Network healed — Packet loss 0%', 4500);
    await step('ok', '✅ Backlog of 342 retries cleared in 1.2s', 5200);
    await step('ok', '🏆 Queue absorbed full load — Zero data lost', 6000);
  }

  /* ─────────────────────────────────────────
     3. 1000 SUBMISSION OVERLOAD
     ───────────────────────────────────────── */
  else if (type === 'overload') {
    setStatus('degraded', '🟡 LOAD TEST — 1000 Submission Spike');
    const prevWorkers = state.workers.length;
    notify('⚡ OVERLOAD TEST', '1000 submissions injected — watch the queue spike!', 'warning', 6000);

    await step('warn', `⚡ Injecting 1000 simultaneous submissions...`, 0);

    // Inject submissions in 4 batches for realism
    let injected = 0;
    const injectBatch = (count, delay) => setTimeout(() => {
      for (let i = 0; i < count; i++) enqueueSubmission(createSubmission());
      injected += count;
      chaosLog(`📥 ${injected}/1000 injected — Queue: ${state.queue.incoming.length + state.queue.processing.length}`, 'warn');
    }, delay);
    injectBatch(250, 100);
    injectBatch(250, 500);
    injectBatch(250, 900);
    injectBatch(250, 1300);

    await step('warn', '📦 Queue depth: CRITICAL — Spike detected', 500);
    await step('warn', `🏭 Current workers: ${prevWorkers} — Threshold exceeded`, 1000);
    await step('warn', '🤖 Auto-scaler triggered — Requesting new worker instances', 1500);

    // Auto-scale: add workers progressively
    const addWorker = (delay, id) => setTimeout(() => {
      const newWorker = { id, status: 'IDLE', processed: 0, errors: 0, currentTask: null, uptime: 0, cpu: 0 };
      state.workers.push(newWorker);
      setText('nb-workers', state.workers.length);
      chaosLog(`⚙️ Worker-${String(id).padStart(2, '0')} spawned (auto-scale) — Total: ${state.workers.length}`, 'ok');
      addResponseItem('ok', `⚙️ Worker-${String(id).padStart(2, '0')} spawned — Total workers: ${state.workers.length}`);
      feedLog('⚙️', `<strong>AUTO-SCALE:</strong> Worker-${String(id).padStart(2, '0')} spawned — pool now ${state.workers.length} workers`, 'success');
    }, delay);

    addWorker(2000, 7);
    addWorker(2500, 8);
    addWorker(3000, 9);
    addWorker(3500, 10);
    addWorker(4000, 11);
    addWorker(4500, 12);

    await step('ok', '✅ Worker-07 spawned (auto-scale +1)', 2200);
    await step('ok', '✅ Worker-08 spawned (auto-scale +2)', 2700);
    await step('ok', '✅ Worker-09, 10, 11, 12 spawned (auto-scale +6)', 4700);
    await step('ok', `🏭 Worker pool scaled: ${prevWorkers} → 12 workers`, 5000);
    await step('ok', '📊 Throughput normalising — Queue draining at 24 submissions/s', 5500);

    // After 30 seconds, scale back down
    setTimeout(() => {
      const toRemove = state.workers.length - prevWorkers;
      if (toRemove > 0) {
        state.workers.splice(prevWorkers, toRemove);
        setText('nb-workers', state.workers.length);
        chaosLog(`📉 Auto-scale-down: Pool reduced to ${state.workers.length} workers`, 'ok');
        feedLog('📉', `<strong>AUTO-SCALE-DOWN:</strong> Pool reduced back to ${state.workers.length} workers`, 'info');
      }
      setStatus('operational', '✅ All Systems Operational');
    }, 30000);
    await step('ok', '🏆 Overload test complete — 1000 submissions absorbed, zero lost', 6200);
  }

  /* ─────────────────────────────────────────
     4. KILL ALL WORKERS
     ───────────────────────────────────────── */
  else if (type === 'workers') {
    setStatus('critical', '🔴 CRITICAL — All Workers Terminated');
    // Kill all workers
    const savedWorkers = state.workers.map(w => ({ ...w }));
    state.workers.forEach(w => { w.status = 'OFFLINE'; w.currentTask = null; });
    state.simulation.paused = true;
    updateHealthCards();
    secLog('🔪', '<strong>ALL WORKERS TERMINATED</strong> — Processing halted', 'fail');

    await step('fail', `🔪 SIGKILL sent to all ${savedWorkers.length} worker processes`, 0);
    await step('fail', '⚠️ Worker pool: 0 active — Queue halted', 400);
    await step('warn', '📦 Queue holding safely — 0 items lost (FIFO preserved)', 800);
    await step('warn', `📊 ${state.queue.incoming.length + state.queue.processing.length} submissions queued, awaiting workers`, 1200);
    await step('warn', '🤖 Auto-respawn system activating...', 2000);

    // Respawn workers one by one
    state.workers.forEach((w, i) => {
      setTimeout(() => {
        w.status = 'IDLE'; w.processed = 0; w.errors = 0; w.cpu = 0;
        chaosLog(`✅ Worker-${String(w.id).padStart(2, '0')} respawned (${i + 1}/${savedWorkers.length})`, 'ok');
        if (i === savedWorkers.length - 1) {
          state.simulation.paused = false;
          setStatus('operational', '✅ All Systems Operational');
          updateHealthCards();
          secLog('✅', '<strong>All workers restored</strong> — Processing resumed', 'ok');
        }
      }, 2500 + i * 300);
    });

    await step('ok', '✅ Workers 01–03 respawned', 2700);
    await step('ok', '✅ Workers 04–06 respawned — Full pool restored', 3500);
    await step('ok', '📊 Queue draining — Backlog clearing at full speed', 4000);
    await step('ok', '🏆 Worker recovery complete — All submissions preserved', 4500);
  }

  /* ─────────────────────────────────────────
     5. ENCRYPTION FAILURE
     ───────────────────────────────────────── */
  else if (type === 'encrypt') {
    setStatus('critical', '🔴 CRITICAL — Encryption Module Failure');
    p2State.healthStatus = { ...p2State.healthStatus, encrypt: 'CRITICAL' };
    // Cause workers to fail their encrypt stage
    state.workers.forEach(w => { w._encryptFail = true; });
    updateHealthCards();
    secLog('🔐', '<strong>ENCRYPTION MODULE CRASHED</strong> — AES-256 unavailable!', 'fail');
    // Force some submissions to fail
    const toFail = state.queue.incoming.splice(0, Math.min(5, state.queue.incoming.length));
    toFail.forEach(s => { s.retryCount = 0; state.queue.failed.push(s); state.stats.totalFailed++; });

    await step('fail', '🔐 AES-256-GCM module crash — Encryption unavailable!', 0);
    await step('fail', `⚠️ ${toFail.length} submissions rejected — Cannot encrypt`, 500);
    await step('fail', '🚨 Security policy: REJECT all unencrypted submissions', 800);
    await step('warn', '🔄 Loading backup HSM cipher module...', 1200);
    await step('warn', '⚙️ Initialising AES-256-GCM fallback module...', 1800);

    setTimeout(() => {
      state.workers.forEach(w => { delete w._encryptFail; });
      p2State.healthStatus = { ...p2State.healthStatus, encrypt: 'OPERATIONAL' };
      setStatus('operational', '✅ All Systems Operational');
      updateHealthCards();
      secLog('✅', '<strong>Encryption restored</strong> — HSM failover active', 'ok');
    }, 3000);

    await step('ok', '✅ Backup AES-256-GCM module active', 3200);
    await step('ok', '✅ Primary cipher re-keyed and restored', 4000);
    await step('ok', '🏆 Encryption failover: <50ms RTO achieved', 4500);
  }

  /* ─────────────────────────────────────────
     6. QUEUE SATURATION
     ───────────────────────────────────────── */
  else if (type === 'queue') {
    setStatus('degraded', '🟡 DEGRADED — Queue Saturation');
    const satCount = 200;
    // Actually fill the queue
    for (let i = 0; i < satCount; i++) state.queue.incoming.push(createSubmission());
    state.stats.totalSubmitted += satCount;
    setText('nb-queue', state.queue.incoming.length);

    await step('warn', `📦 Queue saturating — Injecting ${satCount} items...`, 0);
    await step('warn', `📊 Queue depth: ${state.queue.incoming.length} items (${Math.round(state.queue.incoming.length / 50 * 100)}% capacity)`, 400);
    await step('warn', '⚠️ Back-pressure alert — Rate limiter activating', 800);
    await step('warn', '🛑 New submissions throttled to 10/s (from 100/s)', 1400);
    await step('warn', '⚙️ All workers reassigned to drain mode', 1800);
    // Fast-drain: pause intake, process more
    state.workers.forEach(w => { w._drainMode = true; });

    await step('ok', '📉 Queue depth declining: 180 → 140 → 90...', 2500);

    setTimeout(() => {
      state.workers.forEach(w => { delete w._drainMode; });
      setStatus('operational', '✅ All Systems Operational');
    }, 4000);
    await step('ok', '✅ Rate limiter lifted — Normal throughput restored', 4200);
    await step('ok', '🏆 Queue drained — Back-pressure control validated', 5000);
  }

  /* ─────────────────────────────────────────
     WRAP UP
     ───────────────────────────────────────── */
  const resultMap = {
    db: '✅ DB Failover — Zero Data Lost',
    net: '✅ Network Resilience — Queue Absorbed Load',
    overload: '✅ Auto-Scale — 1000 Submissions Handled',
    workers: '✅ Worker Recovery — FIFO Preserved',
    encrypt: '✅ Cipher Failover — <50ms RTO',
    queue: '✅ Back-Pressure Control — Validated',
  };
  addResponseItem('ok', `🏆 ${resultMap[type]}`);
  const el = eid(`cbr-${type}`); if (el) { el.textContent = resultMap[type]; el.style.color = 'var(--success)'; }
  auditLog(`Chaos test completed: ${type}`, `Result: ${resultMap[type]}`, activeRole, 'ADMIN');
  p2State.chaosActive = null;
  if (btn) btn.disabled = false;
  notify('🧪 Chaos Test Complete', `${type.toUpperCase()}: ${resultMap[type]}`, 'success', 5000);
}

function addResponseItem(type, msg) {
  const panel = eid('response-panel'); if (!panel) return;
  const empty = panel.querySelector('.rp-idle'); if (empty) empty.remove();
  const item = document.createElement('div'); item.className = `rp-item ${type === 'ok' ? 'ok' : type === 'fail' ? 'fail' : 'warn'}`;
  item.innerHTML = `<span style="color:var(--text-muted);font-size:.65rem">${formatTime()}</span><span style="margin-left:.5rem">${msg}</span>`;
  panel.appendChild(item); panel.scrollTop = panel.scrollHeight;
}

/* ─── AUDIT FILTERS ───────────────────────────────────────── */
function initAuditFilters() {
  ['audit-search', 'audit-filter-role', 'audit-filter-action'].forEach(id => { const el = eid(id); if (el) el.addEventListener('input', () => renderAuditLog()); });
  const exportBtn = eid('btn-export-audit');
  if (exportBtn) exportBtn.addEventListener('click', () => {
    const csv = ['#,Timestamp,User,Role,Action,Details,IP,Status', ...p2State.auditEntries.map(e => `${e.index},"${e.timestamp.toLocaleString()}","${e.user}","${e.role}","${e.action}","${e.details}","${e.ip}","${e.status}"`)].join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'evalsync-audit.csv'; a.click();
  });
}

/* ─── PATCH switchView ────────────────────────────────────── */
const _origSwitchView = switchView;
window.switchView = function (viewName) {
  _origSwitchView(viewName);
  const extra = { health: 'System Health', dlq: 'Dead Letter Queue', loadbalancer: 'Load Balancer', prediction: 'AI Prediction', audit: 'Audit Log', metrics: 'Performance', testing: 'Resilience Test' };
  if (extra[viewName]) setText('bc-current', extra[viewName]);
  if (viewName === 'prediction') setTimeout(drawPredictionChart, 100);
  if (viewName === 'loadbalancer') setTimeout(updateLoadBalancerView, 100);
  if (viewName === 'metrics') setTimeout(updatePerformanceMetrics, 100);
  if (viewName === 'audit') renderAuditLog();
  if (viewName === 'dlq') renderDLQ();
  if (viewName === 'health') { drawHealthLatencyChart(); updateWorkerCPUGrid(); }
};

/* ─── PATCH initApp ───────────────────────────────────────── */
const _origInitApp = initApp;
window.initApp = function (user) {
  _origInitApp(user);
  applyRoleBadge(activeRole);
  startSessionTimer();
  auditLog('Logged in from ' + pick(FAKE_IPS), 'Session started · Role: ' + (ROLES[activeRole] || ROLES.evaluator).label, activeRole, 'LOGIN');
  // Initialize phase 2 modules (only if role allows them)
  initSystemHealth();
  initLoadBalancer();
  initAIPrediction();
  initPerformanceMetrics();
  initResilienceTesting();
  initAuditFilters();
  initMySubmissions();
  setManagedInterval('smartAlerts', checkSmartAlerts, 5000);
  setManagedInterval('auditAndSubmissionRefresh', () => {
    if (Math.random() < 0.25) {
      const r = pick(Object.keys(ROLES)), acts = [{ d: 'Script uploaded', t: 'SUBMIT' }, { d: 'Queue threshold cleared', t: 'ADMIN' }, { d: 'Failed login attempt from ' + pick(FAKE_IPS), t: 'SECURITY' }, { d: 'Config updated', t: 'ADMIN' }];
      const a = pick(acts); auditLog(a.d, a.d, r, a.t);
    }
    // DLQ routing — permanently failed items
    state.queue.failed.filter(s => s.retryCount >= 3 && !s._inDLQ).forEach(s => { s._inDLQ = true; moveToDLQ(s); });
    // Update My Submissions
    updateMySubmissions();
  }, 8000);
};

/* ─── MY SUBMISSIONS MODULE (Evaluator) ─────────────────────── */
// mySubmissions array declared at top of file
function initMySubmissions() {
  updateMySubmissions();
}

function trackMySubmission(sub) {
  // Guard: only run if function exists (Phase 2 loaded)
  if (!Array.isArray(mySubmissions)) return;
  mySubmissions.unshift({ ...sub, trackedAt: new Date(), lastStatus: 'queued' });
  if (mySubmissions.length > 20) mySubmissions.pop();
  updateMySubmissions();
}

function updateMySubmissions() {
  const tbody = eid('mysub-tbody'); if (!tbody) return;
  // Sync statuses from main queue state
  mySubmissions.forEach(ms => {
    const inProcessing = state.queue.processing.find(s => s.id === ms.id);
    const inCompleted = state.queue.completed.find(s => s.id === ms.id);
    const inFailed = state.queue.failed.find(s => s.id === ms.id);
    const inDLQ = p2State.dlq.find(s => s.id === ms.id);
    if (inCompleted) ms.lastStatus = 'completed';
    else if (inProcessing) ms.lastStatus = 'processing';
    else if (inDLQ) ms.lastStatus = 'dlq';
    else if (inFailed) ms.lastStatus = 'failed';
    else ms.lastStatus = 'queued';
  });

  // Update nav count badge
  const nbMysub = eid('nb-mysub');
  if (nbMysub) nbMysub.textContent = mySubmissions.length;

  // Update stat cards
  const completed = mySubmissions.filter(m => m.lastStatus === 'completed').length;
  const queued = mySubmissions.filter(m => m.lastStatus === 'queued' || m.lastStatus === 'processing').length;
  setText('eic-submitted', mySubmissions.length);
  setText('eic-completed', completed);
  setText('eic-pending', queued);
  setText('mysub-count', mySubmissions.length + ' submission' + (mySubmissions.length !== 1 ? 's' : ''));

  const statusConfig = {
    queued: { cls: 'info', icon: '⏳', label: 'In Queue' },
    processing: { cls: 'warn', icon: '⚙️', label: 'Processing' },
    completed: { cls: 'ok', icon: '✅', label: 'Completed' },
    failed: { cls: 'fail', icon: '❌', label: 'Failed' },
    dlq: { cls: 'fail', icon: '☠️', label: 'Dead Letter Queue' },
  };

  if (mySubmissions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:2rem">📋 No submissions yet — <a href="#" onclick="switchView('submit');return false;" style="color:var(--primary)">Upload your first script</a></td></tr>`;
    return;
  }

  tbody.innerHTML = mySubmissions.map(ms => {
    const sc = statusConfig[ms.lastStatus] || statusConfig.queued;
    const qPos = state.queue.incoming.findIndex(s => s.id === ms.id);
    return `<tr>
      <td><code style="font-size:.72rem;color:var(--secondary)">${ms.id.substring(0, 22)}…</code></td>
      <td>${ms.subject || '—'}</td>
      <td>${ms.roll || '—'}</td>
      <td><code style="font-size:.68rem">${ms.hash ? ms.hash.substring(0, 14) + '…' : '—'}</code></td>
      <td style="font-weight:700;color:var(--warning)">${qPos >= 0 ? '#' + (qPos + 1) : ms.lastStatus === 'processing' ? '⚙️ Active' : '—'}</td>
      <td><span class="status-badge ${sc.cls}">${sc.icon} ${sc.label}</span></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:.72rem">${ms.trackedAt.toLocaleTimeString()}</td>
    </tr>`;
  }).join('');
}

// Hook into the submission flow to track manual submissions
const _origRunSubmissionProcessing = runSubmissionProcessing;
window.runSubmissionProcessing_orig = _origRunSubmissionProcessing;
