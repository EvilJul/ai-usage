'use strict';
/**
 * AI 用量前端。两种部署模式共用同一套代码：
 *   - server：从 /api/* 取数
 *   - static：读 data/ 下的预生成文件，在浏览器里解密并合并各机器数据
 */

const state = {
  mode: 'server',
  encrypted: false,
  snapshotMs: 0,
  days: 30,        // 0 = 全部
  data: null,
  view: 'models',
  expanded: false,
  refreshId: 0,
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

// ---------- 格式化 ----------

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

/** 整数缩写：1.2K / 3.4M / 5.6B，保留三位有效数字 */
function fmtInt(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  const a = Math.abs(n);
  if (a >= 1e9) return (n / 1e9).toFixed(a >= 1e10 ? 1 : 2) + 'B';
  if (a >= 1e6) return (n / 1e6).toFixed(a >= 1e7 ? 1 : 2) + 'M';
  if (a >= 1e4) return (n / 1e3).toFixed(a >= 1e5 ? 0 : 1) + 'K';
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** 金额：小于 1 分也显示，不显示成 $0 */
function fmtUSD(micro) {
  if (micro == null || !Number.isFinite(micro)) return '—';
  const v = micro / 1e6;
  if (v === 0) return '$0';
  if (v >= 10000) return '$' + (v / 1000).toFixed(1) + 'K';
  if (v >= 100) return '$' + v.toFixed(0);
  if (v >= 1) return '$' + v.toFixed(2);
  if (v >= 0.01) return '$' + v.toFixed(3);
  return '$' + v.toFixed(4);
}

function fmtMoney(v, unit) {
  if (v == null) return '—';
  if (unit === 'USD') return '$' + v.toFixed(2);
  if (unit === 'CNY') return '¥' + v.toFixed(2);
  if (unit === 'percent') return v.toFixed(1) + '%';
  if (unit === 'requests') return fmtInt(v) + ' 次';
  return String(v);
}

/** 相对时间：刚刚 / 12 分钟前 / 3 小时前 / 10-24 */
function fmtAgo(ms) {
  if (!ms) return '—';
  const diff = Date.now() - ms;
  if (diff < 0) return '即将';
  if (diff < 90e3) return '刚刚';
  if (diff < 3600e3) return Math.floor(diff / 60e3) + ' 分钟前';
  if (diff < 86400e3) return Math.floor(diff / 3600e3) + ' 小时前';
  const d = new Date(ms);
  return `${d.getMonth() + 1}-${String(d.getDate()).padStart(2, '0')}`;
}

function fmtClock(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const dayKey = (d) => {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

function daysAgoKey(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return dayKey(d);
}

// ---------- 静态模式：解密与合并 ----------

let staticData = null;
let staticPass = null;

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function decryptJSON(enc, passphrase) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBytes(enc.salt), iterations: enc.iter, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(enc.iv) }, key, b64ToBytes(enc.ct));
  if (enc.enc === 'gzip+aes-256-gcm') {
    plain = await new Response(
      new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip')),
    ).arrayBuffer();
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

/** 价格表索引（与采集端口径一致） */
function buildPriceIdx(prices) {
  const eff = (prices && prices.d) || '1970-01-01';
  const idx = new Map();
  for (const m of (prices && prices.models) || []) {
    let name; let input; let output; let cacheRead; let cacheCreate;
    if (Array.isArray(m)) [name, input, output, cacheRead, cacheCreate] = m;
    else {
      name = m.model; input = m.input_per_mtok; output = m.output_per_mtok;
      cacheRead = m.cache_read_per_mtok; cacheCreate = m.cache_creation_per_mtok;
    }
    if (!name) continue;
    if (!idx.has(name)) idx.set(name, []);
    idx.get(name).push({
      effective_from: (m && m.effective_from) || eff,
      input: +input || 0, output: +output || 0,
      cacheRead: +cacheRead || 0, cacheCreate: +cacheCreate || 0,
    });
  }
  for (const l of idx.values()) l.sort((a, b) => a.effective_from.localeCompare(b.effective_from));
  return idx;
}

function normalizeName(s) {
  let v = String(s || '').trim().toLowerCase();
  const m = v.match(/^(.*)-(\d{8})$/);
  if (m) v = m[1];
  const at = v.indexOf('@');
  if (at > 0) v = v.slice(0, at);
  if (v.endsWith('-latest')) v = v.slice(0, -7);
  return v;
}

function costMicro(priceIdx, row) {
  const seen = new Set();
  const names = [];
  for (const c of [row.pricing_model, row.model, row.request_model]) {
    const v = String(c || '').trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    names.push(v, normalizeName(v));
  }
  const pick = (list) => {
    let best = null;
    for (const p of list) if (p.effective_from <= row.date) best = p;
    return best || list[0] || null;
  };
  let price = null;
  for (const n of names) {
    if (!n) continue;
    const exact = priceIdx.get(n);
    if (exact) { price = pick(exact); if (price) break; }
    for (const [k, list] of priceIdx) {
      if (normalizeName(k) === n) { price = pick(list); if (price) break; }
    }
    if (price) break;
  }
  if (!price) return 0;
  let input = row.input_tokens;
  if (row.input_token_semantics === 1) input = Math.max(0, input - row.cache_read_tokens);
  const micro = input * price.input
    + row.output_tokens * price.output
    + row.cache_read_tokens * price.cacheRead
    + row.cache_creation_tokens * price.cacheCreate;
  return Number.isFinite(micro) && micro > 0 ? Math.round(micro) : 0;
}

async function loadJSON(path) {
  const url = state.mode === 'static' ? `${path}?t=${Math.floor(Date.now() / 300000)}` : path;
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** 口令门：等用户在页面上输入 */
function askPassphrase(message = '') {
  return new Promise((resolve) => {
    document.body.classList.add('locked');
    const panel = $('#unlock');
    const form = $('#unlock-form');
    const input = $('#pass');
    const msg = $('#unlock-msg');
    panel.hidden = false;
    msg.textContent = message;
    input.value = '';
    setTimeout(() => input.focus(), 50);

    const onSubmit = (e) => {
      e.preventDefault();
      const v = input.value;
      if (!v) return;
      form.removeEventListener('submit', onSubmit);
      panel.hidden = true;
      document.body.classList.remove('locked');
      resolve(v);
    };
    form.addEventListener('submit', onSubmit);
  });
}

async function loadStaticData() {
  if (staticData) return staticData;
  const index = await loadJSON('./data/index.json');
  const prices = await loadJSON('./data/prices.json').catch(() => ({ models: [] }));
  const priceIdx = buildPriceIdx(prices);

  const rows = [];
  const quotas = [];

  for (const m of index.machines || []) {
    const raw = await loadJSON('./data/' + m.file);
    let doc = raw;
    if (index.encrypted) {
      if (!staticPass) staticPass = await askPassphrase();
      doc = await decryptJSON(raw, staticPass);
    }

    const label = doc.machine_label || String(doc.machine_id).slice(0, 8);
    for (const r of doc.usage || []) {
      rows.push({
        ...r,
        machine_id: doc.machine_id,
        machine_label: label,
        cost_micro_usd: costMicro(priceIdx, r),
      });
    }
    for (const q of doc.quotas || []) quotas.push(q);
  }

  staticData = { rows, quotas, snapshotMs: index.generated_at_ms };
  return staticData;
}

// ---------- 聚合 ----------

const emptyAgg = () => ({
  request_count: 0, success_count: 0, input_tokens: 0, output_tokens: 0,
  cache_read_tokens: 0, cache_creation_tokens: 0, cost_micro_usd: 0,
});

function addInto(acc, r) {
  acc.request_count += r.request_count || 0;
  acc.success_count += r.success_count || 0;
  acc.input_tokens += r.input_tokens || 0;
  acc.output_tokens += r.output_tokens || 0;
  acc.cache_read_tokens += r.cache_read_tokens || 0;
  acc.cache_creation_tokens += r.cache_creation_tokens || 0;
  acc.cost_micro_usd += r.cost_micro_usd || 0;
}

function groupBy(rows, keyFn, labelFn) {
  const m = new Map();
  for (const r of rows) {
    const k = keyFn(r);
    if (!m.has(k)) m.set(k, { key: k, label: labelFn(r), ...emptyAgg() });
    addInto(m.get(k), r);
  }
  return [...m.values()].sort((a, b) => b.cost_micro_usd - a.cost_micro_usd);
}

function renderKpis(total) {
  const items = [
    ['总花费', fmtUSD(total.cost_micro_usd)],
    ['请求次数', fmtInt(total.request_count)],
    ['输入 Token', fmtInt(total.input_tokens)],
    ['输出 Token', fmtInt(total.output_tokens)],
  ];
  $('#kpis').innerHTML = items.map(([label, value]) => `<div class="kpi">
    <div class="k">${label}</div>
    <div class="v num">${value}</div>
  </div>`).join('');
}

// ---------- 渲染：图表 ----------

function renderChart(days) {
  const el = $('#chart');
  const series = days.slice().sort((a, b) => a.key.localeCompare(b.key));

  $('#chart-note').textContent = series.length ? `${series.length} 天有用量` : '';
  if (!series.length) {
    el.innerHTML = '<div class="empty">这段时间没有用量</div>';
    return;
  }
  if (!series.some((day) => day.cost_micro_usd > 0)) {
    el.innerHTML = '<div class="empty">这段时间没有可显示的花费</div>';
    return;
  }

  const today = dayKey(new Date());
  // 窄屏用更小的画布，保证柱子不会被压得太细
  const narrow = window.innerWidth < 760;
  const W = narrow ? 340 : 720;
  const H = narrow ? 170 : 200;
  const padL = narrow ? 40 : 46, padR = 8, padT = 10, padB = 22;
  const iw = W - padL - padR;
  const ih = H - padT - padB;
  const max = Math.max(...series.map((d) => d.cost_micro_usd || 0), 1);
  const gap = series.length > 20 ? 2 : 4;
  const bw = Math.max(1.5, Math.min(40, iw / series.length - gap));

  const bars = series.map((d, i) => {
    const x = padL + (iw * (i + 0.5)) / series.length - bw / 2;
    const h = Math.max(0.8, ((d.cost_micro_usd || 0) / max) * ih);
    const y = padT + ih - h;
    const isToday = d.key === today;
    return `<rect class="chart-bar${isToday ? ' today' : ''}" x="${x.toFixed(1)}" y="${y.toFixed(1)}"
      width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="${Math.min(2.5, bw / 3).toFixed(1)}">
      <title>${esc(d.key)}　${fmtUSD(d.cost_micro_usd)}　${fmtInt(d.request_count)} 次</title></rect>`;
  }).join('');

  // Y 轴：0 / 中 / 顶
  const ticks = [0, 0.5, 1].map((f) => {
    const y = padT + ih - f * ih;
    return `<line class="grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}"></line>
      <text class="lbl" x="${padL - 7}" y="${(y + 3.5).toFixed(1)}" text-anchor="end">${fmtUSD(max * f)}</text>`;
  }).join('');

  // X 轴：均匀取 3 个点
  const idxs = [...new Set([0, Math.floor(series.length / 2), series.length - 1])]
    .filter((i) => series[i]);
  const xLabels = idxs.map((i) => {
    const x = padL + (iw * (i + 0.5)) / series.length;
    return `<text class="lbl" x="${x.toFixed(1)}" y="${H - 6}" text-anchor="middle">${esc(series[i].key.slice(5))}</text>`;
  }).join('');

  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img"
      aria-label="每日花费，最高 ${fmtUSD(max)}">
    ${ticks}
    <line class="axis" x1="${padL}" y1="${padT + ih}" x2="${W - padR}" y2="${padT + ih}"></line>
    ${bars}${xLabels}
  </svg>`;
}

// ---------- 渲染：额度 ----------

function windowLabel(w) {
  switch (w) {
    case '5h': return '5 小时';
    case 'weekly': return '每周';
    case 'daily': return '每日';
    case 'monthly': return '每月';
    case 'absolute': return '余额';
    case 'used': return '已用';
    case 'unknown': return '余额';
    default: return w || '';
  }
}

function renderQuotas(quotas) {
  const el = $('#details');

  // 同一账号的同一种额度只显示最新的快照。
  const merged = new Map();
  for (const q of quotas) {
    const key = `${q.usage_account_key || q.account_key}\u0000${q.window_key}`;
    const prev = merged.get(key);
    if (!prev) {
      merged.set(key, { ...q, apps: new Set([q.app_type]) });
    } else {
      prev.apps.add(q.app_type);
      const newer = (q.observed_at_ms || 0) > (prev.observed_at_ms || 0);
      const same = (q.observed_at_ms || 0) === (prev.observed_at_ms || 0);
      const smaller = q.remaining != null && (prev.remaining == null || q.remaining < prev.remaining);
      if (newer || (same && smaller)) {
        const apps = prev.apps;
        merged.set(key, { ...q, apps });
      }
    }
  }

  const list = [...merged.values()];

  // 过滤：没有套餐额度、又不是余额的，属于噪音
  const meaningful = list.filter((q) => {
    const noPlan = q.unit === 'requests' && q.total === 0 && q.remaining === 0;
    return !noPlan;
  });

  if (!meaningful.length) {
    el.innerHTML = `<div class="empty">
      此时段有用量的账号暂无可显示的额度
    </div>`;
    return;
  }

  // 排序：真余额（有 total 的、越少越靠前，更需要留意）
  // → 余额类的绝对值 → 已用量 → 其它
  const rank = (q) => {
    if (q.window_key === 'used') return 2;
    if (q.remaining == null) return 3;
    return q.total ? 0 : 1;
  };
  meaningful.sort((a, b) => {
    const ra = rank(a); const rb = rank(b);
    if (ra !== rb) return ra - rb;
    if (ra === 0) return (a.remaining / a.total) - (b.remaining / b.total);
    if (ra === 1) return (a.remaining ?? 0) - (b.remaining ?? 0);
    if (ra === 2) return (b.remaining ?? 0) - (a.remaining ?? 0);
    return String(a.provider_label).localeCompare(String(b.provider_label));
  });

  const cards = meaningful.map((q) => {
    const pct = (q.remaining != null && q.total)
      ? Math.max(0, Math.min(100, q.remaining / q.total * 100))
      : null;
    const cls = pct == null ? '' : pct < 10 ? 'critical' : pct < 30 ? 'low' : '';
    const tags = [];
    if (q.stale) tags.push('<span class="tag warn">数据陈旧</span>');
    if (q.conflict_note) tags.push('<span class="tag warn">多机不一致</span>');
    if (q.reset_at_ms && q.reset_at_ms > Date.now()) {
      tags.push(`<span class="tag">${esc(fmtAgo(q.reset_at_ms))}重置</span>`);
    }
    const apps = [...(q.apps || [q.app_type])].join(' · ');

    return `<div class="quota${q.stale ? ' stale' : ''}">
      <div class="quota-top">
        <span class="quota-name">${esc(q.provider_label)}</span>
        <span class="quota-win">${esc(windowLabel(q.window_key))}</span>
      </div>
      <div class="quota-val num">${fmtMoney(q.remaining, q.unit)}${
        q.total ? `<span class="of"> / ${fmtMoney(q.total, q.unit)}</span>` : ''
      }</div>
      ${pct != null ? `<div class="quota-track"><div class="quota-fill ${cls}" style="width:${pct}%"></div></div>` : ''}
      <div class="quota-meta"><span>${esc(apps)}</span><span>${esc(fmtAgo(q.observed_at_ms))}</span>${tags.join('')}</div>
    </div>`;
  }).join('');
  el.innerHTML = `<p class="detail-note">显示时段内有用量的账号，余额为最近一次采集值。</p>
    <div class="quotas">${cards}</div>`;
}

// ---------- 渲染：排行列表 ----------

function renderDetails() {
  if (!state.data) return;
  const { summary, quotas } = state.data;
  if (state.view === 'quotas') {
    const accounts = new Set((summary.accounts || []).map((row) => row.key));
    renderQuotas(quotas.filter((quota) => accounts.has(quota.usage_account_key || quota.account_key)));
    return;
  }

  const tokens = state.view === 'tokens';
  const rows = summary[tokens ? 'models' : state.view] || [];
  const el = $('#details');
  if (rows.length === 0) {
    el.innerHTML = '<div class="empty">这段时间没有用量</div>';
    return;
  }

  const name = { models: '模型', accounts: '账号', machines: '设备', tokens: '模型' }[state.view];
  const columns = tokens
    ? [['输入', 'input_tokens'], ['输出', 'output_tokens'], ['缓存读取', 'cache_read_tokens'], ['缓存写入', 'cache_creation_tokens']]
    : [['请求次数', 'request_count'], ['花费', 'cost_micro_usd', fmtUSD]];
  const shown = state.expanded ? rows : rows.slice(0, 6);
  el.innerHTML = `<div class="table-scroll" role="region" aria-label="${name}用量" tabindex="0">
    <table class="usage-table">
      <thead><tr><th scope="col">${name}</th>${columns.map(([label]) => `<th scope="col">${label}</th>`).join('')}</tr></thead>
      <tbody>${shown.map((row) => `<tr>
        <th scope="row">${esc(row.label || row.key || '未知')}</th>
        ${columns.map(([label, key, format = fmtInt]) => `<td class="num"><span class="mobile-field" aria-hidden="true">${label}</span>${format(row[key] || 0)}</td>`).join('')}
      </tr>`).join('')}</tbody>
    </table>
  </div>${rows.length > 6 ? `<button type="button" class="show-more" aria-expanded="${state.expanded}">
    ${state.expanded ? '收起' : `查看全部 ${rows.length} 项`}</button>` : ''}`;
  el.querySelector('.show-more')?.addEventListener('click', () => {
    state.expanded = !state.expanded;
    renderDetails();
    el.querySelector('.show-more')?.focus();
  });
}

async function refresh() {
  const refreshId = ++state.refreshId;
  const from = state.days ? daysAgoKey(state.days - 1) : '0001-01-01';
  const to = dayKey(new Date());
  const dashboard = $('#dashboard');
  dashboard.setAttribute('aria-busy', 'true');
  $('#open-share').disabled = true;

  try {
    let summary;
    let quotas;
    let stats;
    if (state.mode === 'static') {
      const data = await loadStaticData();
      const rows = data.rows.filter((row) => row.date >= from && row.date <= to);
      const total = emptyAgg();
      for (const row of rows) addInto(total, row);
      summary = {
        total,
        days: groupBy(rows, (r) => r.date, (r) => r.date),
        accounts: groupBy(rows, (r) => r.account_key, (r) => r.provider_label || r.account_key),
        models: groupBy(rows, (r) => r.model, (r) => r.model),
        machines: groupBy(rows, (r) => r.machine_id, (r) => r.machine_label),
      };
      quotas = data.quotas;
      state.snapshotMs = data.snapshotMs;
    } else {
      const [usage, quotaData, serverStats] = await Promise.all([
        loadJSON(`/api/summary?from=${from}&to=${to}`),
        loadJSON('/api/quotas'),
        loadJSON('/api/stats'),
      ]);
      summary = usage;
      quotas = quotaData.quotas || [];
      stats = serverStats;
    }

    if (refreshId !== state.refreshId) return;
    $('#onboarding').hidden = !stats || stats.usage_rows > 0;
    $('#local-sync').hidden = !stats?.local_sync;
    $('#local-setup').hidden = !stats?.local_sync;
    $('#manual-setup').hidden = !!stats?.local_sync;

    const firstDay = state.days ? from : (summary.days || []).reduce(
      (first, day) => first === '' || day.key < first ? day.key : first, '');
    $('#range-context').textContent = firstDay && firstDay !== to ? `${firstDay} 至 ${to}`
      : firstDay || '全部时间';
    state.data = { summary, quotas, period: $('#range-context').textContent, endDate: to };
    renderKpis(summary.total || emptyAgg());
    renderChart(summary.days || []);
    renderDetails();
    $('#foot').textContent = state.mode === 'static' && state.snapshotMs
      ? `数据截至 ${fmtClock(state.snapshotMs)}` : '';
    return stats;
  } catch (error) {
    if (refreshId !== state.refreshId) return;
    console.error(error);
    if (state.encrypted && error.name === 'OperationError') {
      document.body.classList.add('locked');
      staticPass = await askPassphrase('无法解密，请检查口令后重试。');
      return refresh();
    }
    state.data = null;
    $('#range-context').textContent = `用量加载失败，请刷新页面。(${error.message})`;
    $('#kpis').replaceChildren();
    $('#details').replaceChildren();
    $('#chart').replaceChildren();
    $('#chart-note').textContent = '';
  } finally {
    if (refreshId === state.refreshId) {
      dashboard.setAttribute('aria-busy', 'false');
      $('#open-share').disabled = !state.data?.summary.days?.length;
    }
  }
}

async function syncLocalUsage() {
  const button = $('#local-sync');
  const status = $('#sync-status');
  button.disabled = true;
  status.hidden = false;
  status.textContent = '正在读取并同步本机用量…';
  try {
    const response = await fetch('/api/local-sync', { method: 'POST' });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || '同步失败，请重试。');
    const stats = await selectRange($('#range-tabs [data-days="0"]'));
    status.textContent = !stats ? '同步完成。看板暂时加载失败，请刷新页面。'
      : stats.usage_rows > 0 ? '同步完成，已切换到「全部」查看历史用量。'
        : '本机还没有可导入的用量。产生用量后可以再次同步。';
  } catch (error) {
    status.textContent = error.message;
    await refresh();
  } finally {
    button.disabled = false;
  }
}

function selectRange(button) {
  $$('#range-tabs button').forEach((btn) => {
    btn.classList.toggle('on', btn === button);
    btn.setAttribute('aria-pressed', String(btn === button));
  });
  state.days = Number(button.dataset.days);
  state.expanded = false;
  $('#range-context').textContent = '正在加载用量…';
  return refresh();
}

function bindTabs() {
  $$('#range-tabs button').forEach((btn) => {
    btn.addEventListener('click', () => selectRange(btn));
  });
  const detailButtons = $$('#detail-nav button');
  detailButtons.forEach((button) => {
    button.addEventListener('click', () => {
      if (state.view === button.dataset.view) return;
      state.view = button.dataset.view;
      state.expanded = false;
      detailButtons.forEach((btn) => btn.setAttribute('aria-pressed', String(btn === button)));
      renderDetails();
    });
  });
  if (state.mode === 'server') {
    setInterval(() => {
      if ($('#dashboard').getAttribute('aria-busy') === 'false') refresh();
    }, 30000);
  }
}

const posterThemes = {
  iris: { background: '#140e23', paper: '#f7eefc', muted: '#cdbdde', accent: '#d9b8ff' },
  mint: { background: '#102721', paper: '#eff8ed', muted: '#b5d2c6', accent: '#a7f0c8' },
  sunset: { background: '#2d171d', paper: '#fff1e8', muted: '#e6c0b4', accent: '#ffbf9d' },
};

function drawPoster(canvas, { summary, period }, theme, includeCost, artwork) {
  const ctx = canvas.getContext('2d');
  const { width, height } = canvas;
  const palette = posterThemes[theme];
  ctx.fillStyle = palette.background;
  ctx.fillRect(0, 0, width, height);

  if (artwork) {
    ctx.save();
    ctx.globalCompositeOperation = 'screen';
    ctx.globalAlpha = 0.77;
    ctx.drawImage(artwork, 390, -12, 730, 730);
    ctx.restore();
    const feather = ctx.createLinearGradient(390, 0, 635, 0);
    feather.addColorStop(0, palette.background);
    feather.addColorStop(1, palette.background + '00');
    ctx.fillStyle = feather;
    ctx.fillRect(390, 0, 245, 718);
  }
  const shade = ctx.createLinearGradient(0, 265, 0, 730);
  shade.addColorStop(0, palette.background + '00');
  shade.addColorStop(1, palette.background);
  ctx.fillStyle = shade;
  ctx.fillRect(0, 265, width, 465);

  function text(value, x, y, size, { weight = 500, color = palette.paper, serif = false, maxWidth = width - x - 86 } = {}) {
    const family = serif ? 'Georgia, "Songti SC", "Noto Serif CJK SC", serif'
      : 'system-ui, "PingFang SC", "Microsoft YaHei", sans-serif';
    ctx.font = `${weight} ${size}px ${family}`;
    ctx.fillStyle = color;
    ctx.fillText(value, x, y, maxWidth);
  }

  function rule(y) {
    ctx.fillStyle = palette.muted + '55';
    ctx.fillRect(86, y, 908, 2);
  }

  const total = summary.total || emptyAgg();
  const days = summary.days.slice().sort((a, b) => a.key.localeCompare(b.key));
  text('我的 AI 使用记录', 86, 146, 60, { serif: true, weight: 600 });
  text(period.replaceAll('-', '.'), 88, 206, 30, { color: palette.muted });

  text(fmtInt(total.request_count), 74, 510, 212, { serif: true, maxWidth: 890 });
  text('次请求', 89, 581, 42, { color: palette.accent });
  rule(650);

  const metrics = [
    ['输入 Token', fmtInt(total.input_tokens)],
    ['输出 Token', fmtInt(total.output_tokens)],
  ];
  metrics.forEach(([label, value], index) => {
    const x = 87 + index * 470;
    text(label, x, 726, 32, { color: palette.muted });
    text(value, x, 816, 69, { serif: true, maxWidth: 425 });
  });
  if (includeCost) text(`总花费  ${fmtUSD(total.cost_micro_usd)}`, 88, 888, 34, { color: palette.accent });

  const sectionTop = includeCost ? 929 : 885;
  rule(sectionTop);
  text('每日请求', 87, sectionTop + 64, 36, { weight: 600 });
  text(`${days.length} 天有记录`, 780, sectionTop + 62, 28, { color: palette.muted });

  const chartLeft = 88;
  const chartRight = 992;
  const chartBottom = 1260;
  const chartHeight = chartBottom - sectionTop - 104;
  const first = Date.parse(days[0].key);
  const span = Math.round((Date.parse(days[days.length - 1].key) - first) / 86400000) + 1;
  const step = (chartRight - chartLeft) / span;
  const max = days.reduce((highest, day) => Math.max(highest, day.request_count), 1);
  for (const ratio of [0, 0.5, 1]) rule(chartBottom - chartHeight * ratio);

  const gradient = ctx.createLinearGradient(0, chartBottom - chartHeight, 0, chartBottom);
  gradient.addColorStop(0, palette.accent);
  gradient.addColorStop(1, palette.accent + '64');
  ctx.fillStyle = gradient;
  const barWidth = Math.max(1, Math.min(32, step * 0.72));
  for (const day of days) {
    const offset = (Date.parse(day.key) - first) / 86400000;
    const x = chartLeft + step * (offset + 0.5) - barWidth / 2;
    const barHeight = day.request_count / max * chartHeight;
    ctx.fillRect(x, chartBottom - barHeight, barWidth, barHeight);
  }
  text(days[0].key.slice(5).replace('-', '.'), 88, 1314, 27, { color: palette.muted });
  if (days.length > 1) {
    ctx.textAlign = 'right';
    text(days[days.length - 1].key.slice(5).replace('-', '.'), 992, 1314, 27,
      { color: palette.muted, maxWidth: 200 });
    ctx.textAlign = 'left';
  }
}

function bindShareControls() {
  const picker = $('#theme-picker');
  const dialog = $('#share-dialog');
  const cost = $('#include-cost');
  const nativeShare = $('#native-share');
  const preview = $('#share-preview');
  const save = $('#save-poster');
  const canvas = document.createElement('canvas');
  canvas.width = 1080;
  canvas.height = 1440;
  let snapshot;
  let file;
  const artwork = new Image();
  artwork.src = './usage-cover.webp';

  try {
    const saved = localStorage.getItem('usage-theme');
    if (Object.hasOwn(posterThemes, saved)) picker.value = saved;
  } catch { /* 浏览器可能禁用本地存储 */ }
  document.documentElement.dataset.theme = picker.value;
  picker.addEventListener('change', () => {
    document.documentElement.dataset.theme = picker.value;
    try { localStorage.setItem('usage-theme', picker.value); } catch { /* 仅在本次页面生效 */ }
  });

  const updatePoster = () => {
    drawPoster(canvas, snapshot, picker.value, cost.checked, artwork.naturalWidth ? artwork : null);
    const data = canvas.toDataURL('image/png');
    const filename = `AI-用量-${snapshot.endDate}.png`;
    preview.src = data;
    save.href = data;
    save.download = filename;
    file = new File([b64ToBytes(data.split(',')[1])], filename, { type: 'image/png' });
    nativeShare.hidden = !navigator.canShare?.({ files: [file] });
  };
  $('#open-share').addEventListener('click', () => {
    if (!state.data?.summary.days?.length) return;
    snapshot = state.data;
    updatePoster();
    dialog.showModal();
  });
  artwork.addEventListener('load', () => {
    if (dialog.open) updatePoster();
  });
  cost.addEventListener('change', updatePoster);
  nativeShare.addEventListener('click', async () => {
    try {
      await navigator.share({ files: [file], title: '我的 AI 用量' });
    } catch (error) {
      if (error.name !== 'AbortError') {
        nativeShare.hidden = true;
        save.focus();
      }
    }
  });
}

async function boot() {
  bindShareControls();
  // 判定模式：存在 data/index.json 且 mode=static 就是静态站
  try {
    const res = await fetch('./data/index.json', { cache: 'no-store' });
    if (res.ok) {
      const j = await res.json();
      if (j.mode === 'static') {
        state.mode = 'static';
        state.encrypted = !!j.encrypted;
        if (j.encrypted) document.body.classList.add('locked');
      }
    }
  } catch { /* 没有清单就是 server 模式 */ }

  await refresh();
  bindTabs();
  $('#local-sync').addEventListener('click', syncLocalUsage);
}

boot();
