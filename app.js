'use strict';
/**
 * AI 用量前端。两种部署模式共用同一套代码：
 *   - server：从 /api/* 取数
 *   - static：读 data/ 下的预生成文件，在浏览器里解密并合并各机器数据
 *
 * 展示原则（用户明确要求）：数据是给人看的，不是抓到了就全列出来。
 *   - 今天的数字放最前，因为它是最常被问的
 *   - 空值 / 无意义的条目直接不显示，而不是显示 0 或「无数据」
 *   - 数字按量级缩写（1.2K / 3.4M / 5.6B），不丢有效位数
 */

const state = {
  mode: 'server',
  encrypted: false,
  snapshotMs: 0,
  days: 30,        // 0 = 全部
  summary: null,
  quotas: [],
  machines: [],
  accountsExpanded: false,
  modelsExpanded: false,
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
function askPassphrase() {
  return new Promise((resolve) => {
    document.body.classList.add('locked');
    const panel = $('#unlock');
    const form = $('#unlock-form');
    const input = $('#pass');
    const msg = $('#unlock-msg');
    panel.hidden = false;
    msg.textContent = '';
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
  const machines = [];

  for (const m of index.machines || []) {
    const raw = await loadJSON('./data/' + m.file);
    let doc;
    if (index.encrypted) {
      if (!staticPass) staticPass = await askPassphrase();
      try {
        doc = await decryptJSON(raw, staticPass);
      } catch {
        staticData = null;
        staticPass = null;
        document.body.classList.add('locked');
        $('#unlock').hidden = false;
        $('#unlock-msg').textContent = '口令不正确，请重试。';
        $('#pass').value = '';
        $('#pass').focus();
        throw new Error('口令不正确');
      }
    } else {
      doc = raw;
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
    machines.push({ machine_id: doc.machine_id, label, last_seen_ms: doc.generated_at_ms });
  }

  staticData = { rows, quotas, machines, snapshotMs: index.generated_at_ms };
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

// ---------- 渲染：今天 ----------

function renderToday(allRows) {
  const today = dayKey(new Date());
  const yest = daysAgoKey(1);

  const t = emptyAgg();
  let tRows = 0;
  for (const r of allRows) if (r.date === today) { addInto(t, r); tRows++; }

  const y = emptyAgg();
  for (const r of allRows) if (r.date === yest) addInto(y, r);

  $('#today-cost').textContent = tRows ? fmtUSD(t.cost_micro_usd) : '—';

  const okRate = t.request_count > 0
    ? (t.success_count / t.request_count * 100).toFixed(1)
    : null;

  $('#today-sub').innerHTML = tRows
    ? `<span class="num">${fmtInt(t.request_count)}</span> 次请求` +
      (okRate ? `　成功 <span class="num">${okRate}%</span>` : '') +
      `　<span class="num">${fmtInt(t.input_tokens + t.output_tokens)}</span> tokens`
    : '今天还没有用量';

  // 与昨天同期对比
  const side = [];
  if (tRows && y.request_count > 0) {
    const diff = t.cost_micro_usd - y.cost_micro_usd;
    const pct = y.cost_micro_usd > 0 ? (diff / y.cost_micro_usd) * 100 : 0;
    const cls = diff > 0 ? 'delta-up' : diff < 0 ? 'delta-down' : '';
    const arrow = diff > 0 ? '↑' : diff < 0 ? '↓' : '→';
    side.push(`<div><div class="k">对比昨天</div>
      <div class="v ${cls}">${arrow} ${Math.abs(pct).toFixed(0)}%</div></div>`);
    side.push(`<div><div class="k">昨天</div>
      <div class="v num">${fmtUSD(y.cost_micro_usd)}</div></div>`);
  }
  if (t.request_count > 0) {
    side.push(`<div><div class="k">今日 token</div>
      <div class="v num">${fmtInt(t.input_tokens + t.output_tokens)}</div></div>`);
  }
  $('#today-side').innerHTML = side.join('');
}

// ---------- 渲染：KPI ----------

function renderKpis(total) {
  const okRate = total.request_count > 0
    ? (total.success_count / total.request_count * 100).toFixed(1) + '%'
    : null;
  const cacheBase = total.input_tokens + total.cache_read_tokens;
  const cacheHit = cacheBase > 0 ? (total.cache_read_tokens / cacheBase * 100).toFixed(0) + '%' : null;

  const items = [
    ['总花费', fmtUSD(total.cost_micro_usd), '统一价格表重算'],
    ['请求', fmtInt(total.request_count), okRate ? `成功 ${okRate}` : ''],
    ['输入', fmtInt(total.input_tokens), total.output_tokens ? `输出 ${fmtInt(total.output_tokens)}` : ''],
    ['缓存读取', fmtInt(total.cache_read_tokens), cacheHit ? `占比 ${cacheHit}` : ''],
    ['缓存写入', fmtInt(total.cache_creation_tokens), ''],
  ];

  $('#kpis').innerHTML = items
    // 值为 0 且没有补充说明的，不占位
    .filter(([, v, s]) => v !== '0' && v !== '—' || s)
    .map(([k, v, s]) => `<div class="kpi">
        <div class="k">${esc(k)}</div>
        <div class="v num">${esc(v)}</div>
        ${s ? `<div class="s">${esc(s)}</div>` : ''}
      </div>`).join('');
}

// ---------- 渲染：图表 ----------

function renderChart(days, windowDays) {
  const el = $('#chart');
  const series = days.slice().sort((a, b) => a.key.localeCompare(b.key));

  let note = '';
  if (windowDays === 1) {
    note = '最近 14 天，今天高亮';
  } else if (series.length > 1) {
    note = `${series.length} 天`;
  }

  if (!series.length) {
    el.innerHTML = '<div class="empty">这段时间没有用量</div>';
    $('#chart-note').textContent = '';
    return;
  }
  $('#chart-note').textContent = note;

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
    return `<rect class="bar${isToday ? ' today' : ''}" x="${x.toFixed(1)}" y="${y.toFixed(1)}"
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
    default: return w || '';
  }
}

function renderQuotas(quotas) {
  const el = $('#quotas');

  // 同一份额度会在多个应用/多个域名上报多条，按「账号名 + 窗口」收敛
  const nameOf = (k) => String(k || '').split('|').slice(2).join('|').trim();
  const merged = new Map();
  for (const q of quotas) {
    const key = `${nameOf(q.account_key)}\u0000${q.window_key}`;
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
      没有可显示额度<br>
      <span style="font-size:12px">供应商的额度查询没配置，或该账号没有余额信息</span>
    </div>`;
    return;
  }

  // 有余额的排前，余额少的排前（更值得注意）
  meaningful.sort((a, b) => {
    const av = a.remaining != null ? a.remaining : Infinity;
    const bv = b.remaining != null ? b.remaining : Infinity;
    if (av !== bv) return av - bv;
    return String(a.provider_label).localeCompare(String(b.provider_label));
  });

  el.innerHTML = meaningful.map((q) => {
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
}

// ---------- 渲染：排行列表 ----------

function renderRows(el, rows, opts = {}) {
  const { expanded = false, limit = 8, onToggle = null, unit = 'cost' } = opts;
  if (!rows || !rows.length) {
    el.innerHTML = '<div class="empty">无数据</div>';
    return;
  }

  const max = Math.max(...rows.map((r) => r.cost_micro_usd || 0), 1);
  const shown = expanded ? rows : rows.slice(0, limit);

  const head = `<div class="row-head">
    <span>名称</span><span>花费</span><span>请求</span><span>输入</span><span>输出</span><span>缓存</span>
  </div>`;

  const body = shown.map((r) => {
    const w = Math.max(1, Math.round((r.cost_micro_usd / max) * 100));
    return `<div class="row">
      <div class="row-name" title="${esc(r.label)}">${esc(r.label)}</div>
      <div class="row-cost">${fmtUSD(r.cost_micro_usd)}</div>
      <div class="row-meta">
        <span class="bar-mini"><i style="width:${w}%"></i></span>
        <span class="req">${fmtInt(r.request_count)} 次</span>
        <span class="in">${fmtInt(r.input_tokens)}</span>
        <span class="out">${fmtInt(r.output_tokens)}</span>
        <span class="cache">${fmtInt(r.cache_read_tokens)}</span>
      </div>
    </div>`;
  }).join('');

  const more = rows.length > limit
    ? `<button type="button" class="row more" data-toggle>
        ${expanded ? '收起' : `还有 ${rows.length - limit} 项`}
      </button>`
    : '';

  el.innerHTML = head + body + more;

  if (onToggle) {
    const b = el.querySelector('[data-toggle]');
    if (b) b.addEventListener('click', onToggle);
  }
}

// ---------- 主流程 ----------

function setFoot() {
  const bits = [];
  if (state.mode === 'static') {
    bits.push(`数据截至 ${fmtClock(state.snapshotMs)}（${fmtAgo(state.snapshotMs)}）`);
    bits.push('每日自动更新');
  } else {
    bits.push('自建服务 · 实时');
  }
  bits.push('不含任何凭据');
  $('#foot').textContent = bits.join(' · ');
}

async function refresh() {
  try {
    let summary; let quotas; let machines; let allRows;

    if (state.mode === 'static') {
      const d = await loadStaticData();
      allRows = d.rows;
      quotas = d.quotas;
      machines = d.machines;
      state.snapshotMs = d.snapshotMs;
    } else {
      const days = state.days || 3650;
      const from = daysAgoKey(days);
      const to = dayKey(new Date());
      const [s, q, m] = await Promise.all([
        loadJSON(`/api/summary?from=${from}&to=${to}`),
        loadJSON('/api/quotas'),
        loadJSON('/api/machines'),
      ]);
      summary = s;
      quotas = q.quotas || [];
      machines = m.machines || [];
      // server 模式没有原始行，用分组结果直接展示
      allRows = null;
      state.snapshotMs = Date.now();
    }

    if (allRows) {
      const from = state.days ? daysAgoKey(state.days) : '0000-00-00';
      const inRange = allRows.filter((r) => r.date >= from);

      // 今天与 KPI 用全量行算，不受范围影响
      renderToday(allRows);

      const total = emptyAgg();
      for (const r of inRange) addInto(total, r);
      renderKpis(total);

      // 选「今天」时，范围里只有一天，图表没有趋势可看 → 改画最近 14 天
      const chartSrc = state.days === 1
        ? allRows.filter((r) => r.date >= daysAgoKey(13))
        : inRange;
      const chartDays = groupBy(chartSrc, (r) => r.date, (r) => r.date)
        .sort((a, b) => a.key.localeCompare(b.key));
      renderChart(chartDays, state.days);

      renderRows($('#accounts'), groupBy(inRange, (r) => r.account_key, (r) => r.provider_label || r.account_key),
        { expanded: state.accountsExpanded, onToggle: () => { state.accountsExpanded = !state.accountsExpanded; refresh(); } });
      renderRows($('#models'), groupBy(inRange, (r) => r.model, (r) => r.model),
        { expanded: state.modelsExpanded, onToggle: () => { state.modelsExpanded = !state.modelsExpanded; refresh(); } });

      const mrows = groupBy(inRange, (r) => r.machine_id, (r) => r.machine_label);
      $('#machines-panel').hidden = mrows.length <= 1;
      if (mrows.length > 1) renderRows($('#machines'), mrows, {});
    } else {
      // server 模式：后端已聚合好
      renderTodayFallback(summary);
      renderKpis(summary.total || {});
      renderChart(summary.days || [], state.days);
      renderRows($('#accounts'), summary.accounts || []);
      renderRows($('#models'), summary.models || []);
      const mrows = summary.machines || [];
      $('#machines-panel').hidden = mrows.length <= 1;
      if (mrows.length > 1) renderRows($('#machines'), mrows, {});
    }

    renderQuotas(quotas);
    setFoot();
  } catch (e) {
    console.error(e);
    $('#today-cost').textContent = '—';
    $('#today-sub').textContent = '加载失败：' + e.message;
  }
}

/** server 模式下没有原始行，用今天这一天的汇总近似渲染 */
function renderTodayFallback(summary) {
  const days = (summary.days || []).slice().sort((a, b) => a.key.localeCompare(b.key));
  const today = dayKey(new Date());
  const t = days.find((d) => d.key === today);
  $('#today-cost').textContent = t ? fmtUSD(t.cost_micro_usd) : '—';
  $('#today-sub').innerHTML = t
    ? `<span class="num">${fmtInt(t.request_count)}</span> 次请求　<span class="num">${fmtInt(t.input_tokens + t.output_tokens)}</span> tokens`
    : '今天还没有用量';
  $('#today-side').innerHTML = '';
  $('#chart-note').textContent = days.length > 1 ? `${days.length} 天` : '';
}

function bindTabs() {
  $$('#range-tabs button').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('#range-tabs button').forEach((b) => {
        b.classList.toggle('on', b === btn);
        b.setAttribute('aria-selected', b === btn ? 'true' : 'false');
      });
      state.days = Number(btn.dataset.days);
      state.accountsExpanded = false;
      state.modelsExpanded = false;
      refresh();
    });
  });
}

async function boot() {
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

  bindTabs();
  $('#admin-panel').hidden = true;
  await refresh();
}

boot();
