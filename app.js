'use strict';
/**
 * 前端：两种部署模式共用同一套代码。
 *
 *  - server 模式（默认）：从 /api/* 实时取数，需要后端。
 *  - static 模式（GitHub Pages）：读同目录 data/ 下的预生成 JSON，纯静态托管。
 *
 * 判定方式：页面 <html data-mode="static"> 或在 data/config.json 里写 {"mode":"static"}。
 * 静态模式下，「账号管理」只显示提示，不做写操作。
 */

const state = {
  mode: 'server',
  encrypted: false,
  snapshotMs: 0,
  from: '',
  to: '',
  machine: '',
  app: '',
  summary: null,
  quotas: [],
  machines: [],
  adminOpen: false,
};

// ---------- 工具 ----------

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtInt(n) {
  if (n == null) return '—';
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'K';
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function fmtUSD(micro) {
  if (micro == null) return '—';
  const v = micro / 1e6;
  if (v >= 1000) return '$' + (v / 1000).toFixed(2) + 'K';
  if (v >= 1) return '$' + v.toFixed(2);
  if (v > 0) return '$' + v.toFixed(3);
  return '$0';
}

function fmtNum(v, unit) {
  if (v == null) return '未采集';
  if (unit === 'USD') return '$' + v.toFixed(2);
  if (unit === 'CNY') return '¥' + v.toFixed(2);
  if (unit === 'percent') return v.toFixed(1) + '%';
  if (unit === 'requests') return fmtInt(v) + ' 次';
  return String(v);
}

function fmtTime(ms) {
  if (!ms) return '—';
  const d = new Date(ms);
  const now = Date.now();
  const diff = now - ms;
  if (diff < 60000) return '刚刚';
  if (diff < 3600000) return Math.floor(diff / 60000) + ' 分钟前';
  if (diff < 86400000) return Math.floor(diff / 3600000) + ' 小时前';
  return `${d.getMonth() + 1}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function isoDaysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 10);
}

// ---------- 数据源 ----------

async function loadJSON(path) {
  // 静态模式加时间戳避免 CDN 缓存陈旧
  const url = state.mode === 'static' ? `${path}?t=${Math.floor(Date.now() / 60000)}` : path;
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function buildQuery() {
  const p = new URLSearchParams();
  if (state.from) p.set('from', state.from);
  if (state.to) p.set('to', state.to);
  if (state.machine) p.set('machine', state.machine);
  if (state.app) p.set('app', state.app);
  return p.toString();
}

// ---------- 静态模式：在浏览器里合并各机器数据 ----------
//
// 没有后端，所以跨机汇总必须在浏览器完成：
// 每台机器发布自己的一个数据文件，这里全部拉下来解密、合并、按需聚合。

let staticData = null; // {rows, quotas, machines, priceIdx}
let staticPass = null; // 口令只在内存里

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function decryptJSON(enc, passphrase) {
  const encBuf = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBytes(enc.salt), iterations: enc.iter, hash: 'SHA-256' },
    encBuf, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  // ct 尾部带 GCM auth tag，WebCrypto 直接接受
  let plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(enc.iv) }, key, b64ToBytes(enc.ct));
  // v2 是 gzip 后再加密的
  if (enc.enc === 'gzip+aes-256-gcm') {
    plain = await new Response(
      new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip')),
    ).arrayBuffer();
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

/** 价格表索引。兼容紧凑格式 [name, in, out, cr, cc] 与旧的对象格式 */
function buildPriceIdx(prices) {
  const eff = (prices && prices.d) || '1970-01-01';
  const idx = new Map();
  for (const m of (prices && prices.models) || []) {
    let name; let input; let output; let cacheRead; let cacheCreate;
    if (Array.isArray(m)) {
      [name, input, output, cacheRead, cacheCreate] = m;
    } else {
      name = m.model; input = m.input_per_mtok; output = m.output_per_mtok;
      cacheRead = m.cache_read_per_mtok; cacheCreate = m.cache_creation_per_mtok;
    }
    if (!name) continue;
    if (!idx.has(name)) idx.set(name, []);
    idx.get(name).push({
      effective_from: (m && m.effective_from) || eff,
      input: +input || 0,
      output: +output || 0,
      cacheRead: +cacheRead || 0,
      cacheCreate: +cacheCreate || 0,
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

function priceOf(priceIdx, row) {
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
  for (const n of names) {
    if (!n) continue;
    const exact = priceIdx.get(n);
    if (exact) { const p = pick(exact); if (p) return p; }
    for (const [k, list] of priceIdx) {
      if (normalizeName(k) === n) { const p = pick(list); if (p) return p; }
    }
  }
  return null;
}

function costMicro(priceIdx, row) {
  const p = priceOf(priceIdx, row);
  if (!p) return 0;
  let input = row.input_tokens;
  if (row.input_token_semantics === 1) input = Math.max(0, input - row.cache_read_tokens);
  const micro = input * p.input
    + row.output_tokens * p.output
    + row.cache_read_tokens * p.cacheRead
    + row.cache_creation_tokens * p.cacheCreate;
  return Number.isFinite(micro) && micro > 0 ? Math.round(micro) : 0;
}

/** 等用户在页面上输入口令 */
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
    input.focus();

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

/** 口令错误时重来 */
async function retryPassphrase(reason) {
  const msg = $('#unlock-msg');
  if (msg) msg.textContent = reason;
  const panel = $('#unlock');
  if (panel) panel.hidden = false;
  const input = $('#pass');
  if (input) { input.value = ''; input.focus(); }
}

/** 拉取所有机器文件并合并 */
async function loadStaticData() {
  if (staticData) return staticData;
  const index = await loadJSON('./data/index.json');
  const prices = await loadJSON('./data/prices.json').catch(() => ({ models: [] }));
  const priceIdx = buildPriceIdx(prices);

  const rows = [];
  const quotas = [];
  const machines = [];

  for (const m of index.machines || []) {
    let doc;
    const raw = await loadJSON('./data/' + m.file);
    if (index.encrypted) {
      if (!staticPass) {
        document.body.classList.add('locked');
        staticPass = await askPassphrase();
      }
      try {
        doc = await decryptJSON(raw, staticPass);
      } catch {
        // 口令错：清掉已解出的数据，回到输入框
        staticData = null;
        staticPass = null;
        document.body.classList.remove('locked');
        await retryPassphrase('口令不正确，请重试。');
        throw new Error('口令不正确');
      }
    } else {
      doc = raw;
    }
    for (const r of doc.usage || []) {
      rows.push({
        ...r,
        machine_id: doc.machine_id,
        machine_label: doc.machine_label || String(doc.machine_id).slice(0, 8),
        cost_micro_usd: costMicro(priceIdx, r),
      });
    }
    for (const q of doc.quotas || []) quotas.push(q);
    machines.push({
      machine_id: doc.machine_id,
      label: doc.machine_label || String(doc.machine_id).slice(0, 8),
      last_seen_ms: doc.generated_at_ms,
    });
  }

  staticData = { rows, quotas, machines, priceIdx, snapshotMs: index.generated_at_ms };
  document.body.classList.remove('locked');
  const panel = $('#unlock');
  if (panel) panel.hidden = true;
  return staticData;
}

// ---------- 聚合（静态模式在浏览器里做） ----------

const EMPTY_AGG = () => ({
  request_count: 0, success_count: 0, input_tokens: 0, output_tokens: 0,
  cache_read_tokens: 0, cache_creation_tokens: 0, cost_micro_usd: 0,
});

function addInto(acc, r) {
  acc.request_count += r.request_count;
  acc.success_count += r.success_count;
  acc.input_tokens += r.input_tokens;
  acc.output_tokens += r.output_tokens;
  acc.cache_read_tokens += r.cache_read_tokens;
  acc.cache_creation_tokens += r.cache_creation_tokens;
  acc.cost_micro_usd += r.cost_micro_usd;
}

function groupBy(rows, keyFn, labelFn) {
  const m = new Map();
  for (const r of rows) {
    const k = keyFn(r);
    if (!m.has(k)) m.set(k, { key: k, label: labelFn(r), ...EMPTY_AGG() });
    addInto(m.get(k), r);
  }
  return [...m.values()].sort((a, b) => b.cost_micro_usd - a.cost_micro_usd);
}

function aggregateRows(rows) {
  const total = EMPTY_AGG();
  for (const r of rows) addInto(total, r);
  const days = groupBy(rows, (r) => r.date, (r) => r.date)
    .sort((a, b) => a.key.localeCompare(b.key));
  return {
    total,
    days,
    models: groupBy(rows, (r) => r.model, (r) => r.model),
    accounts: groupBy(rows, (r) => r.account_key, (r) => r.provider_label || r.account_key),
    machines: groupBy(rows, (r) => r.machine_id, (r) => r.machine_label),
    apps: groupBy(rows, (r) => r.app_type, (r) => r.app_type),
  };
}

/** 静态模式下按当前筛选条件从内存算一份 summary */
function summaryFromFilters() {
  const d = staticData;
  const rows = d.rows.filter((r) => {
    if (r.date < state.from || r.date > state.to) return false;
    if (state.machine && r.machine_id !== state.machine) return false;
    if (state.app && r.app_type !== state.app) return false;
    return true;
  });
  return aggregateRows(rows);
}

async function fetchData() {
  if (state.mode === 'static') {
    const d = await loadStaticData();
    return { summary: summaryFromFilters(), quotas: d.quotas, machines: d.machines };
  }
  const [summary, q, m] = await Promise.all([
    loadJSON('/api/summary?' + buildQuery()),
    loadJSON('/api/quotas'),
    loadJSON('/api/machines'),
  ]);
  return { summary, quotas: q.quotas || [], machines: m.machines || [] };
}

// ---------- 渲染 ----------

function renderCards(total) {
  const el = $('#cards');
  const okRate = total.request_count > 0
    ? (total.success_count / total.request_count * 100).toFixed(1) + '%'
    : '—';
  const totalTokens = total.input_tokens + total.output_tokens;
  const cacheHit = (total.input_tokens + total.cache_read_tokens) > 0
    ? (total.cache_read_tokens / (total.input_tokens + total.cache_read_tokens) * 100).toFixed(1) + '%'
    : '—';

  el.innerHTML = `
    <div class="card"><div class="k">花费</div><div class="v">${fmtUSD(total.cost_micro_usd ?? total.client_cost_micro_usd)}</div>
      <div class="s">按服务端统一价格重算</div></div>
    <div class="card"><div class="k">请求数</div><div class="v">${fmtInt(total.request_count)}</div>
      <div class="s">成功 ${okRate}</div></div>
    <div class="card"><div class="k">输入 token</div><div class="v">${fmtInt(total.input_tokens)}</div>
      <div class="s">输出 ${fmtInt(total.output_tokens)}</div></div>
    <div class="card"><div class="k">缓存读取</div><div class="v">${fmtInt(total.cache_read_tokens)}</div>
      <div class="s">缓存占比 ${cacheHit}</div></div>
    <div class="card"><div class="k">创建缓存</div><div class="v">${fmtInt(total.cache_creation_tokens)}</div>
      <div class="s">两列合计 ${fmtInt(totalTokens)}</div></div>
  `;
}

/** 分组行的日期：后端按天分组时字段是 key，兼容 date */
const dayOf = (d) => String(d.key || d.date || '');

function renderChart(days) {
  const el = $('#chart');
  if (!days || !days.length) {
    el.innerHTML = '<div class="empty">这段时间没有数据</div>';
    return;
  }
  days = days.slice().sort((a, b) => dayOf(a).localeCompare(dayOf(b)));
  const W = 900, H = 260, padL = 58, padR = 16, padT = 12, padB = 34;
  const iw = W - padL - padR, ih = H - padT - padB;
  const max = Math.max(...days.map((d) => d.cost_micro_usd || 0), 1);
  const bw = Math.max(2, Math.min(38, iw / days.length - 3));

  const bars = days.map((d, i) => {
    const x = padL + (iw * (i + 0.5)) / days.length - bw / 2;
    const h = Math.max(1, ((d.cost_micro_usd || 0) / max) * ih);
    const y = padT + ih - h;
    return `<rect class="bar" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2">
      <title>${esc(dayOf(d))}　${fmtUSD(d.cost_micro_usd)}　${fmtInt(d.request_count)} 次</title></rect>`;
  }).join('');

  // Y 轴三档
  const ticks = [0, 0.5, 1].map((f) => {
    const y = padT + ih - f * ih;
    return `<line class="grid" x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}"></line>
            <text class="lbl" x="${padL - 8}" y="${y + 4}" text-anchor="end">${fmtUSD(max * f)}</text>`;
  }).join('');

  // X 轴：首、中、尾
  const xLabels = [0, Math.floor(days.length / 2), days.length - 1]
    .filter((v, i, a) => a.indexOf(v) === i && days[v])
    .map((i) => {
      const x = padL + (iw * (i + 0.5)) / days.length;
      return `<text class="lbl" x="${x.toFixed(1)}" y="${H - 12}" text-anchor="middle">${esc(dayOf(days[i]).slice(5))}</text>`;
    }).join('');

  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="每日花费柱状图">
    ${ticks}<line class="axis" x1="${padL}" y1="${padT + ih}" x2="${W - padR}" y2="${padT + ih}"></line>
    ${bars}${xLabels}
  </svg>`;
}

/** 窗口名的中文说明 */
function windowLabel(w) {
  switch (w) {
    case '5h': return '5 小时窗口';
    case 'weekly': return '每周';
    case 'daily': return '每日';
    case 'monthly': return '每月';
    case 'absolute': return '余额';
    default: return w || '未知窗口';
  }
}

function renderQuotas(quotas) {
  const el = $('#quotas');
  if (!quotas.length) {
    el.innerHTML = `<div class="empty">还没有额度数据。<br>
      额度需要在采集端配置各供应商的查询方式；部分供应商（官方订阅、余额类）暂不支持自动采集，可在采集端手动录入。</div>`;
    return;
  }
  // 去重：同一份额度会在多个应用下、甚至多个域名上报多条。
  //
  // 实测的两种情况都必须收敛：
  //  - codex 与 claude 各配一遍同一个 DeepSeek 账号 → account_key 只差 app 前缀
  //  - MiniMax 国际站/国内站是两个域名（api.minimaxi.com / api.minimax.cn），
  //    但背后是同一个账号 → 主机不同、账号名相同
  // 所以只用「账号名」做键，主机与 app 都进不了键；主机仅用于同分时择一。
  const deduped = new Map();
  const accountName = (k) => String(k || '').split('|').slice(2).join('|').trim();
  for (const q of quotas) {
    const key = `${accountName(q.account_key)}\u0000${q.window_key}`;
    const prev = deduped.get(key);
    if (!prev) {
      deduped.set(key, { ...q, apps: new Set([q.app_type]) });
    } else {
      prev.apps.add(q.app_type);
      // 越新越优先；一样新则保留剩余更小的（保守）
      const newer = (q.observed_at_ms || 0) > (prev.observed_at_ms || 0);
      const sameTime = (q.observed_at_ms || 0) === (prev.observed_at_ms || 0);
      const smaller = q.remaining != null && (prev.remaining == null || q.remaining < prev.remaining);
      if (newer || (sameTime && smaller)) {
        const apps = prev.apps;
        deduped.set(key, { ...q, apps });
      }
    }
  }

  // 有余额的排前面，其次按账号名
  const list = [...deduped.values()].sort((a, b) => {
    const av = a.remaining != null ? 1 : 0;
    const bv = b.remaining != null ? 1 : 0;
    if (av !== bv) return bv - av;
    return String(a.provider_label).localeCompare(String(b.provider_label));
  });

  const html = [];
  for (const q of list) {
    const pct = (q.remaining != null && q.total) ? Math.max(0, Math.min(100, q.remaining / q.total * 100)) : null;
    const cls = pct == null ? '' : pct < 10 ? 'critical' : pct < 30 ? 'low' : '';
    const tags = [];
    if (q.stale) tags.push('<span class="tag warn">数据陈旧</span>');
    if (q.conflict_note) tags.push(`<span class="tag warn" title="${esc(q.conflict_note)}">多机不一致</span>`);
    // 重置时间只在它是未来时才有意义
    if (q.reset_at_ms && q.reset_at_ms > Date.now()) {
      tags.push(`<span class="tag">${esc(fmtTime(q.reset_at_ms))}重置</span>`);
    }
    const apps = [...(q.apps || [q.app_type])].join(' / ');
    // 套餐类 remaining=0 且 total=0 说明这个账号根本没有该套餐，别当「余额 0」吓人
    const noPlan = q.unit === 'requests' && q.total === 0 && q.remaining === 0;
    const numText = noPlan ? '<span class="win">无套餐额度</span>' : fmtNum(q.remaining, q.unit);
    const totalText = (!noPlan && q.total) ? `<span class="win"> / ${fmtNum(q.total, q.unit)}</span>` : '';

    html.push(`<div class="quota ${q.stale ? 'stale' : ''}">
        <div class="name"><span>${esc(q.provider_label)}</span>
          <span class="win">${esc(windowLabel(q.window_key))}</span></div>
        <div class="num">${numText}${totalText}</div>
        ${pct != null && !noPlan ? `<div class="bar-wrap"><div class="bar-fill ${cls}" style="width:${pct}%"></div></div>` : ''}
        <div class="meta">${esc(apps)}　观测 ${esc(fmtTime(q.observed_at_ms))}${tags.length ? ' ' + tags.join(' ') : ''}</div>
      </div>`);
  }
  el.innerHTML = html.join('');
}

function renderTable(el, rows, firstCol, maxRows = 12) {
  if (!rows || !rows.length) {
    el.innerHTML = '<div class="empty">无数据</div>';
    return;
  }
  const shown = rows.slice(0, maxRows);
  el.innerHTML = `<table><thead><tr>
      <th>${esc(firstCol)}</th><th>花费</th><th>请求</th><th>输入</th><th>输出</th><th>缓存读</th>
    </tr></thead><tbody>
    ${shown.map((r) => `<tr>
      <td>${esc(r.label || r.key)}</td>
      <td>${fmtUSD(r.cost_micro_usd)}</td>
      <td>${fmtInt(r.request_count)}</td>
      <td>${fmtInt(r.input_tokens)}</td>
      <td>${fmtInt(r.output_tokens)}</td>
      <td>${fmtInt(r.cache_read_tokens)}</td>
    </tr>`).join('')}
    ${rows.length > maxRows ? `<tr><td colspan="6" class="hint">还有 ${rows.length - maxRows} 项…</td></tr>` : ''}
    </tbody></table>`;
}

function renderMachineSelect(machines) {
  const sel = $('#machine');
  const cur = sel.value;
  sel.innerHTML = '<option value="">全部</option>' +
    machines.map((m) => `<option value="${esc(m.machine_id)}">${esc(m.label || m.machine_id.slice(0, 8))}</option>`).join('');
  sel.value = cur;
}

function renderAdmin(accounts) {
  const el = $('#admin');
  if (state.mode === 'static') {
    el.innerHTML = '<div class="empty">静态部署下不支持修改；如需合并账号，请在自建服务器版操作，或改采集端的账号别名配置。</div>';
    return;
  }
  if (!accounts || !accounts.length) {
    el.innerHTML = '<div class="empty">暂无账号</div>';
    return;
  }
  el.innerHTML = accounts.map((a) => `
    <div class="admin-row">
      <span class="key">${esc(a.key)}</span>
      <span>${esc(a.label || '')}</span>
      <button class="btn" data-merge="${esc(a.key)}">合并到…</button>
    </div>`).join('');
  el.querySelectorAll('[data-merge]').forEach((b) => {
    b.addEventListener('click', async () => {
      const src = b.getAttribute('data-merge');
      const target = prompt(`把「${src}」合并到哪个 account_key？\n（留空则取消合并）`, '');
      if (target === null) return;
      await postMerge(src, target.trim());
      await refresh();
    });
  });
}

async function postMerge(accountKey, mergedInto) {
  const res = await fetch('/api/accounts/merge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ account_key: accountKey, merged_into: mergedInto }),
  });
  if (!res.ok) {
    const t = await res.json().catch(() => ({}));
    alert('合并失败：' + (t.error || res.status));
  }
}

// ---------- 主流程 ----------

function setStatus(text, isError) {
  const el = $('#status');
  el.textContent = text;
  el.className = 'status' + (isError ? ' error' : '');
}

async function refresh() {
  setStatus('加载中…');
  const range = $('#range').value;
  state.machine = $('#machine').value;
  state.app = $('#app').value;
  state.to = new Date().toISOString().slice(0, 10);
  state.from = range === 'all' ? '2000-01-01' : isoDaysAgo(Number(range));

  try {
    const { summary, quotas, machines } = await fetchData();
    state.summary = summary;
    state.quotas = quotas;
    state.machines = machines;

    renderCards(summary.total || {});
    renderChart(summary.days || []);
    renderQuotas(quotas);
    renderTable($('#accounts'), summary.accounts, '账号');
    renderTable($('#models'), summary.models, '模型');
    renderTable($('#machines'), summary.machines, '设备');
    renderMachineSelect(machines);
    renderAdmin(summary.accounts);

    // 应用下拉框取自全量数据，而不是当前筛选结果 ——
    // 否则选了某个应用后，选项就只剩它自己，再也切不回去。
    const allApps = state.mode === 'static'
      ? [...new Set(staticData.rows.map((r) => r.app_type))].sort()
      : (summary.apps || []).map((a) => a.key);
    const appSel = $('#app');
    const curApp = appSel.value;
    appSel.innerHTML = '<option value="">全部</option>' +
      allApps.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join('');
    appSel.value = curApp;

    const tot = summary.total || {};
    const extra = state.mode === 'static'
      ? `　·　静态快照 ${fmtTime(state.snapshotMs)}`
      : '';
    setStatus(`共 ${fmtInt(tot.request_count)} 次请求${extra}`);
  } catch (e) {
    setStatus('加载失败：' + e.message, true);
  }
}

async function boot() {
  // 判定模式：存在 data/index.json 就是静态站
  try {
    const cfg = await fetch('./data/index.json', { cache: 'no-store' });
    if (cfg.ok) {
      const j = await cfg.json();
      if (j.mode === 'static') {
        state.mode = 'static';
        state.encrypted = !!j.encrypted;
        state.snapshotMs = j.generated_at_ms;
      }
    }
  } catch { /* 没有清单就是 server 模式 */ }

  // 静态模式也能筛选（数据已在浏览器里，本地过滤即可）；
  // 只有「账号管理」需要写后端，静态下隐藏。
  $('#admin-panel').hidden = state.mode === 'static';

  $('#range').addEventListener('change', refresh);
  $('#machine').addEventListener('change', refresh);
  $('#app').addEventListener('change', refresh);

  $('#foot').textContent = state.mode === 'static'
    ? '静态部署 · 数据为定时生成的快照 · 不含任何凭据'
    : '自建服务 · 只接收日汇总数据 · 不含任何凭据';

  await refresh();

  if (state.mode !== 'static') {
    // 60 秒自动刷新，小服务器压力可忽略
    setInterval(() => { if (!document.hidden) refresh(); }, 60000);
  }
}

boot();
