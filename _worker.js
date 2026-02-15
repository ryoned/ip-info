import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- 后端 API 接口 ---

    // 1. TCP 延迟检测 (CF IP 兼容版)
    if (path === '/api/tcping') {
      const target = url.searchParams.get('target');
      const port = parseInt(url.searchParams.get('port')) || 443;
      if (!target) return new Response('Missing target', { status: 400 });

      const start = performance.now();
      try {
        const socket = connect({ hostname: target, port: port });
        await Promise.race([
          socket.opened,
          new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2500))
        ]);
        const rtt = Math.round(performance.now() - start);
        socket.close();
        return new Response(JSON.stringify({ status: 'success', rtt, type: 'TCP' }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        // TCP 失败，尝试 HTTP (针对 Cloudflare IP)
        try {
          const fetchStart = performance.now();
          await fetch(`https://${target}/cdn-cgi/trace`, { method: 'HEAD', cache: 'no-store' });
          const rtt = Math.round(performance.now() - fetchStart);
          return new Response(JSON.stringify({ status: 'success', rtt, type: 'HTTP(CF)' }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        } catch (err) {
          return new Response(JSON.stringify({ status: 'error', message: e.message }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
      }
    }

    // 2. 地理位置查询 (修复版：更换为 ipwho.is 以解决 1103 报错)
    if (path === '/api/geoip') {
      const target = url.searchParams.get('target');
      if (!target) return new Response('Missing target', { status: 400 });
      try {
        // 使用 ipwho.is，它对 Workers 更友好且识别精准
        const response = await fetch(`https://ipwho.is/${target}?lang=zh-CN`);
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'fail' }), { status: 500 });
      }
    }

    // 3. 域名解析 (保持不变)
    if (path === '/api/resolve') {
      const domain = url.searchParams.get('domain');
      if (!domain) return new Response('Missing domain', { status: 400 });
      try {
        const ips = await resolveDomain(domain);
        return new Response(JSON.stringify({ status: 'success', ips }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'error', message: e.message }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
    }

    // --- 前端页面渲染 (UI 保持不变) ---
    const currentColo = request.cf?.colo || '未知';
    const currentCity = request.cf?.city || '未知';
    const currentCountry = request.cf?.country || '未知';
    const currentIP = request.headers.get('CF-Connecting-IP') || '未知';

    return new Response(renderHTML(currentColo, currentCity, currentCountry, currentIP), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

async function resolveDomain(domain) {
  const endpoints = [
    { url: 'https://dns.google/resolve', name: 'Google' },
    { url: 'https://223.5.5.5/resolve', name: 'AliDNS' }
  ];
  for (const endpoint of endpoints) {
    try {
      const [v4, v6] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`).then(r => r.json()),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`).then(r => r.json())
      ]);
      const ips = new Set();
      if (v4.Answer) v4.Answer.filter(r => r.type === 1).forEach(r => ips.add(r.data));
      if (v6.Answer) v6.Answer.filter(r => r.type === 28).forEach(r => ips.add(r.data));
      if (ips.size > 0) return Array.from(ips);
    } catch (e) { continue; }
  }
  return [domain];
}

function renderHTML(colo, city, country, ip) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Advanced Link Tracer</title>
  <style>
    :root { --primary: #06b6d4; --bg: #0f172a; --card: #1e293b; --text: #f1f5f9; --border: #334155; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
    .container { max-width: 1000px; margin: 0 auto; }
    .card { background: var(--card); border-radius: 16px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); margin-bottom: 20px; border: 1px solid var(--border); }
    h1 { margin: 0 0 20px 0; font-size: 24px; color: var(--primary); display: flex; align-items: center; gap: 10px; }
    .local-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; background: rgba(6, 182, 212, 0.1); padding: 15px; border-radius: 12px; border: 1px solid rgba(6, 182, 212, 0.2); margin-bottom: 25px; }
    .info-item label { display: block; font-size: 12px; opacity: 0.7; margin-bottom: 4px; }
    .info-item span { font-weight: 600; font-size: 15px; color: var(--primary); }
    textarea { width: 100%; height: 100px; background: #0f172a; border: 1px solid var(--border); color: white; padding: 15px; border-radius: 12px; font-family: monospace; resize: vertical; box-sizing: border-box; outline: none; transition: 0.2s; }
    textarea:focus { border-color: var(--primary); }
    .controls { margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
    .btn { padding: 10px 20px; border-radius: 8px; border: none; font-weight: 600; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px; }
    .btn-primary { background: var(--primary); color: #000; }
    .btn-ghost { background: var(--border); color: white; }
    .history { margin-top: 15px; display: flex; gap: 8px; overflow-x: auto; padding-bottom: 5px; }
    .tag { background: #334155; padding: 4px 10px; border-radius: 20px; font-size: 12px; cursor: pointer; white-space: nowrap; border: 1px solid transparent; }
    .tag:hover { border-color: var(--primary); color: var(--primary); }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; min-width: 600px; }
    th { text-align: left; padding: 12px; color: var(--primary); border-bottom: 2px solid var(--border); font-weight: 600; }
    td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    .rtt-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 13px; }
    .rtt-green { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .rtt-yellow { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .rtt-red { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .target-sub { font-size: 12px; opacity: 0.6; display: block; margin-top: 2px; }
    .type-label { font-size: 10px; opacity: 0.4; margin-left: 4px; border: 1px solid rgba(255,255,255,0.1); padding: 0 2px; }
    .loading-spin { display: inline-block; width: 12px; height: 12px; border: 2px solid var(--primary); border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
<div class="container">
  <div class="card">
    <h1>📡 Link Tracer <span style="font-size:12px; opacity:0.6; color:var(--text); margin-left:auto;">Advanced</span></h1>
    <div class="local-bar">
      <div class="info-item"><label>当前节点 (Colo)</label><span>${colo}</span></div>
      <div class="info-item"><label>物理位置</label><span>${country} - ${city}</span></div>
      <div class="info-item"><label>本机 IP</label><span>${ip}</span></div>
    </div>
    <textarea id="input-area" placeholder="输入目标地址（支持域名或IP），一行一个..."></textarea>
    <div class="controls">
      <button class="btn btn-primary" onclick="startBatch()">🚀 开始探测</button>
      <button class="btn btn-ghost" onclick="document.getElementById('file-input').click()">📂 上传 TXT</button>
      <input type="file" id="file-input" accept=".txt" onchange="handleFile(this)">
      <button class="btn btn-ghost" onclick="clearTable()">🗑️ 清空表格</button>
    </div>
    <div class="history" id="history-box"></div>
  </div>
  <div class="card" id="result-panel" style="display:none;">
    <div class="table-container">
      <table>
        <thead><tr><th>目标地址 (Target)</th><th>TCP 延迟</th><th>物理位置</th><th>运营商 / 机房 (ISP)</th></tr></thead>
        <tbody id="result-body"></tbody>
      </table>
    </div>
  </div>
</div>
<script>
  const historyKey = 'tracer_history_v2';
  const inputArea = document.getElementById('input-area');
  const resultBody = document.getElementById('result-body');
  function saveHistory(val) {
    if(!val) return;
    let list = JSON.parse(localStorage.getItem(historyKey) || '[]');
    const preview = val.split('\\n')[0].substring(0, 15) + (val.length>15?'...':'');
    list = list.filter(i => i.val !== val);
    list.unshift({ name: preview, val: val });
    if(list.length > 5) list.pop();
    localStorage.setItem(historyKey, JSON.stringify(list));
    renderHistory();
  }
  function renderHistory() {
    const list = JSON.parse(localStorage.getItem(historyKey) || '[]');
    const box = document.getElementById('history-box');
    box.innerHTML = list.map(item => \`<div class="tag" onclick="fillInput('\${encodeURIComponent(item.val)}')">\${item.name}</div>\`).join('');
  }
  window.fillInput = (val) => { inputArea.value = decodeURIComponent(val); }
  window.handleFile = (input) => {
    const file = input.files[0];
    if(file) { const reader = new FileReader(); reader.onload = e => inputArea.value = e.target.result; reader.readAsText(file); }
  }
  window.clearTable = () => { resultBody.innerHTML = ''; document.getElementById('result-panel').style.display = 'none'; }
  window.startBatch = async () => {
    const raw = inputArea.value.trim();
    if(!raw) return alert('请输入目标地址');
    saveHistory(raw);
    document.getElementById('result-panel').style.display = 'block';
    const lines = raw.split('\\n').map(x => x.trim()).filter(x => x);
    for (const target of lines) { await processLine(target); }
  }
  async function processLine(target) {
    const isIP = /^[0-9\\.:]+$/.test(target);
    if (isIP) { addResultRow(target, target); } 
    else {
      const tempId = 'resolving-' + Math.random().toString(36).substr(2, 9);
      addPlaceholderRow(target, tempId);
      try {
        const res = await fetch(\`./api/resolve?domain=\${encodeURIComponent(target)}\`);
        const data = await res.json();
        const placeholder = document.getElementById(tempId);
        if(placeholder) placeholder.remove();
        if (data.status === 'success' && data.ips.length > 0) {
          for (const ip of data.ips) { addResultRow(\`\${target} (\${ip})\`, ip); }
        } else { addResultRow(target, target); }
      } catch(e) {
        if(document.getElementById(tempId)) document.getElementById(tempId).remove();
        addResultRow(target + " [解析失败]", target);
      }
    }
  }
  function addPlaceholderRow(label, id) {
    const tr = document.createElement('tr'); tr.id = id;
    tr.innerHTML = \`<td>\${label}</td><td colspan="3" style="color:#94a3b8"><span class="loading-spin"></span> 正在解析所有IP...</td>\`;
    resultBody.prepend(tr);
  }
  function addResultRow(displayLabel, realTarget) {
    const tr = document.createElement('tr');
    const rowId = 'row-' + Math.random().toString(36).substr(2, 9);
    tr.id = rowId;
    tr.innerHTML = \`<td><div>\${displayLabel.split(' (')[0]}</div>\${displayLabel.includes('(') ? \`<span class="target-sub">\${displayLabel.split(' (')[1].replace(')', '')}</span>\` : ''}</td><td id="\${rowId}-rtt"><span class="loading-spin"></span></td><td id="\${rowId}-geo">...</td><td id="\${rowId}-isp">...</td>\`;
    resultBody.prepend(tr);
    const cleanIP = realTarget.replace(/[\\\\[\\\\]]/g, '');
    
    // TCP/HTTP 延迟检测
    fetch(\`./api/tcping?target=\${encodeURIComponent(cleanIP)}\`).then(r => r.json()).then(d => {
      const el = document.getElementById(\`\${rowId}-rtt\`);
      if(d.status === 'success') {
        let cls = 'rtt-green'; if(d.rtt > 100) cls = 'rtt-yellow'; if(d.rtt > 250) cls = 'rtt-red';
        const typeTag = d.type ? \`<span class="type-label">\${d.type}</span>\` : '';
        el.innerHTML = \`<span class="rtt-badge \${cls}">\${d.rtt} ms</span>\${typeTag}\`;
      } else { el.innerHTML = \`<span style="color:#ef4444; font-size:12px">连接超时</span>\`; }
    });

    // GeoIP 检测 (已适配 ipwho.is 的返回字段)
    fetch(\`./api/geoip?target=\${encodeURIComponent(cleanIP)}\`).then(r => r.json()).then(d => {
      // 字段适配：ipwho.is 使用 connection.isp 等字段
      const city = d.city || '';
      const country = d.country || '';
      document.getElementById(\`\${rowId}-geo\`).innerText = \`\${country} \${city}\`;
      
      const ispName = d.connection ? (d.connection.isp || d.connection.org) : (d.isp || '未知');
      const asn = d.connection ? d.connection.asn : (d.asn || '');
      document.getElementById(\`\${rowId}-isp\`).innerHTML = \`\${ispName} <br><span class="target-sub">AS\${asn}</span>\`;
    });
  }
  renderHistory();
</script>
</body>
</html>`;
}
