import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- 后端 API 逻辑 ---

    // 1. TCP 延迟检测 API
    if (path === '/api/tcping') {
      const target = url.searchParams.get('target');
      const port = parseInt(url.searchParams.get('port')) || 443;
      if (!target) return new Response('Missing target', { status: 400 });

      const start = performance.now();
      try {
        const socket = connect({ hostname: target, port: port });
        await Promise.race([
          socket.opened,
          new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 3000))
        ]);
        const rtt = Math.round(performance.now() - start);
        socket.close();
        return new Response(JSON.stringify({ status: 'success', rtt }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'error', message: e.message }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
    }

    // 2. 地理位置查询 API
    if (path === '/api/geoip') {
      const target = url.searchParams.get('target');
      if (!target) return new Response('Missing target', { status: 400 });
      try {
        const response = await fetch(`http://ip-api.com/json/${target}?lang=zh-CN`);
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'fail' }), { status: 500 });
      }
    }

    // --- 前端 UI 渲染 ---
    const currentColo = request.cf?.colo || '未知机房';
    const currentCity = request.cf?.city || '未知城市';
    const currentCountry = request.cf?.country || '未知国家';
    const currentIP = request.headers.get('CF-Connecting-IP') || '未知IP';

    return new Response(renderHTML(currentColo, currentCity, currentCountry, currentIP), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

function renderHTML(colo, city, country, ip) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Tracer - 批量路由分析</title>
  <style>
    :root { --primary: #6366f1; --bg: #0f172a; --card: #1e293b; --border: #334155; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: #f8fafc; margin: 0; padding: 20px; }
    .container { width: 100%; max-width: 900px; margin: 0 auto; }
    .card { background: var(--card); border-radius: 16px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); margin-bottom: 20px; }
    h1 { text-align: center; color: var(--primary); margin-bottom: 30px; font-weight: 800; }
    
    /* 本地信息区域 */
    .local-info { display: flex; justify-content: space-between; align-items: center; padding: 15px; background: rgba(99, 102, 241, 0.1); border: 1px solid var(--primary); border-radius: 12px; margin-bottom: 25px; }
    .local-info div { font-size: 14px; }
    .local-info strong { color: var(--primary); }

    /* 输入区域 */
    .input-section { margin-bottom: 20px; }
    textarea { width: 100%; height: 120px; padding: 15px; border-radius: 12px; border: 1px solid var(--border); background: #0f172a; color: white; outline: none; font-family: monospace; resize: vertical; margin-bottom: 15px; box-sizing: border-box; }
    textarea:focus { border-color: var(--primary); }
    
    .action-bar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    .btn { padding: 12px 24px; background: var(--primary); color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn-secondary { background: #475569; }
    
    #file-label { cursor: pointer; padding: 12px 20px; background: #334155; border-radius: 8px; font-size: 14px; border: 1px dashed var(--primary); }
    #file-input { display: none; }

    /* 历史记录 */
    .history-tags { margin-top: 10px; display: flex; gap: 8px; }
    .history-tag { font-size: 12px; background: #334155; padding: 4px 10px; border-radius: 6px; cursor: pointer; }
    .history-tag:hover { background: var(--primary); }

    /* 结果表格 */
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
    th { text-align: left; background: #334155; padding: 12px; color: var(--primary); border-bottom: 2px solid var(--bg); }
    td { padding: 12px; border-bottom: 1px solid var(--border); }
    .status-ok { color: #10b981; font-weight: bold; }
    .status-err { color: #ef4444; }
    .loading-row { opacity: 0.5; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>🌐 Link Tracer Batch</h1>
      
      <div class="local-info">
        <div>📍 当前节点: <strong>${colo}</strong></div>
        <div>🌍 物理位置: <strong>${country} - ${city}</strong></div>
        <div>🆔 本机IP: <strong>${ip}</strong></div>
      </div>

      <div class="input-section">
        <textarea id="target-area" placeholder="请输入目标地址（域名或IP），一行一个..."></textarea>
        <div class="action-bar">
          <button class="btn" onclick="startBatchTrace()">批量追踪</button>
          <label id="file-label" for="file-input">📄 上传 TXT 列表</label>
          <input type="file" id="file-input" accept=".txt" onchange="handleFileUpload(this)">
          <button class="btn btn-secondary" onclick="clearResults()">清空结果</button>
        </div>
        <div class="history-tags" id="history-box"></div>
      </div>

      <div id="results-container" style="display:none">
        <table>
          <thead>
            <tr>
              <th width="30%">目标地址</th>
              <th width="15%">延迟 (RTT)</th>
              <th width="30%">地理位置</th>
              <th width="25%">运营商/AS</th>
            </tr>
          </thead>
          <tbody id="result-body"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const historyBox = document.getElementById('history-box');
    const targetArea = document.getElementById('target-area');
    const resultBody = document.getElementById('result-body');
    const resultContainer = document.getElementById('results-container');

    // 记忆功能逻辑
    function updateHistory(rawInput) {
      if(!rawInput) return;
      let list = JSON.parse(localStorage.getItem('trace_history_batch') || '[]');
      // 记录整个输入块的前30个字符作为标识
      const summary = rawInput.split('\\n')[0].substring(0, 20) + (rawInput.includes('\\n') ? '...' : '');
      list = list.filter(i => i.val !== rawInput);
      list.unshift({ label: summary, val: rawInput });
      list = list.slice(0, 3);
      localStorage.setItem('trace_history_batch', JSON.stringify(list));
      renderHistory();
    }

    function renderHistory() {
      const list = JSON.parse(localStorage.getItem('trace_history_batch') || '[]');
      historyBox.innerHTML = list.length > 0 ? '<span>最近记录:</span>' : '';
      list.forEach(item => {
        const span = document.createElement('span');
        span.className = 'history-tag';
        span.innerText = item.label;
        span.onclick = () => { targetArea.value = item.val; };
        historyBox.appendChild(span);
      });
    }

    // 文件上传处理
    function handleFileUpload(input) {
      const file = input.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (e) => {
        targetArea.value = e.target.result;
      };
      reader.readAsText(file);
    }

    function clearResults() {
      resultBody.innerHTML = '';
      resultContainer.style.display = 'none';
    }

    // 批量执行逻辑
    async function startBatchTrace() {
      const content = targetArea.value.trim();
      if(!content) return alert('请输入目标');
      
      updateHistory(content);
      const lines = content.split('\\n').map(l => l.trim()).filter(l => l !== '');
      
      resultContainer.style.display = 'block';
      
      // 为每个目标创建一行占位符
      for (const target of lines) {
        const rowId = 'row-' + btoa(target).substring(0, 10);
        if (document.getElementById(rowId)) continue; // 避免重复添加

        const tr = document.createElement('tr');
        tr.id = rowId;
        tr.className = 'loading-row';
        tr.innerHTML = \`
          <td>\${target}</td>
          <td class="rtt-cell">探测中...</td>
          <td class="geo-cell">正在查询...</td>
          <td class="isp-cell">--</td>
        \`;
        resultBody.prepend(tr);

        // 异步执行单个探测（不阻塞循环）
        runSingleTrace(target, rowId);
      }
    }

    async function runSingleTrace(target, rowId) {
      const row = document.getElementById(rowId);
      const cleanTarget = target.split(':')[0]; // 提取域名或IP，忽略端口输入

      try {
        // 并行请求后端接口
        const [latRes, geoRes] = await Promise.all([
          fetch(\`./api/tcping?target=\${encodeURIComponent(cleanTarget)}\`).then(r => r.json()),
          fetch(\`./api/geoip?target=\${encodeURIComponent(cleanTarget)}\`).then(r => r.json())
        ]);

        row.className = '';
        
        // 渲染延迟
        const rttCell = row.querySelector('.rtt-cell');
        if(latRes.status === 'success') {
          rttCell.innerHTML = \`<span class="status-ok">\${latRes.rtt} ms</span>\`;
        } else {
          rttCell.innerHTML = \`<span class="status-err">超时</span>\`;
        }

        // 渲染地理位置和运营商
        const geoCell = row.querySelector('.geo-cell');
        const ispCell = row.querySelector('.isp-cell');
        if(geoRes.status === 'success' || geoRes.query) {
          geoCell.innerText = \`\${geoRes.country || ''} \${geoRes.city || ''} (\${geoRes.countryCode || '??'})\`;
          ispCell.innerText = \`\${geoRes.isp || '未知'} (\${geoRes.as || '--'})\`;
        } else {
          geoCell.innerText = '查询失败';
        }

      } catch(e) {
        row.querySelector('.rtt-cell').innerText = '错误';
        console.error(e);
      }
    }

    // 初始化显示
    renderHistory();
  </script>
</body>
</html>`;
}
