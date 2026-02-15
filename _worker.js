import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- API 接口部分 ---

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

    // --- 前端页面部分 ---
    const currentColo = request.cf?.colo || '未知机房';
    const currentCity = request.cf?.city || '未知城市';
    const currentCountry = request.cf?.country || '未知国家';

    return new Response(renderHTML(currentColo, currentCity, currentCountry), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

function renderHTML(colo, city, country) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Tracer - 路由追踪</title>
  <style>
    :root { --primary: #6366f1; --bg: #0f172a; --card: #1e293b; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: #f8fafc; margin: 0; padding: 20px; display: flex; justify-content: center; }
    .container { width: 100%; max-width: 700px; }
    .card { background: var(--card); border-radius: 16px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); margin-bottom: 20px; }
    h1 { text-align: center; color: var(--primary); margin-top: 0; }
    
    .input-row { display: flex; gap: 10px; margin-bottom: 20px; position: relative; }
    input { flex: 1; padding: 14px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: white; outline: none; }
    input:focus { border-color: var(--primary); }
    .btn { padding: 0 24px; background: var(--primary); color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }

    .history-list {
      position: absolute; top: 100%; left: 0; right: 80px; background: #334155; border-radius: 8px; 
      display: none; z-index: 10; border: 1px solid var(--primary);
    }
    .history-item { padding: 12px; cursor: pointer; border-bottom: 1px solid #475569; font-size: 14px; }
    .history-item:last-child { border: none; }
    .history-item:hover { background: var(--primary); }

    .route-map { position: relative; padding: 20px 0; margin: 20px 0; border-top: 1px solid #334155; }
    .step { display: flex; align-items: flex-start; gap: 15px; margin-bottom: 20px; position: relative; }
    .step::before { content: ''; position: absolute; left: 14px; top: 30px; bottom: -10px; width: 2px; background: #334155; }
    .step:last-child::before { display: none; }
    .dot { width: 30px; height: 30px; border-radius: 50%; background: var(--primary); display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 2; }
    .info { flex: 1; background: #334155; padding: 15px; border-radius: 12px; }
    .info h4 { margin: 0 0 5px; color: var(--primary); }
    .info p { margin: 0; font-size: 13px; color: #cbd5e1; }
    .latency { float: right; color: #10b981; font-weight: bold; }

    .loading { text-align: center; display: none; color: var(--primary); }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>🌐 Link Tracer</h1>
      <div class="input-row">
        <input type="text" id="target" placeholder="目的地址 (域名或 IP)" autocomplete="off">
        <button class="btn" onclick="startTrace()">追踪</button>
        <div class="history-list" id="history"></div>
      </div>
      
      <div id="loading" class="loading">正在探测节点信息...</div>

      <div class="route-map" id="result-box" style="display:none">
        <div class="step">
          <div class="dot">1</div>
          <div class="info">
            <span class="latency">本机</span>
            <h4>Cloudflare Edge (${colo})</h4>
            <p>${country} - ${city}</p>
          </div>
        </div>

        <div class="step">
          <div class="dot">2</div>
          <div class="info">
            <span class="latency" id="res-rtt">-- ms</span>
            <h4 id="res-title">目标服务器</h4>
            <p id="res-geo">等待输入...</p>
            <p id="res-isp" style="margin-top:5px; font-size:11px; opacity:0.7"></p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const historyBox = document.getElementById('history');
    const input = document.getElementById('target');

    // 记忆功能逻辑
    function updateHistory(val) {
      if(!val) return;
      let list = JSON.parse(localStorage.getItem('trace_history') || '[]');
      list = list.filter(i => i !== val);
      list.unshift(val);
      list = list.slice(0, 3);
      localStorage.setItem('trace_history', JSON.stringify(list));
      renderHistory();
    }

    function renderHistory() {
      const list = JSON.parse(localStorage.getItem('trace_history') || '[]');
      if(list.length > 0) {
        historyBox.innerHTML = list.map(i => \`<div class="history-item" onclick="selectHistory('\${i}')">\${i}</div>\`).join('');
      } else {
        historyBox.innerHTML = '<div class="history-item">暂无记录</div>';
      }
    }

    function selectHistory(val) {
      input.value = val;
      historyBox.style.display = 'none';
      startTrace();
    }

    input.addEventListener('focus', () => {
      renderHistory();
      historyBox.style.display = 'block';
    });

    document.addEventListener('click', (e) => {
      if(!e.target.closest('.input-row')) historyBox.style.display = 'none';
    });

    // 核心追踪逻辑
    async function startTrace() {
      const target = input.value.trim();
      if(!target) return;
      
      updateHistory(target);
      historyBox.style.display = 'none';
      
      document.getElementById('loading').style.display = 'block';
      document.getElementById('result-box').style.display = 'none';

      try {
        // 并行请求延迟和地理位置
        const [latRes, geoRes] = await Promise.all([
          fetch(\`./api/tcping?target=\${encodeURIComponent(target)}\`).then(r => r.json()),
          fetch(\`./api/geoip?target=\${encodeURIComponent(target)}\`).then(r => r.json())
        ]);

        document.getElementById('loading').style.display = 'none';
        document.getElementById('result-box').style.display = 'block';

        // 填充结果
        if(latRes.status === 'success') {
          document.getElementById('res-rtt').innerText = latRes.rtt + ' ms';
        } else {
          document.getElementById('res-rtt').innerText = '连接超时';
          document.getElementById('res-rtt').style.color = '#ef4444';
        }

        if(geoRes.status === 'success' || geoRes.query) {
          document.getElementById('res-title').innerText = geoRes.query;
          document.getElementById('res-geo').innerText = \`\${geoRes.country} - \${geoRes.city} (\${geoRes.countryCode})\`;
          document.getElementById('res-isp').innerText = \`运营商: \${geoRes.isp} | AS: \${geoRes.as}\`;
        }

      } catch(e) {
        alert('追踪失败: ' + e.message);
        document.getElementById('loading').style.display = 'none';
      }
    }
  </script>
</body>
</html>`;
}
