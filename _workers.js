import { connect } from "cloudflare:sockets";

// 全局变量
let 临时TOKEN, 永久TOKEN;

export default {
  async fetch(request, env, ctx) {
    const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
    const url = new URL(request.url);
    const UA = request.headers.get('User-Agent') || 'null';
    const path = url.pathname;
    const hostname = url.hostname;
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); // 每31分钟一个时间戳
    
    // 生成 Token
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    // 不区分大小写检查路径
    if (path.toLowerCase() === '/check') {
      if (!url.searchParams.has('proxyip')) return new Response('Missing proxyip parameter', { status: 400 });
      if (url.searchParams.get('proxyip') === '') return new Response('Invalid proxyip parameter', { status: 400 });
      if (!url.searchParams.get('proxyip').includes('.') && !(url.searchParams.get('proxyip').includes('[') && url.searchParams.get('proxyip').includes(']'))) return new Response('Invalid proxyip format', { status: 400 });

      if (env.TOKEN) {
        if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) {
          return new Response(JSON.stringify({
            status: "error",
            message: `ProxyIP查询失败: 无效的TOKEN`,
            timestamp: new Date().toISOString()
          }, null, 4), {
            status: 403,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // 获取参数中的IP或使用默认IP
      const proxyIP = url.searchParams.get('proxyip').toLowerCase();
      const colo = request.cf?.colo || 'CF';
      // 调用CheckProxyIP函数
      const result = await CheckProxyIP(proxyIP, colo);

      // 返回JSON响应，根据检查结果设置不同的状态码
      return new Response(JSON.stringify(result, null, 2), {
        status: result.success ? 200 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } else if (path.toLowerCase() === '/resolve') {
      // 检查 Token
      if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) {
        return new Response(JSON.stringify({
          status: "error",
          message: `域名查询失败: 无效的TOKEN`,
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 403,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
      if (!url.searchParams.has('domain')) return new Response('Missing domain parameter', { status: 400 });
      const domain = url.searchParams.get('domain');

      try {
        const ips = await resolveDomain(domain);
        return new Response(JSON.stringify({ success: true, domain, ips }), {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        });
      }
    } else if (path.toLowerCase() === '/ip-info') {
      if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) {
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: 无效的TOKEN`,
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 403,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(JSON.stringify({
          status: "error",
          message: "IP参数未提供",
          code: "MISSING_PARAMETER",
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      if (ip.includes('[')) {
        ip = ip.replace('[', '').replace(']', '');
      }

      try {
        // 使用Worker代理请求HTTP的IP API
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();

        // 添加时间戳到成功的响应数据中
        data.timestamp = new Date().toISOString();

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });

      } catch (error) {
        console.error("IP查询失败:", error);
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: ${error.message}`,
          code: "API_REQUEST_FAILED",
          query: ip,
          timestamp: new Date().toISOString(),
          details: {
            errorType: error.name,
            stack: error.stack ? error.stack.split('\n')[0] : null
          }
        }, null, 4), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    } else {
      const envKey = env.URL302 ? 'URL302' : (env.URL ? 'URL' : null);
      if (envKey) {
        const URLs = await 整理(env[envKey]);
        const URL = URLs[Math.floor(Math.random() * URLs.length)];
        return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request));
      } 
      // === 核心逻辑修改：带 Token 传参可访问 ===
      else if (env.TOKEN && url.searchParams.get('token') !== 永久TOKEN) {
        return new Response(await nginx(), {
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
          },
        });
      } else if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(网站图标, 302);
      }
      // 直接返回HTML页面，传递永久TOKEN供前端JS调用
      return await HTML(hostname, 网站图标, 永久TOKEN);
    }
  }
};

// ============================================
// 修复版域名解析函数 (使用 Google DNS 和 AliDNS)
// ============================================
async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  const endpoints = [
    { url: 'https://dns.google/resolve', name: 'Google DNS' },
    { url: 'https://223.5.5.5/resolve', name: 'AliDNS' }
  ];

  for (const endpoint of endpoints) {
    try {
      const [ipv4Res, ipv6Res] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`)
      ]);
      if (!ipv4Res.ok || !ipv6Res.ok) continue;
      const [ipv4Data, ipv6Data] = await Promise.all([ipv4Res.json(), ipv6Res.json()]);
      const ips = [];
      if (ipv4Data.Answer) {
        ipv4Data.Answer.filter(r => r.type === 1).forEach(r => ips.push(r.data));
      }
      if (ipv6Data.Answer) {
        ipv6Data.Answer.filter(r => r.type === 28).forEach(r => ips.push(`[${r.data}]`));
      }
      if (ips.length > 0) return ips;
    } catch (error) {
      continue;
    }
  }
  throw new Error('无法解析域名: 所有 DNS 服务均未返回有效 IP');
}

// -------------------------------------------------------------
// 原有 CheckProxyIP 逻辑（保持完整）
async function CheckProxyIP(proxyIP, colo = 'CF') {
  let portRemote = 443;
  if (proxyIP.includes('.tp')) {
    const portMatch = proxyIP.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1]);
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1]);
    proxyIP = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':')) {
    portRemote = parseInt(proxyIP.split(':')[1]);
    proxyIP = proxyIP.split(':')[0];
  }

  const tcpSocket = connect({ hostname: proxyIP, port: portRemote });

  try {
    const httpRequest = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: CheckProxyIP/cmliu\r\nConnection: close\r\n\r\n";
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000))
      ]);
      if (done || !value) break;
      const newData = new Uint8Array(responseData.length + value.length);
      newData.set(responseData); newData.set(value, responseData.length);
      responseData = newData;
      const text = new TextDecoder().decode(responseData);
      if (text.includes("\r\n\r\n") && (text.includes("Connection: close") || text.includes("content-length"))) break;
    }
    reader.releaseLock();
    await tcpSocket.close();

    const responseText = new TextDecoder().decode(responseData);
    if (responseText.includes("cloudflare") && responseText.includes("400 Bad Request")) {
      const tls握手 = await 验证反代IP(proxyIP, portRemote);
      return { success: tls握手[0], proxyIP, portRemote, colo, responseTime: tls握手[2], message: tls握手[1], timestamp: new Date().toISOString() };
    }
    return { success: false, proxyIP, portRemote, colo, message: "无法通过ProxyIP访问Cloudflare", timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, proxyIP: -1, portRemote: -1, colo, message: error.message, timestamp: new Date().toISOString() };
  }
}

async function 整理(内容) {
  var 替换后的内容 = 内容.replace(/[\r\n]+/g, '|').replace(/\|+/g, '|');
  const 地址数组 = 替换后的内容.split('|');
  return 地址数组.filter((item, index) => item !== '' && 地址数组.indexOf(item) === index);
}

async function 双重哈希(文本) {
  const enc = new TextEncoder();
  const h1 = await crypto.subtle.digest('MD5', enc.encode(文本));
  const s1 = Array.from(new Uint8Array(h1)).map(b => b.toString(16).padStart(2, '0')).join('');
  const h2 = await crypto.subtle.digest('MD5', enc.encode(s1.slice(7, 27)));
  return Array.from(new Uint8Array(h2)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function 验证反代IP(反代IP地址, 指定端口) {
  const 最大重试次数 = 4;
  let 最后错误 = null;
  const 开始时间 = performance.now();
  for (let i = 0; i < 最大重试次数; i++) {
    let TCP接口 = null;
    try {
      TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 指定端口 }, 1000 + (i * 500));
      const 传输数据 = TCP接口.writable.getWriter();
      const 读取数据 = TCP接口.readable.getReader();
      await 传输数据.write(构建TLS握手());
      const { value, 超时 } = await 带超时读取(读取数据, 1500);
      if (!超时 && value && value[0] === 0x16) {
        TCP接口.close();
        return [true, `第${i + 1}次验证有效`, Math.round(performance.now() - 开始时间)];
      }
      throw new Error("Invalid TLS response");
    } catch (e) { 最后错误 = e.message; } finally { if (TCP接口) TCP接口.close(); }
    await new Promise(r => setTimeout(r, 100));
  }
  return [false, 最后错误, -1];
}

function 构建TLS握手() {
  const hex = '16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6d';
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function 带超时连接({ hostname, port }, ms) {
  const socket = connect({ hostname, port });
  await Promise.race([socket.opened, new Promise((_, r) => setTimeout(() => r("Connect Timeout"), ms))]);
  return socket;
}

function 带超时读取(reader, ms) {
  return new Promise(res => {
    const t = setTimeout(() => res({ 超时: true }), ms);
    reader.read().then(v => { clearTimeout(t); res({ ...v, 超时: false }); });
  });
}

async function nginx() {
  return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>`;
}

// HTML 界面部分
async function HTML(hostname, 网站图标, token) {
  const html = \`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset=\"UTF-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
  <title>Check ProxyIP</title>
  <link rel=\"icon\" href=\"\${网站图标}\">
  <style>
    :root { --primary-color: #3498db; --bg-secondary: #f8f9fa; --text-primary: #2c3e50; }
    body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; padding: 20px; color: var(--text-primary); }
    .container { max-width: 1000px; margin: 0 auto; }
    .card { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.15); margin-bottom: 32px; }
    .input-group { display: flex; gap: 16px; margin-top: 20px; }
    .form-input { flex: 1; padding: 16px; border: 2px solid #dee2e6; border-radius: 8px; font-size: 16px; }
    .btn-primary { padding: 16px 32px; background: var(--primary-color); color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; }
    #result { margin-top: 32px; display: none; }
    .result-card { border-radius: 8px; padding: 24px; border-left: 4px solid; margin-bottom: 16px; }
    .result-success { background: #d4edda; border-color: #2ecc71; color: #155724; }
    .result-error { background: #f8d7da; border-color: #e74c3c; color: #721c24; }
    .tag { padding: 4px 8px; border-radius: 16px; font-size: 12px; background: #e3f2fd; color: #1976d2; margin-right: 8px; }
  </style>
</head>
<body>
  <div class=\"container\">
    <h1 style=\"color:white; text-align:center; margin-bottom:40px;\">Check ProxyIP</h1>
    <div class=\"card\">
      <label class=\"form-label\">🔍 输入 ProxyIP 地址</label>
      <div class=\"input-group\">
        <input type=\"text\" id=\"proxyip\" class=\"form-input\" placeholder=\"例如: 1.2.3.4:443 或 example.com\">
        <button class=\"btn-primary\" onclick=\"checkProxyIP()\">检测</button>
      </div>
      <div id=\"result\"></div>
    </div>
  </div>

  <script>
    const token = \"\${token}\";
    async function checkProxyIP() {
      const input = document.getElementById('proxyip').value.trim();
      const resDiv = document.getElementById('result');
      if(!input) return;
      resDiv.innerHTML = \"检测中...\"; resDiv.style.display = \"block\";
      
      try {
        const r = await fetch(\`./check?proxyip=\${encodeURIComponent(input)}&token=\${token}\`);
        const data = await r.json();
        if(data.success) {
          const infoR = await fetch(\`./ip-info?ip=\${data.proxyIP}&token=\${token}\`);
          const info = await infoR.json();
          resDiv.innerHTML = \`<div class=\"result-card result-success\">
            <h3>✅ ProxyIP 有效</h3>
            <p>IP: \${data.proxyIP} [\${data.responseTime}ms]</p>
            <p><span class=\"tag\">\${info.country || '未知'}</span><span class=\"tag\">\${info.as || ''}</span></p>
          </div>\`;
        } else {
          resDiv.innerHTML = \`<div class=\"result-card result-error\"><h3>❌ ProxyIP 失效</h3><p>\${data.message}</p></div>\`;
        }
      } catch(e) { resDiv.innerHTML = \"检测失败: \" + e.message; }
    }
  </script>
</body>
</html>\`;
  return new Response(html, { headers: { \"content-type\": \"text/html;charset=UTF-8\" } });
}
