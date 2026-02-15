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
      // === TOKEN 传参访问逻辑 (核心修复) ===
      else if (env.TOKEN && url.searchParams.get('token') !== 永久TOKEN) {
        return new Response(await nginx(), {
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
          },
        });
      } else if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(网站图标, 302);
      }
      // 直接返回HTML页面，传递永久TOKEN
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
        return [true, `验证有效`, Math.round(performance.now() - 开始时间)];
      }
      throw new Error("Invalid TLS response");
    } catch (e) { 最后错误 = e.message; } finally { if (TCP接口) TCP接口.close(); }
    await new Promise(r => setTimeout(r, 100));
  }
  return [false, 最后错误, -1];
}

function 构建TLS握手() {
  const hex = '16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6dff01000100002b0007061a1a03040303003304ef04edcaca00010011ec04c05eac5510812e46c13826d28279b13ce62b6464e01ae1bb6d49640e57fb3191c656c4b0167c246930699d4f467c19d60dacaa86933a49e5c97390c3249db33c1aa59f47205701419461569cb01a22b4378f5f3bb21d952700f250a6156841f2cc952c75517a481112653400913f9ab58982a3f2d0010aba5ae99a2d69f6617a4220cd616de58ccbf5d10c5c68150152b60e2797521573b10413cb7a3aab25409d426a5b64a9f3134e01dc0dd0fc1a650c7aafec00ca4b4dddb64c402252c1c69ca347bb7e49b52b214a7768657a808419173bcbea8aa5a8721f17c82bc6636189b9ee7921faa76103695a638585fe678bcbb8725831900f808863a74c52a1b2caf61f1dec4a9016261c96720c221f45546ce0e93af3276dd090572db778a865a07189ae4f1a64c6dbaa25a5b71316025bd13a6012994257929d199a7d90a59285c75bd4727a8c93484465d62379cd110170073aad2a3fd947087634574315c09a7ccb60c301d59a7c37a330253a994a6857b8556ce0ac3cda4c6fe3855502f344c0c8160313a3732bce289b6bda207301e7b318277331578f370ccbcd3730890b552373afeb162c0cb59790f79559123b2d437308061608a704626233d9f73d18826e27f1c00157b792460eda9b35d48b4515a17c6125bdb96b114503c99e7043b112a398888318b956a012797c8a039a51147b8a58071793c14a3611fb0424e865f48a61cac7c43088c634161cea089921d229e1a370effc5eff2215197541394854a201a6ebf74942226573bb95710454bd27a52d444690837d04611b676269873c50c3406a79077e6606478a841f96f7b076a2230fd34f3eea301b77bf00750c28357a9df5b04f192b9c0bbf4f71891f1842482856b021280143ae74356c5e6a8e3273893086a90daa7a92426d8c370a45e3906994b8fa7a57d66b503745521e40948e83641de2a751b4a836da54f2da413074c3d856c954250b5c8332f1761e616437e527c0840bc57d522529b9259ccac34d7a3888f0aade0a66c392458cc1a698443052413217d29fbb9a1124797638d76100f82807934d58f30fcff33197fc171cfa3b0daa7f729591b1d7389ad476fde2328af74effd946265b3b81fa33066923db476f71babac30b590e05a7ba2b22f86925abca7ef8058c2481278dd9a240c8816bba6b5e6603e30670dffa7e6e3b995b0b18ec404614198a43a07897d84b439878d179c7d6895ac3f42ecb7998d4491060d2b8a5316110830c3f20a3d9a488a85976545917124c1eb6eb7314ea9696712b7bcab1cfd2b66e5a85106b2f651ab4b8a145e18ac41f39a394da9f327c5c92d4a297a0c94d1b8dcc3b111a700ac8d81c45f983ca029fd2887ad4113c7a23badf807c6d0068b4fa7148402aae15cc55971b57669a4840a22301caaec392a6ea6d46dab63890594d41545ebc2267297e3f4146073814bb3239b3e566684293b9732894193e71f3b388228641bb8be6f5847abb9072d269cb40b353b6aa3259ccb7e438d6a37ffa8cc1b7e4911575c41501321769900d19792aa3cfbe58b0aaf91c91d3b63900697279ad6c1aa44897a07d937e0d5826c24439420ca5d8a63630655ce9161e58d286fc885fcd9b19d096080225d16c89939a24aa1e98632d497b5604073b13f65bdfddc1de4b40d2a829b0521010c5f0f241b1ccc759049579db79983434fac2748829b33f001d0020a8e86c9d3958e0257c867e59c8082238a1ea0a9f2cac9e41f9b3cb0294f34b484a4a000100002900eb00c600c0afc8dade37ae62fa550c8aa50660d8e73585636748040b8e01d67161878276b1ec1ee2aff7614889bb6a36d2bdf9ca097ff6d7bf05c4de1d65c2b8db641f1c8dfbd59c9f7e0fed0b8e0394567eda55173d198e9ca40883b291ab4cada1a91ca8306ca1c37e047ebfe12b95164219b06a24711c2182f5e37374d43c668d45a3ca05eda90e90e510e628b4cfa7ae880502dae9a70a8eced26ad4b3c2f05d77f136cfaa622e40eb084dd3eb52e23a9aeff6ae9018100af38acfd1f6ce5d8c53c4a61c547258002120fe93e5c7a5c9c1a04bf06858c4dd52b01875844e15582dd566d03f41133183a0';
  return new Uint8Array(hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function 带超时连接({ hostname, port }, ms) {
  const socket = connect({ hostname, port });
  await Promise.race([socket.opened, new Promise((_, r) => setTimeout(() => r("Timeout"), ms))]);
  return socket;
}

function 带超时读取(reader, ms) {
  return new Promise(res => {
    const t = setTimeout(() => res({ 超时: true }), ms);
    reader.read().then(v => { clearTimeout(t); res({ ...v, 超时: false }); });
  });
}

async function nginx() {
  const text = `
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    <style>
        body {
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }
    </style>
    </head>
    <body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and
    working. Further configuration is required.</p>
    
    <p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.<br/>
    Commercial support is available at
    <a href="http://nginx.com/">nginx.com</a>.</p>
    
    <p><em>Thank you for using nginx.</em></p>
    </body>
    </html>
    `
  return text;
}

// 修改 HTML 函数，接收 token 参数
async function HTML(hostname, 网站图标, token) {
  // 首页 HTML
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Check ProxyIP</title>
  <link rel="icon" href="${网站图标}">
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
  <div class="container">
    <h1 style="color:white; text-align:center; margin-bottom:40px;">Check ProxyIP</h1>
    <div class="card">
      <label class="form-label">🔍 输入 ProxyIP 地址</label>
      <div class="input-group">
        <input type="text" id="proxyip" class="form-input" placeholder="例如: 1.2.3.4:443 或 example.com">
        <button class="btn-primary" onclick="checkProxyIP()">检测</button>
      </div>
      <div id="result"></div>
    </div>
  </div>

  <script>
    const token = "${token}";
    async function checkProxyIP() {
      const input = document.getElementById('proxyip').value.trim();
      const resDiv = document.getElementById('result');
      if(!input) return;
      resDiv.innerHTML = "检测中..."; resDiv.style.display = "block";
      try {
        const r = await fetch(\`./check?proxyip=\${encodeURIComponent(input)}&token=\${token}\`);
        const data = await r.json();
        if(data.success) {
          const infoR = await fetch(\`./ip-info?ip=\${data.proxyIP}&token=\${token}\`);
          const info = await infoR.json();
          resDiv.innerHTML = \`<div class="result-card result-success">
            <h3>✅ ProxyIP 有效</h3>
            <p>IP: \${data.proxyIP} [\${data.responseTime}ms]</p>
            <p><span class="tag">\${info.country || '未知'}</span><span class="tag">\${info.as || ''}</span></p>
          </div>\`;
        } else {
          resDiv.innerHTML = \`<div class="result-card result-error"><h3>❌ ProxyIP 失效</h3><p>\${data.message}</p></div>\`;
        }
      } catch(e) { resDiv.innerHTML = "检测失败: " + e.message; }
    }
  </script>
</body>
</html>`;
  return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8" } });
}
