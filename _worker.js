import { connect } from "cloudflare:sockets";

// 全局变量 (来自 _worker.js)
let 临时TOKEN, 永久TOKEN;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const UA = request.headers.get('User-Agent') || 'null';
    const hostname = url.hostname;
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); // 每31分钟一个时间戳
    
    // 生成 Token (_worker.js 逻辑)
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    // --- 来自 a_worker.js 的后端 API 接口 ---

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

    // 2. 地理位置查询 (修复版：使用 ipwho.is)
    if (path === '/api/geoip') {
      const target = url.searchParams.get('target');
      if (!target) return new Response('Missing target', { status: 400 });
      try {
        const response = await fetch(`https://ipwho.is/${target}?lang=zh-CN`);
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'fail' }), { status: 500 });
      }
    }

    // 3. 域名解析 (来自 a_worker.js)
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

    // --- 来自 _worker.js 的功能路由 (全部保留，路径不变) ---

    // /check 路由 - ProxyIP检测
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

      const proxyIP = url.searchParams.get('proxyip').toLowerCase();
      const colo = request.cf?.colo || 'CF';
      const result = await CheckProxyIP(proxyIP, colo);

      return new Response(JSON.stringify(result, null, 2), {
        status: result.success ? 200 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });
    }

    // /resolve 路由 - 域名解析 (来自 _worker.js，注意与上面的 /api/resolve 区分)
    if (path.toLowerCase() === '/resolve') {
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
        const ips = await resolveDomainForWorker(domain); // 使用专门为 _worker.js 准备的解析函数
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
    }

    // /ip-info 路由 - IP信息查询
    if (path.toLowerCase() === '/ip-info') {
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
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();
        data.timestamp = new Date().toISOString();

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
    }

    // 处理其他路径 (来自 _worker.js 的 fallback 逻辑)
    const envKey = env.URL302 ? 'URL302' : (env.URL ? 'URL' : null);
    if (envKey) {
      const URLs = await 整理(env[envKey]);
      const URL = URLs[Math.floor(Math.random() * URLs.length)];
      return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request));
    } else if (env.TOKEN) {
      return new Response(await nginx(), {
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
        },
      });
    } else if (path.toLowerCase() === '/favicon.ico') {
      const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
      return Response.redirect(网站图标, 302);
    }

    // 默认返回 _worker.js 的 HTML 页面
    const currentColo = request.cf?.colo || '未知';
    const currentCity = request.cf?.city || '未知';
    const currentCountry = request.cf?.country || '未知';
    const currentIP = request.headers.get('CF-Connecting-IP') || '未知';
    const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';

    // 根据是否有 TOKEN 返回不同的页面
    if (env.TOKEN) {
      return new Response(await nginx(), {
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
        },
      });
    }
    
    // 返回 _worker.js 的 HTML 页面
    return await HTML(hostname, 网站图标, 临时TOKEN, currentColo, currentCity, currentCountry, currentIP);
  }
};

// ============================================
// 来自 a_worker.js 的辅助函数
// ============================================

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

// ============================================
// 来自 _worker.js 的辅助函数 (全部保留，函数名保持原样)
// ============================================

// 专门为 _worker.js 的 /resolve 路由准备的解析函数
async function resolveDomainForWorker(domain) {
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

      const [ipv4Data, ipv6Data] = await Promise.all([
        ipv4Res.json(),
        ipv6Res.json()
      ]);

      const ips = [];
      
      if (ipv4Data.Answer) {
        ipv4Data.Answer.filter(r => r.type === 1).forEach(r => ips.push(r.data));
      }
      if (ipv6Data.Answer) {
        ipv6Data.Answer.filter(r => r.type === 28).forEach(r => ips.push(`[${r.data}]`));
      }

      if (ips.length > 0) return ips;
      
    } catch (error) {
      console.warn(`${endpoint.name} 解析失败，尝试下一个...`, error);
      continue;
    }
  }

  throw new Error('无法解析域名: 所有 DNS 服务均未返回有效 IP');
}

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

  const tcpSocket = connect({
    hostname: proxyIP,
    port: portRemote,
  });

  try {
    const httpRequest =
      "GET /cdn-cgi/trace HTTP/1.1\r\n" +
      "Host: speed.cloudflare.com\r\n" +
      "User-Agent: CheckProxyIP/cmliu\r\n" +
      "Connection: close\r\n\r\n";

    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    let receivedData = false;

    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000))
      ]);

      if (done) break;
      if (value) {
        receivedData = true;
        const newData = new Uint8Array(responseData.length + value.length);
        newData.set(responseData);
        newData.set(value, responseData.length);
        responseData = newData;

        const responseText = new TextDecoder().decode(responseData);
        if (responseText.includes("\r\n\r\n") &&
          (responseText.includes("Connection: close") || responseText.includes("content-length"))) {
          break;
        }
      }
    }
    reader.releaseLock();

    const responseText = new TextDecoder().decode(responseData);
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;

    function isValidProxyResponse(responseText, responseData) {
      const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
      const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;
      const looksLikeCloudflare = responseText.includes("cloudflare") && responseText.includes("CF-RAY");
      const isExpectedError = responseText.includes("The plain HTTP request was sent to HTTPS port") && responseText.includes("400 Bad Request");
      const hasBody = responseData.length > 100;

      return statusCode !== null && looksLikeCloudflare && isExpectedError && hasBody;
    }
    
    await tcpSocket.close();

    const isSuccessful = isValidProxyResponse(responseText, responseData);
    if (isSuccessful) {
      console.log(`成功通过ProxyIP ${proxyIP}:${portRemote} 连接到Cloudflare，状态码: ${statusCode}`);
      const tls握手 = await 验证反代IP(proxyIP, portRemote);

      return {
        success: tls握手[0],
        proxyIP: proxyIP,
        portRemote: portRemote,
        colo: colo,
        responseTime: tls握手[2] ? tls握手[2] : -1,
        message: tls握手[1],
        timestamp: new Date().toISOString(),
      };
    } else {
      console.log(`无法通过ProxyIP ${proxyIP}:${portRemote} 访问Cloudflare`);
      return {
        success: false,
        proxyIP: proxyIP,
        portRemote: portRemote,
        colo: colo,
        responseTime: -1,
        message: "无法通过ProxyIP访问Cloudflare",
        timestamp: new Date().toISOString()
      };
    }
  } catch (error) {
    return {
      success: false,
      proxyIP: -1,
      portRemote: -1,
      colo: colo,
      responseTime: -1,
      message: error.message || error.toString(),
      timestamp: new Date().toISOString()
    };
  }
}

async function 整理(内容) {
  var 替换后的内容 = 内容.replace(/[\r\n]+/g, '|').replace(/\|+/g, '|');
  const 地址数组 = 替换后的内容.split('|');
  const 整理数组 = 地址数组.filter((item, index) => {
    return item !== '' && 地址数组.indexOf(item) === index;
  });
  return 整理数组;
}

async function 双重哈希(文本) {
  const 编码器 = new TextEncoder();
  const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
  const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
  const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
  const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
  const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
  const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
  return 第二次十六进制.toLowerCase();
}

async function 验证反代IP(反代IP地址, 指定端口) {
  const 最大重试次数 = 4;
  let 最后错误 = null;
  const 开始时间 = performance.now();
  
  for (let 重试次数 = 0; 重试次数 < 最大重试次数; 重试次数++) {
    let TCP接口 = null;
    let 传输数据 = null;
    let 读取数据 = null;

    try {
      const 连接超时 = 1000 + (重试次数 * 500);
      TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 指定端口 }, 连接超时);

      传输数据 = TCP接口.writable.getWriter();
      读取数据 = TCP接口.readable.getReader();

      await 传输数据.write(构建TLS握手());

      const 读取超时 = 连接超时;
      const { value: 返回数据, 超时 } = await 带超时读取(读取数据, 读取超时);

      if (超时) {
        最后错误 = `第${重试次数 + 1}次重试：读取响应超时`;
        throw new Error(最后错误);
      }

      if (!返回数据 || 返回数据.length === 0) {
        最后错误 = `第${重试次数 + 1}次重试：未收到任何响应数据`;
        throw new Error(最后错误);
      }

      if (返回数据[0] === 0x16) {
        try {
          读取数据.cancel();
          TCP接口.close();
        } catch (cleanupError) {
          console.log('清理资源时出错:', cleanupError);
        }
        return [true, `第${重试次数 + 1}次验证有效ProxyIP`, Math.round(performance.now() - 开始时间)];
      } else {
        最后错误 = `第${重试次数 + 1}次重试：收到非TLS响应(0x${返回数据[0].toString(16).padStart(2, '0')})`;
        throw new Error(最后错误);
      }

    } catch (error) {
      最后错误 = `第${重试次数 + 1}次重试失败: ${error.message || error.toString()}`;
      const 错误信息 = error.message || error.toString();
      const 不应重试的错误 = [
        '连接被拒绝', 'Connection refused', '网络不可达', 'Network unreachable', '主机不可达', 'Host unreachable'
      ];

      if (不应重试的错误.some(p => 错误信息.toLowerCase().includes(p.toLowerCase()))) {
        最后错误 = `连接失败，无需重试: ${错误信息}`;
        break;
      }

    } finally {
      try {
        if (读取数据) 读取数据.cancel();
        if (TCP接口) TCP接口.close();
      } catch (cleanupError) {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (重试次数 < 最大重试次数 - 1) {
      const 等待时间 = 200 + (重试次数 * 300);
      await new Promise(resolve => setTimeout(resolve, 等待时间));
    }
  }
  return [false, 最后错误 || '连接验证失败', -1];
}

function 构建TLS握手() {
  const hexStr =
    '16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6dff01000100002b0007061a1a03040303003304ef04edcaca00010011ec04c05eac5510812e46c13826d28279b13ce62b6464e01ae1bb6d49640e57fb3191c656c4b0167c246930699d4f467c19d60dacaa86933a49e5c97390c3249db33c1aa59f47205701419461569cb01a22b4378f5f3bb21d952700f250a6156841f2cc952c75517a481112653400913f9ab58982a3f2d0010aba5ae99a2d69f6617a4220cd616de58ccbf5d10c5c68150152b60e2797521573b10413cb7a3aab25409d426a5b64a9f3134e01dc0dd0fc1a650c7aafec00ca4b4dddb64c402252c1c69ca347bb7e49b52b214a7768657a808419173bcbea8aa5a8721f17c82bc6636189b9ee7921faa76103695a638585fe678bcbb8725831900f808863a74c52a1b2caf61f1dec4a9016261c96720c221f45546ce0e93af3276dd090572db778a865a07189ae4f1a64c6dbaa25a5b71316025bd13a6012994257929d199a7d90a59285c75bd4727a8c93484465d62379cd110170073aad2a3fd947087634574315c09a7ccb60c301d59a7c37a330253a994a6857b8556ce0ac3cda4c6fe3855502f344c0c8160313a3732bce289b6bda207301e7b318277331578f370ccbcd3730890b552373afeb162c0cb59790f79559123b2d437308061608a704626233d9f73d18826e27f1c00157b792460eda9b35d48b4515a17c6125bdb96b114503c99e7043b112a398888318b956a012797c8a039a51147b8a58071793c14a3611fb0424e865f48a61cac7c43088c634161cea089921d229e1a370effc5eff2215197541394854a201a6ebf74942226573bb95710454bd27a52d444690837d04611b676269873c50c3406a79077e6606478a841f96f7b076a2230fd34f3eea301b77bf00750c28357a9df5b04f192b9c0bbf4f71891f1842482856b021280143ae74356c5e6a8e3273893086a90daa7a92426d8c370a45e3906994b8fa7a57d66b503745521e40948e83641de2a751b4a836da54f2da413074c3d856c954250b5c8332f1761e616437e527c0840bc57d522529b9259ccac34d7a3888f0aade0a66c392458cc1a698443052413217d29fbb9a1124797638d76100f82807934d58f30fcff33197fc171cfa3b0daa7f729591b1d7389ad476fde2328af74effd946265b3b81fa33066923db476f71babac30b590e05a7ba2b22f86925abca7ef8058c2481278dd9a240c8816bba6b5e6603e30670dffa7e6e3b995b0b18ec404614198a43a07897d84b439878d179c7d6895ac3f42ecb7998d4491060d2b8a5316110830c3f20a3d9a488a85976545917124c1eb6eb7314ea9696712b7bcab1cfd2b66e5a85106b2f651ab4b8a145e18ac41f39a394da9f327c5c92d4a297a0c94d1b8dcc3b111a700ac8d81c45f983ca029fd2887ad4113c7a23badf807c6d0068b4fa7148402aae15cc55971b57669a4840a22301caaec392a6ea6d46dab63890594d41545ebc2267297e3f4146073814bb3239b3e566684293b9732894193e71f3b388228641bb8be6f5847abb9072d269cb40b353b6aa3259ccb7e438d6a37ffa8cc1b7e4911575c41501321769900d19792aa3cfbe58b0aaf91c91d3b63900697279ad6c1aa44897a07d937e0d5826c24439420ca5d8a63630655ce9161e58d286fc885fcd9b19d096080225d16c89939a24aa1e98632d497b5604073b13f65bdfddc1de4b40d2a829b0521010c5f0f241b1ccc759049579db79983434fac2748829b33f001d0020a8e86c9d3958e0257c867e59c8082238a1ea0a9f2cac9e41f9b3cb0294f34b484a4a000100002900eb00c600c0afc8dade37ae62fa550c8aa50660d8e73585636748040b8e01d67161878276b1ec1ee2aff7614889bb6a36d2bdf9ca097ff6d7bf05c4de1d65c2b8db641f1c8dfbd59c9f7e0fed0b8e0394567eda55173d198e9ca40883b291ab4cada1a91ca8306ca1c37e047ebfe12b95164219b06a24711c2182f5e37374d43c668d45a3ca05eda90e90e510e628b4cfa7ae880502dae9a70a8eced26ad4b3c2f05d77f136cfaa622e40eb084dd3eb52e23a9aeff6ae9018100af38acfd1f6ce5d8c53c4a61c547258002120fe93e5c7a5c9c1a04bf06858c4dd52b01875844e15582dd566d03f41133183a0';
  return new Uint8Array(hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function 带超时连接({ hostname, port }, 超时时间) {
  const TCP接口 = connect({ hostname, port });
  try {
    await Promise.race([
      TCP接口.opened,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("连接超时")), 超时时间)
      ),
    ]);
    return TCP接口; 
  } catch (err) {
    TCP接口.close?.(); 
    throw err; 
  }
}

function 带超时读取(reader, 超时) {
  return new Promise(resolve => {
    const timeoutId = setTimeout(() => resolve({ done: true, value: null, 超时: true }), 超时);
    reader.read().then(result => {
      clearTimeout(timeoutId);
      resolve({ ...result, 超时: false });
    });
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
    `;
  return text;
}

// 修改 HTML 函数，接收 token 和其他参数
async function HTML(hostname, 网站图标, token, colo, city, country, ip) {
  // 首页 HTML - 合并两个页面的内容，并添加 Link Tracer 的入口
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Check ProxyIP & Link Tracer - 综合网络工具</title>
  <link rel="icon" href="${网站图标}" type="image/x-icon">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary-color: #3498db;
      --primary-dark: #2980b9;
      --secondary-color: #1abc9c;
      --success-color: #2ecc71;
      --warning-color: #f39c12;
      --error-color: #e74c3c;
      --bg-primary: #ffffff;
      --bg-secondary: #f8f9fa;
      --bg-tertiary: #e9ecef;
      --text-primary: #2c3e50;
      --text-secondary: #6c757d;
      --text-light: #adb5bd;
      --border-color: #dee2e6;
      --shadow-sm: 0 2px 4px rgba(0,0,0,0.1);
      --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
      --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
      --border-radius: 12px;
      --border-radius-sm: 8px;
      --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: var(--text-primary);
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
    }
    
    .container {
      max-width: 1000px;
      margin: 0 auto;
      padding: 20px;
    }
    
    .header {
      text-align: center;
      margin-bottom: 50px;
      animation: fadeInDown 0.8s ease-out;
    }
    
    .main-title {
      font-size: clamp(2.5rem, 5vw, 4rem);
      font-weight: 700;
      background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 16px;
      text-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    
    .subtitle {
      font-size: 1.2rem;
      color: rgba(255,255,255,0.9);
      font-weight: 400;
      margin-bottom: 8px;
    }
    
    .badge {
      display: inline-block;
      background: rgba(255,255,255,0.2);
      backdrop-filter: blur(10px);
      padding: 8px 16px;
      border-radius: 50px;
      color: white;
      font-size: 0.9rem;
      font-weight: 500;
      border: 1px solid rgba(255,255,255,0.3);
    }
    
    .card {
      background: var(--bg-primary);
      border-radius: var(--border-radius);
      padding: 32px;
      box-shadow: var(--shadow-lg);
      margin-bottom: 32px;
      border: 1px solid var(--border-color);
      transition: var(--transition);
      animation: fadeInUp 0.8s ease-out;
      backdrop-filter: blur(20px);
      position: relative;
      overflow: hidden;
    }
    
    .card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
    }
    
    .card:hover {
      transform: translateY(-4px);
      box-shadow: 0 20px 40px rgba(0,0,0,0.15);
    }
    
    .local-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      background: rgba(6, 182, 212, 0.1);
      padding: 15px;
      border-radius: 12px;
      border: 1px solid rgba(6, 182, 212, 0.2);
      margin-bottom: 25px;
    }
    
    .info-item label {
      display: block;
      font-size: 12px;
      opacity: 0.7;
      margin-bottom: 4px;
      color: var(--text-primary);
    }
    
    .info-item span {
      font-weight: 600;
      font-size: 15px;
      color: var(--primary-color);
    }
    
    .form-section {
      margin-bottom: 32px;
    }
    
    .form-label {
      display: block;
      font-weight: 600;
      font-size: 1.1rem;
      margin-bottom: 12px;
      color: var(--text-primary);
    }
    
    .input-group {
      display: flex;
      gap: 16px;
      align-items: flex-end;
      flex-wrap: wrap;
    }
    
    .input-wrapper {
      flex: 1;
      min-width: 300px;
      position: relative;
    }
    
    .form-input {
      width: 100%;
      padding: 16px 20px;
      border: 2px solid var(--border-color);
      border-radius: var(--border-radius-sm);
      font-size: 16px;
      font-family: inherit;
      transition: var(--transition);
      background: var(--bg-primary);
      color: var(--text-primary);
    }
    
    .form-input:focus {
      outline: none;
      border-color: var(--primary-color);
      box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.1);
      transform: translateY(-1px);
    }
    
    .form-input::placeholder {
      color: var(--text-light);
    }
    
    textarea {
      width: 100%;
      height: 100px;
      background: var(--bg-primary);
      border: 2px solid var(--border-color);
      color: var(--text-primary);
      padding: 15px;
      border-radius: var(--border-radius-sm);
      font-family: monospace;
      resize: vertical;
      box-sizing: border-box;
      outline: none;
      transition: var(--transition);
      font-size: 14px;
    }
    
    textarea:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.1);
    }
    
    .btn {
      padding: 16px 32px;
      border: none;
      border-radius: var(--border-radius-sm);
      font-size: 16px;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      transition: var(--transition);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      min-width: 120px;
      position: relative;
      overflow: hidden;
    }
    
    .btn::before {
      content: "";
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.6s;
    }
    
    .btn:hover::before {
      left: 100%;
    }
    
    .btn-primary {
      background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
      color: white;
      box-shadow: var(--shadow-md);
    }
    
    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(52, 152, 219, 0.3);
    }
    
    .btn-ghost {
      background: var(--bg-tertiary);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
    }
    
    .btn-ghost:hover {
      background: var(--bg-secondary);
    }
    
    .btn-primary:active {
      transform: translateY(0);
    }
    
    .btn-primary:disabled {
      background: var(--text-light);
      cursor: not-allowed;
      transform: none;
      box-shadow: var(--shadow-sm);
    }
    
    .btn-loading {
      pointer-events: none;
    }
    
    .loading-spinner {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top: 2px solid white;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    
    .loading-spin {
      display: inline-block;
      width: 12px;
      height: 12px;
      border: 2px solid var(--primary-color);
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .result-section {
      margin-top: 32px;
      opacity: 0;
      transform: translateY(20px);
      transition: var(--transition);
    }
    
    .result-section.show {
      opacity: 1;
      transform: translateY(0);
    }
    
    .result-card {
      border-radius: var(--border-radius-sm);
      padding: 24px;
      margin-bottom: 16px;
      border-left: 4px solid;
      position: relative;
      overflow: hidden;
    }
    
    .result-success {
      background: linear-gradient(135deg, #d4edda, #c3e6cb);
      border-color: var(--success-color);
      color: #155724;
    }
    
    .result-error {
      background: linear-gradient(135deg, #f8d7da, #f5c6cb);
      border-color: var(--error-color);
      color: #721c24;
    }
    
    .result-warning {
      background: linear-gradient(135deg, #fff3cd, #ffeaa7);
      border-color: var(--warning-color);
      color: #856404;
    }
    
    .ip-grid {
      display: grid;
      gap: 16px;
      margin-top: 20px;
    }
    
    .ip-item {
      background: rgba(255,255,255,0.9);
      border: 1px solid var(--border-color);
      border-radius: var(--border-radius-sm);
      padding: 20px;
      transition: var(--transition);
      position: relative;
    }
    
    .ip-item:hover {
      transform: translateY(-2px);
      box-shadow: var(--shadow-md);
    }
    
    .ip-status-line {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    
    .status-icon {
      font-size: 18px;
      margin-left: auto;
    }
    
    .copy-btn {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 14px;
      cursor: pointer;
      transition: var(--transition);
      display: inline-flex;
      align-items: center;
      gap: 4px;
      margin: 4px 0;
    }
    
    .copy-btn:hover {
      background: var(--primary-color);
      color: white;
      border-color: var(--primary-color);
    }
    
    .copy-btn.copied {
      background: var(--success-color);
      color: white;
      border-color: var(--success-color);
    }
    
    .info-tags {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
    
    .tag {
      padding: 4px 8px;
      border-radius: 16px;
      font-size: 12px;
      font-weight: 500;
    }
    
    .tag-country {
      background: #e3f2fd;
      color: #1976d2;
    }
    
    .tag-as {
      background: #f3e5f5;
      color: #7b1fa2;
    }
    
    .history {
      margin-top: 15px;
      display: flex;
      gap: 8px;
      overflow-x: auto;
      padding-bottom: 5px;
    }
    
    .tag {
      background: var(--bg-tertiary);
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      cursor: pointer;
      white-space: nowrap;
      border: 1px solid var(--border-color);
      color: var(--text-primary);
    }
    
    .tag:hover {
      border-color: var(--primary-color);
      color: var(--primary-color);
    }
    
    .table-container {
      overflow-x: auto;
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
      font-size: 14px;
      min-width: 600px;
    }
    
    th {
      text-align: left;
      padding: 12px;
      color: var(--primary-color);
      border-bottom: 2px solid var(--border-color);
      font-weight: 600;
    }
    
    td {
      padding: 12px;
      border-bottom: 1px solid var(--border-color);
      vertical-align: middle;
    }
    
    .rtt-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: bold;
      font-size: 13px;
    }
    
    .rtt-green {
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
    }
    
    .rtt-yellow {
      background: rgba(245, 158, 11, 0.2);
      color: #fbbf24;
    }
    
    .rtt-red {
      background: rgba(239, 68, 68, 0.2);
      color: #f87171;
    }
    
    .target-sub {
      font-size: 12px;
      opacity: 0.6;
      display: block;
      margin-top: 2px;
    }
    
    .type-label {
      font-size: 10px;
      opacity: 0.4;
      margin-left: 4px;
      border: 1px solid var(--border-color);
      padding: 0 2px;
    }
    
    .api-docs {
      background: var(--bg-primary);
      border-radius: var(--border-radius);
      padding: 32px;
      box-shadow: var(--shadow-lg);
      animation: fadeInUp 0.8s ease-out 0.2s both;
    }
    
    .section-title {
      font-size: 1.8rem;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 24px;
      position: relative;
      padding-bottom: 12px;
    }
    
    .section-title::after {
      content: "";
      position: absolute;
      bottom: 0;
      left: 0;
      width: 60px;
      height: 3px;
      background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
      border-radius: 2px;
    }
    
    .code-block {
      background: #2d3748;
      color: #e2e8f0;
      padding: 20px;
      border-radius: var(--border-radius-sm);
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 14px;
      overflow-x: auto;
      margin: 16px 0;
      border: 1px solid #4a5568;
      position: relative;
    }
    
    .code-block::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, #48bb78, #38b2ac);
    }
    
    .highlight {
      color: #f56565;
      font-weight: 600;
    }
    
    .footer {
      text-align: center;
      padding: 20px 20px 20px;
      color: rgba(255,255,255,0.8);
      font-size: 14px;
      margin-top: 40px;
      border-top: 1px solid rgba(255,255,255,0.1);
    }
    
    .github-corner {
      position: fixed;
      top: 0;
      right: 0;
      z-index: 1000;
      transition: var(--transition);
    }
    
    .github-corner:hover {
      transform: scale(1.1);
    }
    
    .github-corner svg {
      fill: rgba(255,255,255,0.9);
      color: var(--primary-color);
      width: 80px;
      height: 80px;
      filter: drop-shadow(0 4px 8px rgba(0,0,0,0.1));
    }
    
    @keyframes fadeInDown {
      from {
        opacity: 0;
        transform: translateY(-30px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(30px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    @keyframes octocat-wave {
      0%, 100% { transform: rotate(0); }
      20%, 60% { transform: rotate(-25deg); }
      40%, 80% { transform: rotate(10deg); }
    }
    
    .github-corner:hover .octo-arm {
      animation: octocat-wave 560ms ease-in-out;
    }
    
    @media (max-width: 768px) {
      .container {
        padding: 16px;
      }
      
      .card {
        padding: 24px;
        margin-bottom: 24px;
      }
      
      .input-group {
        flex-direction: column;
        align-items: stretch;
      }
      
      .input-wrapper {
        min-width: auto;
      }
      
      .btn {
        width: 100%;
      }
      
      .github-corner svg {
        width: 60px;
        height: 60px;
      }
      
      .github-corner:hover .octo-arm {
        animation: none;
      }
      
      .github-corner .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
      }
      
      .main-title {
        font-size: 2.5rem;
      }
    }
    
    .toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--text-primary);
      color: white;
      padding: 12px 20px;
      border-radius: var(--border-radius-sm);
      box-shadow: var(--shadow-lg);
      transform: translateY(100px);
      opacity: 0;
      transition: var(--transition);
      z-index: 1000;
    }
    
    .toast.show {
      transform: translateY(0);
      opacity: 1;
    }
    
    .tooltip {
      position: relative;
      display: inline-block;
      cursor: help;
    }
    
    .tooltip .tooltiptext {
      visibility: hidden;
      width: 420px;
      background-color: #2c3e50;
      color: #fff;
      text-align: left;
      border-radius: 8px;
      padding: 12px 16px;
      position: fixed;
      z-index: 9999;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      opacity: 0;
      transition: opacity 0.3s;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      font-size: 14px;
      line-height: 1.4;
      font-weight: 400;
      border: 1px solid rgba(255,255,255,0.1);
      backdrop-filter: blur(10px);
      max-width: 90vw;
      max-height: 80vh;
      overflow-y: auto;
    }
    
    .tooltip .tooltiptext::after {
      display: none;
    }
    
    .tooltip:hover .tooltiptext {
      visibility: visible;
      opacity: 1;
    }
    
    @media (max-width: 768px) {
      .tooltip .tooltiptext {
        width: 90vw;
        max-width: 90vw;
        font-size: 13px;
        padding: 10px 12px;
      }
    }
    
    .tab-container {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 10px;
    }
    
    .tab {
      padding: 10px 20px;
      border-radius: var(--border-radius-sm) var(--border-radius-sm) 0 0;
      cursor: pointer;
      font-weight: 600;
      transition: var(--transition);
      background: var(--bg-secondary);
      color: var(--text-secondary);
      border: 1px solid var(--border-color);
      border-bottom: none;
    }
    
    .tab.active {
      background: var(--bg-primary);
      color: var(--primary-color);
      border-color: var(--primary-color);
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
  </style>
</head>
<body>
  <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>

  <div class="container">
    <header class="header">
      <h1 class="main-title">Check ProxyIP & Link Tracer</h1>
      <p class="subtitle">综合网络工具 - ProxyIP检测 / 链路追踪 / IP信息查询</p>
    </header>

    <div class="card">
      <div class="tab-container">
        <div class="tab active" onclick="switchTab('proxyip')">🔍 ProxyIP 检测</div>
        <div class="tab" onclick="switchTab('tracer')">📡 Link Tracer</div>
      </div>

      <div id="proxyip-tab" class="tab-content active">
        <div class="form-section">
          <label for="proxyip" class="form-label">🔍 输入 ProxyIP 地址</label>
          <div class="input-group">
            <div class="input-wrapper">
              <input type="text" id="proxyip" class="form-input" placeholder="例如: 1.2.3.4:443 或 example.com" autocomplete="off">
            </div>
            <button id="checkBtn" class="btn btn-primary" onclick="checkProxyIP()">
              <span class="btn-text">检测</span>
              <div class="loading-spinner" style="display: none;"></div>
            </button>
          </div>
        </div>
        
        <div id="result" class="result-section"></div>
      </div>

      <div id="tracer-tab" class="tab-content">
        <div class="local-bar">
          <div class="info-item"><label>当前节点 (Colo)</label><span>${colo}</span></div>
          <div class="info-item"><label>物理位置</label><span>${country} - ${city}</span></div>
          <div class="info-item"><label>本机 IP</label><span>${ip}</span></div>
        </div>
        <textarea id="input-area" placeholder="输入目标地址（支持域名或IP），一行一个..."></textarea>
        <div class="controls">
          <button class="btn btn-primary" onclick="startBatch()">🚀 开始探测</button>
          <button class="btn btn-ghost" onclick="document.getElementById('file-input').click()">📂 上传 TXT</button>
          <input type="file" id="file-input" accept=".txt" onchange="handleFile(this)" style="display:none;">
          <button class="btn btn-ghost" onclick="clearTable()">🗑️ 清空表格</button>
        </div>
        <div class="history" id="history-box"></div>
        <div id="result-panel" style="display:none;">
          <div class="table-container">
            <table>
              <thead><tr><th>目标地址 (Target)</th><th>TCP 延迟</th><th>物理位置</th><th>运营商 / 机房 (ISP)</th></tr></thead>
              <tbody id="result-body"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    
    <div class="api-docs" style="margin-top: 50px;">
      <h2 class="section-title">📚 API 文档</h2>
      <p style="margin-bottom: 24px; color: var(--text-secondary); font-size: 1.1rem;">
        提供简单易用的 RESTful API 接口，支持批量检测和域名解析
      </p>
      
      <h3 style="color: var(--text-primary); margin: 24px 0 16px;">📍 检查ProxyIP</h3>
      <div class="code-block">
        <strong style="color: #68d391;">GET</strong> /check?proxyip=<span class="highlight">YOUR_PROXY_IP</span>
      </div>
      
      <h3 style="color: var(--text-primary); margin: 24px 0 16px;">📍 TCP延迟检测</h3>
      <div class="code-block">
        <strong style="color: #68d391;">GET</strong> /api/tcping?target=<span class="highlight">1.2.3.4</span>&port=443
      </div>
      
      <h3 style="color: var(--text-primary); margin: 24px 0 16px;">📍 IP地理位置查询</h3>
      <div class="code-block">
        <strong style="color: #68d391;">GET</strong> /api/geoip?target=<span class="highlight">1.2.3.4</span>
      </div>
      
      <h3 style="color: var(--text-primary); margin: 24px 0 16px;">📍 域名解析</h3>
      <div class="code-block">
        <strong style="color: #68d391;">GET</strong> /api/resolve?domain=<span class="highlight">example.com</span>
      </div>
      
      <h3 style="color: var(--text-primary); margin: 24px 0 16px;">💡 使用示例</h3>
      <div class="code-block">
proxyip.hk.fxxk.dedyn.io<br>
proxyip.jp.fxxk.dedyn.io<br>
curl "https://${hostname}/check?proxyip=1.2.3.4:443"<br>
curl "https://${hostname}/check?proxyip=1.2.3.4:443&token=${token}"<br>
curl "https://${hostname}/api/tcping?target=1.2.3.4"<br>
curl "https://${hostname}/api/geoip?target=1.2.3.4"
      </div>

      <h3 style="color: var(--text-primary); margin: 24px 0 16px;">🔗 响应Json格式 (ProxyIP检测)</h3>
      <div class="code-block">
{<br>
&nbsp;&nbsp;"success": true|false, // 代理 IP 是否有效<br>
&nbsp;&nbsp;"proxyIP": "1.2.3.4", // 如果有效,返回代理 IP,否则为 -1<br>
&nbsp;&nbsp;"portRemote": 443, // 如果有效,返回端口,否则为 -1<br>
&nbsp;&nbsp;"colo": "HKG", // 执行此次请求的Cloudflare机房<br>
&nbsp;&nbsp;"responseTime": "166", // 如果有效,返回响应毫秒时间,否则为 -1<br>
&nbsp;&nbsp;"message": "第1次验证有效ProxyIP", // 返回验证信息<br>
&nbsp;&nbsp;"timestamp": "2025-06-03T17:27:52.946Z" // 检查时间<br>
}<br>
      </div>
    </div>
    
    <div class="footer">
      <p style="margin-top: 8px; opacity: 0.8;">© 2025 Check ProxyIP & Link Tracer - 基于 Cloudflare Workers 构建的综合网络工具 | 由 <strong>cmliu</strong> 开发</p>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    // 全局变量
    let isChecking = false;
    const ipCheckResults = new Map(); // 缓存IP检查结果
    let pageLoadTimestamp; // 页面加载时的时间戳
    const historyKey = 'tracer_history_v2';
    
    // 计算时间戳的函数
    function calculateTimestamp() {
      const currentDate = new Date();
      return Math.ceil(currentDate.getTime() / (1000 * 60 * 13)); // 每13分钟一个时间戳
    }
    
    // 添加前端的代理IP格式验证函数
    function isValidProxyIPFormat(input) {
      // 检查是否为域名格式
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$/;
      // 检查是否为IP格式
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;

      // 允许带端口的格式
      const withPortRegex = /^.+:\\d+$/;
      const tpPortRegex = /^.+\\.tp\\d+\\./;

      return domainRegex.test(input) ||
        ipv4Regex.test(input) ||
        ipv6Regex.test(input) ||
        withPortRegex.test(input) ||
        tpPortRegex.test(input);
    }
    
    // 初始化
    document.addEventListener('DOMContentLoaded', function() {
      // 记录页面加载时的时间戳
      pageLoadTimestamp = calculateTimestamp();
      console.log('页面加载完成，时间戳:', pageLoadTimestamp);
      
      const input = document.getElementById('proxyip');
      if (input) input.focus();
      
      // 直接解析当前URL路径
      const currentPath = window.location.pathname;
      let autoCheckValue = null;
      
      // 检查URL参数中的autocheck（保持兼容性）
      const urlParams = new URLSearchParams(window.location.search);
      autoCheckValue = urlParams.get('autocheck');
      
      // 如果没有autocheck参数，检查路径
      if (!autoCheckValue && currentPath.length > 1) {
        const pathContent = currentPath.substring(1); // 移除开头的 '/'
        
        // 检查路径是否为有效的代理IP格式
        if (isValidProxyIPFormat(pathContent)) {
          autoCheckValue = pathContent;
          // 清理URL，移除路径部分
          const newUrl = new URL(window.location);
          newUrl.pathname = '/';
          window.history.replaceState({}, '', newUrl);
        }
      }
      
      // 如果没有从URL获取到值，尝试从localStorage获取上次搜索的地址
      if (!autoCheckValue) {
        try {
          const lastSearch = localStorage.getItem('lastProxyIP');
          if (lastSearch && isValidProxyIPFormat(lastSearch)) {
            input.value = lastSearch;
            // 不自动执行检测，只是填充输入框
          }
        } catch (error) {
          console.log('读取历史记录失败:', error);
        }
      }
      
      if (autoCheckValue) {
        input.value = autoCheckValue;
        // 如果来自URL参数，清除参数
        if (urlParams.has('autocheck')) {
          const newUrl = new URL(window.location);
          newUrl.searchParams.delete('autocheck');
          window.history.replaceState({}, '', newUrl);
        }
        
        // 延迟执行搜索，确保页面完全加载
        setTimeout(() => {
          if (!isChecking) {
            checkProxyIP();
          }
        }, 500);
      }
      
      // 输入框回车事件
      if (input) {
        input.addEventListener('keypress', function(event) {
          if (event.key === 'Enter' && !isChecking) {
            checkProxyIP();
          }
        });
      }
      
      // 添加事件委托处理复制按钮点击
      document.addEventListener('click', function(event) {
        if (event.target.classList.contains('copy-btn')) {
          const text = event.target.getAttribute('data-copy');
          if (text) {
            copyToClipboard(text, event.target);
          }
        }
      });
      
      renderHistory();
    });
    
    // 切换标签页
    window.switchTab = function(tabName) {
      document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      
      event.target.classList.add('active');
      document.getElementById(tabName + '-tab').classList.add('active');
    };
    
    // 保存历史记录
    function saveHistory(val) {
      if(!val) return;
      let list = JSON.parse(localStorage.getItem(historyKey) || '[]');
      const preview = val.split('\\n')[0].substring(0, 15) + (val.length > 15 ? '...' : '');
      list = list.filter(i => i.val !== val);
      list.unshift({ name: preview, val: val });
      if(list.length > 5) list.pop();
      localStorage.setItem(historyKey, JSON.stringify(list));
      renderHistory();
    }
    
    function renderHistory() {
      const list = JSON.parse(localStorage.getItem(historyKey) || '[]');
      const box = document.getElementById('history-box');
      if (box) {
        box.innerHTML = list.map(item => \`<div class="tag" onclick="fillInput('\${encodeURIComponent(item.val)}')">\${item.name}</div>\`).join('');
      }
    }
    
    window.fillInput = (val) => {
      const inputArea = document.getElementById('input-area');
      if (inputArea) inputArea.value = decodeURIComponent(val);
    };
    
    window.handleFile = (input) => {
      const file = input.files[0];
      if(file) { 
        const reader = new FileReader(); 
        reader.onload = e => {
          const inputArea = document.getElementById('input-area');
          if (inputArea) inputArea.value = e.target.result;
        }; 
        reader.readAsText(file); 
      }
    };
    
    window.clearTable = () => { 
      const resultBody = document.getElementById('result-body');
      const resultPanel = document.getElementById('result-panel');
      if (resultBody) resultBody.innerHTML = ''; 
      if (resultPanel) resultPanel.style.display = 'none'; 
    };
    
    window.startBatch = async () => {
      const inputArea = document.getElementById('input-area');
      const raw = inputArea ? inputArea.value.trim() : '';
      if(!raw) return alert('请输入目标地址');
      saveHistory(raw);
      const resultPanel = document.getElementById('result-panel');
      if (resultPanel) resultPanel.style.display = 'block';
      const lines = raw.split('\\n').map(x => x.trim()).filter(x => x);
      for (const target of lines) { await processLine(target); }
    };
    
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
          if (data.status === 'success' && data.ips && data.ips.length > 0) {
            for (const ip of data.ips) { addResultRow(\`\${target} (\${ip})\`, ip); }
          } else { addResultRow(target, target); }
        } catch(e) {
          const placeholder = document.getElementById(tempId);
          if(placeholder) placeholder.remove();
          addResultRow(target + " [解析失败]", target);
        }
      }
    }
    
    function addPlaceholderRow(label, id) {
      const resultBody = document.getElementById('result-body');
      if (!resultBody) return;
      const tr = document.createElement('tr'); tr.id = id;
      tr.innerHTML = \`<td>\${label}</td><td colspan="3" style="color:#94a3b8"><span class="loading-spin"></span> 正在解析所有IP...</td>\`;
      resultBody.prepend(tr);
    }
    
    function addResultRow(displayLabel, realTarget) {
      const resultBody = document.getElementById('result-body');
      if (!resultBody) return;
      const tr = document.createElement('tr');
      const rowId = 'row-' + Math.random().toString(36).substr(2, 9);
      tr.id = rowId;
      tr.innerHTML = \`<td><div>\${displayLabel.split(' (')[0]}</div>\${displayLabel.includes('(') ? \`<span class="target-sub">\${displayLabel.split(' (')[1].replace(')', '')}</span>\` : ''}</td><td id="\${rowId}-rtt"><span class="loading-spin"></span></td><td id="\${rowId}-geo">...</td><td id="\${rowId}-isp">...</td>\`;
      resultBody.prepend(tr);
      const cleanIP = realTarget.replace(/[\\[\\]]/g, '');
      
      // TCP/HTTP 延迟检测
      fetch(\`./api/tcping?target=\${encodeURIComponent(cleanIP)}\`).then(r => r.json()).then(d => {
        const el = document.getElementById(\`\${rowId}-rtt\`);
        if(el) {
          if(d.status === 'success') {
            let cls = 'rtt-green'; if(d.rtt > 100) cls = 'rtt-yellow'; if(d.rtt > 250) cls = 'rtt-red';
            const typeTag = d.type ? \`<span class="type-label">\${d.type}</span>\` : '';
            el.innerHTML = \`<span class="rtt-badge \${cls}">\${d.rtt} ms</span>\${typeTag}\`;
          } else { el.innerHTML = \`<span style="color:#ef4444; font-size:12px">连接超时</span>\`; }
        }
      });

      // GeoIP 检测
      fetch(\`./api/geoip?target=\${encodeURIComponent(cleanIP)}\`).then(r => r.json()).then(d => {
        const geoEl = document.getElementById(\`\${rowId}-geo\`);
        const ispEl = document.getElementById(\`\${rowId}-isp\`);
        if(geoEl && ispEl) {
          const city = d.city || '';
          const country = d.country || '';
          geoEl.innerText = \`\${country} \${city}\`;
          
          const ispName = d.connection ? (d.connection.isp || d.connection.org) : (d.isp || '未知');
          const asn = d.connection ? d.connection.asn : (d.asn || '');
          ispEl.innerHTML = \`\${ispName} <br><span class="target-sub">AS\${asn}</span>\`;
        }
      });
    }
    
    // 显示toast消息
    function showToast(message, duration = 3000) {
      const toast = document.getElementById('toast');
      if (!toast) return;
      toast.textContent = message;
      toast.classList.add('show');
      
      setTimeout(() => {
        toast.classList.remove('show');
      }, duration);
    }
    
    // 复制到剪贴板
    function copyToClipboard(text, element) {
      navigator.clipboard.writeText(text).then(() => {
        const originalText = element.textContent;
        element.classList.add('copied');
        element.textContent = '已复制 ✓';
        showToast('复制成功！');
        
        setTimeout(() => {
          element.classList.remove('copied');
          element.textContent = originalText;
        }, 2000);
      }).catch(err => {
        console.error('复制失败:', err);
        showToast('复制失败，请手动复制');
      });
    }
    
    // 创建复制按钮
    function createCopyButton(text) {
      return \`<span class="copy-btn" data-copy="\${text}">\${text}</span>\`;
    }
    
    // 检查是否为IP地址
    function isIPAddress(input) {
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;
      const ipv6WithPortRegex = /^\\[[0-9a-fA-F:]+\\]:\\d+$/;
      const ipv4WithPortRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\\d+$/;
      
      return ipv4Regex.test(input) || ipv6Regex.test(input) || ipv6WithPortRegex.test(input) || ipv4WithPortRegex.test(input);
    }
    
    // 添加输入预处理函数
    function preprocessInput(input) {
      if (!input) return input;
      
      // 去除首尾空格
      let processed = input.trim();
      
      // 检查是否还有空格
      if (processed.includes(' ')) {
        // 只保留第一个空格前的内容
        processed = processed.split(' ')[0];
      }
      
      return processed;
    }
    
    // 主检测函数 (来自 _worker.js)
    async function checkProxyIP() {
      if (isChecking) return;
      
      const proxyipInput = document.getElementById('proxyip');
      const resultDiv = document.getElementById('result');
      const checkBtn = document.getElementById('checkBtn');
      const btnText = checkBtn.querySelector('.btn-text');
      const spinner = checkBtn.querySelector('.loading-spinner');
      
      const rawInput = proxyipInput.value;
      const proxyip = preprocessInput(rawInput);
      
      // 如果预处理后的值与原值不同，更新输入框
      if (proxyip !== rawInput) {
        proxyipInput.value = proxyip;
        showToast('已自动清理输入内容');
      }
      
      if (!proxyip) {
        showToast('请输入代理IP地址');
        proxyipInput.focus();
        return;
      }
      
      // 检查时间戳是否过期
      const currentTimestamp = calculateTimestamp();
      console.log('点击检测时的时间戳:', currentTimestamp);
      console.log('页面加载时的时间戳:', pageLoadTimestamp);
      console.log('时间戳是否一致:', currentTimestamp === pageLoadTimestamp);
      
      if (currentTimestamp !== pageLoadTimestamp) {
        // 时间戳已过期，需要重新加载页面获取最新TOKEN
        const currentHost = window.location.host;
        const currentProtocol = window.location.protocol;
        const redirectUrl = \`\${currentProtocol}//\${currentHost}/\${encodeURIComponent(proxyip)}\`;
        
        console.log('时间戳过期，即将跳转到:', redirectUrl);
        showToast('TOKEN已过期，正在刷新页面...');
        
        // 延迟跳转，让用户看到提示
        setTimeout(() => {
          window.location.href = redirectUrl;
        }, 1000);
        
        return;
      }
      
      console.log('时间戳验证通过，继续执行检测逻辑');
      
      // 保存到localStorage
      try {
        localStorage.setItem('lastProxyIP', proxyip);
      } catch (error) {
        console.log('保存历史记录失败:', error);
      }
      
      // 设置加载状态
      isChecking = true;
      checkBtn.classList.add('btn-loading');
      checkBtn.disabled = true;
      btnText.style.display = 'none';
      spinner.style.display = 'block';
      resultDiv.classList.remove('show');
      
      try {
        if (isIPAddress(proxyip)) {
          await checkSingleIP(proxyip, resultDiv);
        } else {
          await checkDomain(proxyip, resultDiv);
        }
      } catch (err) {
        resultDiv.innerHTML = \`
          <div class="result-card result-error">
            <h3>❌ 检测失败</h3>
            <p><strong>错误信息:</strong> \${err.message}</p>
            <p><strong>检测时间:</strong> \${new Date().toLocaleString()}</p>
          </div>
        \`;
        resultDiv.classList.add('show');
      } finally {
        isChecking = false;
        checkBtn.classList.remove('btn-loading');
        checkBtn.disabled = false;
        btnText.style.display = 'block';
        spinner.style.display = 'none';
      }
    }
    
    // 检查单个IP
    async function checkSingleIP(proxyip, resultDiv) {
      const response = await fetch(\`./check?proxyip=\${encodeURIComponent(proxyip)}\`);
      const data = await response.json();
      
      if (data.success) {
        const ipInfo = await getIPInfo(data.proxyIP);
        const ipInfoHTML = formatIPInfo(ipInfo);
        const responseTimeHTML = data.responseTime && data.responseTime > 0 ? 
          \`<div class="tooltip">
            <span style="background: var(--success-color); color: white; padding: 4px 8px; border-radius: 6px; font-weight: 600; font-size: 14px;">\${data.responseTime}ms</span>
            <span class="tooltiptext">该延迟并非 <strong>您当前网络</strong> 到 ProxyIP 的实际延迟，<br>而是 <strong>Cloudflare.\${data.colo || 'CF'} 机房</strong> 到 ProxyIP 的响应时间。</span>
          </div>\` : 
          '<span style="color: var(--text-light);">延迟未知</span>';
        
        resultDiv.innerHTML = \`
          <div class="result-card result-success">
            <h3>✅ ProxyIP 有效</h3>
            <div style="margin-top: 20px;">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap;">
                <strong>🌐 ProxyIP 地址:</strong>
                \${createCopyButton(data.proxyIP)}
                \${ipInfoHTML}
                \${responseTimeHTML}
              </div>
              <p><strong>🔌 端口:</strong> \${createCopyButton(data.portRemote.toString())}</p>
              <p><strong>🏢 机房信息:</strong> \${data.colo || 'CF'}</p>
              <p><strong>🕒 检测时间:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
            </div>
          </div>
        \`;
      } else {
        resultDiv.innerHTML = \`
          <div class="result-card result-error">
            <h3>❌ ProxyIP 失效</h3>
            <div style="margin-top: 20px;">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap;">
                <strong>🌐 IP地址:</strong>
                \${createCopyButton(proxyip)}
                <span style="color: var(--error-color); font-weight: 600; font-size: 18px;">❌</span>
              </div>
              <p><strong>🔌 端口:</strong> \${data.portRemote && data.portRemote !== -1 ? createCopyButton(data.portRemote.toString()) : '未知'}</p>
              <p><strong>🏢 机房信息:</strong> \${data.colo || 'CF'}</p>
              \${data.message ? \`<p><strong>错误信息:</strong> \${data.message}</p>\` : ''}
              <p><strong>🕒 检测时间:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
            </div>
          </div>
        \`;
      }
      resultDiv.classList.add('show');
    }
    
    // 检查域名
    async function checkDomain(domain, resultDiv) {
      let portRemote = 443;
      let cleanDomain = domain;
      
      // 解析端口
      if (domain.includes('.tp')) {
        portRemote = domain.split('.tp')[1].split('.')[0] || 443;
      } else if (domain.includes('[') && domain.includes(']:')) {
        portRemote = parseInt(domain.split(']:')[1]) || 443;
        cleanDomain = domain.split(']:')[0] + ']';
      } else if (domain.includes(':')) {
        portRemote = parseInt(domain.split(':')[1]) || 443;
        cleanDomain = domain.split(':')[0];
      }
      
      // 解析域名 - 这里的 token 是由 JS 直接插入的
      const resolveResponse = await fetch(\`./resolve?domain=\${encodeURIComponent(cleanDomain)}&token=${token}\`);
      const resolveData = await resolveResponse.json();
      
      if (!resolveData.success) {
        throw new Error(resolveData.error || '域名解析失败');
      }
      
      const ips = resolveData.ips;
      if (!ips || ips.length === 0) {
        throw new Error('未找到域名对应的IP地址');
      }
      
      // 清空缓存
      ipCheckResults.clear();
      
      // 显示初始结果
      resultDiv.innerHTML = \`
        <div class="result-card result-warning">
          <h3>🔍 域名解析结果</h3>
          <div style="margin-top: 20px;">
            <p><strong>🌐 ProxyIP 域名:</strong> \${createCopyButton(cleanDomain)}</p>
            <p><strong>🔌 端口:</strong> \${createCopyButton(portRemote.toString())}</p>
            <p><strong>🏢 机房信息:</strong> <span id="domain-colo">检测中...</span></p>
            <p><strong>📋 发现IP:</strong> \${ips.length} 个</p>
            <p><strong>🕒 解析时间:</strong> \${new Date().toLocaleString()}</p>
          </div>
          <div class="ip-grid" id="ip-grid">
            \${ips.map((ip, index) => \`
              <div class="ip-item" id="ip-item-\${index}">
                <div class="ip-status-line" id="ip-status-line-\${index}">
                  <strong>IP:</strong>
                  \${createCopyButton(ip)}
                  <span id="ip-info-\${index}" style="color: var(--text-secondary);">获取信息中...</span>
                  <span class="status-icon" id="status-icon-\${index}">🔄</span>
                </div>
              </div>
            \`).join('')}
          </div>
        </div>
      \`;
      resultDiv.classList.add('show');
      
      // 并发检查所有IP和获取IP信息
      const checkPromises = ips.map((ip, index) => checkIPWithIndex(ip, portRemote, index));
      const ipInfoPromises = ips.map((ip, index) => getIPInfoWithIndex(ip, index));
      
      await Promise.all([...checkPromises, ...ipInfoPromises]);
      
      // 使用缓存的结果更新整体状态和机房信息
      const validCount = Array.from(ipCheckResults.values()).filter(r => r.success).length;
      const totalCount = ips.length;
      const resultCard = resultDiv.querySelector('.result-card');
      
      // 获取第一个有效结果的colo信息
      const firstValidResult = Array.from(ipCheckResults.values()).find(r => r.success && r.colo);
      const coloInfo = firstValidResult?.colo || 'CF';
      
      // 更新机房信息
      const coloElement = document.getElementById('domain-colo');
      if (coloElement) {
        coloElement.textContent = coloInfo;
      }
      
      if (validCount === totalCount) {
        resultCard.className = 'result-card result-success';
        resultCard.querySelector('h3').innerHTML = '✅ 所有IP均有效';
      } else if (validCount === 0) {
        resultCard.className = 'result-card result-error';
        resultCard.querySelector('h3').innerHTML = '❌ 所有IP均失效';
      } else {
        resultCard.className = 'result-card result-warning';
        resultCard.querySelector('h3').innerHTML = \`⚠️ 部分IP有效 (\${validCount}/\${totalCount})\`;
      }
    }
    
    // 检查单个IP（带索引）
    async function checkIPWithIndex(ip, port, index) {
      try {
        const cacheKey = \`\${ip}:\${port}\`;
        let result;
        
        // 检查是否已有缓存结果
        if (ipCheckResults.has(cacheKey)) {
          result = ipCheckResults.get(cacheKey);
        } else {
          // 调用API检查IP状态
          result = await checkIPStatus(cacheKey);
          // 缓存结果
          ipCheckResults.set(cacheKey, result);
        }
        
        const itemElement = document.getElementById(\`ip-item-\${index}\`);
        const statusIcon = document.getElementById(\`status-icon-\${index}\`);
        
        if (result.success) {
          if (itemElement) {
            itemElement.style.background = 'linear-gradient(135deg, #d4edda, #c3e6cb)';
            itemElement.style.borderColor = 'var(--success-color)';
          }
          
          const responseTimeHTML = result.responseTime && result.responseTime > 0 ? 
            \`<div class="tooltip">
              <span style="background: var(--success-color); color: white; padding: 2px 6px; border-radius: 4px; font-size: 12px; font-weight: 600;">\${result.responseTime}ms</span>
              <span class="tooltiptext">该延迟并非 <strong>您当前网络</strong> 到 ProxyIP 的实际延迟，<br>而是 <strong>Cloudflare.\${result.colo || 'CF'} 机房</strong> 到 ProxyIP 的响应时间。</span>
            </div>\` : 
            '<span style="color: var(--text-light); font-size: 12px;">延迟未知</span>';
            
          if (statusIcon) {
            statusIcon.innerHTML = responseTimeHTML;
            statusIcon.className = 'status-icon status-success';
          }
        } else {
          if (itemElement) {
            itemElement.style.background = 'linear-gradient(135deg, #f8d7da, #f5c6cb)';
            itemElement.style.borderColor = 'var(--error-color)';
          }
          if (statusIcon) {
            statusIcon.textContent = '❌';
            statusIcon.className = 'status-icon status-error';
            statusIcon.style.color = 'var(--error-color)';
            statusIcon.style.fontSize = '18px';
          }
        }
      } catch (error) {
        console.error('检查IP失败:', error);
        const statusIcon = document.getElementById(\`status-icon-\${index}\`);
        if (statusIcon) {
          statusIcon.textContent = '❌';
          statusIcon.className = 'status-icon status-error';
          statusIcon.style.color = 'var(--error-color)';
          statusIcon.style.fontSize = '18px';
        }
        // 将失败结果也缓存起来
        const cacheKey = \`\${ip}:\${port}\`;
        ipCheckResults.set(cacheKey, { success: false, error: error.message, colo: 'CF' });
      }
    }
    
    // 获取IP信息（带索引）
    async function getIPInfoWithIndex(ip, index) {
      try {
        const ipInfo = await getIPInfo(ip);
        const infoElement = document.getElementById(\`ip-info-\${index}\`);
        if (infoElement) {
          infoElement.innerHTML = formatIPInfo(ipInfo);
        }
      } catch (error) {
        console.error('获取IP信息失败:', error);
        const infoElement = document.getElementById(\`ip-info-\${index}\`);
        if (infoElement) {
          infoElement.innerHTML = '<span style="color: var(--text-light);">信息获取失败</span>';
        }
      }
    }
    
    // 获取IP信息
    async function getIPInfo(ip) {
      try {
        const cleanIP = ip.replace(/[\\[\\]]/g, '');
        // 这里的 token 也是 JS 插入的
        const response = await fetch(\`./ip-info?ip=\${encodeURIComponent(cleanIP)}&token=${token}\`);
        const data = await response.json();
        return data;
      } catch (error) {
        return null;
      }
    }
    
    // 格式化IP信息
    function formatIPInfo(ipInfo) {
      if (!ipInfo || ipInfo.status !== 'success') {
        return '<span style="color: var(--text-light);">信息获取失败</span>';
      }
      
      const country = ipInfo.country || '未知';
      const as = ipInfo.as || '未知';
      
      return \`
        <span class="tag tag-country">\${country}</span>
        <span class="tag tag-as">\${as}</span>
      \`;
    }
    
    // 检查IP状态
    async function checkIPStatus(ip) {
      try {
        const response = await fetch(\`./check?proxyip=\${encodeURIComponent(ip)}\`);
        const data = await response.json();
        return data;
      } catch (error) {
        return { success: false, error: error.message };
      }
    }
  </script>
</body>
</html>`;
  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" }
  });
}
