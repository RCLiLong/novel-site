// 公共中间件：安全头 + CORS + 错误处理 + 请求大小限制 + 访问统计
export async function onRequest(context) {
  const url = new URL(context.request.url);
  const isAdminApi = url.pathname.startsWith('/api/admin') || url.pathname.startsWith('/api/auth');

  // admin API不返回CORS头（仅同源访问）
  const corsOrigin = isAdminApi ? null : '*';

  // OPTIONS 预检请求
  if (context.request.method === 'OPTIONS') {
    // admin/auth API 不返回 CORS 头（仅同源访问）
    if (isAdminApi) {
      return new Response(null, { status: 204 });
    }
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };
    return new Response(null, { status: 204, headers });
  }

  // 请求大小限制（10MB）
  const contentLength = parseInt(context.request.headers.get('Content-Length') || '0');
  if (contentLength > 10 * 1024 * 1024) {
    return Response.json({ error: 'Request too large' }, { status: 413 });
  }

  // CSRF防护：admin/auth API的写操作必须携带正确的Content-Type
  // 简单请求（form提交）无法设置application/json，因此可阻止跨站POST
  const method = context.request.method;
  if (isAdminApi && ['POST', 'PUT', 'DELETE'].includes(method)) {
    const ct = context.request.headers.get('Content-Type') || '';
    // 允许 application/json 和 multipart/form-data（封面/字体上传）
    // GitHub OAuth callback 是 GET 不受影响
    if (!ct.startsWith('application/json') && !ct.startsWith('multipart/form-data')) {
      return Response.json({ error: 'Invalid Content-Type' }, { status: 415 });
    }
  }

  try {
    const response = await context.next();

    // CORS（仅公开API）
    if (corsOrigin) {
      response.headers.set('Access-Control-Allow-Origin', corsOrigin);
      response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }

    // 安全头
    response.headers.set('X-Frame-Options', 'DENY');
    // CSP：允许 Google AdSense 与常见广告资源（自定义广告通常引用 https 图片/iframe）
    response.headers.set('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://pagead2.googlesyndication.com https://www.googletagservices.com https://googleads.g.doubleclick.net",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net",
      "frame-src https://googleads.g.doubleclick.net https://www.google.com https://tpc.googlesyndication.com",
      "frame-ancestors 'none'"
    ].join('; '));
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    // 访问统计（异步，不阻塞响应）
    if (!isAdminApi && context.request.method === 'GET' && url.pathname.startsWith('/api/')) {
      context.waitUntil(trackVisit(context.env, context.request));
    }

    return response;
  } catch (err) {
    console.error('Internal error:', err);
    return Response.json(
      { error: 'Internal Server Error' },
      { status: 500 }
    );
  }
}

// 异步记录PV/UV
async function trackVisit(env, request) {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    // IP哈希（不存原始IP）
    const encoder = new TextEncoder();
    const data = encoder.encode(ip + (env.IP_SALT || 'novel-site-default-salt'));
    const hashBuf = await crypto.subtle.digest('SHA-256', data);
    const ipHash = [...new Uint8Array(hashBuf)].map(b => b.toString(16).padStart(2, '0')).join('');

    // PV +1
    await env.DB.prepare(
      "INSERT INTO site_visits (date, pv, uv) VALUES (?, 1, 0) ON CONFLICT(date) DO UPDATE SET pv = pv + 1"
    ).bind(today).run();

    // UV去重
    const exists = await env.DB.prepare(
      "SELECT 1 FROM daily_visitors WHERE date = ? AND ip_hash = ?"
    ).bind(today, ipHash).first();

    if (!exists) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO daily_visitors (date, ip_hash) VALUES (?, ?)"
      ).bind(today, ipHash).run();
      await env.DB.prepare(
        "UPDATE site_visits SET uv = uv + 1 WHERE date = ?"
      ).bind(today).run();
    }

    // 10%概率清理7天前的UV明细（节省空间）
    if (Math.random() < 0.1) {
      const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
      await env.DB.prepare("DELETE FROM daily_visitors WHERE date < ?").bind(weekAgo).run();
    }
    // 1%概率清理90天前的book_stats（防DB膨胀）
    if (Math.random() < 0.01) {
      const ninetyDaysAgo = new Date(Date.now() - 90 * 86400000).toISOString().slice(0, 10);
      await env.DB.prepare("DELETE FROM book_stats WHERE date < ?").bind(ninetyDaysAgo).run();
    }
  } catch (e) {
    console.error('Track visit error:', e);
  }
}
