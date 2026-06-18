// 读者用户认证：注册（邮箱验证码）/ 登录 / 登出
// POST /api/user/auth?action=send-code — 发送验证码
// POST /api/user/auth?action=verify     — 校验并创建用户
// POST /api/user/auth?action=login      — 密码登录
// POST /api/user/auth?action=logout     — 登出
// GET  /api/user/auth?action=me         — 当前用户信息
import {
  parseJsonBody, sha256Hash, hashPassword, verifyPassword,
  makeAuthCookie, clearAuthCookie,
  checkUserAdmin, generateUserToken
} from '../../_utils.js';

const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_SEND_PER_HOUR_EMAIL = 5;
const MAX_SEND_PER_HOUR_IP = 10;
const MAX_VERIFY_ATTEMPTS = 5;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 天
const MAX_SESSIONS_PER_USER = 10;
const REGISTRATION_BONUS = 10; // 注册送 10 积分

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_]+$/;

function generateCode() {
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  const n = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
  return String(n % 1000000).padStart(CODE_LENGTH, '0');
}
const CODE_LENGTH = 6;

async function sendResendEmail(env, to, subject, html, text) {
  const apiKeyRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_api_key'").first();
  const fromRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_from'").first();
  const apiKey = env.RESEND_API_KEY || apiKeyRow?.value;
  const from = env.RESEND_FROM || fromRow?.value;
  if (!apiKey || !from) return { ok: false, reason: 'not_configured' };
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from, to: [to], subject, html, text }),
    });
    if (!res.ok) {
      const err = await res.text().catch(() => '');
      console.error('Resend send failed:', res.status, err);
      return { ok: false, reason: 'send_failed' };
    }
    return { ok: true };
  } catch (e) {
    console.error('Resend send exception:', e);
    return { ok: false, reason: 'network_error' };
  }
}

async function isRegistrationEnabled(env) {
  const row = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'user_registration_enabled'").first();
  // 默认开启（与 author_registration_enabled 独立）
  if (row === null || row === undefined) return true;
  return row.value === 'true';
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  // 登出无需启用注册
  if (action === 'logout') {
    const auth = await checkUserAdmin(request, env);
    if (auth.ok && auth._token) {
      const tokenHash = await sha256Hash(auth._token);
      await env.DB.prepare('DELETE FROM user_sessions WHERE token = ?').bind(tokenHash).run();
    }
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearAuthCookie('user_token') }
    });
  }

  if (!await isRegistrationEnabled(env)) {
    return Response.json({ error: '注册功能未启用' }, { status: 403 });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256Hash('user_reg:' + ip);

  // ===== 发送验证码 =====
  if (action === 'send-code') {
    const body = await parseJsonBody(request);
    if (!body) return Response.json({ error: '请求格式错误' }, { status: 400 });

    const email = String(body.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 200) {
      return Response.json({ error: '邮箱格式不正确' }, { status: 400 });
    }

    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) {
      return Response.json({ error: '该邮箱已注册' }, { status: 409 });
    }

    // 限流
    const emailCountRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM pending_user_registrations WHERE email = ? AND created_at > datetime('now', '-1 hour')"
    ).bind(email).first();
    if ((emailCountRow?.c || 0) >= MAX_SEND_PER_HOUR_EMAIL) {
      return Response.json({ error: '该邮箱发送过于频繁，请稍后再试' }, { status: 429 });
    }
    const ipCountRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM pending_user_registrations WHERE ip_hash = ? AND created_at > datetime('now', '-1 hour')"
    ).bind(ipHash).first();
    if ((ipCountRow?.c || 0) >= MAX_SEND_PER_HOUR_IP) {
      return Response.json({ error: '当前网络发送过于频繁，请稍后再试' }, { status: 429 });
    }

    const code = generateCode();
    const codeHash = await sha256Hash('user_code:' + email + ':' + code);
    const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();

    await env.DB.prepare("DELETE FROM pending_user_registrations WHERE email = ? AND verified = 0").bind(email).run();
    await env.DB.prepare(
      'INSERT INTO pending_user_registrations (email, code_hash, ip_hash, expires_at) VALUES (?, ?, ?, ?)'
    ).bind(email, codeHash, ipHash, expiresAt).run();

    const subjectRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_subject'").first();
    const siteNameRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'site_name'").first();
    const subject = (subjectRow?.value || '【%s】注册验证码').replace(/%s/g, siteNameRow?.value || '小说站');
    const siteName = siteNameRow?.value || '小说站';
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#333">
        <h2 style="color:#d4a574;margin:0 0 16px">${siteName} 读者注册</h2>
        <p style="line-height:1.6">欢迎注册「${siteName}」读者账号！请使用以下验证码完成注册：</p>
        <div style="font-size:28px;font-weight:700;letter-spacing:6px;text-align:center;padding:16px;background:#faf8f5;border-radius:8px;margin:20px 0;color:#b8895a">${code}</div>
        <p style="color:#666;font-size:13px;line-height:1.6">验证码 10 分钟内有效，请勿向他人透露。如果这不是您本人的操作，请忽略此邮件。</p>
      </div>
    `;
    const text = `${siteName} 读者注册验证码：${code}\n\n验证码 10 分钟内有效。`;
    const sendRes = await sendResendEmail(env, email, subject, html, text);
    if (!sendRes.ok) {
      const reason = sendRes.reason === 'not_configured'
        ? '邮件服务未配置'
        : '邮件发送失败';
      return Response.json({ error: reason }, { status: 500 });
    }
    return Response.json({ success: true, message: '验证码已发送', expiresInSec: CODE_TTL_MS / 1000 });
  }

  // ===== 校验并创建用户 =====
  if (action === 'verify') {
    const body = await parseJsonBody(request);
    if (!body) return Response.json({ error: '请求格式错误' }, { status: 400 });
    const email = String(body.email || '').trim().toLowerCase();
    const code = String(body.code || '').trim();
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!EMAIL_RE.test(email)) return Response.json({ error: '邮箱格式不正确' }, { status: 400 });
    if (!/^\d{6}$/.test(code)) return Response.json({ error: '验证码格式不正确' }, { status: 400 });
    if (!username || username.length < 2 || username.length > 32) return Response.json({ error: '用户名长度 2-32 位' }, { status: 400 });
    if (!USERNAME_RE.test(username)) return Response.json({ error: '用户名只能包含字母数字下划线' }, { status: 400 });
    if (password.length < 8 || password.length > 128) return Response.json({ error: '密码长度 8-128 位' }, { status: 400 });
    if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) return Response.json({ error: '密码需包含字母和数字' }, { status: 400 });

    const userExists = await env.DB.prepare('SELECT id FROM users WHERE username = ? OR email = ?').bind(username, email).first();
    if (userExists) return Response.json({ error: '用户名或邮箱已存在' }, { status: 409 });

    const rec = await env.DB.prepare(
      "SELECT id, code_hash, attempts, expires_at FROM pending_user_registrations WHERE email = ? AND verified = 0 ORDER BY id DESC LIMIT 1"
    ).bind(email).first();
    if (!rec) return Response.json({ error: '请先获取验证码' }, { status: 400 });
    if (new Date(rec.expires_at) < new Date()) {
      await env.DB.prepare('DELETE FROM pending_user_registrations WHERE id = ?').bind(rec.id).run().catch(() => {});
      return Response.json({ error: '验证码已过期' }, { status: 400 });
    }
    if (rec.attempts >= MAX_VERIFY_ATTEMPTS) {
      await env.DB.prepare('DELETE FROM pending_user_registrations WHERE id = ?').bind(rec.id).run().catch(() => {});
      return Response.json({ error: '验证次数过多，请重新获取' }, { status: 429 });
    }

    const codeHash = await sha256Hash('user_code:' + email + ':' + code);
    if (codeHash !== rec.code_hash) {
      await env.DB.prepare('UPDATE pending_user_registrations SET attempts = attempts + 1 WHERE id = ?').bind(rec.id).run();
      return Response.json({ error: '验证码错误' }, { status: 400 });
    }

    const passwordHash = await hashPassword(password);
    let userId;
    try {
      const r = await env.DB.prepare(
        "INSERT INTO users (username, password_hash, email, status, balance) VALUES (?, ?, ?, 'active', ?)"
      ).bind(username, passwordHash, email, REGISTRATION_BONUS).run();
      userId = r.meta.last_row_id;
      await env.DB.prepare(
        "INSERT INTO user_balance_log (user_id, delta, reason) VALUES (?, ?, '注册奖励')"
      ).bind(userId, REGISTRATION_BONUS).run();
    } catch (e) {
      if (e.message && e.message.includes('UNIQUE')) {
        return Response.json({ error: '用户名或邮箱已存在' }, { status: 409 });
      }
      return Response.json({ error: '注册失败' }, { status: 500 });
    }

    await env.DB.batch([
      env.DB.prepare('UPDATE pending_user_registrations SET verified = 1 WHERE id = ?').bind(rec.id),
      env.DB.prepare('DELETE FROM pending_user_registrations WHERE email = ? AND id != ?').bind(email, rec.id),
    ]);

    // 创建 session
    const token = generateUserToken();
    const tokenHash = await sha256Hash(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    await env.DB.prepare('INSERT INTO user_sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(tokenHash, userId, expiresAt).run();
    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE user_id = ? AND token NOT IN (SELECT token FROM user_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ${MAX_SESSIONS_PER_USER})`
    ).bind(userId, userId).run().catch(() => {});

    return new Response(JSON.stringify({
      success: true,
      message: '注册成功，已赠送 ' + REGISTRATION_BONUS + ' 积分',
      user: { id: userId, username, email, balance: REGISTRATION_BONUS }
    }), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': makeAuthCookie('user_token', token, SESSION_TTL_MS / 1000) }
    });
  }

  // ===== 密码登录 =====
  if (action === 'login') {
    const body = await parseJsonBody(request);
    if (!body) return Response.json({ error: '请求格式错误' }, { status: 400 });
    const { username, password } = body;
    if (!username || !password) return Response.json({ error: '用户名和密码不能为空' }, { status: 400 });

    const user = await env.DB.prepare('SELECT id, username, password_hash, status, balance, email FROM users WHERE username = ? OR email = ?')
      .bind(String(username).trim(), String(username).trim().toLowerCase()).first();
    if (!user) return Response.json({ error: '用户名或密码错误' }, { status: 401 });
    if (user.status === 'banned') return Response.json({ error: '账号已被封禁' }, { status: 403 });

    // 密码验证
    const result = await verifyPassword(password, user.password_hash);
    if (!result.match) return Response.json({ error: '用户名或密码错误' }, { status: 401 });

    const token = generateUserToken();
    const tokenHash = await sha256Hash(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    await env.DB.prepare('INSERT INTO user_sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(tokenHash, user.id, expiresAt).run();
    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE user_id = ? AND token NOT IN (SELECT token FROM user_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ${MAX_SESSIONS_PER_USER})`
    ).bind(user.id, user.id).run().catch(() => {});

    return new Response(JSON.stringify({
      success: true,
      user: { id: user.id, username: user.username, email: user.email, balance: user.balance }
    }), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': makeAuthCookie('user_token', token, SESSION_TTL_MS / 1000) }
    });
  }

  return Response.json({ error: 'Unknown action' }, { status: 400 });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  if (action === 'me') {
    const auth = await checkUserAdmin(request, env);
    if (!auth.ok) return Response.json({ authenticated: false }, { status: 401 });
    return Response.json({
      authenticated: true,
      userId: auth.userId,
      username: auth.username,
      email: auth.email,
      balance: auth.balance,
    });
  }
  return Response.json({ error: 'Unknown action' }, { status: 400 });
}
