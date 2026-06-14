// 作者注册（邮箱验证码 + 等待管理员审核）
// POST /api/auth/register?action=send-code — 发送验证码
// POST /api/auth/register?action=verify     — 校验验证码并创建待审账号
import { parseJsonBody, sha256Hash, hashPassword } from '../_utils.js';

const CODE_TTL_MS = 10 * 60 * 1000;        // 验证码有效期 10 分钟
const CODE_LENGTH = 6;                      // 6 位数字
const MAX_SEND_PER_HOUR_EMAIL = 5;          // 单邮箱每小时最多发送 5 次
const MAX_SEND_PER_HOUR_IP = 10;            // 单 IP 每小时最多发送 10 次
const MAX_VERIFY_ATTEMPTS = 5;              // 单验证码最多尝试 5 次

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_]+$/;

function generateCode() {
  // 用 crypto 随机生成 6 位数字（避免可预测）
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  const n = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
  return String(n % 1000000).padStart(CODE_LENGTH, '0');
}

async function sendResendEmail(env, to, subject, html, text) {
  const apiKeyRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_api_key'").first();
  const fromRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_from'").first();
  // 环境变量优先于 DB（运维更安全）
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
  const row = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'author_registration_enabled'").first();
  return row?.value === 'true';
}

async function cleanupExpired(env) {
  try {
    await env.DB.prepare("DELETE FROM pending_registrations WHERE expires_at < datetime('now', '-1 day')").run();
  } catch {}
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  if (!await isRegistrationEnabled(env)) {
    return Response.json({ error: '作者注册未启用，请联系管理员' }, { status: 403 });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256Hash('reg:' + ip);

  // ===== 发送验证码 =====
  if (action === 'send-code') {
    const body = await parseJsonBody(request);
    if (!body) return Response.json({ error: '请求格式错误' }, { status: 400 });

    const email = String(body.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 200) {
      return Response.json({ error: '邮箱格式不正确' }, { status: 400 });
    }

    // 邮箱已存在（已激活的账号）
    const existing = await env.DB.prepare('SELECT id, status FROM admin_users WHERE email = ?').bind(email).first();
    if (existing) {
      return Response.json({ error: '该邮箱已注册' }, { status: 409 });
    }

    // 限流：单邮箱
    const emailCountRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM pending_registrations WHERE email = ? AND created_at > datetime('now', '-1 hour')"
    ).bind(email).first();
    if ((emailCountRow?.c || 0) >= MAX_SEND_PER_HOUR_EMAIL) {
      return Response.json({ error: '该邮箱发送过于频繁，请稍后再试' }, { status: 429 });
    }

    // 限流：单 IP
    const ipCountRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM pending_registrations WHERE ip_hash = ? AND created_at > datetime('now', '-1 hour')"
    ).bind(ipHash).first();
    if ((ipCountRow?.c || 0) >= MAX_SEND_PER_HOUR_IP) {
      return Response.json({ error: '当前网络发送过于频繁，请稍后再试' }, { status: 429 });
    }

    // 生成验证码 & 入库
    const code = generateCode();
    const codeHash = await sha256Hash('code:' + email + ':' + code);
    const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();

    // 让旧的未使用验证码失效（同邮箱只保留最新一条）
    await env.DB.prepare("DELETE FROM pending_registrations WHERE email = ? AND verified = 0").bind(email).run();

    await env.DB.prepare(
      'INSERT INTO pending_registrations (email, code_hash, ip_hash, expires_at) VALUES (?, ?, ?, ?)'
    ).bind(email, codeHash, ipHash, expiresAt).run();

    // 发送邮件
    const subjectRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_subject'").first();
    const siteNameRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'site_name'").first();
    const subject = subjectRow?.value || '【小说站】注册验证码';
    const siteName = siteNameRow?.value || '小说站';
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#333">
        <h2 style="color:#d4a574;margin:0 0 16px">${siteName} 作者注册</h2>
        <p style="line-height:1.6">您正在申请成为「${siteName}」的作者，请使用以下验证码完成注册：</p>
        <div style="font-size:28px;font-weight:700;letter-spacing:6px;text-align:center;padding:16px;background:#faf8f5;border-radius:8px;margin:20px 0;color:#b8895a">${code}</div>
        <p style="color:#666;font-size:13px;line-height:1.6">验证码 10 分钟内有效，请勿向他人透露。如果这不是您本人的操作，请忽略此邮件。</p>
      </div>
    `;
    const text = `${siteName} 作者注册验证码：${code}\n\n验证码 10 分钟内有效，请勿向他人透露。`;
    const sendRes = await sendResendEmail(env, email, subject, html, text);
    if (!sendRes.ok) {
      const reason = sendRes.reason === 'not_configured'
        ? '邮件服务未配置，请联系管理员'
        : '邮件发送失败，请稍后再试';
      return Response.json({ error: reason }, { status: 500 });
    }

    // 异步清理过期数据
    context.waitUntil(cleanupExpired(env));

    return Response.json({ success: true, message: '验证码已发送，请查收邮箱', expiresInSec: CODE_TTL_MS / 1000 });
  }

  // ===== 验证并创建账号 =====
  if (action === 'verify') {
    const body = await parseJsonBody(request);
    if (!body) return Response.json({ error: '请求格式错误' }, { status: 400 });

    const email = String(body.email || '').trim().toLowerCase();
    const code = String(body.code || '').trim();
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!EMAIL_RE.test(email)) return Response.json({ error: '邮箱格式不正确' }, { status: 400 });
    if (!/^\d{6}$/.test(code)) return Response.json({ error: '验证码格式不正确' }, { status: 400 });
    if (!username || username.length < 2 || username.length > 32) {
      return Response.json({ error: '用户名长度需 2-32 位' }, { status: 400 });
    }
    if (!USERNAME_RE.test(username)) return Response.json({ error: '用户名只能包含字母数字下划线' }, { status: 400 });
    if (/^gh_/i.test(username)) return Response.json({ error: '用户名不能以 gh_ 开头' }, { status: 400 });
    if (!password || password.length < 8) return Response.json({ error: '密码至少 8 位' }, { status: 400 });
    if (password.length > 128) return Response.json({ error: '密码最长 128 位' }, { status: 400 });
    if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
      return Response.json({ error: '密码需包含字母和数字' }, { status: 400 });
    }

    // 用户名占用
    const userExists = await env.DB.prepare('SELECT id FROM admin_users WHERE username = ?').bind(username).first();
    if (userExists) return Response.json({ error: '用户名已存在' }, { status: 409 });

    // 邮箱占用
    const emailExists = await env.DB.prepare('SELECT id FROM admin_users WHERE email = ?').bind(email).first();
    if (emailExists) return Response.json({ error: '该邮箱已注册' }, { status: 409 });

    // 取最新一条未使用的验证记录
    const rec = await env.DB.prepare(
      "SELECT id, code_hash, attempts, expires_at FROM pending_registrations WHERE email = ? AND verified = 0 ORDER BY id DESC LIMIT 1"
    ).bind(email).first();
    if (!rec) return Response.json({ error: '请先获取验证码' }, { status: 400 });

    if (new Date(rec.expires_at) < new Date()) {
      await env.DB.prepare('DELETE FROM pending_registrations WHERE id = ?').bind(rec.id).run().catch(() => {});
      return Response.json({ error: '验证码已过期，请重新获取' }, { status: 400 });
    }
    if (rec.attempts >= MAX_VERIFY_ATTEMPTS) {
      await env.DB.prepare('DELETE FROM pending_registrations WHERE id = ?').bind(rec.id).run().catch(() => {});
      return Response.json({ error: '验证次数过多，请重新获取验证码' }, { status: 429 });
    }

    const codeHash = await sha256Hash('code:' + email + ':' + code);
    if (codeHash !== rec.code_hash) {
      await env.DB.prepare('UPDATE pending_registrations SET attempts = attempts + 1 WHERE id = ?').bind(rec.id).run();
      return Response.json({ error: '验证码错误' }, { status: 400 });
    }

    // 验证通过：创建 author 账号（status=pending 等待审核）
    const passwordHash = await hashPassword(password);
    try {
      await env.DB.prepare(
        "INSERT INTO admin_users (username, password_hash, role, email, status) VALUES (?, ?, 'author', ?, 'pending')"
      ).bind(username, passwordHash, email).run();
    } catch (e) {
      if (e.message && e.message.includes('UNIQUE')) {
        return Response.json({ error: '用户名或邮箱已存在' }, { status: 409 });
      }
      return Response.json({ error: '注册失败，请稍后再试' }, { status: 500 });
    }

    // 标记验证记录已使用，并清理同邮箱其它记录
    await env.DB.batch([
      env.DB.prepare('UPDATE pending_registrations SET verified = 1 WHERE id = ?').bind(rec.id),
      env.DB.prepare('DELETE FROM pending_registrations WHERE email = ? AND id != ?').bind(email, rec.id),
    ]);

    return Response.json({
      success: true,
      message: '注册成功，请等待管理员审核通过后登录',
      pending: true,
    });
  }

  return Response.json({ error: 'Unknown action' }, { status: 400 });
}
