// PUT /api/admin/settings — 更新站点设置
// GET /api/admin/settings?section=github — 读取 GitHub OAuth 配置（仅超管）
// POST /api/admin/settings?section=github — 保存 GitHub OAuth 配置（仅超管）
// GET /api/admin/settings?section=ads — 读取广告配置（仅超管）
// POST /api/admin/settings?section=ads — 保存广告配置（仅超管）
// GET /api/admin/settings?section=email — 读取 Resend 邮件配置（仅超管）
// POST /api/admin/settings?section=email — 保存 Resend 邮件配置（仅超管）
import { checkAdmin, requireSuperAdmin, parseJsonBody } from '../_utils.js';

const ALLOWED_KEYS = ['site_name', 'site_desc', 'footer_text', 'download_enabled'];
const MAX_VALUE_LENGTH = 500;
// 广告 HTML 允许更长（嵌入广告代码 / iframe）
const MAX_AD_HTML_LENGTH = 10000;

export async function onRequestPut(context) {
  const { request, env } = context;

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    const status = auth.reason === 'locked' ? 429 : 401;
    const msg = auth.reason === 'locked' ? 'Too many failed attempts, try again later' : 'Unauthorized';
    return Response.json({ error: msg }, { status });
  }
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可修改设置' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || typeof body.settings !== 'object') {
    return Response.json({ error: 'Invalid request, expected { settings: { key: value } }' }, { status: 400 });
  }

  const updates = [];
  for (const [key, value] of Object.entries(body.settings)) {
    if (!ALLOWED_KEYS.includes(key)) continue;
    // 字符串字段
    if (typeof value === 'string') {
      const trimmed = value.trim().slice(0, MAX_VALUE_LENGTH);
      updates.push(
        env.DB.prepare('INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)')
          .bind(key, trimmed)
      );
      continue;
    }
    // 布尔字段：序列化为 'true' / 'false'
    if (key === 'download_enabled' && typeof value === 'boolean') {
      updates.push(
        env.DB.prepare('INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)')
          .bind(key, value ? 'true' : 'false')
      );
    }
  }

  if (updates.length > 0) {
    await env.DB.batch(updates);
  }

  return Response.json({ success: true, updated: updates.length });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可查看' }, { status: 403 });

  const url = new URL(request.url);
  const section = url.searchParams.get('section');

  // GET /api/admin/settings?section=github
  if (section === 'github') {
    const enabled = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'github_oauth_enabled'").first();
    const clientId = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'github_client_id'").first();
    const hasSecret = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'github_client_secret'").first();
    const demoLimitRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'demo_user_limit'").first();
    return Response.json({
      enabled: enabled?.value === 'true',
      clientId: clientId?.value || '',
      hasSecret: !!hasSecret?.value,
      demoLimit: demoLimitRow ? Number(demoLimitRow.value) : 100,
    });
  }

  // GET /api/admin/settings?section=ads
  if (section === 'ads') {
    const keys = [
      'ad_enabled', 'ad_mode',
      'ad_left_html', 'ad_right_html', 'ad_popup_html',
      'ad_adsense_client',
      'ad_adsense_slot_left', 'ad_adsense_slot_right', 'ad_adsense_slot_popup',
      'ad_popup_delay', 'ad_popup_interval'
    ];
    const { results } = await env.DB.prepare(
      `SELECT key, value FROM site_settings WHERE key IN (${keys.map(() => '?').join(',')})`
    ).bind(...keys).all();
    const map = {};
    for (const row of results) map[row.key] = row.value;
    return Response.json({
      enabled: map.ad_enabled === 'true',
      mode: map.ad_mode || 'custom',
      leftHtml: map.ad_left_html || '',
      rightHtml: map.ad_right_html || '',
      popupHtml: map.ad_popup_html || '',
      adsenseClient: map.ad_adsense_client || '',
      adsenseSlotLeft: map.ad_adsense_slot_left || '',
      adsenseSlotRight: map.ad_adsense_slot_right || '',
      adsenseSlotPopup: map.ad_adsense_slot_popup || '',
      popupDelay: map.ad_popup_delay ? Number(map.ad_popup_delay) : 5,
      popupInterval: map.ad_popup_interval ? Number(map.ad_popup_interval) : 30,
    });
  }

  // GET /api/admin/settings?section=email
  if (section === 'email') {
    const enabled = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'author_registration_enabled'").first();
    const fromRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_from'").first();
    const hasKey = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_api_key'").first();
    const subjectRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'resend_subject'").first();
    return Response.json({
      registrationEnabled: enabled?.value === 'true',
      from: fromRow?.value || '',
      hasApiKey: !!hasKey?.value,
      subject: subjectRow?.value || '【小说站】注册验证码',
    });
  }

  return Response.json({ error: 'Unknown section' }, { status: 400 });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可修改' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });

  const url = new URL(request.url);
  const section = url.searchParams.get('section');

  // POST /api/admin/settings?section=github
  if (section === 'github') {
    const { enabled, clientId, clientSecret, demoLimit } = body;

    await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('github_oauth_enabled', ?)")
      .bind(enabled ? 'true' : 'false').run();

    if (clientId !== undefined) {
      const id = (clientId || '').trim().slice(0, 100);
      await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('github_client_id', ?)")
        .bind(id).run();
    }

    if (clientSecret && clientSecret.trim()) {
      await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('github_client_secret', ?)")
        .bind(clientSecret.trim().slice(0, 200)).run();
    }

    if (demoLimit !== undefined) {
      const limit = Math.max(0, Math.min(10000, Math.floor(Number(demoLimit) || 0)));
      await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('demo_user_limit', ?)")
        .bind(String(limit)).run();
    }

    return Response.json({ success: true });
  }

  // POST /api/admin/settings?section=ads
  if (section === 'ads') {
    const {
      enabled, mode, leftHtml, rightHtml, popupHtml,
      adsenseClient, adsenseSlotLeft, adsenseSlotRight, adsenseSlotPopup,
      popupDelay, popupInterval
    } = body;

    const VALID_MODES = ['custom', 'adsense', 'both'];
    const safeMode = VALID_MODES.includes(mode) ? mode : 'custom';

    const updates = [
      env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('ad_enabled', ?)")
        .bind(enabled ? 'true' : 'false'),
      env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('ad_mode', ?)")
        .bind(safeMode),
    ];

    const htmlFields = [
      ['ad_left_html', leftHtml],
      ['ad_right_html', rightHtml],
      ['ad_popup_html', popupHtml],
    ];
    for (const [key, val] of htmlFields) {
      if (val !== undefined) {
        const safe = String(val || '').slice(0, MAX_AD_HTML_LENGTH);
        updates.push(env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)").bind(key, safe));
      }
    }

    const idFields = [
      ['ad_adsense_client', adsenseClient],
      ['ad_adsense_slot_left', adsenseSlotLeft],
      ['ad_adsense_slot_right', adsenseSlotRight],
      ['ad_adsense_slot_popup', adsenseSlotPopup],
    ];
    for (const [key, val] of idFields) {
      if (val !== undefined) {
        const safe = String(val || '').trim().slice(0, 100);
        updates.push(env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)").bind(key, safe));
      }
    }

    if (popupDelay !== undefined) {
      const d = Math.max(0, Math.min(60, Math.floor(Number(popupDelay) || 0)));
      updates.push(env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('ad_popup_delay', ?)").bind(String(d)));
    }
    if (popupInterval !== undefined) {
      const i = Math.max(0, Math.min(1440, Math.floor(Number(popupInterval) || 0)));
      updates.push(env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('ad_popup_interval', ?)").bind(String(i)));
    }

    await env.DB.batch(updates);
    return Response.json({ success: true });
  }

  // POST /api/admin/settings?section=email
  if (section === 'email') {
    const { registrationEnabled, from, apiKey, subject } = body;

    await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('author_registration_enabled', ?)")
      .bind(registrationEnabled ? 'true' : 'false').run();

    if (from !== undefined) {
      const safeFrom = String(from || '').trim().slice(0, 200);
      // 简单的邮箱格式校验
      if (safeFrom && !/^([^<>"\s]+ <)?[^@<>"\s]+@[^@<>"\s]+\.[^@<>"\s]+>?$/.test(safeFrom)) {
        return Response.json({ error: '发件人格式不正确，应为 邮箱 或 "名称 <邮箱>"' }, { status: 400 });
      }
      await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('resend_from', ?)")
        .bind(safeFrom).run();
    }

    if (apiKey && apiKey.trim()) {
      await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('resend_api_key', ?)")
        .bind(apiKey.trim().slice(0, 200)).run();
    }

    if (subject !== undefined) {
      const safeSubject = String(subject || '【小说站】注册验证码').trim().slice(0, 200);
      await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES ('resend_subject', ?)")
        .bind(safeSubject).run();
    }

    return Response.json({ success: true });
  }

  return Response.json({ error: 'Unknown section' }, { status: 400 });
}
