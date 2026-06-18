// GET /api/settings — 公开读取站点设置（白名单过滤）
const PUBLIC_KEYS = ['site_name', 'site_desc', 'footer_text', 'custom_fonts', 'download_enabled'];
const AD_KEYS = [
  'ad_enabled', 'ad_mode',
  'ad_left_html', 'ad_right_html', 'ad_popup_html',
  'ad_adsense_client',
  'ad_adsense_slot_left', 'ad_adsense_slot_right', 'ad_adsense_slot_popup',
  'ad_popup_delay', 'ad_popup_interval'
];

export async function onRequestGet(context) {
  const { env, request } = context;
  const url = new URL(request.url);

  // GET /api/settings?check=github — 检查 GitHub 登录是否启用（公开）
  if (url.searchParams.get('check') === 'github') {
    const enabled = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'github_oauth_enabled'").first();
    return Response.json({ githubLoginEnabled: enabled?.value === 'true' });
  }

  // GET /api/settings?check=register — 检查作者邮箱注册是否启用（公开）
  if (url.searchParams.get('check') === 'register') {
    const enabled = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'author_registration_enabled'").first();
    const userEnabled = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'user_registration_enabled'").first();
    return Response.json({
      authorRegistrationEnabled: enabled?.value === 'true',
      userRegistrationEnabled: userEnabled?.value === 'true',
    });
  }

  // GET /api/settings?check=ads — 获取广告配置（公开，阅读页使用）
  if (url.searchParams.get('check') === 'ads') {
    const { results } = await env.DB.prepare(
      `SELECT key, value FROM site_settings WHERE key IN (${AD_KEYS.map(() => '?').join(',')})`
    ).bind(...AD_KEYS).all();
    const ads = {};
    for (const row of results) ads[row.key] = row.value;
    const enabled = ads.ad_enabled === 'true';
    if (!enabled) return Response.json({ enabled: false });
    return Response.json({
      enabled: true,
      mode: ads.ad_mode || 'custom', // 'custom' | 'adsense' | 'both'
      leftHtml: ads.ad_left_html || '',
      rightHtml: ads.ad_right_html || '',
      popupHtml: ads.ad_popup_html || '',
      adsenseClient: ads.ad_adsense_client || '',
      adsenseSlotLeft: ads.ad_adsense_slot_left || '',
      adsenseSlotRight: ads.ad_adsense_slot_right || '',
      adsenseSlotPopup: ads.ad_adsense_slot_popup || '',
      popupDelay: Number(ads.ad_popup_delay) || 5,
      popupInterval: Number(ads.ad_popup_interval) || 30,
    });
  }

  const { results } = await env.DB.prepare('SELECT key, value FROM site_settings').all();
  const settings = {};
  for (const row of results) {
    if (PUBLIC_KEYS.includes(row.key)) {
      settings[row.key] = row.value;
    }
  }
  // 规范化布尔字段
  if ('download_enabled' in settings) {
    settings.download_enabled = settings.download_enabled === 'true';
  }
  return Response.json({ settings });
}
