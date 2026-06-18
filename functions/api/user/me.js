// 用户中心：余额 / 订阅 / 看广告奖励 / 购买解锁 / 充值
// GET  /api/user/me                        — 当前用户信息（未登录 401）
// GET  /api/user/me?action=balance         — 余额 + 流水 + 今日广告剩余
// GET  /api/user/me?action=subscriptions   — 已订阅列表
// POST /api/user/me?action=watch-ad        — 看广告奖励积分
// POST /api/user/me?action=unlock          — 购买解锁一本书（body: { book_id }）
// POST /api/user/me?action=recharge        — 充值（默认拒绝，留待支付接入）
import { checkUserAdmin, parseJsonBody } from '../_utils.js';

const AD_REWARD_CREDITS = 5;
const MAX_AD_REWARDS_PER_DAY = 5;

// ===== GET =====
export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const auth = await checkUserAdmin(request, env);
  if (!auth.ok) return Response.json({ error: '请先登录' }, { status: 401 });

  if (action === 'balance' || action === null) {
    const todayCount = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM ad_rewards WHERE user_id = ? AND created_at > datetime('now', '-1 day')"
    ).bind(auth.userId).first();
    const recentLog = await env.DB.prepare(
      "SELECT delta, reason, related_book_id, created_at FROM user_balance_log WHERE user_id = ? ORDER BY id DESC LIMIT 20"
    ).bind(auth.userId).all();
    return Response.json({
      balance: auth.balance,
      adRemainingToday: Math.max(0, MAX_AD_REWARDS_PER_DAY - (todayCount?.c || 0)),
      log: recentLog.results || [],
    });
  }

  if (action === 'subscriptions') {
    const { results } = await env.DB.prepare(`
      SELECT s.id, s.book_id, s.amount, s.source, s.created_at,
             b.title, b.author, b.cover_key,
             (SELECT COUNT(*) FROM chapters WHERE book_id = b.id) as chapter_count
      FROM subscriptions s
      JOIN books b ON s.book_id = b.id
      WHERE s.user_id = ?
      ORDER BY s.created_at DESC
    `).bind(auth.userId).all();
    return Response.json({ subscriptions: results });
  }

  return Response.json({ error: 'Unknown action' }, { status: 400 });
}

// ===== POST =====
export async function onRequestPost(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const auth = await checkUserAdmin(request, env);
  if (!auth.ok) return Response.json({ error: '请先登录读者账号' }, { status: 401 });

  const body = await parseJsonBody(request) || {};

  if (action === 'watch-ad') {
    const slot = String(body.slot || 'user-center').slice(0, 50);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const { sha256Hash } = await import('../_utils.js');
    const ipHash = await sha256Hash('ad_reward:' + ip);
    const todayCount = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM ad_rewards WHERE user_id = ? AND created_at > datetime('now', '-1 day')"
    ).bind(auth.userId).first();
    if ((todayCount?.c || 0) >= MAX_AD_REWARDS_PER_DAY) {
      return Response.json({ error: '今日广告奖励已达上限' }, { status: 429 });
    }
    await env.DB.batch([
      env.DB.prepare('INSERT INTO ad_rewards (user_id, ad_slot, credits, ip_hash) VALUES (?, ?, ?, ?)')
        .bind(auth.userId, slot, AD_REWARD_CREDITS, ipHash),
      env.DB.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').bind(AD_REWARD_CREDITS, auth.userId),
      env.DB.prepare("INSERT INTO user_balance_log (user_id, delta, reason) VALUES (?, ?, '看广告奖励')")
        .bind(auth.userId, AD_REWARD_CREDITS),
    ]);
    const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(auth.userId).first();
    return Response.json({
      success: true,
      creditsAdded: AD_REWARD_CREDITS,
      balance: user?.balance || 0,
      remainingToday: MAX_AD_REWARDS_PER_DAY - (todayCount?.c || 0) - 1,
    });
  }

  if (action === 'recharge') {
    const credits = Number(body.credits || 0);
    if (!Number.isInteger(credits) || credits <= 0 || credits > 100000) {
      return Response.json({ error: '充值积分数值不合法' }, { status: 400 });
    }
    return Response.json({ error: '当前未接入在线支付渠道，请联系管理员充值或通过看广告赚取积分' }, { status: 403 });
  }

  if (action === 'unlock') {
    const bookId = Number(body.book_id);
    if (!bookId || !/^\d{1,18}$/.test(String(bookId))) {
      return Response.json({ error: '书籍ID不合法' }, { status: 400 });
    }
    const book = await env.DB.prepare('SELECT id, title FROM books WHERE id = ?').bind(bookId).first();
    if (!book) return Response.json({ error: '书籍不存在' }, { status: 404 });
    const pricing = await env.DB.prepare('SELECT free_chapters, price FROM book_pricing WHERE book_id = ?').bind(bookId).first();
    const price = pricing?.price || 0;
    if (price <= 0) {
      return Response.json({ error: '该书籍免费，无需购买', free: true }, { status: 400 });
    }
    const sub = await env.DB.prepare('SELECT id FROM subscriptions WHERE user_id = ? AND book_id = ?')
      .bind(auth.userId, bookId).first();
    if (sub) {
      return Response.json({ success: true, alreadyUnlocked: true, message: '已订阅过该书' });
    }
    const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(auth.userId).first();
    if (!user || user.balance < price) {
      return Response.json({ error: '积分不足，请充值或看广告赚取', need: price, balance: user?.balance || 0 }, { status: 402 });
    }
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET balance = balance - ?, updated_at = datetime(\'now\') WHERE id = ?').bind(price, auth.userId),
      env.DB.prepare("INSERT INTO user_balance_log (user_id, delta, reason, related_book_id) VALUES (?, ?, '购买订阅', ?)").bind(auth.userId, -price, bookId),
      env.DB.prepare('INSERT OR IGNORE INTO subscriptions (user_id, book_id, amount, source) VALUES (?, ?, ?, \'recharge\')').bind(auth.userId, bookId, price),
    ]);
    const newBal = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(auth.userId).first();
    return Response.json({ success: true, message: '订阅成功', balance: newBal?.balance || 0 });
  }

  return Response.json({ error: 'Unknown action' }, { status: 400 });
}
