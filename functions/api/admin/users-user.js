// 读者用户管理 API（仅超管可用）
// GET    /api/admin/users-user              — 用户列表
// POST   /api/admin/users-user              — 调整用户积分（充值/扣款）
// DELETE /api/admin/users-user              — 封禁/删除用户
// PUT    /api/admin/users-user              — 启用/封禁
import { checkAdmin, requireSuperAdmin, validateId, parseJsonBody } from '../_utils.js';

// GET: 用户列表
export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可管理读者' }, { status: 403 });

  const { results } = await env.DB.prepare(`
    SELECT u.id, u.username, u.email, u.status, u.balance, u.created_at, u.updated_at,
      (SELECT COUNT(*) FROM subscriptions WHERE user_id = u.id) as book_count,
      (SELECT COUNT(*) FROM user_sessions WHERE user_id = u.id AND expires_at > datetime('now')) as active_sessions
    FROM users u
    ORDER BY u.id
  `).all();
  return Response.json({ users: results });
}

// POST: 调整用户积分（超管手动充值/扣款）
export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可充值' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少用户ID' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '无效的用户ID' }, { status: 400 });

  const credits = Math.floor(Number(body.credits || 0));
  if (!Number.isInteger(credits) || credits === 0 || Math.abs(credits) > 100000) {
    return Response.json({ error: '积分数值不合法' }, { status: 400 });
  }
  const reason = String(body.reason || (credits > 0 ? '管理员充值' : '管理员扣款')).trim().slice(0, 200);

  const user = await env.DB.prepare('SELECT username, balance FROM users WHERE id = ?').bind(body.id).first();
  if (!user) return Response.json({ error: '用户不存在' }, { status: 404 });

  await env.DB.batch([
    env.DB.prepare('UPDATE users SET balance = balance + ?, updated_at = datetime(\'now\') WHERE id = ?').bind(credits, body.id),
    env.DB.prepare('INSERT INTO user_balance_log (user_id, delta, reason) VALUES (?, ?, ?)').bind(body.id, credits, reason),
  ]);
  const newBal = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(body.id).first();
  return Response.json({ success: true, message: `已为 ${user.username} ${credits > 0 ? '充值' : '扣款'} ${Math.abs(credits)} 积分`, balance: newBal.balance });
}

// DELETE: 删除用户
export async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可删除读者' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少用户ID' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '无效的用户ID' }, { status: 400 });

  const user = await env.DB.prepare('SELECT username, status FROM users WHERE id = ?').bind(body.id).first();
  if (!user) return Response.json({ error: '用户不存在' }, { status: 404 });

  // 原子：清理会话、订阅、点赞关联
  await env.DB.batch([
    env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(body.id),
    env.DB.prepare('DELETE FROM subscriptions WHERE user_id = ?').bind(body.id),
    env.DB.prepare('DELETE FROM ad_rewards WHERE user_id = ?').bind(body.id),
    env.DB.prepare('DELETE FROM user_balance_log WHERE user_id = ?').bind(body.id),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(body.id),
  ]);
  return Response.json({ success: true, message: `用户 ${user.username} 已删除` });
}

// PUT: 修改用户状态
export async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '仅超级管理员可管理读者' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少用户ID' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '无效的用户ID' }, { status: 400 });

  const VALID_STATUS = ['active', 'banned'];
  if (body.status !== undefined && !VALID_STATUS.includes(body.status)) {
    return Response.json({ error: '无效的状态值' }, { status: 400 });
  }

  const user = await env.DB.prepare('SELECT username FROM users WHERE id = ?').bind(body.id).first();
  if (!user) return Response.json({ error: '用户不存在' }, { status: 404 });

  if (body.status !== undefined) {
    await env.DB.prepare('UPDATE users SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(body.status, body.id).run();
    if (body.status === 'banned') {
      await env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(body.id).run().catch(() => {});
    }
  }
  return Response.json({ success: true });
}
