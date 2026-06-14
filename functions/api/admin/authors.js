// 作者账号管理 API（admin 及超级管理员可用）
// 作者（author）角色：只能管理自己创建的书籍/章节，无 demo 配额限制
// GET /api/admin/authors                 — 已激活作者列表
// GET /api/admin/authors?status=pending  — 待审核作者列表
// POST /api/admin/authors                — 管理员直接创建作者（默认 active）
// PUT /api/admin/authors                 — 更新作者（password_locked / new_password / status / action=approve|reject）
// DELETE /api/admin/authors              — 删除作者
import { checkAdmin, requireMinRole, validateId, hashPassword, parseJsonBody } from '../_utils.js';

const VALID_STATUS = ['active', 'pending', 'rejected'];

// GET: 获取作者列表（admin+ 可查看）
export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '仅管理员及以上可管理作者' }, { status: 403 });

  const url = new URL(request.url);
  const statusFilter = url.searchParams.get('status'); // pending / active / rejected / all

  let where = "u.role = 'author'";
  let binds = [];
  if (statusFilter === 'pending' || statusFilter === 'active' || statusFilter === 'rejected') {
    where += " AND (u.status = ? OR (u.status IS NULL AND ? = 'active'))";
    binds.push(statusFilter, statusFilter);
  }

  const { results } = await env.DB.prepare(
    `SELECT u.id, u.username, u.email, u.status, u.role, u.password_locked, u.github_id, u.github_login, u.avatar_url, u.created_at, u.updated_at,
      (SELECT COUNT(*) FROM books WHERE created_by = u.id) as book_count,
      (SELECT COALESCE(SUM(word_count), 0) FROM chapters WHERE book_id IN (SELECT id FROM books WHERE created_by = u.id)) as total_words
    FROM admin_users u WHERE ${where} ORDER BY u.id`
  ).bind(...binds).all();

  // 同时返回待审核计数（前端做角标用）
  const pendingCountRow = await env.DB.prepare(
    "SELECT COUNT(*) as c FROM admin_users WHERE role = 'author' AND status = 'pending'"
  ).first();

  return Response.json({ authors: results, pendingCount: pendingCountRow?.c || 0 });
}

// POST: 创建新作者（admin+ 可创建，默认 active 状态）
export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '仅管理员及以上可创建作者' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: '无效的请求' }, { status: 400 });

  const { username, password, password_locked, email } = body;
  if (!username || !password) return Response.json({ error: '用户名和密码不能为空' }, { status: 400 });
  if (username.length < 2 || username.length > 32) return Response.json({ error: '用户名长度2-32位' }, { status: 400 });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return Response.json({ error: '用户名只能包含字母数字下划线' }, { status: 400 });
  if (/^gh_/i.test(username)) return Response.json({ error: '用户名不能以 gh_ 开头（保留给 GitHub 登录用户）' }, { status: 400 });
  if (password.length < 8) return Response.json({ error: '密码至少8位' }, { status: 400 });
  if (password.length > 128) return Response.json({ error: '密码最长128位' }, { status: 400 });
  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) return Response.json({ error: '密码需包含字母和数字' }, { status: 400 });

  let safeEmail = null;
  if (email !== undefined && email !== null && String(email).trim() !== '') {
    safeEmail = String(email).trim().toLowerCase().slice(0, 200);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(safeEmail)) {
      return Response.json({ error: '邮箱格式不正确' }, { status: 400 });
    }
    const emailUsed = await env.DB.prepare('SELECT id FROM admin_users WHERE email = ?').bind(safeEmail).first();
    if (emailUsed) return Response.json({ error: '该邮箱已被占用' }, { status: 409 });
  }

  const pwdLocked = password_locked === 1 ? 1 : 0;

  const existing = await env.DB.prepare('SELECT id FROM admin_users WHERE username = ?').bind(username).first();
  if (existing) return Response.json({ error: '用户名已存在' }, { status: 409 });

  const passwordHash = await hashPassword(password);

  await env.DB.prepare("INSERT INTO admin_users (username, password_hash, role, password_locked, email, status) VALUES (?, ?, 'author', ?, ?, 'active')")
    .bind(username, passwordHash, pwdLocked, safeEmail).run();

  return Response.json({ success: true, message: `作者 ${username} 创建成功` });
}

// DELETE: 删除作者，并将其书籍转交给当前操作的管理员
export async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '仅管理员及以上可删除作者' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少作者ID' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '无效的作者ID' }, { status: 400 });

  const user = await env.DB.prepare('SELECT username, role FROM admin_users WHERE id = ?').bind(body.id).first();
  if (!user) return Response.json({ error: '作者不存在' }, { status: 404 });
  if (user.role !== 'author') return Response.json({ error: '此账号不是作者，无法通过此接口删除' }, { status: 400 });

  // 内容接收者：优先第一个超管，否则当前操作者
  const superAdmin = await env.DB.prepare(
    "SELECT id FROM admin_users WHERE role = 'super_admin' ORDER BY id ASC LIMIT 1"
  ).first();
  const newOwner = superAdmin ? superAdmin.id : auth.userId;

  await env.DB.batch([
    env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(body.id),
    env.DB.prepare('UPDATE books SET created_by = ? WHERE created_by = ?').bind(newOwner, body.id),
    env.DB.prepare('DELETE FROM admin_users WHERE id = ?').bind(body.id),
  ]);

  return Response.json({ success: true, message: `作者 ${user.username} 已删除，其书籍已转交保管` });
}

// PUT: 修改作者属性（password_locked / new_password / status / action=approve|reject）
export async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '仅管理员及以上可修改作者' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少参数' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '无效的作者ID' }, { status: 400 });

  const target = await env.DB.prepare('SELECT id, role, email, status FROM admin_users WHERE id = ?').bind(body.id).first();
  if (!target) return Response.json({ error: '作者不存在' }, { status: 404 });
  if (target.role !== 'author') return Response.json({ error: '此账号不是作者，请前往管理员管理' }, { status: 400 });

  const hasPwdLock = body.password_locked !== undefined;
  const hasNewPwd = typeof body.new_password === 'string' && body.new_password.length > 0;
  const hasStatus = body.status !== undefined || body.action !== undefined;

  if (!hasPwdLock && !hasNewPwd && !hasStatus) return Response.json({ error: '没有可更新的字段' }, { status: 400 });

  // 审核：action 简写
  let newStatus = body.status;
  if (body.action === 'approve') newStatus = 'active';
  else if (body.action === 'reject') newStatus = 'rejected';

  if (hasStatus) {
    if (!VALID_STATUS.includes(newStatus)) return Response.json({ error: '无效的状态值' }, { status: 400 });
    await env.DB.prepare("UPDATE admin_users SET status = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(newStatus, body.id).run();
    // 拒绝或冻结：清理 session
    if (newStatus !== 'active') {
      await env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(body.id).run().catch(() => {});
    }
  }

  // 重置密码：仅超管可执行
  if (hasNewPwd) {
    if (auth.role !== 'super_admin') return Response.json({ error: '仅超级管理员可重置作者密码' }, { status: 403 });
    const pwd = body.new_password;
    if (pwd.length < 8) return Response.json({ error: '密码至少8位' }, { status: 400 });
    if (pwd.length > 128) return Response.json({ error: '密码最长128位' }, { status: 400 });
    if (!/[a-zA-Z]/.test(pwd) || !/\d/.test(pwd)) return Response.json({ error: '密码需包含字母和数字' }, { status: 400 });
    const passwordHash = await hashPassword(pwd);
    await env.DB.prepare("UPDATE admin_users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(passwordHash, body.id).run();
    await env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(body.id).run().catch(() => {});
  }

  if (hasPwdLock) {
    if (body.password_locked !== 0 && body.password_locked !== 1) {
      return Response.json({ error: '无效的锁定状态' }, { status: 400 });
    }
    await env.DB.prepare("UPDATE admin_users SET password_locked = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(body.password_locked, body.id).run();
  }

  return Response.json({ success: true });
}
