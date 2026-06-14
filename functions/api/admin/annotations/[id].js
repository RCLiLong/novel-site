import { checkAdmin } from '../../_utils.js';

// PUT /api/admin/annotations/[id] - 修改批注状态（移除/恢复）
export async function onRequestPut(context) {
  const { request, env, params } = context;
  const annoId = params.id;

  if (!/^\d{1,18}$/.test(annoId)) {
    return Response.json({ error: 'invalid id' }, { status: 400 });
  }

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '请先登录' }, { status: 401 });
  }

  // 获取批注信息
  const anno = await env.DB.prepare(`
    SELECT a.*, u.role as user_role, b.created_by as book_owner
    FROM annotations a
    LEFT JOIN admin_users u ON a.user_id = u.id
    LEFT JOIN books b ON a.book_id = b.id
    WHERE a.id = ?
  `).bind(annoId).first();

  if (!anno) {
    return Response.json({ error: '批注不存在' }, { status: 404 });
  }

  // 权限检查
  if (auth.role === 'demo') {
    // demo 只能操作自己的批注或自己书上的 demo 批注
    const canOperate = anno.user_id === auth.userId || 
      (anno.book_owner === auth.userId && anno.user_role === 'demo');
    if (!canOperate) {
      return Response.json({ error: '无权操作此批注' }, { status: 403 });
    }
  } else if (auth.role === 'author') {
    // author 可操作：自己的批注 + 自己书上的非超管批注
    const canOperate = anno.user_id === auth.userId ||
      (anno.book_owner === auth.userId && anno.user_role !== 'super_admin');
    if (!canOperate) {
      return Response.json({ error: '无权操作此批注' }, { status: 403 });
    }
  } else if (auth.role === 'admin') {
    // admin 不能操作超管的批注
    if (anno.user_role === 'super_admin') {
      return Response.json({ error: '无权操作超级管理员的批注' }, { status: 403 });
    }
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'invalid JSON' }, { status: 400 });
  }

  const { status } = body;
  if (!['normal', 'removed', 'hidden'].includes(status)) {
    return Response.json({ error: '无效的状态' }, { status: 400 });
  }

  await env.DB.prepare(`
    UPDATE annotations SET status = ?, updated_at = datetime('now') WHERE id = ?
  `).bind(status, annoId).run();

  return Response.json({ success: true, status });
}

// DELETE /api/admin/annotations/[id] - 永久删除批注（仅超管）
export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const annoId = params.id;

  if (!/^\d{1,18}$/.test(annoId)) {
    return Response.json({ error: 'invalid id' }, { status: 400 });
  }

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '请先登录' }, { status: 401 });
  }

  // 仅超管可永久删除
  if (auth.role !== 'super_admin') {
    return Response.json({ error: '仅超级管理员可永久删除批注' }, { status: 403 });
  }

  // 检查批注是否存在且已移除
  const anno = await env.DB.prepare('SELECT status FROM annotations WHERE id = ?').bind(annoId).first();
  if (!anno) {
    return Response.json({ error: '批注不存在' }, { status: 404 });
  }
  if (anno.status !== 'removed') {
    return Response.json({ error: '只能永久删除已移除的批注' }, { status: 400 });
  }

  // 删除相关点赞
  await env.DB.prepare('DELETE FROM annotation_likes WHERE annotation_id = ?').bind(annoId).run();
  // 删除批注
  await env.DB.prepare('DELETE FROM annotations WHERE id = ?').bind(annoId).run();

  return Response.json({ success: true });
}
