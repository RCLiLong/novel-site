import { checkAdmin } from '../../_utils.js';

// POST /api/admin/annotations/batch - 批量操作
export async function onRequestPost(context) {
  const { request, env } = context;
  
  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '请先登录' }, { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'invalid JSON' }, { status: 400 });
  }

  const { ids, action } = body;

  if (!Array.isArray(ids) || ids.length === 0) {
    return Response.json({ error: '请选择要操作的批注' }, { status: 400 });
  }
  if (ids.length > 100) {
    return Response.json({ error: '单次最多操作100条' }, { status: 400 });
  }
  if (!['remove', 'restore'].includes(action)) {
    return Response.json({ error: '无效的操作' }, { status: 400 });
  }

  // 验证所有 ID 格式
  for (const id of ids) {
    if (!/^\d{1,18}$/.test(String(id))) {
      return Response.json({ error: '无效的批注ID' }, { status: 400 });
    }
  }

  const newStatus = action === 'remove' ? 'removed' : 'normal';
  const placeholders = ids.map(() => '?').join(',');

  // 根据权限构建过滤条件
  let permFilter = '';
  const permBinds = [];
  
  if (auth.role === 'admin') {
    // admin 不能操作超管的批注
    permFilter = `AND a.id IN (
      SELECT a2.id FROM annotations a2
      LEFT JOIN admin_users u2 ON a2.user_id = u2.id
      WHERE u2.role != 'super_admin' OR u2.role IS NULL
    )`;
  } else if (auth.role === 'author') {
    // author 可操作：自己的批注 + 自己书上的非超管批注
    permFilter = `AND a.id IN (
      SELECT a2.id FROM annotations a2
      LEFT JOIN admin_users u2 ON a2.user_id = u2.id
      LEFT JOIN books b2 ON a2.book_id = b2.id
      WHERE a2.user_id = ? OR (b2.created_by = ? AND (u2.role IS NULL OR u2.role != 'super_admin'))
    )`;
    permBinds.push(auth.userId, auth.userId);
  } else if (auth.role === 'demo') {
    // demo 只能操作自己的批注或自己书上的 demo 批注
    permFilter = `AND a.id IN (
      SELECT a2.id FROM annotations a2
      LEFT JOIN admin_users u2 ON a2.user_id = u2.id
      LEFT JOIN books b2 ON a2.book_id = b2.id
      WHERE a2.user_id = ? OR (b2.created_by = ? AND u2.role = 'demo')
    )`;
    permBinds.push(auth.userId, auth.userId);
  }

  const result = await env.DB.prepare(`
    UPDATE annotations a
    SET status = ?, updated_at = datetime('now')
    WHERE id IN (${placeholders}) ${permFilter}
  `).bind(newStatus, ...ids, ...permBinds).run();

  return Response.json({ 
    success: true, 
    affected: result.meta.changes 
  });
}
