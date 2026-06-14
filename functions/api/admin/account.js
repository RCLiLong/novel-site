// DELETE /api/admin/account — demo / author 用户自助注销
import { checkAdmin, requireMinRole } from '../_utils.js';

export async function onRequestDelete(context) {
  const { request, env } = context;

  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  // 只有 demo / author 用户可以自助注销
  if (requireMinRole(auth, 'admin')) {
    return Response.json({ error: '管理员及以上角色请联系超级管理员注销' }, { status: 403 });
  }

  const userId = auth.userId;

  // 找到第一个 super_admin 作为内容接收者
  const superAdmin = await env.DB.prepare(
    "SELECT id FROM admin_users WHERE role = 'super_admin' ORDER BY id ASC LIMIT 1"
  ).first();

  if (!superAdmin) {
    return Response.json({ error: '系统异常：无超级管理员' }, { status: 500 });
  }

  // 原子操作：转移内容所有权 + 清理用户数据
  await env.DB.batch([
    // 转移书籍所有权给第一个超管
    env.DB.prepare('UPDATE books SET created_by = ? WHERE created_by = ?').bind(superAdmin.id, userId),
    // 删除所有 session
    env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(userId),
    // 删除用户记录
    env.DB.prepare('DELETE FROM admin_users WHERE id = ?').bind(userId),
  ]);

  return Response.json({
    success: true,
    message: '账号已注销，您创建的内容已转交管理员保管'
  });
}
