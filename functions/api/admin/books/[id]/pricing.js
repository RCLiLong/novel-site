// 书籍定价管理（超管 + 书籍所有者可管理）
// GET  /api/admin/books/:id/pricing — 读取
// PUT  /api/admin/books/:id/pricing — 更新 free_chapters / price
import { checkAdmin, requireMinRole, checkBookOwnership, validateId, parseJsonBody } from '../../../_utils.js';

const MAX_FREE_CHAPTERS = 100000;     // 单本最多允许的免费章节
const MAX_PRICE = 1000000;             // 积分上限

export async function onRequestGet(context) {
  const { env, params, request } = context;
  const bookId = params.id;
  if (!validateId(bookId)) {
    return Response.json({ error: 'Invalid book ID' }, { status: 400 });
  }
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin') && !await checkBookOwnership(auth, env, bookId)) {
    return Response.json({ error: '无权查看此书定价' }, { status: 403 });
  }

  const pricing = await env.DB.prepare('SELECT free_chapters, price, updated_at FROM book_pricing WHERE book_id = ?').bind(bookId).first();
  return Response.json({
    pricing: pricing || { free_chapters: 0, price: 0, updated_at: null }
  });
}

export async function onRequestPut(context) {
  const { env, params, request } = context;
  const bookId = params.id;
  if (!validateId(bookId)) {
    return Response.json({ error: 'Invalid book ID' }, { status: 400 });
  }
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  // author 仅能管理自己书的定价
  if (!requireMinRole(auth, 'admin') && !await checkBookOwnership(auth, env, bookId)) {
    return Response.json({ error: '无权修改此书定价' }, { status: 403 });
  }

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });

  const freeChapters = body.free_chapters !== undefined ? Math.floor(Number(body.free_chapters)) : 0;
  const price = body.price !== undefined ? Math.floor(Number(body.price)) : 0;
  if (!Number.isInteger(freeChapters) || freeChapters < 0 || freeChapters > MAX_FREE_CHAPTERS) {
    return Response.json({ error: '免费章节数不合法' }, { status: 400 });
  }
  if (!Number.isInteger(price) || price < 0 || price > MAX_PRICE) {
    return Response.json({ error: '价格不合法' }, { status: 400 });
  }

  // 确认书籍存在
  const book = await env.DB.prepare('SELECT id FROM books WHERE id = ?').bind(bookId).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });

  // 章节数检查：免费章节数不能超过实际章节数
  const { count } = await env.DB.prepare('SELECT COUNT(*) as count FROM chapters WHERE book_id = ?').bind(bookId).first();
  if (freeChapters > count + 100) {
    return Response.json({ error: '免费章节数过多（当前 ' + count + ' 章）' }, { status: 400 });
  }

  await env.DB.prepare(
    `INSERT INTO book_pricing (book_id, free_chapters, price, updated_at)
     VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(book_id) DO UPDATE SET
       free_chapters = excluded.free_chapters,
       price = excluded.price,
       updated_at = datetime('now')`
  ).bind(bookId, freeChapters, price).run();

  return Response.json({ success: true, free_chapters: freeChapters, price });
}
