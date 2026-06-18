// GET /api/books/:id/download?format=txt|json
// 服务端导出：受 download_enabled 后台开关 + 付费门槛双重控制
// 即使前端绕过，download_enabled 关闭时仍返回 403
import { validateId, checkUserAdmin } from '../../_utils.js';

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const bookId = params.id;
  if (!validateId(bookId)) {
    return Response.json({ error: 'Invalid book ID' }, { status: 400 });
  }

  // ===== 后台开关检查 =====
  const downloadSetting = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'download_enabled'").first();
  if (downloadSetting?.value !== 'true') {
    return Response.json({ error: '下载功能已被管理员关闭' }, { status: 403 });
  }

  // ===== 书籍存在 + 正常状态 =====
  const book = await env.DB.prepare('SELECT id, title, author, description, status FROM books WHERE id = ?').bind(bookId).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });
  if (book.status && book.status !== 'normal') {
    return Response.json({ error: 'Book not found' }, { status: 404 });
  }

  // ===== 付费门槛：未订阅的付费章节不能导出 =====
  const pricing = await env.DB.prepare('SELECT free_chapters, price FROM book_pricing WHERE book_id = ?').bind(bookId).first();
  const freeChapters = pricing?.free_chapters ?? 0;
  const price = pricing?.price ?? 0;
  const userAuth = await checkUserAdmin(request, env);
  const isUnlocked = price <= 0 || (userAuth.ok && !!(await env.DB.prepare('SELECT id FROM subscriptions WHERE user_id = ? AND book_id = ?').bind(userAuth.userId, bookId).first()));

  // ===== 拉取所有章节元数据 =====
  const { results: chapters } = await env.DB.prepare(
    'SELECT id, title, sort_order, word_count FROM chapters WHERE book_id = ? ORDER BY sort_order ASC'
  ).bind(bookId).all();

  // ===== 拉取每章内容 =====
  const allChapters = [];
  for (const ch of chapters) {
    // 付费门槛：sort_order 超过 freeChapters 且未订阅 → 跳过该章正文
    if (price > 0 && ch.sort_order > freeChapters && !isUnlocked) {
      allChapters.push({ id: ch.id, title: ch.title, sort_order: ch.sort_order, word_count: ch.word_count, content: '', paywall: true });
      continue;
    }
    const meta = await env.DB.prepare('SELECT content_key FROM chapters WHERE id = ?').bind(ch.id).first();
    let content = '';
    if (meta?.content_key && meta.content_key !== 'pending') {
      const obj = await env.R2.get(meta.content_key);
      if (obj) content = await obj.text();
    }
    allChapters.push({ id: ch.id, title: ch.title, sort_order: ch.sort_order, word_count: ch.word_count, content });
  }

  const url = new URL(request.url);
  const format = (url.searchParams.get('format') || 'json').toLowerCase();

  if (format === 'txt') {
    const BOM = '\uFEFF';
    const sep = '\n\n' + '='.repeat(40) + '\n\n';
    const header = `《${book.title}》\n${book.author ? '作者：' + book.author + '\n' : ''}${book.description ? '简介：' + book.description + '\n' : ''}\n`;
    let text = BOM + header;
    for (let i = 0; i < allChapters.length; i++) {
      const ch = allChapters[i];
      if (i > 0) text += sep;
      text += `${ch.title}\n\n${ch.paywall ? '[本章需订阅后查看]' : (ch.content || '')}`;
    }
    const safeName = (book.title || 'book').replace(/[<>:"/\\|?*]/g, '_');
    return new Response(text, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="${safeName}.txt"`,
        'Cache-Control': 'no-store',
      }
    });
  }

  return Response.json({
    book: { id: book.id, title: book.title, author: book.author, description: book.description },
    chapters: allChapters,
    exportedAt: new Date().toISOString(),
  });
}
