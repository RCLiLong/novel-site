-- ============================================================
-- 小说站数据库 Schema
-- ============================================================
-- 版本: 1.0
-- 最后更新: 2026-03
-- 说明: 使用 SQLite 语法，适用于 Cloudflare D1
-- ============================================================

-- ============================================================
-- 作品相关表
-- ============================================================

-- 作品表：存储小说/书籍基本信息
-- 字段说明:
--   id: 主键，自增
--   title: 书名
--   description: 简介/描述
--   author: 作者名
--   cover_key: 封面图片存储键（R2对象存储）
--   created_at/updated_at: 时间戳
CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,                    -- 书名，必填
  description TEXT DEFAULT '',            -- 简介，可选
  author TEXT DEFAULT '',                 -- 作者，可选
  cover_key TEXT DEFAULT '',              -- 封面R2存储键
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- 章节表：存储书籍章节信息
-- 字段说明:
--   id: 主键，自增
--   book_id: 所属书籍ID，外键关联books
--   title: 章节标题
--   sort_order: 排序序号（用于章节顺序）
--   word_count: 字数统计
--   content_key: 章节内容存储键（R2对象存储）
--   version: 乐观锁版本号（防止并发编辑冲突）
CREATE TABLE IF NOT EXISTS chapters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id INTEGER NOT NULL,               -- 所属书籍ID
  title TEXT NOT NULL,                    -- 章节标题
  sort_order INTEGER NOT NULL,            -- 排序序号
  word_count INTEGER DEFAULT 0,           -- 字数
  content_key TEXT NOT NULL,              -- 内容R2存储键
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  version INTEGER DEFAULT 0,              -- 乐观锁版本号
  FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
);

-- 章节索引（优化查询性能）
CREATE INDEX IF NOT EXISTS idx_chapters_book_id ON chapters(book_id);
CREATE INDEX IF NOT EXISTS idx_chapters_sort_order ON chapters(book_id, sort_order);

-- ============================================================
-- 用户与认证相关表
-- ============================================================

-- 管理员账号表：存储后台管理用户
-- 字段说明:
--   id: 主键，自增
--   username: 用户名，唯一
--   password_hash: 密码哈希（PBKDF2格式）
--   role: 角色（super_admin/admin/author/demo）
--   github_id: GitHub OAuth用户ID
--   github_login: GitHub用户名
--   avatar_url: 头像URL
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,          -- 用户名，唯一
  password_hash TEXT NOT NULL,            -- 密码哈希
  role TEXT DEFAULT 'editor',             -- 角色: super_admin/admin/author/demo（editor 为旧 admin 别名）
  email TEXT UNIQUE,                      -- 邮箱（作者注册时填写，唯一）
  status TEXT DEFAULT 'active',           -- 账号状态: active / pending（待审核）/ rejected（已拒绝）
  github_id TEXT UNIQUE,                  -- GitHub OAuth ID
  github_login TEXT,                      -- GitHub用户名
  avatar_url TEXT,                        -- 头像URL
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- 会话表：存储登录Token
-- 字段说明:
--   token: 会话Token（存储哈希值）
--   user_id: 关联用户ID
--   expires_at: 过期时间
CREATE TABLE IF NOT EXISTS admin_sessions (
  token TEXT PRIMARY KEY,                 -- Token哈希值
  user_id INTEGER NOT NULL,               -- 用户ID
  expires_at TEXT NOT NULL,               -- 过期时间
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
);

-- 会话索引
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);

-- GitHub OAuth索引
CREATE INDEX IF NOT EXISTS idx_admin_users_github_id ON admin_users(github_id);

-- 待验证注册表：邮箱验证码注册流程的临时存储（作者注册）
-- 字段说明:
--   email: 注册邮箱
--   code_hash: 验证码 SHA-256 哈希（含 email 加盐）
--   ip_hash: 请求来源 IP 哈希（用于限流）
--   attempts: 验证尝试次数（>=5 失效）
--   verified: 是否已使用
--   expires_at: 验证码过期时间（10 分钟）
CREATE TABLE IF NOT EXISTS pending_registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  username TEXT,
  password_hash TEXT,
  ip_hash TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pending_reg_email ON pending_registrations(email, expires_at);

-- ============================================================
-- 系统配置表
-- ============================================================

-- 站点设置表：存储站点个性化配置
-- 字段说明:
--   key: 配置项名称
--   value: 配置值（JSON或字符串）
CREATE TABLE IF NOT EXISTS site_settings (
  key TEXT PRIMARY KEY,                   -- 配置项键
  value TEXT NOT NULL                     -- 配置值
);

-- 默认站点设置
INSERT OR IGNORE INTO site_settings (key, value) VALUES ('site_name', '我的书架');
INSERT OR IGNORE INTO site_settings (key, value) VALUES ('site_desc', '私人小说站');
INSERT OR IGNORE INTO site_settings (key, value) VALUES ('footer_text', '');

-- 认证限流表：防止暴力破解
-- 字段说明:
--   ip_hash: IP地址哈希（隐私保护）
--   fail_count: 失败次数
--   locked_until: 锁定截止时间
--   last_attempt: 最后尝试时间
CREATE TABLE IF NOT EXISTS auth_attempts (
  ip_hash TEXT PRIMARY KEY,               -- IP哈希
  fail_count INTEGER DEFAULT 0,           -- 失败次数
  locked_until TEXT,                      -- 锁定截止时间
  last_attempt TEXT DEFAULT (datetime('now'))
);

-- ============================================================
-- 访问统计表
-- ============================================================

-- 站点日访问统计：PV/UV
-- 字段说明:
--   date: 日期（YYYY-MM-DD）
--   pv: 页面访问量
--   uv: 独立访客数
CREATE TABLE IF NOT EXISTS site_visits (
  date TEXT PRIMARY KEY,                  -- 日期
  pv INTEGER DEFAULT 0,                   -- 页面访问量
  uv INTEGER DEFAULT 0                    -- 独立访客数
);

-- UV去重辅助表：按日期+IP哈希去重
CREATE TABLE IF NOT EXISTS daily_visitors (
  date TEXT NOT NULL,                     -- 日期
  ip_hash TEXT NOT NULL,                  -- IP哈希
  PRIMARY KEY (date, ip_hash)
);

-- 书籍日阅读统计
-- 字段说明:
--   book_id: 书籍ID
--   date: 日期
--   views: 当日阅读量
CREATE TABLE IF NOT EXISTS book_stats (
  book_id INTEGER NOT NULL,               -- 书籍ID
  date TEXT NOT NULL,                     -- 日期
  views INTEGER DEFAULT 0,                -- 阅读量
  PRIMARY KEY (book_id, date),
  FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
);

-- 章节累计阅读量
-- 字段说明:
--   chapter_id: 章节ID
--   views: 累计阅读量
CREATE TABLE IF NOT EXISTS chapter_stats (
  chapter_id INTEGER PRIMARY KEY,         -- 章节ID
  views INTEGER DEFAULT 0,                -- 累计阅读量
  FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE
);

-- 统计索引
CREATE INDEX IF NOT EXISTS idx_book_stats_book_date ON book_stats(book_id, date);
CREATE INDEX IF NOT EXISTS idx_daily_visitors_date ON daily_visitors(date);
