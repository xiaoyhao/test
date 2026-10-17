"""
EdgeChat-LAN —— 局域网部署版聊天系统
参考 https://github.com/aozorae/Edgechat 的功能与实时协议风格（WebSocket v1 帧格式），
去除全部 Telegram 联动 / Cloudflare Workers / D1/KV/R2 依赖，改为单机常驻进程 + SQLite。

特性：
- 邀请制注册 + 管理员账号体系（RBAC：admin / member）
- 频道群聊 + 一对一私信（会话列表、未读数、@提及）
- WebSocket 实时推送（protocolVersion:1，ready/message/message_deleted/room_message/presence/typing）
- 一次性 realtime ticket（60 秒有效，对齐上游 WS 鉴权设计，token 不进 URL）
- 消息服务端加密落盘（AES-256-GCM，密钥版本化，支持一键轮换）
- 文件上传下载（本地磁盘存储，替代 R2）
- 消息撤回 / 置顶 / 回复 / 引用预览
- 在线状态（presence）、临时封禁（到期自动解除）
- 管理后台聚合统计（不提供正文搜索，隐私边界对齐上游）
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ------------------------------------------------------------------ 配置
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("EDGECHAT_DATA", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "edgechat.db"

HOST = os.environ.get("EDGECHAT_HOST", "0.0.0.0")
PORT = int(os.environ.get("EDGECHAT_PORT", "8790"))
MAX_UPLOAD_MB = int(os.environ.get("EDGECHAT_MAX_UPLOAD_MB", "50"))
SESSION_TTL_DAYS = 30

app = FastAPI(title="EdgeChat-LAN", version="1.0.0")

# ------------------------------------------------------------------ 加密（AES-256-GCM via cryptography，缺失时回落纯 Python GHASH-AES-CTR-HMAC 简化实现）
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AESGCM = True
except Exception:  # pragma: no cover
    _HAS_AESGCM = False


class MessageCipher:
    """密钥版本化加密：密文格式 enc:v{N}:{base64(nonce|ct|tag)}"""

    def __init__(self, keyring_path: Path):
        self.keyring_path = keyring_path
        self.keys: dict[int, bytes] = {}
        self.current_version = 0
        if keyring_path.exists():
            for line in keyring_path.read_text().splitlines():
                if not line.strip():
                    continue
                ver, b64 = line.split(":", 1)
                self.keys[int(ver)] = base64.b64decode(b64)
            self.current_version = max(self.keys)
        else:
            self.rotate()

    def rotate(self):
        self.current_version += 1
        self.keys[self.current_version] = secrets.token_bytes(32)
        with open(self.keyring_path, "a") as f:
            f.write(f"{self.current_version}:{base64.b64encode(self.keys[self.current_version]).decode()}\n")

    def encrypt(self, text: str) -> str:
        raw = text.encode("utf-8")
        key = self.keys[self.current_version]
        nonce = secrets.token_bytes(12)
        if _HAS_AESGCM:
            ct = AESGCM(key).encrypt(nonce, raw, None)
            return f"enc:v{self.current_version}:{base64.b64encode(nonce + ct).decode()}"
        # 回落：HMAC-SHA256 CTR keystream（无 cryptography 依赖时的安全退化方案）
        stream = b""
        counter = 0
        while len(stream) < len(raw):
            block = nonce + counter.to_bytes(4, "big")
            stream += hmac.new(key, block, hashlib.sha256).digest()
            counter += 1
        ct = bytes(a ^ b for a, b in zip(raw, stream))
        tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16]
        return f"enc:v0-basic:{base64.b64encode(nonce + tag + ct).decode()}"

    def decrypt(self, blob: str) -> str:
        if not blob.startswith("enc:"):
            return blob
        _, ver, b64 = blob.split(":", 2)
        data = base64.b64decode(b64)
        if ver == "v0-basic":
            key = self.keys.get(1) or next(iter(self.keys.values()))
            nonce, tag, ct = data[:12], data[12:28], data[28:]
            if not hmac.compare_digest(hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16], tag):
                raise ValueError("decrypt integrity failure")
            stream = b""
            counter = 0
            while len(stream) < len(ct):
                stream += hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
                counter += 1
            return bytes(a ^ b for a, b in zip(ct, stream)).decode("utf-8")
        version = int(ver[1:])
        key = self.keys.get(version)
        if key is None:
            return "[无法解密的旧版本消息]"
        return AESGCM(key).decrypt(data[:12], data[12:], None).decode("utf-8")


cipher = MessageCipher(DATA_DIR / "keyring.txt")

# ------------------------------------------------------------------ 数据库
_db_lock = threading.RLock()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',          -- admin | member
  avatar_color TEXT DEFAULT '',
  banned_until TEXT DEFAULT '',                 -- ISO8601，空=未封禁；到期自动解除
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites(
  code TEXT PRIMARY KEY,
  created_by INTEGER REFERENCES users(id),
  used_by INTEGER REFERENCES users(id),
  note TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS rooms(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                           -- channel | private
  name TEXT DEFAULT '',
  topic TEXT DEFAULT '',
  private_pair_key TEXT UNIQUE,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL,
  archived INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS room_members(
  room_id INTEGER REFERENCES rooms(id),
  user_id INTEGER REFERENCES users(id),
  joined_at TEXT NOT NULL,
  last_read_msg_id INTEGER DEFAULT 0,
  PRIMARY KEY(room_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER REFERENCES rooms(id),
  sender_id INTEGER REFERENCES users(id),
  content_enc TEXT NOT NULL,                    -- 服务端加密正文
  content_type TEXT DEFAULT 'text',             -- text | file | image | audio
  file_id INTEGER,
  reply_to_id INTEGER,
  mention_ids TEXT DEFAULT '',
  client_message_id TEXT DEFAULT '',
  pinned INTEGER DEFAULT 0,
  deleted_at TEXT,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_client_msg ON messages(room_id, client_message_id) WHERE client_message_id != '';
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uploader_id INTEGER REFERENCES users(id),
  fname TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  mime TEXT DEFAULT 'application/octet-stream',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets(
  ticket TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  scope TEXT NOT NULL,                          -- inbox | room
  room_id INTEGER DEFAULT 0,
  expires_at REAL NOT NULL,
  consumed INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""


def init_db():
    with _db_lock, db() as conn:
        conn.executescript(SCHEMA)
        if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            pwd = os.environ.get("EDGECHAT_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
            conn.execute(
                "INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                ("admin", "管理员", hash_password(pwd), "admin", now_iso()),
            )
            print("=" * 60)
            print("首次启动：已创建管理员账号 admin")
            if not os.environ.get("EDGECHAT_ADMIN_PASSWORD"):
                print(f"随机初始密码: {pwd}")
            print("=" * 60)
        # 默认欢迎频道 + 系统机器人消息
        if not conn.execute("SELECT 1 FROM rooms LIMIT 1").fetchone():
            cur = conn.execute(
                "INSERT INTO rooms(kind,name,topic,created_by,created_at) VALUES('channel','综合','局域网聊天默认频道',1,?)",
                (now_iso(),))
            conn.execute("INSERT INTO room_members(room_id,user_id,joined_at) VALUES(?,1,?)", (cur.lastrowid, now_iso()))
            hello = cipher.encrypt("欢迎来到 EdgeChat-LAN 🛰️ 这是运行在你自己局域网里的聊天空间。")
            conn.execute(
                "INSERT INTO messages(room_id,sender_id,content_enc,content_type,created_at) VALUES(?,?,?,'text',?)",
                (cur.lastrowid, 1, hello, now_iso()))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(pw: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000)
    return f"pbkdf2${salt}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, hx = stored.split("$")
        h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000)
        return hmac.compare_digest(h.hex(), hx)
    except Exception:
        return False


# ------------------------------------------------------------------ 实时 Hub（对应上游 Durable Objects UserInbox / ChannelRoom）
@dataclass
class Connection:
    ws: WebSocket
    user_id: int
    scope: str          # inbox | room
    room_id: int = 0


class Hub:
    def __init__(self):
        self.conns: list[Connection] = []
        self.lock = threading.Lock()
        self.typing: dict[tuple[int, int], float] = {}  # (room_id,user_id)->deadline

    def add(self, c: Connection):
        with self.lock:
            self.conns.append(c)

    def remove(self, c: Connection):
        with self.lock:
            self.conns = [x for x in self.conns if x is not c]

    def sockets_for_user(self, uid: int):
        with self.lock:
            return [x for x in self.conns if x.user_id == uid and x.scope == "inbox"]

    def sockets_for_room(self, rid: int):
        with self.lock:
            return [x for x in self.conns if x.scope == "room" and x.room_id == rid]

    async def send_users(self, uids, frame: dict):
        targets = set()
        for u in uids:
            targets.update(self.sockets_for_user(u))
        await self._send_all(targets, frame)

    async def send_room(self, rid: int, frame: dict):
        await self._send_all(set(self.sockets_for_room(rid)), frame)

    async def _send_all(self, conns, frame: dict):
        payload = json.dumps(frame, ensure_ascii=False, default=str)
        for c in list(conns):
            try:
                await c.ws.send_text(payload)
            except Exception:
                self.remove(c)

    def online_user_ids(self) -> set[int]:
        with self.lock:
            return {c.user_id for c in self.conns}


hub = Hub()

# ------------------------------------------------------------------ 通用序列化
def public_user(row: sqlite3.Row) -> dict:
    return {
        "kind": "local",
        "id": row["id"],
        "username": row["username"],
        "displayName": row["display_name"],
        "avatarUrl": "",
        "color": row["avatar_color"],
        "source": "edgechat-lan",
    }


def message_payload(conn: sqlite3.Connection, m: sqlite3.Row) -> dict:
    sender = conn.execute("SELECT * FROM users WHERE id=?", (m["sender_id"],)).fetchone()
    out = {
        "id": m["id"],
        "roomId": m["room_id"],
        "clientMessageId": m["client_message_id"],
        "createdAt": m["created_at"],
        "pinned": bool(m["pinned"]),
        "replyToMessageId": m["reply_to_id"],
        "mentionUserIds": [int(x) for x in m["mention_ids"].split(",") if x],
        "type": m["content_type"],
        "sender": public_user(sender) if sender else None,
        "content": cipher.decrypt(m["content_enc"]) if not m["deleted_at"] else None,
        "deleted": bool(m["deleted_at"]),
    }
    if m["file_id"]:
        f = conn.execute("SELECT * FROM files WHERE id=?", (m["file_id"],)).fetchone()
        if f:
            out["file"] = {
                "id": f["id"], "name": f["fname"], "size": f["size"], "mime": f["mime"],
                "url": f"/api/v1/files/{f['id']}",
            }
    return out


def room_view(conn: sqlite3.Connection, room: sqlite3.Row, me_id: int) -> dict:
    unread_row = conn.execute(
        "SELECT COALESCE(MAX(m.id),0) mx FROM messages m WHERE m.room_id=? AND m.deleted_at IS NULL AND m.sender_id<>? "
        "AND m.id > COALESCE((SELECT last_read_msg_id FROM room_members WHERE room_id=? AND user_id=?),0)",
        (room["id"], me_id, room["id"], me_id),
    ).fetchone()
    last = conn.execute(
        "SELECT * FROM messages WHERE room_id=? AND deleted_at IS NULL ORDER BY id DESC LIMIT 1", (room["id"],)
    ).fetchone()
    preview = ""
    if last:
        text = cipher.decrypt(last["content_enc"])
        preview = (text[:40] + "…") if len(text) > 40 else text
    members = conn.execute(
        "SELECT u.* FROM room_members rm JOIN users u ON u.id=rm.user_id WHERE rm.room_id=?", (room["id"],)
    ).fetchall()
    name = room["name"]
    if room["kind"] == "private":
        other = [public_user(u) for u in members if u["id"] != me_id]
        name = other[0]["displayName"] if other else "私信"
    return {
        "id": room["id"], "kind": room["kind"], "name": name, "topic": room["topic"],
        "unreadCount": count_unread(conn, room["id"], me_id),
        "lastPreview": preview,
        "members": [public_user(u) for u in members],
        "archived": bool(room["archived"]),
    }


def count_unread(conn: sqlite3.Connection, rid: int, uid: int) -> int:
    lr = conn.execute("SELECT last_read_msg_id x FROM room_members WHERE room_id=? AND user_id=?", (rid, uid)).fetchone()
    seen = lr["x"] if lr else 0
    return conn.execute(
        "SELECT COUNT(*) c FROM messages WHERE room_id=? AND id>? AND sender_id<>? AND deleted_at IS NULL",
        (rid, seen, uid),
    ).fetchone()["c"]


# ------------------------------------------------------------------ 鉴权
def get_user(request: Request) -> sqlite3.Row | None:
    token = ""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    token = token or request.query_params.get("token", "")
    if not token:
        return None
    with _db_lock, db() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires_at>?", (token, now_iso())
        ).fetchone()
        if row and is_banned(conn, row["id"]):
            return None
        return row


def require_user(request: Request) -> sqlite3.Row:
    u = get_user(request)
    if not u:
        raise HTTPException(401, "未登录或会话已过期")
    return u


def require_admin(request: Request) -> sqlite3.Row:
    u = require_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "需要管理员权限")
    return u


def is_banned(conn: sqlite3.Connection, uid: int) -> bool:
    row = conn.execute("SELECT banned_until FROM users WHERE id=?", (uid,)).fetchone()
    if not row or not row["banned_until"]:
        return False
    try:
        until = datetime.fromisoformat(row["banned_until"])
    except ValueError:
        return False
    if until >= datetime.now(timezone.utc):
        return True
    # 到期自动解除
    conn.execute("UPDATE users SET banned_until='' WHERE id=?", (uid,))
    return False


MENTION_RE = re.compile(r"@([A-Za-z0-9_\u4e00-\u9fff.\-]+)")


def extract_mentions(conn: sqlite3.Connection, text: str, room_id: int) -> list[int]:
    ids = []
    for name in set(MENTION_RE.findall(text)):
        row = conn.execute(
            "SELECT rm.user_id FROM room_members rm JOIN users u ON u.id=rm.user_id "
            "WHERE rm.room_id=? AND u.username=?", (room_id, name)).fetchone()
        if row:
            ids.append(row["user_id"])
    return ids


# ------------------------------------------------------------------ API：认证
@app.post("/api/v1/auth/login")
async def login(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    with _db_lock, db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            raise HTTPException(401, "用户名或密码错误")
        if is_banned(conn, row["id"]):
            raise HTTPException(403, "账号已被封禁")
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
            (token, row["id"], now_iso(), (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()),
        )
    return {"token": token, "user": public_user(row), "role": row["role"]}


@app.post("/api/v1/auth/register")
async def register(request: Request):
    """邀请制注册：必须携带管理员生成的邀请码，不开放自助注册。"""
    body = await request.json()
    code = (body.get("inviteCode") or "").strip()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    display = (body.get("displayName") or username).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\u4e00-\u9fff\-]{2,32}", username):
        raise HTTPException(400, "用户名需为 2-32 位字母数字或中文")
    if len(password) < 6:
        raise HTTPException(400, "密码至少 6 位")
    with _db_lock, db() as conn:
        inv = conn.execute("SELECT * FROM invites WHERE code=?", (code,)).fetchone()
        if not inv or inv["used_by"]:
            raise HTTPException(400, "邀请码无效或已被使用")
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(400, "用户名已存在")
        cur = conn.execute(
            "INSERT INTO users(username,display_name,password_hash,created_at,avatar_color) VALUES(?,?,?,?,?)",
            (username, display, hash_password(password), now_iso(), random_color()),
        )
        uid = cur.lastrowid
        conn.execute("UPDATE invites SET used_by=?, used_at=? WHERE code=?", (uid, now_iso(), code))
        welcome = conn.execute("SELECT id FROM rooms WHERE kind='channel' AND name='综合'").fetchone()
        if welcome:
            conn.execute("INSERT OR IGNORE INTO room_members(room_id,user_id,joined_at) VALUES(?,?,?)",
                         (welcome["id"], uid, now_iso()))
        token = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                     (token, uid, now_iso(), (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()))
    return {"token": token, "user": {"id": uid, "username": username, "displayName": display}}


def random_color():
    return "#%06x" % secrets.randbelow(0xFFFFFF)


@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    u = require_user(request)
    auth = request.headers.get("authorization", "")
    with _db_lock, db() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (auth[7:],))
    return {"ok": True}


@app.get("/api/v1/me")
async def me(request: Request):
    u = require_user(request)
    return {"user": public_user(u), "role": u["role"]}


# ------------------------------------------------------------------ API：realtime ticket（对齐上游一次性票据设计）
@app.post("/api/v1/realtime/tickets")
async def create_ticket(request: Request):
    u = require_user(request)
    body = await request.json()
    scope = body.get("scope", "inbox")
    room_id = int(body.get("roomId", 0) or 0)
    if scope == "room":
        with _db_lock, db() as conn:
            if not conn.execute("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?", (room_id, u["id"])).fetchone():
                raise HTTPException(403, "无权访问该会话")
    ticket = secrets.token_urlsafe(24)
    with _db_lock, db() as conn:
        conn.execute("INSERT INTO tickets(ticket,user_id,scope,room_id,expires_at) VALUES(?,?,?,?,?)",
                     (ticket, u["id"], scope, room_id, time.time() + 60))
    return {"ticket": ticket, "wsPath": "/api/v1/realtime/ws"}


# ------------------------------------------------------------------ API：会话
@app.post("/api/v1/rooms")
async def create_room(request: Request):
    u = require_user(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "请求体必须为 JSON")
    kind = body.get("kind", "channel")
    name = (body.get("name") or "").strip()
    with _db_lock, db() as conn:
        if kind == "channel":
            if u["role"] != "admin":
                raise HTTPException(403, "仅管理员可创建频道")
            if not name:
                raise HTTPException(400, "频道名不能为空")
            cur = conn.execute(
                "INSERT INTO rooms(kind,name,topic,created_by,created_at) VALUES(?,?,?,?,?)",
                (kind, name, body.get("topic", ""), u["id"], now_iso()))
            rid = cur.lastrowid
            for uid in [x["id"] for x in conn.execute("SELECT id FROM users").fetchall()]:
                conn.execute("INSERT OR IGNORE INTO room_members(room_id,user_id,joined_at) VALUES(?,?,?)",
                             (rid, uid, now_iso()))
        elif kind == "private":
            peer_id = int(body.get("userId", 0))
            pair = "|".join(str(x) for x in sorted({u["id"], peer_id}))
            existing = conn.execute("SELECT id FROM rooms WHERE private_pair_key=?", (pair,)).fetchone()
            if existing:
                return {"room": room_view(conn, conn.execute("SELECT * FROM rooms WHERE id=?", (existing["id"],)).fetchone(), u["id"])}
            cur = conn.execute(
                "INSERT INTO rooms(kind,private_pair_key,created_by,created_at) VALUES('private',?,?,?)",
                (pair, u["id"], now_iso()))
            rid = cur.lastrowid
            for uid in {u["id"], peer_id}:
                conn.execute("INSERT OR IGNORE INTO room_members(room_id,user_id,joined_at) VALUES(?,?,?)",
                             (rid, uid, now_iso()))
        else:
            raise HTTPException(400, "未知会话类型")
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (rid,)).fetchone()
        return {"room": room_view(conn, room, u["id"])}


@app.get("/api/v1/rooms/{rid}/messages")
async def room_messages(request: Request, rid: int, before: int = 0, limit: int = 50):
    u = require_user(request)
    with _db_lock, db() as conn:
        if not conn.execute("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?", (rid, u["id"])).fetchone():
            raise HTTPException(403, "无权访问该会话")
        q = "SELECT * FROM messages WHERE room_id=? AND deleted_at IS NULL"
        args: list = [rid]
        if before:
            q += " AND id<?"
            args.append(before)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(limit, 100)))
        rows = list(reversed(conn.execute(q, args).fetchall()))
        return {"messages": [message_payload(conn, m) for m in rows]}


@app.post("/api/v1/rooms/{rid}/read")
async def mark_read(request: Request, rid: int):
    u = require_user(request)
    body = await request.json()
    with _db_lock, db() as conn:
        conn.execute(
            "UPDATE room_members SET last_read_msg_id=? WHERE room_id=? AND user_id=?",
            (int(body.get("lastMessageId", 0)), rid, u["id"]))
    return {"ok": True}


@app.get("/api/v1/rooms")
async def list_rooms(request: Request):
    u = require_user(request)
    with _db_lock, db() as conn:
        rows = conn.execute(
            "SELECT r.* FROM rooms r JOIN room_members rm ON rm.room_id=r.id "
            "WHERE rm.user_id=? AND r.archived=0 ORDER BY r.kind, r.id", (u["id"],)
        ).fetchall()
        return {"rooms": [room_view(conn, r, u["id"]) for r in rows]}


# ------------------------------------------------------------------ API：发送消息（幂等 clientMessageId，对齐上游）
@app.post("/api/v1/rooms/{rid}/messages")
async def send_message(request: Request, rid: int):
    u = require_user(request)
    body = await request.json()
    text = (body.get("content") or "").strip()
    client_msg_id = (body.get("clientMessageId") or "").strip()
    reply_to = int(body.get("replyToMessageId", 0) or 0)
    file_id = int(body.get("fileId", 0) or 0)
    if not text and not file_id:
        raise HTTPException(400, "消息内容为空")
    with _db_lock, db() as conn:
        if not conn.execute("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?", (rid, u["id"])).fetchone():
            raise HTTPException(403, "无权在该会话发言")
        if client_msg_id:
            dup = conn.execute("SELECT id FROM messages WHERE room_id=? AND client_message_id=?",
                               (rid, client_msg_id)).fetchone()
            if dup:
                m = conn.execute("SELECT * FROM messages WHERE id=?", (dup["id"],)).fetchone()
                return {"message": message_payload(conn, m), "deduplicated": True}
        mentions = extract_mentions(conn, text, rid)
        cur = conn.execute(
            "INSERT INTO messages(room_id,sender_id,content_enc,content_type,reply_to_id,mention_ids,client_message_id,created_at,file_id) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (rid, u["id"], cipher.encrypt(text), body.get("type", "text"), reply_to or None,
             ",".join(map(str, mentions)), client_msg_id, now_iso(), file_id or None))
        m = conn.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
        payload = message_payload(conn, m)
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (rid,)).fetchone()

    # 实时分发：房间套接字收 message，成员 inbox 收 room_message 信号
    await hub.send_room(rid, {"protocolVersion": 1, "type": "message", "message": payload})
    member_ids = [x["user_id"] for x in conn.execute("SELECT user_id FROM room_members WHERE room_id=?", (rid,)).fetchall()]
    signals = []
    for uid in member_ids:
        if uid == u["id"]:
            continue
        with _db_lock, db() as c2:
            unread = count_unread(c2, rid, uid)
        signals.append((uid, {
            "protocolVersion": 1, "type": "room_message",
            "room": {"id": room["id"], "kind": room["kind"], "name": room["name"]},
            "messageId": m["id"], "createdAt": m["created_at"], "unreadCount": unread,
            "mentionsMe": uid in mentions, "contentPreview": (text[:40] if text else "[文件]"),
            "sender": payload["sender"],
        }))
    grouped: dict[int, list] = {}
    for uid, fr in signals:
        grouped.setdefault(uid, []).append(fr)
    for uid, frames in grouped.items():
        await hub.send_users([uid], frames[-1])
    return {"message": payload}


@app.delete("/api/v1/messages/{mid}")
async def delete_message(request: Request, mid: int):
    u = require_user(request)
    with _db_lock, db() as conn:
        m = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        if not m:
            raise HTTPException(404, "消息不存在")
        if m["sender_id"] != u["id"] and u["role"] != "admin":
            raise HTTPException(403, "只能撤回自己的消息")
        if m["deleted_at"]:
            return {"ok": True}
        conn.execute("UPDATE messages SET deleted_at=? WHERE id=?", (now_iso(), mid))
        rid = m["room_id"]
    await hub.send_room(rid, {"protocolVersion": 1, "type": "message_deleted", "messageId": mid})
    return {"ok": True}


@app.post("/api/v1/messages/{mid}/pin")
async def pin_message(request: Request, mid: int):
    u = require_user(request)
    body = await request.json()
    with _db_lock, db() as conn:
        m = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        if not m:
            raise HTTPException(404, "消息不存在")
        if u["role"] != "admin":
            raise HTTPException(403, "仅管理员可置顶")
        conn.execute("UPDATE messages SET pinned=? WHERE id=?", (1 if body.get("pinned", True) else 0, mid))
        fresh = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        payload = message_payload(conn, fresh)
        t = "message_pinned" if fresh["pinned"] else "message_unpinned"
        rid = m["room_id"]
    await hub.send_room(rid, {"protocolVersion": 1, "type": t, "message": payload, "messageId": mid})
    return {"ok": True}


# ------------------------------------------------------------------ API：文件上传（本地磁盘，替代 R2）
@app.post("/api/v1/uploads")
async def upload(request: Request, file: UploadFile = File(...)):
    u = require_user(request)
    data = await file.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"文件超过 {MAX_UPLOAD_MB}MB 限制")
    fid = uuid.uuid4().hex
    stored = UPLOAD_DIR / fid
    stored.write_bytes(data)
    mime = file.content_type or "application/octet-stream"
    ctype = "image" if mime.startswith("image/") else ("audio" if mime.startswith("audio/") else "file")
    with _db_lock, db() as conn:
        cur = conn.execute(
            "INSERT INTO files(uploader_id,fname,stored_name,size,mime,created_at) VALUES(?,?,?,?,?,?)",
            (u["id"], file.filename or "file", fid, len(data), mime, now_iso()))
        f = conn.execute("SELECT * FROM files WHERE id=?", (cur.lastrowid,)).fetchone()
    return {"file": {"id": f["id"], "name": f["fname"], "size": f["size"], "mime": f["mime"],
                     "type": ctype, "url": f"/api/v1/files/{f['id']}"}}


@app.get("/api/v1/files/{fid}")
async def download(fid: int):
    with _db_lock, db() as conn:
        f = conn.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not f or not (UPLOAD_DIR / f["stored_name"]).exists():
        raise HTTPException(404, "文件不存在")
    return FileResponse(UPLOAD_DIR / f["stored_name"], media_type=f["mime"], filename=f["fname"])


# ------------------------------------------------------------------ API：用户目录 & 私聊入口
@app.get("/api/v1/users")
async def list_users(request: Request):
    require_user(request)
    with _db_lock, db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        online = hub.online_user_ids()
        return {"users": [{**public_user(r), "online": r["id"] in online, "role": r["role"]} for r in rows]}


# ------------------------------------------------------------------ API：管理后台（无正文查看/搜索，聚合统计 only）
@app.get("/api/v1/admin/stats")
async def admin_stats(request: Request):
    require_admin(request)
    with _db_lock, db() as conn:
        return {
            "users": conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
            "online": len(hub.online_user_ids()),
            "rooms": conn.execute("SELECT COUNT(*) c FROM rooms").fetchone()["c"],
            "messages": conn.execute("SELECT COUNT(*) c FROM messages").fetchone()["c"],
            "files": conn.execute("SELECT COUNT(*) c, COALESCE(SUM(size),0) s FROM files").fetchone().items(),
            "keyVersion": cipher.current_version,
        }


@app.get("/api/v1/admin/invites")
async def list_invites(request: Request):
    require_admin(request)
    with _db_lock, db() as conn:
        rows = conn.execute("SELECT * FROM invites ORDER BY created_at DESC").fetchall()
        return {"invites": [dict(r) for r in rows]}


@app.post("/api/v1/admin/invites")
async def make_invite(request: Request):
    require_admin(request)
    body = await request.json()
    code = secrets.token_urlsafe(12)
    with _db_lock, db() as conn:
        conn.execute("INSERT INTO invites(code,created_by,note,created_at) VALUES(?,?,?,?)",
                     (code, body.get("_by", 1), body.get("note", ""), now_iso()))
    return {"code": code}


@app.post("/api/v1/admin/users/{uid}/ban")
async def ban_user(request: Request, uid: int):
    admin = require_admin(request)
    body = await request.json()
    minutes = int(body.get("minutes", 0))  # 0 = 永久
    with _db_lock, db() as conn:
        if uid == admin["id"]:
            raise HTTPException(400, "不能封禁自己")
        until = "" if minutes == 0 else (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
        conn.execute("UPDATE users SET banned_until=? WHERE id=?", (until, uid))
        if minutes == 0:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    return {"ok": True, "bannedUntil": until}


@app.post("/api/v1/admin/users/{uid}/unban")
async def unban_user(request: Request, uid: int):
    require_admin(request)
    with _db_lock, db() as conn:
        conn.execute("UPDATE users SET banned_until='' WHERE id=?", (uid,))
    return {"ok": True}


@app.post("/api/v1/admin/keys/rotate")
async def rotate_key(request: Request):
    require_admin(request)
    cipher.rotate()
    return {"keyVersion": cipher.current_version}


@app.post("/api/v1/admin/users")
async def admin_create_user(request: Request):
    """管理员直接创建账号。"""
    require_admin(request)
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if len(password) < 6:
        raise HTTPException(400, "密码至少 6 位")
    with _db_lock, db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(400, "用户名已存在")
        cur = conn.execute(
            "INSERT INTO users(username,display_name,password_hash,role,created_at,avatar_color) VALUES(?,?,?,?,?,?)",
            (username, body.get("displayName", username), hash_password(password),
             body.get("role", "member"), now_iso(), random_color()))
    return {"id": cur.lastrowid}


# ------------------------------------------------------------------ WebSocket 实时通道
@app.websocket("/api/v1/realtime/ws")
async def realtime(ws: WebSocket):
    ticket = ws.query_params.get("ticket", "")
    with _db_lock, db() as conn:
        t = conn.execute("SELECT * FROM tickets WHERE ticket=?", (ticket,)).fetchone()
        ok = bool(t) and not t["consumed"] and t["expires_at"] > time.time()
        if ok:
            conn.execute("UPDATE tickets SET consumed=1 WHERE ticket=?", (ticket,))
    if not ok:
        await ws.close(code=4401)
        return
    await ws.accept()
    c = Connection(ws=ws, user_id=t["user_id"], scope=t["scope"], room_id=t["room_id"] or 0)
    hub.add(c)
    online = hub.online_user_ids()
    try:
        if c.scope == "room":
            with _db_lock, db() as conn:
                room = conn.execute("SELECT * FROM rooms WHERE id=?", (c.room_id,)).fetchone()
                pins = conn.execute(
                    "SELECT * FROM messages WHERE room_id=? AND pinned=1 AND deleted_at IS NULL ORDER BY id DESC LIMIT 5",
                    (c.room_id,)).fetchall()
            await ws.send_text(json.dumps({
                "protocolVersion": 1, "type": "ready",
                "room": {"id": room["id"], "kind": room["kind"], "name": room["name"]},
                "pinned": [message_payload(conn, p) for p in pins],
                "onlineUserIds": sorted(online),
            }, ensure_ascii=False, default=str))
        else:
            await ws.send_text(json.dumps({"protocolVersion": 1, "type": "ready",
                                           "onlineUserIds": sorted(online)}, ensure_ascii=False))
        while True:
            raw = await ws.receive_text()
            try:
                frame = json.loads(raw)
            except json.JSONDecodeError:
                continue
            typ = frame.get("type")
            if typ == "ping":
                await ws.send_text(json.dumps({"protocolVersion": 1, "type": "pong"}))
            elif typ == "typing" and c.scope == "room":
                hub.typing[(c.room_id, c.user_id)] = time.time() + 4
                with _db_lock, db() as conn:
                    who = conn.execute("SELECT * FROM users WHERE id=?", (c.user_id,)).fetchone()
                await hub.send_room(c.room_id, {"protocolVersion": 1, "type": "typing",
                                                "roomId": c.room_id, "user": public_user(who)})
            elif typ == "sync":
                await ws.send_text(json.dumps({"protocolVersion": 1, "type": "presence",
                                               "onlineUserIds": sorted(hub.online_user_ids())}))
    except WebSocketDisconnect:
        pass
    finally:
        hub.remove(c)
        with _db_lock, db() as conn:
            conn.execute("DELETE FROM tickets WHERE user_id=? AND consumed=1 AND expires_at<?",
                         (c.user_id, time.time() - 3600))


# ------------------------------------------------------------------ 前端页面
@app.get("/", response_class=HTMLResponse)
async def index():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


init_db()

if __name__ == "__main__":
    import uvicorn
    print(f"EdgeChat-LAN 启动: http://{HOST}:{PORT}  (局域网内其他设备用本机 IP 访问)")
    uvicorn.run(app, host=HOST, port=PORT)
