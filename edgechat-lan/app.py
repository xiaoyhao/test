"""
EdgeChat-LAN —— 局域网部署版聊天系统（极简版）
参考 https://github.com/aozorae/Edgechat 的实时协议风格（WebSocket v1 帧格式），
去除全部 Telegram 联动 / Cloudflare Workers / D1/KV/R2 依赖，改为单机常驻进程 + SQLite。

特性：
- 免登录：打开页面即自动注册，浏览器指纹标识用户，用户名形如 "Windows Chrome笔记本"
- 无管理员体系：所有用户权限相同，任何人都可创建频道和发起私聊
- 频道群聊 + 一对一私信（会话列表、未读数、@提及）
- WebSocket 实时推送（protocolVersion:1，ready/message/message_deleted/room_message/presence/typing）
- 消息服务端加密落盘（AES-256-GCM，密钥版本化）
- 文件上传下载（本地磁盘存储，替代 R2）
- 消息撤回 / 回复 / 引用预览 / 置顶（任何成员均可置顶与撤回自己的消息）
- 在线状态（presence）
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
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse

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
SESSION_TTL_DAYS = 365  # 指纹登录，token 长期有效

app = FastAPI(title="EdgeChat-LAN", version="2.0.0")

# ------------------------------------------------------------------ 加密（AES-256-GCM via cryptography，缺失时回落 HMAC-CTR 方案）
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
        if not _HAS_AESGCM:
            return "[无法解密：当前运行环境缺少 cryptography 库]"
        try:
            return AESGCM(key).decrypt(data[:12], data[12:], None).decode("utf-8")
        except Exception:
            return "[无法解密的旧版本消息]"


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
  fingerprint TEXT UNIQUE NOT NULL,             -- 浏览器指纹哈希
  username TEXT UNIQUE NOT NULL,                -- 自动生成：系统+设备
  display_name TEXT NOT NULL,
  created_ip TEXT DEFAULT '',
  avatar_color TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
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
  sender_id INTEGER NOT NULL DEFAULT 0,         -- 发送者（0=系统消息，不强制外键）
  content_enc TEXT NOT NULL,
  content_type TEXT DEFAULT 'text',
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
"""


def init_db():
    with _db_lock, db() as conn:
        # 清理旧版本遗留表（邀请制 / 管理员体系已移除）
        conn.execute("DROP TABLE IF EXISTS invites")
        old_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if old_cols and ("password_hash" in old_cols or "role" in old_cols or "fingerprint" not in old_cols):
            # 旧库结构不兼容：重建 users 相关数据（局域网演示场景，直接清库重来）
            conn.executescript("DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS sessions;"
                               "DROP TABLE IF EXISTS room_members; DROP TABLE IF EXISTS messages;"
                               "DROP TABLE IF EXISTS files; DROP TABLE IF EXISTS rooms;")
            old_cols = []
        conn.executescript(SCHEMA)
        if not conn.execute("SELECT 1 FROM rooms LIMIT 1").fetchone():
            cur = conn.execute(
                "INSERT INTO rooms(kind,name,topic,created_at) VALUES('channel','综合','局域网聊天默认频道',?)",
                (now_iso(),))
            hello = cipher.encrypt("欢迎来到 EdgeChat-LAN 🛰️ 打开页面即自动登录，所有人都可以创建频道和私聊。")
            conn.execute(
                "INSERT INTO messages(room_id,sender_id,content_enc,content_type,created_at) VALUES(?,?,?,?,?)",
                (cur.lastrowid, 0, hello, 'text', now_iso()))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def random_color():
    return "#%06x" % secrets.randbelow(0xFFFFFF)


# ------------------------------------------------------------------ 实时 Hub
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
        self.typing: dict[tuple[int, int], float] = {}

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
        targets = {id(x): x for x in []}
        for u in uids:
            for c in self.sockets_for_user(u):
                targets[id(c)] = c
        await self._send_all(list(targets.values()), frame)

    async def send_room(self, rid: int, frame: dict):
        # 注意：Connection 是 unhashable 的 dataclass，不能用 set() 去重，按 id 去重
        seen: dict[int, Connection] = {}
        for c in self.sockets_for_room(rid):
            seen[id(c)] = c
        await self._send_all(list(seen.values()), frame)

    async def broadcast(self, frame: dict):
        with self.lock:
            allc = list(self.conns)
        await self._send_all(allc, frame)

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
        "sender": public_user(sender) if sender else {"kind": "local", "id": 0, "username": "system",
                                                       "displayName": "系统", "avatarUrl": "", "color": "#888",
                                                       "source": "edgechat-lan"},
        "content": cipher.decrypt(m["content_enc"]) if not m["deleted_at"] else None,
        "deleted": bool(m["deleted_at"]),
    }
    if m["file_id"]:
        f = conn.execute("SELECT * FROM files WHERE id=?", (m["file_id"],)).fetchone()
        if f:
            out["file"] = {"id": f["id"], "name": f["fname"], "size": f["size"], "mime": f["mime"],
                           "url": f"/api/v1/files/{f['id']}"}
    return out


def count_unread(conn: sqlite3.Connection, rid: int, uid: int) -> int:
    lr = conn.execute("SELECT last_read_msg_id x FROM room_members WHERE room_id=? AND user_id=?", (rid, uid)).fetchone()
    seen = lr["x"] if lr else 0
    return conn.execute(
        "SELECT COUNT(*) c FROM messages WHERE room_id=? AND id>? AND sender_id<>? AND deleted_at IS NULL",
        (rid, seen, uid),
    ).fetchone()["c"]


def room_view(conn: sqlite3.Connection, room: sqlite3.Row, me_id: int) -> dict:
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


# ------------------------------------------------------------------ 鉴权（token 会话）
def get_user(request: Request) -> sqlite3.Row | None:
    token = ""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    token = token or request.query_params.get("token", "")
    if not token:
        return None
    with _db_lock, db() as conn:
        return conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires_at>?", (token, now_iso())
        ).fetchone()


def require_user(request: Request) -> sqlite3.Row:
    u = get_user(request)
    if not u:
        raise HTTPException(401, "会话已过期，请刷新页面")
    return u


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


# ------------------------------------------------------------------ API：指纹自动注册/登录
OS_MAP = [("windows nt 10", "Windows"), ("windows nt", "Windows"), ("android", "Android"),
          ("iphone", "iPhone"), ("ipad", "iPad"), ("mac os x", "macOS"), ("cros", "ChromeOS"),
          ("linux", "Linux")]
BROWSER_MAP = [("edg/", "Edge"), ("opr/", "Opera"), ("firefox/", "Firefox"), ("chrome/", "Chrome"),
               ("safari/", "Safari")]


def guess_device(ua: str) -> tuple[str, str]:
    low = ua.lower()
    os_name = "未知系统"
    for key, name in OS_MAP:
        if key in low:
            os_name = name
            break
    browser = "未知浏览器"
    for key, name in BROWSER_MAP:
        if key in low:
            browser = name
            break
    return os_name, browser


@app.post("/api/v1/auth/auto-login")
async def auto_login(request: Request):
    """免密自动注册/登录：以浏览器指纹定位用户，首次访问自动建号。"""
    body = await request.json()
    fp = (body.get("fingerprint") or "").strip()
    ua = body.get("userAgent") or request.headers.get("user-agent", "")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{8,64}", fp):
        raise HTTPException(400, "缺少有效的浏览器指纹")
    os_name, browser = guess_device(ua)
    ip = request.client.host if request.client else ""
    with _db_lock, db() as conn:
        row = conn.execute("SELECT * FROM users WHERE fingerprint=?", (fp,)).fetchone()
        is_new = row is None
        if is_new:
            display_name = f"{os_name} {browser}"
            cur = conn.execute(
                "INSERT INTO users(fingerprint,username,display_name,created_ip,avatar_color,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (fp, fp, display_name, ip, random_color(), now_iso()))
            uid = cur.lastrowid
            row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            # 新成员自动加入所有频道
            for w in conn.execute("SELECT id FROM rooms WHERE kind='channel'").fetchall():
                conn.execute("INSERT OR IGNORE INTO room_members(room_id,user_id,joined_at) VALUES(?,?,?)",
                             (w["id"], uid, now_iso()))
        token = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                     (token, row["id"], now_iso(),
                      (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()))
    return {"token": token, "user": public_user(row), "isNew": is_new}


@app.get("/api/v1/me")
async def me(request: Request):
    u = require_user(request)
    return {"user": public_user(u)}


@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    auth = request.headers.get("authorization", "")
    with _db_lock, db() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (auth[7:],))
    return {"ok": True}


# ------------------------------------------------------------------ API：realtime ticket
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


# ------------------------------------------------------------------ API：会话（所有人可建频道/私聊）
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
            if peer_id == u["id"]:
                raise HTTPException(400, "不能和自己私聊")
            pair = "|".join(str(x) for x in sorted({u["id"], peer_id}))
            existing = conn.execute("SELECT id FROM rooms WHERE private_pair_key=?", (pair,)).fetchone()
            if existing:
                room = conn.execute("SELECT * FROM rooms WHERE id=?", (existing["id"],)).fetchone()
                return {"room": room_view(conn, room, u["id"])}
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
        result = {"room": room_view(conn, room, u["id"])}
    await hub.broadcast({"protocolVersion": 1, "type": "room_created",
                         "room": {"id": room["id"], "kind": room["kind"], "name": room["name"]}})
    return result


@app.get("/api/v1/rooms")
async def list_rooms(request: Request):
    u = require_user(request)
    with _db_lock, db() as conn:
        rows = conn.execute(
            "SELECT r.* FROM rooms r JOIN room_members rm ON rm.room_id=r.id "
            "WHERE rm.user_id=? AND r.archived=0 ORDER BY r.kind, r.id", (u["id"],)
        ).fetchall()
        return {"rooms": [room_view(conn, r, u["id"]) for r in rows]}


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
        conn.execute("UPDATE room_members SET last_read_msg_id=? WHERE room_id=? AND user_id=?",
                     (int(body.get("lastMessageId", 0)), rid, u["id"]))
    return {"ok": True}


# ------------------------------------------------------------------ API：发送消息
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
        member_ids = [x["user_id"] for x in conn.execute("SELECT user_id FROM room_members WHERE room_id=?", (rid,)).fetchall()]
        signals = []
        for uid in member_ids:
            if uid == u["id"]:
                continue
            unread = count_unread(conn, rid, uid)
            signals.append((uid, {
                "protocolVersion": 1, "type": "room_message",
                "room": {"id": room["id"], "kind": room["kind"], "name": room["name"]},
                "messageId": m["id"], "createdAt": m["created_at"], "unreadCount": unread,
                "mentionsMe": uid in mentions, "contentPreview": (text[:40] if text else "[文件]"),
                "sender": payload["sender"],
            }))
    await hub.send_room(rid, {"protocolVersion": 1, "type": "message", "message": payload})
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
        if m["sender_id"] != u["id"]:
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
        if not conn.execute("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?",
                            (m["room_id"], u["id"])).fetchone():
            raise HTTPException(403, "仅会话成员可置顶")
        conn.execute("UPDATE messages SET pinned=? WHERE id=?", (1 if body.get("pinned", True) else 0, mid))
        fresh = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        payload = message_payload(conn, fresh)
        t = "message_pinned" if fresh["pinned"] else "message_unpinned"
        rid = m["room_id"]
    await hub.send_room(rid, {"protocolVersion": 1, "type": t, "message": payload, "messageId": mid})
    return {"ok": True}


# ------------------------------------------------------------------ API：文件上传
@app.post("/api/v1/uploads")
async def upload(request: Request, file: UploadFile = File(...)):
    u = require_user(request)
    data = await file.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"文件超过 {MAX_UPLOAD_MB}MB 限制")
    fid = uuid.uuid4().hex
    (UPLOAD_DIR / fid).write_bytes(data)
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


# ------------------------------------------------------------------ API：用户目录
@app.get("/api/v1/users")
async def list_users(request: Request):
    require_user(request)
    with _db_lock, db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        online = hub.online_user_ids()
        return {"users": [{**public_user(r), "online": r["id"] in online} for r in rows]}


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
    await hub.broadcast({"protocolVersion": 1, "type": "presence", "onlineUserIds": sorted(hub.online_user_ids())})
    try:
        if c.scope == "room":
            with _db_lock, db() as conn:
                room = conn.execute("SELECT * FROM rooms WHERE id=?", (c.room_id,)).fetchone()
                pins = conn.execute(
                    "SELECT * FROM messages WHERE room_id=? AND pinned=1 AND deleted_at IS NULL ORDER BY id DESC LIMIT 5",
                    (c.room_id,)).fetchall()
                ready = {
                    "protocolVersion": 1, "type": "ready",
                    "room": {"id": room["id"], "kind": room["kind"], "name": room["name"]} if room else None,
                    "pinned": [message_payload(conn, p) for p in pins],
                    "onlineUserIds": sorted(hub.online_user_ids()),
                }
            await ws.send_text(json.dumps(ready, ensure_ascii=False, default=str))
        else:
            await ws.send_text(json.dumps({"protocolVersion": 1, "type": "ready",
                                           "onlineUserIds": sorted(hub.online_user_ids())}, ensure_ascii=False))
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
                if who:
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
        await hub.broadcast({"protocolVersion": 1, "type": "presence", "onlineUserIds": sorted(hub.online_user_ids())})


# ------------------------------------------------------------------ 前端页面
@app.get("/", response_class=HTMLResponse)
async def index():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


if __name__ == "__main__":
    init_db()
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write("EdgeChat-LAN 启动: http://%s:%s  (局域网内其他设备用本机 IP 访问)\n" % (HOST, PORT))
    sys.stdout.write("免登录模式：打开页面即自动注册，无需账号密码\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.flush()
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
