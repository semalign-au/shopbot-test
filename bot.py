"""Production Telegram Shop Bot — v5.
PostgreSQL + asyncpg. Ledger + idempotency + stock reservation + key rotation.
Fixes: LOG_LEVEL load order, empty-session abort, delivered-refund block, double answer.
"""
from __future__ import annotations

import asyncio, glob, html, io, logging, os, re, secrets, time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from logging.handlers import RotatingFileHandler
from typing import Optional

# 🔧 FIX 1: load_dotenv() moved BEFORE any os.getenv() usage
from dotenv import load_dotenv
load_dotenv()

import asyncpg
from telegram import (InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton,
                      ReplyKeyboardMarkup, Update)
from telegram.error import BadRequest, TelegramError
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

try:
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError, SessionPasswordNeededError
    from telethon.sessions import StringSession
    TELETHON_OK = True
except ImportError:
    TELETHON_OK = False
    class SessionPasswordNeededError(Exception): ...
    class FloodWaitError(Exception): ...

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    class InvalidToken(Exception): ...
    class Fernet:  # type: ignore
        def __init__(self, *a, **k): raise RuntimeError("cryptography not installed")
        def encrypt(self, *a, **k): raise RuntimeError("cryptography not installed")
        def decrypt(self, *a, **k): raise RuntimeError("cryptography not installed")

# ═══════════════ Logging ═══════════════
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(),
              RotatingFileHandler("shopbot.log", maxBytes=5_000_000,
                                  backupCount=3, encoding="utf-8")])
log = logging.getLogger("shopbot")

# ═══════════════ Config ═══════════════
def env(k: str, d: str = "") -> str:
    return os.getenv(k, d).strip()


def _env_int(k: str, d: int = 0) -> int:
    v = env(k)
    if not v:
        return d
    try:
        return int(v)
    except ValueError:
        exit(f"❌ {k} must be an integer, got: {v!r}")


def _env_float(k: str, d: float = 0.0) -> float:
    v = env(k)
    if not v:
        return d
    try:
        return float(v)
    except ValueError:
        exit(f"❌ {k} must be a number, got: {v!r}")


BOT_TOKEN = env("BOT_TOKEN") or exit("❌ BOT_TOKEN required in .env")
ADMIN_CHANNEL_ID = _env_int("ADMIN_CHANNEL_ID", 0)
WELCOME_IMAGE = env("WELCOME_IMAGE", "welcome.jpg")
UPDATES_CHANNEL_LINK = env("UPDATES_CHANNEL_LINK", "https://t.me/")

DATABASE_URL = env("DATABASE_URL")
if not DATABASE_URL:
    exit("❌ DATABASE_URL required in .env\n   e.g. postgresql://user:pass@127.0.0.1:5432/shopbot")

DB_POOL_MIN = _env_int("DB_POOL_MIN", 5)
DB_POOL_MAX = _env_int("DB_POOL_MAX", 20)
BACKUP_DIR = env("BACKUP_DIR", "backups")

_raw_supers = env("SUPER_ADMIN_IDS")
SUPER_ADMIN_IDS: set[int] = set()
for x in _raw_supers.split(","):
    x = x.strip()
    if not x:
        continue
    try:
        SUPER_ADMIN_IDS.add(int(x))
    except ValueError:
        exit(f"❌ SUPER_ADMIN_IDS contains non-integer: {x!r}")

API_COOLDOWN = _env_int("API_COOLDOWN_SECONDS", 300)
RATE_LIMIT_RPS = _env_float("RATE_LIMIT_RPS", 3.0)
RATE_LIMIT_BURST = _env_int("RATE_LIMIT_BURST", 8)
BACKUP_INTERVAL = _env_int("BACKUP_INTERVAL_SECONDS", 3600)
BACKUP_KEEP = _env_int("BACKUP_KEEP", 7)
OTP_CONCURRENCY = _env_int("OTP_CONCURRENCY", 4)

# ── Encryption: primary + optional old keys for rotation ──
if not CRYPTO_OK:
    exit("❌ 'cryptography' package required. Install: pip install cryptography")

ENCRYPTION_KEY = env("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    exit(
        "❌ ENCRYPTION_KEY required in .env (single Fernet key)\n"
        "   Generate one with:\n"
        "   python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
        "   Then paste it as ENCRYPTION_KEY=... in your .env file."
    )

_OLD_KEYS = [k.strip() for k in env("ENCRYPTION_KEY_OLD").split(",") if k.strip()]
try:
    _fernet_primary = Fernet(ENCRYPTION_KEY.encode())
    _fernet_primary.decrypt(_fernet_primary.encrypt(b"ok"))
    _fernet_olds = []
    for k in _OLD_KEYS:
        try:
            _fernet_olds.append(Fernet(k.encode()))
        except Exception as e:
            log.warning("Ignoring invalid ENCRYPTION_KEY_OLD entry: %s", e)
except Exception as e:
    exit(f"❌ Invalid ENCRYPTION_KEY (must be a Fernet key): {e}")

ENC_PREFIX = "enc:v1:"


def _enc(v: Optional[str]) -> str:
    if not v:
        return ""
    return ENC_PREFIX + _fernet_primary.encrypt(str(v).encode()).decode()


def _dec(v: Optional[str]) -> str:
    if not v:
        return ""
    if not v.startswith(ENC_PREFIX):
        return v  # legacy plaintext row
    payload = v[len(ENC_PREFIX):].encode()
    for f in [_fernet_primary, *_fernet_olds]:
        try:
            return f.decrypt(payload).decode()
        except InvalidToken:
            continue
        except Exception as e:
            log.error("Decryption error: %s", e)
            return ""
    log.error("Decryption failed with all keys")
    return ""


# ── 2FA pool ──
TWO_FA_PASSWORDS = [p.strip() for p in env("TWO_FA_PASSWORDS").split(",") if p.strip()]
if not TWO_FA_PASSWORDS:
    exit("❌ TWO_FA_PASSWORDS required in .env (comma-separated)")

DEPOSIT_CONFIG = {
    "bep20": {"name": "USDT (BEP20)", "network": "BNB Smart Chain (BEP20)",
              "min_amount": 1, "address": env("BEP20_ADDRESS"), "emoji": "🟡"},
    "trc20": {"name": "USDT (TRC20)", "network": "Tron (TRC20)",
              "min_amount": 5, "address": env("TRC20_ADDRESS"), "emoji": "🔴"},
}

# ═══════════════ Multi-API Manager ═══════════════
class APIPool:
    def __init__(self, raw: str, cooldown: int):
        self.cooldown = cooldown
        self.lock = asyncio.Lock()
        self.apis: list[dict] = []
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk or ":" not in chunk:
                continue
            try:
                aid_s, ahash = chunk.split(":", 1)
                self.apis.append({
                    "api_id": int(aid_s.strip()), "api_hash": ahash.strip(),
                    "uses": 0, "fails": 0, "disabled_until": 0.0, "last_used": 0.0,
                })
            except Exception as e:
                log.warning("Invalid API credential %r: %s", chunk, e)
        if not self.apis:
            log.error("❌ No valid API credentials in API_CREDENTIALS")

    async def pick(self) -> Optional[dict]:
        async with self.lock:
            now = time.time()
            healthy = [a for a in self.apis if a["disabled_until"] <= now]
            if not healthy:
                healthy = sorted(self.apis, key=lambda a: a["disabled_until"])
            api = min(healthy, key=lambda a: a["last_used"])
            api["last_used"] = now
            api["uses"] += 1
            return api

    async def report_fail(self, api: dict, reason: str = ""):
        async with self.lock:
            api["fails"] += 1
            api["disabled_until"] = time.time() + self.cooldown
            log.warning("API %s failed (%s). Cooldown %ss",
                        api["api_id"], reason or "unknown", self.cooldown)

    async def report_success(self, api: dict):
        async with self.lock:
            api["fails"] = max(0, api["fails"] - 1)

    def stats(self) -> list[str]:
        now = time.time()
        out = []
        for a in self.apis:
            state = "✅" if a["disabled_until"] <= now else f"⏸️ cooldown {int(a['disabled_until'] - now)}s"
            out.append(f"  • {a['api_id']} — uses={a['uses']} fails={a['fails']} {state}")
        return out


API_POOL = APIPool(env("API_CREDENTIALS"), API_COOLDOWN)


async def make_client(session_string: str = "") -> Optional[TelegramClient]:
    if not TELETHON_OK or not API_POOL.apis:
        return None
    api = await API_POOL.pick()
    if not api:
        return None
    client = TelegramClient(StringSession(session_string), api["api_id"], api["api_hash"])
    client._pool_api = api
    await client.connect()
    return client


async def create_client_with_fallback(session_string: str = "",
                                      attempts: int = 0) -> Optional[TelegramClient]:
    max_tries = attempts or max(1, len(API_POOL.apis))
    last_err = None
    for _ in range(max_tries):
        try:
            client = await make_client(session_string)
            if client is None:
                return None
            return client
        except FloodWaitError as e:
            last_err = e
            log.warning("FloodWait during client create: %s", e)
        except Exception as e:
            last_err = e
            log.warning("Client create failed: %s", e)
    log.error("All APIs failed: %s", last_err)
    return None


MAIN_MENU_BUTTONS = {"🛍️ Buy", "👤 Profile", "💵 Deposit", "📞 Support", "🔄 Updates", "⬅️ Back"}
GET_OTP_BTN = "🔐 Get OTP"
FLOW_KEYS = ("state", "deposit_network", "deposit_amount",
             "selected_country", "selected_form", "quantity", "ta_selected_country",
             "ta_withdraw_amount", "ta_withdraw_method")
SESSION_KEYS = ("ta_session_adds", "ta_session_nonspam", "ta_session_spam", "ta_session_frozen")

# ═══════════════ Schema ═══════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    user_id BIGINT PRIMARY KEY,
    role TEXT NOT NULL CHECK(role IN ('super','sub','adder')),
    adds INTEGER NOT NULL DEFAULT 0,
    spam INTEGER NOT NULL DEFAULT 0,
    nonspam INTEGER NOT NULL DEFAULT 0,
    frozen INTEGER NOT NULL DEFAULT 0,
    balance NUMERIC(18,2) NOT NULL DEFAULT 0,
    withdrawals NUMERIC(18,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users (
    user_id BIGINT PRIMARY KEY,
    username TEXT, full_name TEXT,
    balance NUMERIC(18,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS countries (
    code TEXT PRIMARY KEY,
    emoji TEXT NOT NULL, name TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    seller_etb NUMERIC(18,2) NOT NULL,
    buyer_usdt NUMERIC(18,2) NOT NULL
);
CREATE TABLE IF NOT EXISTS stock (
    id BIGSERIAL PRIMARY KEY,
    country_code TEXT NOT NULL REFERENCES countries(code) ON DELETE CASCADE,
    phone TEXT NOT NULL,
    password TEXT NOT NULL,
    session TEXT NOT NULL,
    added_by BIGINT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reserved_by_order BIGINT
);
CREATE INDEX IF NOT EXISTS idx_stock_country ON stock(country_code);
CREATE INDEX IF NOT EXISTS idx_stock_reserved ON stock(country_code, reserved_by_order);

CREATE TABLE IF NOT EXISTS deposits (
    ref_id TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL, amount NUMERIC(18,2) NOT NULL, network TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ, resolved_by BIGINT
);
CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id);

CREATE TABLE IF NOT EXISTS withdrawals (
    ref_id TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL, amount NUMERIC(18,2) NOT NULL,
    method TEXT NOT NULL, account TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ, resolved_by BIGINT
);

CREATE TABLE IF NOT EXISTS orders (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL, country_code TEXT NOT NULL,
    country_label TEXT NOT NULL, form TEXT NOT NULL,
    quantity INTEGER NOT NULL, price NUMERIC(18,2) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivery_status TEXT NOT NULL DEFAULT 'pending',
    delivery_note TEXT,
    delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(delivery_status);

CREATE TABLE IF NOT EXISTS pending_otps (
    user_id BIGINT NOT NULL, phone TEXT NOT NULL,
    session TEXT NOT NULL, password TEXT NOT NULL,
    country_label TEXT, form TEXT, quantity INTEGER,
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (user_id, phone)
);
CREATE TABLE IF NOT EXISTS counters (
    user_id BIGINT NOT NULL, kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, kind)
);
CREATE TABLE IF NOT EXISTS bot_stats (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    total_orders INTEGER NOT NULL DEFAULT 0,
    total_deposits INTEGER NOT NULL DEFAULT 0,
    total_withdrawals INTEGER NOT NULL DEFAULT 0,
    deposit_volume NUMERIC(18,2) NOT NULL DEFAULT 0,
    orders_volume NUMERIC(18,2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ledger (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    delta NUMERIC(18,2) NOT NULL,
    balance_after NUMERIC(18,2) NOT NULL,
    ref TEXT,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON ledger(user_id);
CREATE INDEX IF NOT EXISTS idx_ledger_created ON ledger(created_at);

CREATE TABLE IF NOT EXISTS pending_purchases (
    user_id BIGINT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_actions (
    id BIGSERIAL PRIMARY KEY,
    admin_id BIGINT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_admin_actions_admin ON admin_actions(admin_id);
"""

# ═══════════════ DB pool ═══════════════
_pool: Optional[asyncpg.Pool] = None


def D(x) -> Decimal:
    return Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


async def db_init():
    global _pool
    _pool = await asyncpg.create_pool(
        DATABASE_URL, min_size=DB_POOL_MIN, max_size=DB_POOL_MAX,
        command_timeout=30, server_settings={"application_name": "shopbot"})
    async with _pool.acquire() as conn:
        await conn.execute(SCHEMA)
        try:
            await conn.execute("ALTER TABLE stock ADD COLUMN IF NOT EXISTS reserved_by_order BIGINT")
        except Exception as e:
            log.info("stock column check: %s", e)
        await conn.execute("INSERT INTO bot_stats(id) VALUES (1) ON CONFLICT DO NOTHING")
        await conn.execute(
            "DELETE FROM pending_purchases WHERE created_at < NOW() - INTERVAL '120 seconds'")
        for uid in SUPER_ADMIN_IDS:
            await conn.execute(
                "INSERT INTO admins(user_id, role) VALUES ($1, 'super') "
                "ON CONFLICT (user_id) DO NOTHING", uid)
    log.info("Postgres ready (pool %d–%d)", DB_POOL_MIN, DB_POOL_MAX)
    log.info("APIs loaded: %d | 2FA pool: %d | 🔐 Encryption: ON (%d key(s))",
             len(API_POOL.apis), len(TWO_FA_PASSWORDS), 1 + len(_fernet_olds))


async def db_close():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        log.info("Postgres pool closed")


def db() -> asyncpg.Pool:
    assert _pool is not None, "DB not initialized"
    return _pool


# ═══════════════ Rate limiter ═══════════════
class RateLimiter:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self._buckets: dict[int, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, uid: int) -> bool:
        async with self._lock:
            now = time.monotonic()
            tokens, last = self._buckets.get(uid, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[uid] = (tokens, now)
                return False
            self._buckets[uid] = (tokens - 1, now)
            return True

    def prune(self, max_age: float = 3600):
        now = time.monotonic()
        stale = [k for k, (_, last) in self._buckets.items() if now - last > max_age]
        for k in stale:
            self._buckets.pop(k, None)


RATE_LIMITER = RateLimiter(RATE_LIMIT_RPS, RATE_LIMIT_BURST)


# ═══════════════ Backups ═══════════════
os.makedirs(BACKUP_DIR, exist_ok=True)


def _backup_paths() -> list[str]:
    return sorted(glob.glob(os.path.join(BACKUP_DIR, "shopbot_*.dump")))


async def make_backup() -> Optional[str]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"shopbot_{ts}.dump")
    try:
        proc = await asyncio.create_subprocess_exec(
            "pg_dump", "-Fc", "-f", dst, "-d", DATABASE_URL,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        if proc.returncode != 0:
            log.warning("pg_dump failed (%d): %s", proc.returncode,
                        (err or b"").decode(errors="ignore")[:300])
            return None
        log.info("💾 Backup written: %s", dst)
        for old in _backup_paths()[:-BACKUP_KEEP]:
            try:
                os.remove(old)
                log.info("💾 Pruned: %s", old)
            except Exception as e:
                log.warning("prune failed: %s", e)
        return dst
    except FileNotFoundError:
        log.warning("pg_dump not installed — skipping local backup.")
        return None
    except Exception as e:
        log.warning("backup failed: %s", e)
        return None


async def backup_loop():
    while True:
        await asyncio.sleep(BACKUP_INTERVAL)
        try:
            await make_backup()
            RATE_LIMITER.prune()
            await db().execute(
                "DELETE FROM pending_purchases WHERE created_at < NOW() - INTERVAL '120 seconds'")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning("backup_loop error: %s", e)


# ═══════════════ users ═══════════════
async def user_touch(uid, username, full_name):
    await db().execute(
        """INSERT INTO users(user_id, username, full_name) VALUES ($1,$2,$3)
           ON CONFLICT (user_id) DO UPDATE
             SET username = EXCLUDED.username, full_name = EXCLUDED.full_name""",
        uid, username, full_name)


async def user_balance(uid) -> float:
    row = await db().fetchrow("SELECT balance FROM users WHERE user_id=$1", uid)
    return float(row["balance"]) if row else 0.0


async def users_count() -> int:
    return int(await db().fetchval("SELECT COUNT(*) FROM users"))


# ═══════════════ admins ═══════════════
async def admin_role(uid) -> Optional[str]:
    return await db().fetchval("SELECT role FROM admins WHERE user_id=$1", uid)


async def admin_add(uid, role) -> bool:
    try:
        res = await db().execute(
            "INSERT INTO admins(user_id, role) VALUES ($1,$2) "
            "ON CONFLICT (user_id) DO NOTHING", uid, role)
        return res.endswith("1")
    except Exception as e:
        log.warning("admin_add failed: %s", e)
        return False


async def admin_log(admin_id: int, action: str, target: str = "", detail: str = ""):
    try:
        await db().execute(
            """INSERT INTO admin_actions(admin_id, action, target, detail)
               VALUES ($1,$2,$3,$4)""",
            admin_id, action, target or None, detail or None)
    except Exception as e:
        log.warning("admin_log failed: %s", e)


async def adder_get(uid) -> dict:
    row = await db().fetchrow(
        "SELECT adds, spam, nonspam, frozen, balance, withdrawals FROM admins "
        "WHERE user_id=$1 AND role='adder'", uid)
    if not row:
        return {"adds": 0, "spam": 0, "nonspam": 0, "frozen": 0,
                "balance": 0.0, "withdrawals": 0.0}
    return {
        "adds": row["adds"], "spam": row["spam"], "nonspam": row["nonspam"],
        "frozen": row["frozen"], "balance": float(row["balance"]),
        "withdrawals": float(row["withdrawals"]),
    }


async def adder_bump(uid, *, adds=0, spam=0, nonspam=0, frozen=0, balance=0.0):
    await db().execute(
        """UPDATE admins SET adds=adds+$1, spam=spam+$2, nonspam=nonspam+$3,
             frozen=frozen+$4, balance=ROUND(balance+$5,2)
           WHERE user_id=$6 AND role='adder'""",
        adds, spam, nonspam, frozen, D(balance), uid)


async def adders_count() -> int:
    return int(await db().fetchval("SELECT COUNT(*) FROM admins WHERE role='adder'"))


# ═══════════════ countries / stock ═══════════════
async def country_set(code, emoji, name, cap, etb, usdt):
    await db().execute(
        """INSERT INTO countries(code, emoji, name, capacity, seller_etb, buyer_usdt)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (code) DO UPDATE
             SET emoji=EXCLUDED.emoji, name=EXCLUDED.name,
                 capacity=EXCLUDED.capacity,
                 seller_etb=EXCLUDED.seller_etb,
                 buyer_usdt=EXCLUDED.buyer_usdt""",
        code, emoji, name, cap, D(etb), D(usdt))


async def country_remove(code):
    await db().execute("DELETE FROM countries WHERE code=$1", code)


async def countries_all() -> list[dict]:
    rows = await db().fetch("SELECT * FROM countries ORDER BY code")
    return [dict(r) for r in rows]


async def country_get(code) -> Optional[dict]:
    row = await db().fetchrow("SELECT * FROM countries WHERE code=$1", code)
    return dict(row) if row else None


async def country_stock_count(code) -> int:
    return int(await db().fetchval(
        "SELECT COUNT(*) FROM stock WHERE country_code=$1 AND reserved_by_order IS NULL",
        code))


async def total_stock() -> int:
    return int(await db().fetchval(
        "SELECT COUNT(*) FROM stock WHERE reserved_by_order IS NULL"))


async def stock_push(code, phone, password, session, added_by):
    await db().execute(
        "INSERT INTO stock(country_code, phone, password, session, added_by) "
        "VALUES ($1,$2,$3,$4,$5)",
        code, phone, _enc(password), _enc(session), added_by)


# ═══════════════ counters ═══════════════
async def next_counter(uid, kind) -> int:
    row = await db().fetchrow(
        """INSERT INTO counters(user_id, kind, value) VALUES ($1,$2,1)
           ON CONFLICT (user_id, kind) DO UPDATE
             SET value = counters.value + 1
           RETURNING value""", uid, kind)
    return int(row["value"])


async def next_2fa_password() -> str:
    n = await next_counter(0, "global_2fa")
    idx = (n - 1) % len(TWO_FA_PASSWORDS)
    if n > len(TWO_FA_PASSWORDS):
        log.warning("2FA pool reused (assigned %d > pool %d)", n, len(TWO_FA_PASSWORDS))
    return TWO_FA_PASSWORDS[idx]


def _new_ref(uid: int, kind: str, counter: int) -> str:
    return f"{uid}_#{kind}{counter}_{secrets.token_hex(4)}"


# ═══════════════ Idempotency: purchase lock ═══════════════
async def try_acquire_purchase_lock(uid: int) -> bool:
    async with db().acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "DELETE FROM pending_purchases "
                "WHERE user_id=$1 AND created_at < NOW() - INTERVAL '60 seconds'", uid)
            res = await conn.execute(
                "INSERT INTO pending_purchases(user_id) VALUES ($1) "
                "ON CONFLICT (user_id) DO NOTHING", uid)
            return res.endswith("1")


async def release_purchase_lock(uid: int):
    try:
        await db().execute("DELETE FROM pending_purchases WHERE user_id=$1", uid)
    except Exception as e:
        log.warning("release_purchase_lock failed: %s", e)


# ═══════════════ Ledger ═══════════════
async def _ledger_insert(conn, user_id: int, kind: str, delta: Decimal,
                         balance_after: Decimal, ref: str = "", note: str = ""):
    await conn.execute(
        """INSERT INTO ledger(user_id, kind, delta, balance_after, ref, note)
           VALUES ($1,$2,$3,$4,$5,$6)""",
        user_id, kind, delta, balance_after, ref or None, note or None)


async def ledger_of(uid: int, limit: int = 20) -> list[dict]:
    rows = await db().fetch(
        "SELECT * FROM ledger WHERE user_id=$1 ORDER BY id DESC LIMIT $2",
        uid, limit)
    return [dict(r) for r in rows]


# ═══════════════ ATOMIC: order purchase ═══════════════
class InsufficientBalance(Exception): ...
class InsufficientStock(Exception): ...


async def order_purchase_atomic(uid: int, code: str, qty: int, total: Decimal,
                                form_label: str, label: str) -> tuple[int, list[dict]]:
    async with db().acquire() as conn:
        async with conn.transaction():
            bal_row = await conn.fetchrow(
                "SELECT balance FROM users WHERE user_id=$1 FOR UPDATE", uid)
            if not bal_row or bal_row["balance"] < total:
                raise InsufficientBalance()

            order_id = await conn.fetchval(
                """INSERT INTO orders(user_id, country_code, country_label, form,
                       quantity, price, delivery_status)
                   VALUES ($1,$2,$3,$4,$5,$6,'pending')
                   RETURNING id""",
                uid, code, label, form_label, qty, total)

            rows = await conn.fetch(
                """WITH picked AS (
                       SELECT id FROM stock
                       WHERE country_code=$2 AND reserved_by_order IS NULL
                       ORDER BY id
                       LIMIT $3
                       FOR UPDATE SKIP LOCKED
                   )
                   UPDATE stock SET reserved_by_order=$1
                   WHERE id IN (SELECT id FROM picked)
                   RETURNING id, phone, password, session""",
                order_id, code, qty)
            if len(rows) < qty:
                raise InsufficientStock()

            new_bal = await conn.fetchval(
                "UPDATE users SET balance=ROUND(balance-$1,2) "
                "WHERE user_id=$2 RETURNING balance",
                total, uid)

            await _ledger_insert(conn, uid, "purchase", -total, new_bal,
                                 ref=str(order_id), note=label)

            await conn.execute(
                """UPDATE bot_stats SET total_orders=total_orders+1,
                       orders_volume=ROUND(orders_volume+$1,2) WHERE id=1""", total)

            result = [{"phone": r["phone"], "password": _dec(r["password"]),
                       "session": _dec(r["session"])} for r in rows]
            return order_id, result


async def order_mark_delivery(order_id: int, status: str, note: str = ""):
    async with db().acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """UPDATE orders SET delivery_status=$1, delivery_note=$2,
                       delivered_at = CASE WHEN $1='delivered' THEN NOW() ELSE delivered_at END
                   WHERE id=$3""",
                status, note or None, order_id)
            if status == "delivered":
                await conn.execute(
                    "DELETE FROM stock WHERE reserved_by_order=$1", order_id)


# 🔧 FIX 3: refund now refuses BOTH 'refunded' and 'delivered' orders
async def order_refund(order_id: int, admin_id: int) -> Optional[dict]:
    """
    Idempotent. Refuses to refund already-refunded or already-delivered orders.
    Releases reserved stock back to the pool, credits the user, writes ledger + admin log.
    """
    async with db().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM orders WHERE id=$1 FOR UPDATE", order_id)
            if not row:
                return None
            if row["delivery_status"] in ("refunded", "delivered"):
                return None

            await conn.execute(
                "UPDATE stock SET reserved_by_order=NULL WHERE reserved_by_order=$1",
                order_id)

            new_bal = await conn.fetchval(
                "UPDATE users SET balance=ROUND(balance+$1,2) "
                "WHERE user_id=$2 RETURNING balance",
                row["price"], row["user_id"])

            await _ledger_insert(conn, row["user_id"], "refund", row["price"],
                                 new_bal, ref=str(order_id),
                                 note=f"refund by admin {admin_id}")

            await conn.execute(
                "UPDATE orders SET delivery_status='refunded', "
                "delivery_note=$1, delivered_at=COALESCE(delivered_at, NOW()) "
                "WHERE id=$2",
                f"refunded by {admin_id}", order_id)

            await conn.execute(
                """INSERT INTO admin_actions(admin_id, action, target, detail)
                   VALUES ($1, 'refund', $2, $3)""",
                admin_id, str(order_id), f"amount={row['price']}")

            return dict(row)


# ═══════════════ ATOMIC: deposit claim ═══════════════
async def deposit_claim(ref: str, admin_id: int, approve: bool) -> Optional[dict]:
    new_status = "approved" if approve else "rejected"
    async with db().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """UPDATE deposits
                   SET status=$1, resolved_at=NOW(), resolved_by=$2
                   WHERE ref_id=$3 AND status='pending'
                   RETURNING *""", new_status, admin_id, ref)
            if not row:
                return None

            if approve:
                new_bal = await conn.fetchval(
                    "UPDATE users SET balance=ROUND(balance+$1,2) "
                    "WHERE user_id=$2 RETURNING balance",
                    row["amount"], row["user_id"])
                await _ledger_insert(conn, row["user_id"], "deposit",
                                     row["amount"], new_bal, ref=ref)
                await conn.execute(
                    """UPDATE bot_stats
                       SET deposit_volume = ROUND(deposit_volume + $1, 2)
                       WHERE id=1""", row["amount"])

            await conn.execute(
                """INSERT INTO admin_actions(admin_id, action, target, detail)
                   VALUES ($1, $2, $3, $4)""",
                admin_id, f"deposit_{new_status}", ref, f"amount={row['amount']}")
            return dict(row)


# ═══════════════ ATOMIC: withdrawal claim ═══════════════
async def withdrawal_claim(ref: str, admin_id: int, approve: bool) -> Optional[dict]:
    async with db().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM withdrawals WHERE ref_id=$1 AND status='pending' FOR UPDATE",
                ref)
            if not row:
                return None

            if approve:
                a = await conn.fetchrow(
                    "SELECT balance FROM admins WHERE user_id=$1 AND role='adder' FOR UPDATE",
                    row["user_id"])
                if not a or a["balance"] < row["amount"]:
                    return None
                new_bal = await conn.fetchval(
                    """UPDATE admins
                       SET balance = ROUND(balance - $1, 2),
                           withdrawals = ROUND(withdrawals + $1, 2)
                       WHERE user_id=$2 RETURNING balance""",
                    row["amount"], row["user_id"])
                await _ledger_insert(conn, row["user_id"], "withdraw",
                                     -row["amount"], new_bal, ref=ref,
                                     note=f"{row['method']}")

            new_status = "approved" if approve else "rejected"
            await conn.execute(
                """UPDATE withdrawals SET status=$1, resolved_at=NOW(), resolved_by=$2
                   WHERE ref_id=$3 AND status='pending'""",
                new_status, admin_id, ref)

            await conn.execute(
                """INSERT INTO admin_actions(admin_id, action, target, detail)
                   VALUES ($1, $2, $3, $4)""",
                admin_id, f"withdraw_{new_status}", ref, f"amount={row['amount']}")
            return dict(row)


# ═══════════════ orders / otps / stats ═══════════════
async def orders_of(uid) -> list[dict]:
    rows = await db().fetch(
        "SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC", uid)
    return [dict(r) for r in rows]


async def otp_store(uid, phone, session, password, country, form, qty, ts):
    await db().execute(
        """INSERT INTO pending_otps(user_id, phone, session, password,
               country_label, form, quantity, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           ON CONFLICT (user_id, phone) DO UPDATE
             SET session=EXCLUDED.session, password=EXCLUDED.password,
                 country_label=EXCLUDED.country_label, form=EXCLUDED.form,
                 quantity=EXCLUDED.quantity, created_at=EXCLUDED.created_at""",
        uid, phone, _enc(session), _enc(password), country, form, qty, ts)


async def otps_get(uid) -> list[dict]:
    rows = await db().fetch(
        "SELECT * FROM pending_otps WHERE user_id=$1 ORDER BY created_at ASC", uid)
    out = []
    for r in rows:
        d = dict(r)
        d["session"] = _dec(d["session"])
        d["password"] = _dec(d["password"])
        out.append(d)
    return out


async def otp_delete(uid, phone):
    await db().execute(
        "DELETE FROM pending_otps WHERE user_id=$1 AND phone=$2", uid, phone)


async def otps_clear(uid):
    await db().execute("DELETE FROM pending_otps WHERE user_id=$1", uid)


async def stats_get() -> dict:
    row = await db().fetchrow("SELECT * FROM bot_stats WHERE id=1")
    if not row:
        return {}
    d = dict(row)
    d["deposit_volume"] = float(d["deposit_volume"])
    d["orders_volume"] = float(d["orders_volume"])
    return d


# ═══════════════ Helpers ═══════════════
esc = lambda v: html.escape(str(v), quote=False)
async def is_super_async(uid): return await admin_role(uid) == "super"
async def is_approver_async(uid): return await admin_role(uid) in ("super", "sub")
async def is_adder_async(uid): return await admin_role(uid) == "adder"


def chunk_text(text: str, size: int = 4000) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)]


async def safe_edit(q, text: str, **kw):
    try:
        await q.edit_message_text(text, **kw)
    except BadRequest as e:
        msg = str(e).lower()
        if "not modified" in msg:
            return
        if "too long" in msg:
            for chunk in chunk_text(text):
                try:
                    await q.message.reply_text(chunk, **kw)
                except TelegramError:
                    pass
            return
        raise


async def tg_check_account_status(client, retries: int = 2) -> str:
    for attempt in range(retries):
        try:
            bot = await client.get_entity("SpamBot")
            await client.send_message(bot, "/start")
            deadline = asyncio.get_running_loop().time() + 14
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(2)
                msgs = await client.get_messages(bot, limit=1)
                if not msgs or not msgs[0].text:
                    continue
                t = msgs[0].text.lower()
                if "frozen" in t:
                    return "frozen"
                if any(k in t for k in ("good news", "no limits", "no restrictions", "free")):
                    return "clean"
                if any(k in t for k in ("limited", "spam", "restricted")):
                    return "spam"
            log.warning("spam check attempt %d: no decisive reply", attempt + 1)
        except Exception as e:
            log.warning("spam check attempt %d err: %s", attempt + 1, e)
            await asyncio.sleep(1.5)
    return "error"


async def tg_set_2fa(client, password: str, old: str | None = None) -> bool:
    try:
        if old:
            try:
                await client.edit_2fa(current_password=old, new_password=password)
                return True
            except Exception as e:
                log.info("edit_2fa with old password failed (%s), retrying without", e)
        await client.edit_2fa(new_password=password)
        return True
    except Exception as e:
        log.warning("set 2FA err: %s", e)
        return False


async def tg_disconnect(client):
    try:
        await client.disconnect()
    except Exception as e:
        log.warning("disconnect err: %s", e)


_OTP_PRIMARY = re.compile(
    r"(?:login|log\s*-?\s*in|auth(?:entication)?)\s*code[^0-9A-Za-z]{0,4}([A-Za-z0-9_\-]{4,8})",
    re.IGNORECASE)
_OTP_NUMERIC = re.compile(r"(?<!\d)(\d{5})(?!\d)")
_OTP_NUMERIC_ALT = re.compile(r"(?<!\d)(\d{4,6})(?!\d)")
_OTP_BLOCK = ("do not give", "don't give", "don't share", "do not share",
              "never share", "if you didn't", "if this wasn't you")


def extract_otp(text: str) -> Optional[str]:
    if not text:
        return None
    m = _OTP_PRIMARY.search(text)
    if m:
        return m.group(1)
    low = text.lower()
    if any(k in low for k in _OTP_BLOCK):
        return None
    m = _OTP_NUMERIC.search(text) or _OTP_NUMERIC_ALT.search(text)
    return m.group(1) if m else None


async def fetch_otp(session_string: str, wait: int = 45, min_ts: float | None = None):
    if not session_string:
        return None, "no_session"
    tries = max(1, len(API_POOL.apis))
    last = None
    for _ in range(tries):
        client = None
        try:
            client = await create_client_with_fallback(session_string)
            if client is None:
                return None, "no_api"
            api = getattr(client, "_pool_api", None)
            if not await client.is_user_authorized():
                await tg_disconnect(client)
                return None, "unauthorized"
            loop = asyncio.get_running_loop()
            deadline = loop.time() + wait
            while loop.time() < deadline:
                try:
                    msgs = await client.get_messages(777000, limit=10)
                except FloodWaitError as e:
                    if api:
                        await API_POOL.report_fail(api, f"floodwait {e.seconds}")
                    raise
                except Exception as e:
                    last = str(e)
                    msgs = []
                for m in msgs:
                    if not m or not m.text:
                        continue
                    if min_ts and m.date:
                        try:
                            if m.date.timestamp() < min_ts:
                                continue
                        except Exception:
                            pass
                    otp = extract_otp(m.text)
                    if otp:
                        if api:
                            await API_POOL.report_success(api)
                        return otp, None
                await asyncio.sleep(3)
            return None, last or "no_otp"
        except FloodWaitError as e:
            last = f"floodwait {e.seconds}s"
            log.warning("OTP fetch floodwait, rotating: %s", e)
            continue
        except Exception as e:
            last = str(e)
            log.warning("OTP fetch err, rotating: %s", e)
            continue
        finally:
            if client:
                try:
                    await client.disconnect()
                except Exception:
                    pass
    return None, last or "all_apis_failed"


def make_session_file(session_string: str, phone: str) -> io.BytesIO:
    bio = io.BytesIO(session_string.encode())
    bio.name = f"{phone.replace('+', '').replace(' ', '')}.session"
    return bio


# ═══════════════ Keyboards ═══════════════
def kb_main():
    return ReplyKeyboardMarkup([[KeyboardButton("🛍️ Buy"), KeyboardButton("👤 Profile")],
                                [KeyboardButton("💵 Deposit"), KeyboardButton("📞 Support")],
                                [KeyboardButton("🔄 Updates")]], resize_keyboard=True)


def kb_adder_home():
    return ReplyKeyboardMarkup([[KeyboardButton("➕ Add")],
                                [KeyboardButton("👤 Profile"), KeyboardButton("📞 Support")]],
                               resize_keyboard=True)


def kb_done(): return ReplyKeyboardMarkup([[KeyboardButton("✅ Done")]], resize_keyboard=True)
def kb_back(): return ReplyKeyboardMarkup([[KeyboardButton("⬅️ Back")]], resize_keyboard=True)
def kb_get_otp(): return ReplyKeyboardMarkup([[KeyboardButton(GET_OTP_BTN)]], resize_keyboard=True)


def kb_profile(uid):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📜 View Order History", callback_data="view_orders")],
        [InlineKeyboardButton("📒 View Ledger", callback_data="view_ledger")],
    ])


def kb_third_profile():
    return InlineKeyboardMarkup([[InlineKeyboardButton("💸 Withdraw", callback_data="ta_withdraw")]])


def prompt_deposit_amount(cfg):
    return (f"📥 Enter Amount (USDT):\n━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Note: Minimum deposit for {cfg['name']} is {cfg['min_amount']} USDT")


async def text_profile_buyer(user, uid):
    display = f"@{user.username}" if user.username else (user.full_name or "Unknown")
    bal = await user_balance(uid)
    orders = await orders_of(uid)
    spent = sum(float(o["price"]) for o in orders if o.get("delivery_status") != "refunded")
    return (f"👤 USER PROFILE\n━━━━━━━━━━━━━━━━━━\n"
            f"📛 Name: {display}\n🆔 Account ID: {uid}\n"
            f"💰 Current Balance: {bal:.2f} USDT\n"
            f"💸 Total Spent: {spent:.2f} USDT\n"
            f"🛍️ Total Orders: {len(orders)}\n━━━━━━━━━━━━━━━━━━")


async def text_profile_adder(user, uid):
    display = f"@{user.username}" if user.username else (user.full_name or "Unknown")
    a = await adder_get(uid)
    return (f"👤 USER PROFILE\n━━━━━━━━━━━━━━━━━━\n"
            f"📛 Name: {display}\n🆔 Account ID: {uid}\n"
            f"💰 Current Balance: {a['balance']:.2f} ETB\n"
            f"💸 Total Withdrawals: {a['withdrawals']:.2f} ETB\n"
            f"🛍️ Total Add : {a['adds']}\n━━━━━━━━━━━━━━━━━━")


# ═══════════════ Channel senders ═══════════════
async def _try_send(bot, chat_id, **kw):
    try:
        await bot.send_message(chat_id=chat_id, **kw)
        return True
    except TelegramError as e:
        log.warning("send to %s failed: %s", chat_id, e)
        return False


async def send_to_admin(context, **kw):
    if ADMIN_CHANNEL_ID and await _try_send(context.bot, ADMIN_CHANNEL_ID, **kw):
        return
    for uid in SUPER_ADMIN_IDS:
        await _try_send(context.bot, uid, **kw)


async def send_photo_to_admin(context, **kw):
    if ADMIN_CHANNEL_ID:
        try:
            await context.bot.send_photo(chat_id=ADMIN_CHANNEL_ID, **kw)
            return
        except TelegramError as e:
            log.warning("photo to channel failed: %s", e)
    for uid in SUPER_ADMIN_IDS:
        try:
            await context.bot.send_photo(chat_id=uid, **kw)
        except TelegramError as e:
            log.warning("photo to %s failed: %s", uid, e)


def reset_session(ctx):
    for k in SESSION_KEYS:
        ctx.user_data[k] = 0


def bump_session(ctx, key, n=1):
    ctx.user_data[key] = ctx.user_data.get(key, 0) + n


# ═══════════════ /start ═══════════════
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    await user_touch(uid, update.effective_user.username or "",
                     update.effective_user.full_name or "")
    for k in FLOW_KEYS:
        context.user_data.pop(k, None)
    if await otps_get(uid):
        return await update.message.reply_text(
            "🔐 You have accounts waiting for OTP.\nTap 🔐 Get OTP below.",
            reply_markup=kb_get_otp())
    if await is_adder_async(uid):
        return await update.message.reply_text(
            "🏠 ADDER HOME\n━━━━━━━━━━━━━━━━━━━━━━\nUse ➕ Add to add accounts.",
            reply_markup=kb_adder_home())
    caption = ("✨ WELCOME TO PREMIUM STORE! ✨\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
               "💎 Premium Digital Assets\n⚡ Lightning-Fast Automated Delivery\n"
               "🛡️ 24/7 Dedicated Support\n🔒 100% Safe • Fast • Reliable\n"
               "━━━━━━━━━━━━━━━━━━━━━━━━\n💫 Thank you for choosing us! 💫\n"
               "━━━━━━━━━━━━━━━━━━━━━━━━\n👇 Tap an option below to get started.")
    try:
        with open(WELCOME_IMAGE, "rb") as ph:
            await update.message.reply_photo(photo=ph, caption=caption, reply_markup=kb_main())
    except FileNotFoundError:
        await update.message.reply_text(caption, reply_markup=kb_main())


# ═══════════════ Admin commands ═══════════════
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_super_async(update.effective_user.id):
        return await update.message.reply_text("⛔ Not authorized.")
    s = await stats_get()
    lines = ["📊 BOT STATISTICS", "━━━━━━━━━━━━━━━━━━",
             f"👥 Total Users: {await users_count()}",
             f"🧑‍💻 Account Adders: {await adders_count()}",
             f"🛍️ Total Orders: {s['total_orders']}",
             f"💵 Deposit Requests: {s['total_deposits']}",
             f"💲 Withdraw Requests: {s['total_withdrawals']}",
             "━━━━━━━━━━━━━━━━━━",
             f"💰 Deposit Volume: {s['deposit_volume']:.2f} USDT",
             f"💎 Order Volume: {s['orders_volume']:.2f} USDT",
             "━━━━━━━━━━━━━━━━━━", "🌍 Countries", "━━━━━━━━━━━━━━━━━━"]
    cs = await countries_all()
    if not cs:
        lines.append("(none defined — use /set)")
    else:
        for i, c in enumerate(cs, 1):
            stock = await country_stock_count(c["code"])
            rem = max(c["capacity"] - stock, 0)
            lines.append(f"{i}, {c['emoji']} {c['code']} | 📦 {stock}/{rem} | "
                         f"{float(c['seller_etb']):.2f} ETB | {float(c['buyer_usdt']):.2f} USDT")
    lines += ["━━━━━━━━━━━━━━━━━━", f"🔌 API Pool ({len(API_POOL.apis)})", "━━━━━━━━━━━━━━━━━━"]
    lines += API_POOL.stats() or ["  (no APIs configured)"]
    lines += ["━━━━━━━━━━━━━━━━━━", f"🔐 2FA Pool: {len(TWO_FA_PASSWORDS)} passwords",
              f"🔒 Encryption: ✅ Fernet ({1 + len(_fernet_olds)} key(s))",
              "🐘 DB: PostgreSQL",
              f"🛡️ Rate Limit: {RATE_LIMIT_RPS}/s (burst {RATE_LIMIT_BURST})",
              f"💾 Backups: every {BACKUP_INTERVAL}s, keeping {BACKUP_KEEP}",
              f"🔁 OTP Concurrency: {OTP_CONCURRENCY}",
              "━━━━━━━━━━━━━━━━━━"]
    await update.message.reply_text("\n".join(lines))


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_super_async(update.effective_user.id):
        return await update.message.reply_text("⛔ Not authorized.")
    if not context.args:
        return await update.message.reply_text("Usage: /add <telegram_id>")
    try:
        uid = int(context.args[0])
    except ValueError:
        return await update.message.reply_text("⚠️ Invalid Telegram User ID.")
    if await admin_role(uid) == "super":
        return await update.message.reply_text(
            f"ℹ️ <code>{uid}</code> is already a Super Admin.", parse_mode="HTML")
    if not await admin_add(uid, "sub"):
        return await update.message.reply_text(
            f"ℹ️ <code>{uid}</code> already has a role.", parse_mode="HTML")
    await admin_log(update.effective_user.id, "add_sub", str(uid))
    await update.message.reply_text(
        f"✅ User <code>{uid}</code> is now a Sub-Admin.", parse_mode="HTML")
    try:
        await context.bot.send_message(uid, "🎉 CONGRATULATIONS!\n━━━━━━━━━━━━━━━━━━\n"
                                          "You are now a Sub-Admin. You can approve/reject "
                                          "deposit and withdrawal requests.")
    except TelegramError as e:
        log.warning("notify sub-admin failed: %s", e)


async def cmd_adds(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_approver_async(update.effective_user.id):
        return await update.message.reply_text("⛔ Not authorized.")
    if not context.args:
        return await update.message.reply_text("Usage: /adds <telegram_id>")
    try:
        uid = int(context.args[0])
    except ValueError:
        return await update.message.reply_text("⚠️ Invalid Telegram User ID.")
    if await admin_role(uid) in ("super", "sub"):
        return await update.message.reply_text("ℹ️ That user is already a full admin.")
    if not await admin_add(uid, "adder"):
        return await update.message.reply_text(
            f"ℹ️ <code>{uid}</code> already has a role.", parse_mode="HTML")
    await admin_log(update.effective_user.id, "add_adder", str(uid))
    await update.message.reply_text(
        f"✅ User <code>{uid}</code> is now an Account Adder.", parse_mode="HTML")
    try:
        await context.bot.send_message(uid, "🎉 CONGRATULATIONS!\n━━━━━━━━━━━━━━━━━━\n"
                                          "You have been added as an Account Adder.\n"
                                          "Use ➕ Add to start adding accounts.",
                                      reply_markup=kb_adder_home())
    except TelegramError as e:
        log.warning("notify adder failed: %s", e)


async def cmd_set(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_super_async(update.effective_user.id):
        return await update.message.reply_text("⛔ Not authorized.")
    txt = update.message.text or ""
    if " " not in txt:
        return await update.message.reply_text(
            "Usage: /set <emoji>,<code>,<name>_<capacity>_<ETB>_<USDT>\n"
            "Example: /set 🇪🇹,+251,Ethiopia_200_15_1.5\n• capacity = 0 → removes")
    parts = txt.split(" ", 1)[1].strip().split("_")
    if len(parts) != 4:
        return await update.message.reply_text("⚠️ Wrong format.")
    info, cap_s, etb_s, usdt_s = parts
    ip = info.split(",")
    if len(ip) != 3:
        return await update.message.reply_text("⚠️ Header must be emoji,code,name.")
    emoji, code, name = [p.strip() for p in ip]
    if not emoji or not code.startswith("+") or not name:
        return await update.message.reply_text("⚠️ Emoji/code(+..)/name required.")
    try:
        cap = int(cap_s.strip())
        etb = float(etb_s.strip())
        usdt = float(usdt_s.strip())
    except ValueError:
        return await update.message.reply_text("⚠️ Invalid capacity/ETB/USDT.")
    if cap == 0:
        if await country_get(code):
            await country_remove(code)
            await admin_log(update.effective_user.id, "country_remove", code)
            return await update.message.reply_text(
                f"🗑️ Country <code>{code}</code> ({esc(name)}) removed.", parse_mode="HTML")
        return await update.message.reply_text(
            f"ℹ️ Country <code>{code}</code> not set.", parse_mode="HTML")
    if cap < 0 or etb <= 0 or usdt <= 0:
        return await update.message.reply_text("⚠️ Capacity ≥ 0; ETB & USDT > 0.")
    await country_set(code, emoji, name, cap, etb, usdt)
    await admin_log(update.effective_user.id, "country_set", code,
                    f"cap={cap} etb={etb} usdt={usdt}")
    stock = await country_stock_count(code)
    await update.message.reply_text(
        f"✅ Country set!\n━━━━━━━━━━━━━━━━━━\n🌍 {emoji} {code} {name}\n"
        f"📦 Capacity: {cap} pcs\n💰 Adder Earn: {etb:.2f} ETB\n"
        f"💵 Buyer Price: {usdt:.2f} USDT\n📊 Current stock: {stock} pcs")


async def cmd_refund(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_super_async(update.effective_user.id):
        return await update.message.reply_text("⛔ Not authorized.")
    if not context.args:
        return await update.message.reply_text("Usage: /refund <order_id>")
    try:
        oid = int(context.args[0])
    except ValueError:
        return await update.message.reply_text("⚠️ order_id must be an integer.")
    row = await order_refund(oid, update.effective_user.id)
    if not row:
        return await update.message.reply_text(
            f"ℹ️ Order <code>{oid}</code> not refundable "
            f"(missing, already delivered, or already refunded).", parse_mode="HTML")
    await update.message.reply_text(
        f"✅ Refunded order <code>{oid}</code> — {float(row['price']):.2f} USDT to user "
        f"<code>{row['user_id']}</code>.\n"
        f"Stock released back to pool.", parse_mode="HTML")
    try:
        await context.bot.send_message(
            row["user_id"],
            f"💸 REFUND ISSUED\n━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🛍️ Order #{oid}\n💵 Amount: {float(row['price']):.2f} USDT\n"
            "The amount has been credited back to your balance.")
    except TelegramError:
        pass


# ═══════════════ Adder flow ═══════════════
ACTIVE_ADD_SESSIONS: dict = {}


async def handle_adder(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str):
    uid = update.effective_user.id
    state = context.user_data.get("state")
    if text == "➕ Add":
        reset_session(context)
        cs = await countries_all()
        if not cs:
            return await update.message.reply_text("⚠️ No countries enabled yet.")
        buttons = [[InlineKeyboardButton(
            f"{c['emoji']}({c['code']}){c['name']} | 📦 {c['capacity']} | "
            f"💵 {float(c['seller_etb']):.2f} ETB",
            callback_data=f"ta_add_{c['code']}")] for c in cs]
        return await update.message.reply_text(
            "🌍 SELECT COUNTRY\n━━━━━━━━━━━━━━━━━━━━━━\n✨ Choose a country to add account for:",
            reply_markup=InlineKeyboardMarkup(buttons))
    if text == "✅ Done":
        sess = ACTIVE_ADD_SESSIONS.pop(uid, None)
        if sess and sess.get("client"):
            await tg_disconnect(sess["client"])
        context.user_data.pop("ta_selected_country", None)
        return await adder_show_summary(update, context)
    if text == "👤 Profile":
        return await update.message.reply_text(
            await text_profile_adder(update.effective_user, uid),
            reply_markup=kb_third_profile())
    if text == "📞 Support":
        return await update.message.reply_text(
            "📞 Need Help?\n━━━━━━━━━━━━━━━━━━━━━━\n☎️ Contact our support team!\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n👨‍💻 Supporter:  @xx_tenx",
            reply_markup=kb_adder_home())
    if state == "ta_awaiting_phone":
        return await ta_phone(update, context, text)
    if state == "ta_awaiting_otp":
        return await ta_otp(update, context, text)
    if state == "ta_awaiting_2fa":
        return await ta_2fa(update, context, text)
    if state == "ta_withdraw_amount":
        return await ta_wd_amount(update, context, text)
    if state == "ta_withdraw_account":
        return await ta_wd_account(update, context, text)
    await update.message.reply_text("Please choose an option below.", reply_markup=kb_adder_home())


async def ta_phone(update, context, text):
    uid = update.effective_user.id
    phone = text.strip().replace(" ", "")
    code = context.user_data.get("ta_selected_country")
    if not code or not await country_get(code):
        context.user_data.pop("state", None)
        return await update.message.reply_text("⚠️ Session expired. Tap ➕ Add again.")
    if not phone.startswith(code) or len(phone) < 6:
        return await update.message.reply_text(
            f"⚠️ Phone must start with {code}.\nExample: {code}912345678")
    if not TELETHON_OK:
        return await update.message.reply_text("⚠️ Telethon not configured.")
    if not API_POOL.apis:
        return await update.message.reply_text("⚠️ No API credentials configured.")

    old = ACTIVE_ADD_SESSIONS.pop(uid, None)
    if old and old.get("client"):
        await tg_disconnect(old["client"])

    client = None
    last_err = None
    for _ in range(max(1, len(API_POOL.apis))):
        try:
            client = await create_client_with_fallback()
            if client is None:
                last_err = "no_api"
                continue
            api = getattr(client, "_pool_api", None)
            try:
                sent = await client.send_code_request(phone)
                if api:
                    await API_POOL.report_success(api)
                ACTIVE_ADD_SESSIONS[uid] = {
                    "client": client, "phone": phone,
                    "phone_code_hash": sent.phone_code_hash,
                    "country_code": code, "old_2fa": None,
                }
                context.user_data["state"] = "ta_awaiting_otp"
                return await update.message.reply_text(
                    f"📨 OTP sent to {esc(phone)}\n━━━━━━━━━━━━━━━━━━━━━━\n"
                    "Send the code here (e.g. 12345)",
                    parse_mode="HTML", reply_markup=kb_done())
            except FloodWaitError as e:
                last_err = f"floodwait {e.seconds}s"
                if api:
                    await API_POOL.report_fail(api, last_err)
                await tg_disconnect(client)
                client = None
                continue
            except Exception as e:
                last_err = str(e)
                if api:
                    await API_POOL.report_fail(api, last_err)
                await tg_disconnect(client)
                client = None
                continue
        except Exception as e:
            last_err = str(e)
            log.warning("client err: %s", e)
            if client:
                await tg_disconnect(client)
                client = None
            continue
    ACTIVE_ADD_SESSIONS.pop(uid, None)
    log.warning("send_code failed for %s: %s", phone, last_err)
    await update.message.reply_text(
        "❌ Failed to send OTP. Please try again in a few minutes.",
        reply_markup=kb_adder_home())


async def ta_otp(update, context, text):
    uid = update.effective_user.id
    s = ACTIVE_ADD_SESSIONS.get(uid)
    if not s:
        context.user_data.pop("state", None)
        return await update.message.reply_text("⚠️ Session expired. Tap ➕ Add again.")
    try:
        await s["client"].sign_in(phone=s["phone"], code=text.strip().replace(" ", ""),
                                  phone_code_hash=s.get("phone_code_hash"))
        await ta_finalize(update, context, uid, old_2fa=None)
    except SessionPasswordNeededError:
        context.user_data["state"] = "ta_awaiting_2fa"
        await update.message.reply_text(
            "🔒 Account protected by 2FA\n━━━━━━━━━━━━━━━━━━━━━━\nSend 2FA here:",
            reply_markup=kb_done())
    except Exception as e:
        log.info("sign_in error for %s: %s", s.get("phone"), e)
        await update.message.reply_text(
            "❌ Sign-in failed. Check the code and try again.", reply_markup=kb_done())


async def ta_2fa(update, context, text):
    uid = update.effective_user.id
    s = ACTIVE_ADD_SESSIONS.get(uid)
    if not s:
        context.user_data.pop("state", None)
        return await update.message.reply_text("⚠️ Session expired. Tap ➕ Add again.")
    try:
        await s["client"].sign_in(password=text.strip())
        await ta_finalize(update, context, uid, old_2fa=text.strip())
    except Exception as e:
        log.info("2FA sign_in error for %s: %s", s.get("phone"), e)
        await update.message.reply_text("❌ Wrong 2FA. Try again:", reply_markup=kb_done())


async def ta_finalize(update, context, uid, old_2fa=None):
    s = ACTIVE_ADD_SESSIONS.get(uid)
    if not s:
        return
    client, phone, code = s["client"], s["phone"], s["country_code"]
    await update.message.reply_text("⏳ Verifying OTP...")
    await update.message.reply_text("🔎 Checking account status...")

    status = await tg_check_account_status(client)

    chosen_2fa = await next_2fa_password()
    set_ok = await tg_set_2fa(client, chosen_2fa, old=old_2fa)
    if not set_ok:
        await adder_bump(uid, adds=1)
        bump_session(context, "ta_session_adds", 1)
        await update.message.reply_text(
            "❌ FAILED TO SET 2FA\n━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📱 Phone: <code>{esc(phone)}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\nNot stored. Send the next number, or tap ✅ Done.",
            parse_mode="HTML", reply_markup=kb_done())
        await tg_disconnect(client)
        ACTIVE_ADD_SESSIONS.pop(uid, None)
        context.user_data["state"] = "ta_awaiting_phone"
        return

    try:
        session_string = client.session.save()
    except Exception as e:
        log.warning("save session err: %s", e)
        session_string = ""

    # 🔧 FIX 2: abort add if session string is empty (prevents selling broken sessions)
    if not session_string:
        await adder_bump(uid, adds=1)
        bump_session(context, "ta_session_adds", 1)
        await update.message.reply_text(
            "❌ FAILED TO SAVE SESSION\n━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📱 Phone: <code>{esc(phone)}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\nNot stored. Send the next number, or tap ✅ Done.",
            parse_mode="HTML", reply_markup=kb_done())
        await tg_disconnect(client)
        ACTIVE_ADD_SESSIONS.pop(uid, None)
        context.user_data["state"] = "ta_awaiting_phone"
        return

    await adder_bump(uid, adds=1)
    bump_session(context, "ta_session_adds", 1)

    if status != "clean":
        display = {"spam": "🚫 Spam", "frozen": "❄️ Frozen"}.get(status, "⚠️ Unknown")
        if status == "spam":
            await adder_bump(uid, spam=1)
            bump_session(context, "ta_session_spam")
        elif status == "frozen":
            await adder_bump(uid, frozen=1)
            bump_session(context, "ta_session_frozen")
        else:
            await adder_bump(uid, spam=1)
            bump_session(context, "ta_session_spam")
            log.warning("Account %s got unknown status '%s'", phone, status)
        await update.message.reply_text(
            "🚫 ACCOUNT REJECTED\n━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📱 Phone: <code>{esc(phone)}</code>\n📊 Status: {display}\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n⚠️ Not Logout the account\n"
            "━━━━━━━━━━━━━━━━━━━━━━\nSend the next number, or tap ✅ Done.",
            parse_mode="HTML", reply_markup=kb_done())
        await tg_disconnect(client)
        ACTIVE_ADD_SESSIONS.pop(uid, None)
        context.user_data["state"] = "ta_awaiting_phone"
        return

    c = await country_get(code)
    earn = float(c["seller_etb"]) if c else 0.0
    await adder_bump(uid, nonspam=1, balance=earn)
    bump_session(context, "ta_session_nonspam")
    await stock_push(code, phone, chosen_2fa, session_string, uid)
    await update.message.reply_text(
        "✅ ACCOUNT ADDED\n━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📱 Phone: <code>{esc(phone)}</code>\n📊 Status: ✅ Non-Spam\n"
        f"💰 Earned: +{earn:.2f} ETB\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n📴 You'll be logged out in 300 second\n"
        "━━━━━━━━━━━━━━━━━━━━━━\nSend the next number, or tap ✅ Done.",
        parse_mode="HTML", reply_markup=kb_done())
    await tg_disconnect(client)
    ACTIVE_ADD_SESSIONS.pop(uid, None)
    context.user_data["state"] = "ta_awaiting_phone"


async def adder_show_summary(update, context):
    uid = update.effective_user.id
    a = await adder_get(uid)
    await update.message.reply_text(
        "📊 ADD SUMMARY\n━━━━━━━━━━━━━━━━━━\n"
        f"📱 Added: {context.user_data.get('ta_session_adds', 0)}\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"✅️ Non-spam: {context.user_data.get('ta_session_nonspam', 0)}\n"
        f"🚫 Spam: {context.user_data.get('ta_session_spam', 0)}\n"
        f"❄️ Frozen: {context.user_data.get('ta_session_frozen', 0)}\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"👛 Balance: {a['balance']:.2f} ETB\n━━━━━━━━━━━━━━━━━━",
        reply_markup=kb_adder_home())
    context.user_data.pop("state", None)
    context.user_data.pop("ta_selected_country", None)
    for k in SESSION_KEYS:
        context.user_data.pop(k, None)


async def ta_wd_amount(update, context, text):
    uid = update.effective_user.id
    a = await adder_get(uid)
    try:
        amt = D(text.strip().replace(",", ""))
        if amt <= 0:
            raise ValueError
    except Exception:
        return await update.message.reply_text("⚠️ Send a valid amount in ETB.")
    if float(amt) > a["balance"]:
        return await update.message.reply_text(
            f"⚠️ Amount exceeds balance ({a['balance']:.2f} ETB).")
    context.user_data["ta_withdraw_amount"] = str(amt)
    context.user_data["state"] = "ta_withdraw_method"
    await update.message.reply_text(
        f"💸 Withdrawal Amount: {float(amt):.2f} ETB\nChoose a method:",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("📱 Telebirr", callback_data="ta_wd_telebirr"),
            InlineKeyboardButton("🏦 Account", callback_data="ta_wd_account")]]))


async def ta_wd_account(update, context, text):
    uid = update.effective_user.id
    amt_s = context.user_data.get("ta_withdraw_amount")
    method = context.user_data.get("ta_withdraw_method")
    if not amt_s or not method:
        context.user_data.pop("state", None)
        return await update.message.reply_text("⚠️ Session expired. Try again.")
    amt = D(amt_s)
    acc = text.strip()
    if len(acc) < 3:
        return await update.message.reply_text("⚠️ Send a valid account/number.")

    ref = _new_ref(uid, "W", await next_counter(uid, "withdraw"))
    async with db().acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """INSERT INTO withdrawals(ref_id, user_id, amount, method, account)
                   VALUES ($1,$2,$3,$4,$5)""",
                ref, uid, amt, method, acc)
            await conn.execute(
                "UPDATE bot_stats SET total_withdrawals=total_withdrawals+1 WHERE id=1")

    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Approve", callback_data=f"approve_wd_{ref}"),
        InlineKeyboardButton("❌ Reject", callback_data=f"reject_wd_{ref}")]])
    await send_to_admin(context,
        text=("🔔 WITHDRAWAL REQUEST\n━━━━━━━━━━━━━━━━━━\n"
              f"👤 User: <code>{uid}</code>\n💵 Amount: {float(amt):.2f} ETB\n"
              f"💳 Method: {esc(method)}\n📮 Account: <code>{esc(acc)}</code>\n"
              f"🆔 Ref ID: <code>{esc(ref)}</code>"),
        parse_mode="HTML", reply_markup=kb)
    context.user_data.pop("state", None)
    context.user_data.pop("ta_withdraw_amount", None)
    context.user_data.pop("ta_withdraw_method", None)
    await update.message.reply_text("⏳ Withdrawal request sent to admins.",
                                    reply_markup=kb_adder_home())


# ═══════════════ Buyer flow ═══════════════
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    uid = update.effective_user.id

    if not await is_approver_async(uid):
        if not await RATE_LIMITER.allow(uid):
            return

    if await is_adder_async(uid):
        return await handle_adder(update, context, text)
    if text == GET_OTP_BTN:
        return await handle_get_otp(update, context)
    if text in MAIN_MENU_BUTTONS:
        for k in FLOW_KEYS:
            context.user_data.pop(k, None)
    state = context.user_data.get("state")
    if state == "awaiting_deposit_amount":
        return await handle_deposit_amount(update, context, text)
    if state == "awaiting_screenshot":
        return await update.message.reply_text(
            "📸 Please send a screenshot/photo of your payment receipt.")
    if state == "awaiting_quantity":
        return await handle_quantity(update, context, text)
    if text == "⬅️ Back":
        for k in FLOW_KEYS:
            context.user_data.pop(k, None)
        await update.message.reply_text(
            "🏠 Welcome back to home!\n━━━━━━━━━━━━━━━━━━━\n✨️ Choose option below:",
            reply_markup=kb_main())
        try:
            await update.message.delete()
        except TelegramError:
            pass
    elif text == "👤 Profile":
        await update.message.reply_text(await text_profile_buyer(update.effective_user, uid),
                                        reply_markup=kb_profile(uid))
    elif text == "🛍️ Buy":
        await update.message.reply_text(
            "🛍 Products\n━━━━━━━━━━━━━━━━━━━━\n✨️ Choose a category to buy you want.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("📱 Telegram Account", callback_data="buy_telegram")]]))
    elif text == "💵 Deposit":
        await update.message.reply_text(
            "💵 DEPOSIT FUNDS\n━━━━━━━━━━━━━━━━━━\n✨️ Choose your deposit network below:\n"
            "━━━━━━━━━━━━━━━━━━",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔴 TRC20", callback_data="dep_trc20")],
                [InlineKeyboardButton("🟡 BEP20", callback_data="dep_bep20")]]))
    elif text == "📞 Support":
        await update.message.reply_text(
            "📞 Need Help?\n━━━━━━━━━━━━━━━━━━━━━━\n☎️ Contact our support team!\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n👨‍💻 Supporter:  @xx_tenx", reply_markup=kb_main())
    elif text == "🔄 Updates":
        await update.message.reply_text(
            "🔄 STAY UPDATED!\n━━━━━━━━━━━━━━━━━━━━━━\n    . 🆕 New products & restock.\n"
            "    . 🎁 Exclusive promo codes.\n    . 📣 Important announcements.\n"
            "━━━━━━━━━━━━━━━━━━━━━━",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("Join 🔄 Update's", url=UPDATES_CHANNEL_LINK)]]))


async def _fetch_one_otp(row):
    try:
        otp, err = await fetch_otp(row["session"], wait=45, min_ts=row["created_at"])
        return row, otp, err
    except Exception as e:
        return row, None, str(e)


async def handle_get_otp(update, context):
    uid = update.effective_user.id
    rows = await otps_get(uid)
    if not rows:
        return await update.message.reply_text(
            "⚠️ You have no pending accounts to fetch OTP for.", reply_markup=kb_main())
    progress = await update.message.reply_text(
        "⏳ Fetching OTP from Telegram…\nPlease wait up to 45s.")
    sem = asyncio.Semaphore(OTP_CONCURRENCY)

    async def guarded(row):
        async with sem:
            return await _fetch_one_otp(row)

    results = await asyncio.gather(*[guarded(r) for r in rows])
    any_otp = any(r[1] for r in results)
    try:
        await progress.delete()
    except TelegramError:
        pass
    if not any_otp:
        return await update.message.reply_text("⚠️ Retry, OTP not arrived",
                                               reply_markup=kb_get_otp())
    all_otp = all(r[1] for r in results)
    lines = ["🔑 YOUR OTP CODES", "━━━━━━━━━━━━━━━━━━━━"]
    for i, (r, otp, _) in enumerate(results, 1):
        if otp:
            lines.append(f"{i}. 📱 <code>{esc(r['phone'])}</code>\n"
                         f"   🔑 OTP: <code>{esc(otp)}</code>\n"
                         f"   🔐 2FA: <code>{esc(r['password'])}</code>")
        else:
            lines.append(f"{i}. 📱 <code>{esc(r['phone'])}</code>\n   ⚠️ No OTP yet")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    for chunk in chunk_text("\n".join(lines)):
        await update.message.reply_text(chunk, parse_mode="HTML",
                                        reply_markup=kb_main() if all_otp else kb_get_otp())
    if all_otp:
        first = results[0][0]
        label = first.get("country_label") or "N/A"
        form = first.get("form") or "🔑 OTP"
        qty = first.get("quantity") or len(results)
        await otps_clear(uid)
        await update.message.reply_text(
            "✅️ ORDER COMPLETELY ARRIVED\n━━━━━━━━━━━━━━━━━━\n"
            f"🌍 Country: {label}\n🧩 Form: {form}\n🛍️ Quantity: {qty}\n"
            "━━━━━━━━━━━━━━━━━━\n🤩 Tg store Always Trusted store.",
            reply_markup=kb_main())
    else:
        for r, otp, _ in results:
            if otp:
                await otp_delete(uid, r["phone"])


async def handle_deposit_amount(update, context, text):
    nk = context.user_data.get("deposit_network")
    if not nk:
        context.user_data.pop("state", None)
        return await update.message.reply_text(
            "⚠️ Session expired. Please tap 💵 Deposit again.", reply_markup=kb_main())
    cfg = DEPOSIT_CONFIG[nk]
    try:
        amt = D(text.strip().replace("$", "").replace(",", ""))
    except Exception:
        return await update.message.reply_text(prompt_deposit_amount(cfg))
    if float(amt) < cfg["min_amount"]:
        return await update.message.reply_text(prompt_deposit_amount(cfg))
    context.user_data["deposit_amount"] = str(amt)
    context.user_data["state"] = "awaiting_screenshot"
    await update.message.reply_text(
        "📍 PAYMENT INSTRUCTIONS\n━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💳 Network: {cfg['name']}\n💵 Amount to Send: {float(amt)} USDT\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n📬 Wallet Address:\n"
        f"<code>{cfg['address']}</code>\n━━━━━━━━━━━━━━━━━━━━━━\n"
        "📸 Please send a screenshot of your payment receipt here:", parse_mode="HTML")


async def handle_photo(update, context):
    if context.user_data.get("state") != "awaiting_screenshot":
        return await update.message.reply_text(
            "⚠️ I wasn't expecting a photo right now.\nTap ⬅️ Back or any main menu button to continue.")
    amt_s = context.user_data.pop("deposit_amount", None)
    nk = context.user_data.pop("deposit_network", "trc20")
    context.user_data.pop("state", None)

    if not amt_s:
        return await update.message.reply_text(
            "⚠️ Session expired. Please start the deposit again.", reply_markup=kb_main())
    amt = D(amt_s)

    file_id = update.message.photo[-1].file_id
    user = update.effective_user
    ref = _new_ref(user.id, "D", await next_counter(user.id, "deposit"))

    async with db().acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO deposits(ref_id, user_id, amount, network) VALUES ($1,$2,$3,$4)",
                ref, user.id, amt, nk)
            await conn.execute(
                "UPDATE bot_stats SET total_deposits=total_deposits+1 WHERE id=1")

    await update.message.reply_text(
        "⏳ Deposit is under verification!\n━━━━━━━━━━━━━━━━━━\n"
        "Please wait while the bot verifies your payment.", reply_markup=kb_main())

    await send_photo_to_admin(context, photo=file_id,
        caption=("🔔 NEW DEPOSIT SCREENSHOT\n━━━━━━━━━━━━━━━━━━━━━━\n"
                 f"👤 User: {esc(user.full_name)} (<code>{user.id}</code>)\n"
                 f"💵 Amount: {float(amt)} USDT\n💳 Network: {DEPOSIT_CONFIG[nk]['name']}\n"
                 f"🆔 Ref ID: <code>{esc(ref)}</code>\n"
                 "━━━━━━━━━━━━━━━━━━━━━━\nTap Approve or Reject below:"),
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Approve", callback_data=f"approve_dep_{ref}"),
            InlineKeyboardButton("❌ Reject", callback_data=f"reject_dep_{ref}")]]))


async def handle_quantity(update, context, text):
    uid = update.effective_user.id
    code = context.user_data.get("selected_country")
    form = context.user_data.get("selected_form")
    if not code or not form or not await country_get(code):
        context.user_data.pop("state", None)
        return await update.message.reply_text(
            "⚠️ Session expired. Please tap 🛍️ Buy again.", reply_markup=kb_main())
    try:
        qty = int(text.strip())
        if qty <= 0:
            raise ValueError
    except ValueError:
        return await update.message.reply_text("⚠️ Please send a valid number (e.g. 1, 2, 5).")
    available = await country_stock_count(code)
    if qty > available:
        return await update.message.reply_text(
            f"⚠️ Only {available} account(s) available in stock.\nPlease enter a lower quantity.")
    context.user_data["quantity"] = qty
    context.user_data.pop("state", None)
    c = await country_get(code)
    price = D(c["buyer_usdt"])
    total = (price * qty).quantize(Decimal("0.01"))
    bal = await user_balance(uid)
    await update.message.reply_text(
        "🧾 ORDER INVOICE\n━━━━━━━━━━━━━━━━━━\n"
        f" 🌍 Country: {c['emoji']} {code} {c['name']}\n🧩 Form: {form}\n"
        f"🛍️ Quantity: {qty}\n 💵 Unit Price: {float(price):.2f} USDT\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"💎 Total Payable: {float(total):.2f} USDT\n💳 Your Balance: {bal:.2f} USDT\n"
        "━━━━━━━━━━━━━━━━━━\n⚠️ Please review the details and confirm your purchase.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅️ Confirm & pay", callback_data="confirm_pay")]]))


# ═══════════════ Callback handler ═══════════════
# 🔧 FIX 4: removed top-level `await q.answer()` — each branch answers itself.
async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query

    if not await is_approver_async(q.from_user.id):
        if not await RATE_LIMITER.allow(q.from_user.id):
            try:
                await q.answer()
            except Exception:
                pass
            return

    try:
        if q.data.startswith("ta_add_"):
            if not await is_adder_async(q.from_user.id):
                return await q.answer("⛔ Only adders.", show_alert=True)
            code = q.data[len("ta_add_"):]
            if not await country_get(code):
                await q.answer()
                return await q.edit_message_text("⚠️ This country is no longer available.")
            context.user_data["ta_selected_country"] = code
            context.user_data["state"] = "ta_awaiting_phone"
            await q.answer()
            await q.edit_message_text(
                f"📱 Send the phone number\n━━━━━━━━━━━━━━━━━━━━━━\nEg:(start with {code})")
            await context.bot.send_message(chat_id=q.message.chat_id, text=".",
                                           reply_markup=kb_done())
            return

        if q.data.startswith("approve_dep_"):
            if not await is_approver_async(q.from_user.id):
                return await q.answer("⛔ Only admins.", show_alert=True)
            ref = q.data[len("approve_dep_"):]
            d = await deposit_claim(ref, q.from_user.id, approve=True)
            if not d:
                return await q.answer("⚠️ Already processed.", show_alert=True)
            await q.answer()
            txt = (f"✅ DEPOSIT APPROVED\n━━━━━━━━━━━━━━━━━━\n"
                   f"👤 User: <code>{d['user_id']}</code>\n"
                   f"💵 Amount: {float(d['amount']):.2f} USDT\n"
                   f"🆔 Ref ID: <code>{esc(ref)}</code>\n"
                   f"👮 By: <code>{q.from_user.id}</code>")
            try:
                await q.edit_message_caption(caption=txt, parse_mode="HTML")
            except TelegramError:
                try:
                    await q.edit_message_text(text=txt, parse_mode="HTML")
                except TelegramError:
                    pass
            try:
                newbal = await user_balance(d["user_id"])
                await context.bot.send_message(d["user_id"],
                    "🎉 DEPOSIT CONFIRMED!\n━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"💵 Amount: {float(d['amount']):.2f} USDT\n"
                    f"💳 New Balance: {newbal:.2f} USDT\n"
                    "━━━━━━━━━━━━━━━━━━━━━━\nThank you for depositing!")
            except TelegramError as e:
                log.warning("notify deposit user failed: %s", e)
            return

        if q.data.startswith("reject_dep_"):
            if not await is_approver_async(q.from_user.id):
                return await q.answer("⛔ Only admins.", show_alert=True)
            ref = q.data[len("reject_dep_"):]
            d = await deposit_claim(ref, q.from_user.id, approve=False)
            await q.answer()
            txt = (f"❌ DEPOSIT REJECTED\n━━━━━━━━━━━━━━━━━━\n"
                   f"🆔 Ref ID: <code>{esc(ref)}</code>\n"
                   f"👮 By: <code>{q.from_user.id}</code>")
            try:
                await q.edit_message_caption(caption=txt, parse_mode="HTML")
            except TelegramError:
                try:
                    await q.edit_message_text(text=txt, parse_mode="HTML")
                except TelegramError:
                    pass
            if d:
                try:
                    await context.bot.send_message(d["user_id"],
                        "❌ DEPOSIT REJECTED\n━━━━━━━━━━━━━━━━━━━━━━\n"
                        "Your payment screenshot could not be verified.\n"
                        "Please contact support if you believe this is an error.")
                except TelegramError:
                    pass
            return

        if q.data.startswith("approve_wd_"):
            if not await is_approver_async(q.from_user.id):
                return await q.answer("⛔ Only admins.", show_alert=True)
            ref = q.data[len("approve_wd_"):]
            w = await withdrawal_claim(ref, q.from_user.id, approve=True)
            if not w:
                return await q.answer("⚠️ Already processed or insufficient balance.",
                                      show_alert=True)
            await q.answer()
            try:
                await q.edit_message_text(
                    "✅ WITHDRAWAL APPROVED\n━━━━━━━━━━━━━━━━━━\n"
                    f"👤 User: <code>{w['user_id']}</code>\n"
                    f"💵 Amount: {float(w['amount']):.2f} ETB\n"
                    f"💳 Method: {esc(w['method'])}\n"
                    f"📮 Account: <code>{esc(w['account'])}</code>\n"
                    f"🆔 Ref ID: <code>{esc(ref)}</code>", parse_mode="HTML")
            except TelegramError:
                pass
            try:
                a = await adder_get(w["user_id"])
                await context.bot.send_message(w["user_id"],
                    "✅ WITHDRAWAL APPROVED\n━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"💵 Amount: {float(w['amount']):.2f} ETB\n"
                    f"💳 Method: {esc(w['method'])}\n"
                    f"👛 New Balance: {a['balance']:.2f} ETB\n"
                    "━━━━━━━━━━━━━━━━━━━━━━", parse_mode="HTML")
            except TelegramError:
                pass
            return

        if q.data.startswith("reject_wd_"):
            if not await is_approver_async(q.from_user.id):
                return await q.answer("⛔ Only admins.", show_alert=True)
            ref = q.data[len("reject_wd_"):]
            w = await withdrawal_claim(ref, q.from_user.id, approve=False)
            await q.answer()
            try:
                await q.edit_message_text(f"❌ Withdrawal rejected: <code>{esc(ref)}</code>",
                                          parse_mode="HTML")
            except TelegramError:
                pass
            if w:
                try:
                    await context.bot.send_message(w["user_id"],
                        "❌ WITHDRAWAL REJECTED\n━━━━━━━━━━━━━━━━━━━━━━\n"
                        "Your withdrawal could not be processed. Contact support.")
                except TelegramError:
                    pass
            return

        if q.data.startswith("refund_"):
            if not await is_super_async(q.from_user.id):
                return await q.answer("⛔ Only super admins.", show_alert=True)
            try:
                oid = int(q.data[len("refund_"):])
            except ValueError:
                return await q.answer("⚠️ Bad order id.", show_alert=True)
            row = await order_refund(oid, q.from_user.id)
            if not row:
                return await q.answer("⚠️ Already refunded, delivered, or missing.",
                                      show_alert=True)
            await q.answer()
            try:
                await q.edit_message_text(
                    f"✅ Order <code>{oid}</code> refunded: {float(row['price']):.2f} USDT to "
                    f"<code>{row['user_id']}</code>.\nStock released back to pool.",
                    parse_mode="HTML")
            except TelegramError:
                pass
            try:
                await context.bot.send_message(row["user_id"],
                    f"💸 REFUND ISSUED\n━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🛍️ Order #{oid}\n💵 Amount: {float(row['price']):.2f} USDT\n"
                    "The amount has been credited back to your balance.")
            except TelegramError:
                pass
            return

        if q.data == "ta_withdraw":
            if not await is_adder_async(q.from_user.id):
                return await q.answer("⛔ Only adders.", show_alert=True)
            a = await adder_get(q.from_user.id)
            context.user_data["state"] = "ta_withdraw_amount"
            await q.answer()
            await q.edit_message_text(
                "💸 WITHDRAW FUNDS\n━━━━━━━━━━━━━━━━━━\n"
                f"👛 Available Balance: {a['balance']:.2f} ETB\n"
                "━━━━━━━━━━━━━━━━━━\nSend the amount you want to withdraw (ETB):")
            return

        if q.data in ("ta_wd_telebirr", "ta_wd_account"):
            if not await is_adder_async(q.from_user.id):
                return await q.answer("⛔ Only adders.", show_alert=True)
            method = "Telebirr" if q.data == "ta_wd_telebirr" else "Account"
            context.user_data["ta_withdraw_method"] = method
            context.user_data["state"] = "ta_withdraw_account"
            await q.answer()
            await q.edit_message_text(f"💳 Method: {method}\nSend your {method} account/number:")
            return

        if q.data in ("dep_bep20", "dep_trc20"):
            nk = "bep20" if q.data == "dep_bep20" else "trc20"
            context.user_data["deposit_network"] = nk
            context.user_data["state"] = "awaiting_deposit_amount"
            await q.answer()
            await q.edit_message_text(prompt_deposit_amount(DEPOSIT_CONFIG[nk]))
            return

        if q.data == "buy_telegram":
            if await total_stock() == 0:
                await q.answer()
                return await q.edit_message_text(
                    "📱 Telegram Account\n━━━━━━━━━━━━━━━━━━━━\n"
                    "⚠️ Currently out of stock(Telegram Accounts)!\n"
                    "━━━━━━━━━━━━━━━━━━━━\nPlease check back later!")
            buttons = []
            for c in await countries_all():
                stock = await country_stock_count(c["code"])
                if stock == 0:
                    continue
                buttons.append([InlineKeyboardButton(
                    f"{c['emoji']} {c['code']} {c['name']} | 📦 {stock} pcs | "
                    f"💵 {float(c['buyer_usdt']):.2f} USDT",
                    callback_data=f"tgc_{c['code']}")])
            if not buttons:
                await q.answer()
                return await q.edit_message_text(
                    "📱 Telegram Account\n━━━━━━━━━━━━━━━━━━━━\n"
                    "⚠️ Currently out of stock(Telegram Accounts)!\n"
                    "━━━━━━━━━━━━━━━━━━━━\nPlease check back later!")
            await q.answer()
            await q.edit_message_text(
                "📱 Telegram Account\n━━━━━━━━━━━━━━━━━━━━\n✨️ Choose a country to buy:",
                reply_markup=InlineKeyboardMarkup(buttons))
            try:
                await context.bot.send_message(chat_id=q.message.chat_id, text=".",
                                               reply_markup=kb_back())
            except TelegramError:
                pass
            return

        if q.data.startswith("tgc_"):
            code = q.data[len("tgc_"):]
            c = await country_get(code)
            if not c or await country_stock_count(code) == 0:
                await q.answer()
                return await q.edit_message_text(
                    "📱 Telegram Account\n━━━━━━━━━━━━━━━━━━━━\n"
                    "⚠️ Currently out of stock(Telegram Accounts)!\n"
                    "━━━━━━━━━━━━━━━━━━━━\nPlease check back later!")
            context.user_data["selected_country"] = code
            await q.answer()
            await q.edit_message_text(
                "🧩 SELECT FORM\n━━━━━━━━━━━━━━━━━━\n"
                f"🌍 Country: {c['emoji']} {code} {c['name']}\n"
                f"📦 Available: {await country_stock_count(code)} pcs\n"
                f"💵 Unit Price: {float(c['buyer_usdt']):.2f} USDT\n"
                "━━━━━━━━━━━━━━━━━━\n✨️ Choose the form you want to buy:",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("📁 Session", callback_data="form_session")],
                    [InlineKeyboardButton("🔑 OTP", callback_data="form_otp")]]))
            return

        if q.data in ("form_session", "form_otp"):
            code = context.user_data.get("selected_country")
            c = await country_get(code) if code else None
            if not c:
                await q.answer()
                return await q.edit_message_text("⚠️ Session expired. Please start again.")
            form_label = "📁 Session" if q.data == "form_session" else "🔑 OTP"
            context.user_data["selected_form"] = form_label
            context.user_data["state"] = "awaiting_quantity"
            await q.answer()
            await q.edit_message_text(
                "✅ FORM SELECTED\n━━━━━━━━━━━━━━━━━━\n"
                f"🌍 Country: {c['emoji']} {code} {c['name']}\n🧩 Form: {form_label}\n"
                f"📦 Available: {await country_stock_count(code)} pcs\n"
                f"💵 Unit Price: {float(c['buyer_usdt']):.2f} USDT\n━━━━━━━━━━━━━━━━━━")
            await context.bot.send_message(chat_id=q.message.chat_id,
                text="🛒 How many accounts would you like to purchase? (Send a number)",
                reply_markup=kb_back())
            return

        if q.data == "confirm_pay":
            await _handle_confirm_pay(q, context)
            return

        if q.data == "view_orders":
            await q.answer()
            orders = await orders_of(q.from_user.id)
            if not orders:
                txt = ("📜 ORDER HISTORY\n━━━━━━━━━━━━━━━━━━\n📭 You have no orders yet.\n"
                       "━━━━━━━━━━━━━━━━━━\n💡 Tap 🛍️ Buy to place your first order!")
            else:
                lines = ["📜 ORDER HISTORY", "━━━━━━━━━━━━━━━━━━"]
                for i, o in enumerate(orders, 1):
                    ds = o.get("delivery_status") or "delivered"
                    badge = {"delivered": "✅", "failed": "⚠️",
                             "refunded": "💸", "pending": "⏳"}.get(ds, "•")
                    lines.append(f"{i}. {badge} {o['country_label']} — "
                                 f"{float(o['price']):.2f} USDT\n"
                                 f"   🧩 {o['form']} | 🛍️ x{o['quantity']}\n"
                                 f"   📅 {o['created_at']}")
                lines.append("━━━━━━━━━━━━━━━━━━")
                txt = "\n".join(lines)
            await q.edit_message_text(txt, reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("⬅️ Back to Profile", callback_data="back_to_profile")]]))
            return

        if q.data == "view_ledger":
            await q.answer()
            rows = await ledger_of(q.from_user.id, limit=20)
            if not rows:
                txt = "📒 LEDGER\n━━━━━━━━━━━━━━━━━━\n(no entries yet)"
            else:
                lines = ["📒 LEDGER (last 20)", "━━━━━━━━━━━━━━━━━━"]
                for r in rows:
                    sign = "+" if r["delta"] > 0 else ""
                    lines.append(
                        f"{r['created_at'].strftime('%m-%d %H:%M')} | "
                        f"{r['kind']:<9} | {sign}{float(r['delta']):.2f} | "
                        f"bal={float(r['balance_after']):.2f}")
                lines.append("━━━━━━━━━━━━━━━━━━")
                txt = "\n".join(lines)
            await q.edit_message_text(txt, reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("⬅️ Back to Profile", callback_data="back_to_profile")]]))
            return

        if q.data == "back_to_profile":
            await q.answer()
            await q.edit_message_text(await text_profile_buyer(q.from_user, q.from_user.id),
                                      reply_markup=kb_profile(q.from_user.id))
            return

        # unknown callback
        await q.answer()

    except TelegramError as e:
        log.warning("callback telegram error: %s", e)
        try:
            await q.answer()
        except Exception:
            pass
    except Exception as e:
        log.exception("callback handler crashed")
        try:
            await q.answer("⚠️ Internal error", show_alert=True)
        except Exception:
            pass


async def _handle_confirm_pay(q, context):
    """Confirm-pay with idempotency: acquire lock → purchase → deliver → release lock."""
    uid = q.from_user.id
    code = context.user_data.get("selected_country")
    form_label = context.user_data.get("selected_form")
    qty = context.user_data.get("quantity")
    c = await country_get(code) if code else None
    if not c or not form_label or not qty:
        await q.answer()
        return await q.edit_message_text("⚠️ Session expired. Please start again.")

    if not await try_acquire_purchase_lock(uid):
        return await q.answer(
            "⏳ You already have an order being processed. Please wait.", show_alert=True)

    try:
        price = D(c["buyer_usdt"])
        total = (price * qty).quantize(Decimal("0.01"))
        label = f"{c['emoji']} {code} {c['name']}"

        try:
            order_id, purchased = await order_purchase_atomic(
                uid, code, qty, total, form_label, label)
        except InsufficientBalance:
            await q.answer()
            bal = await user_balance(uid)
            return await q.edit_message_text(
                "⚠️ INSUFFICIENT BALANCE!\n━━━━━━━━━━━━━━━━━━\n"
                f"💎 Required: {float(total):.2f} USDT\n💳 Your Balance: {bal:.2f} USDT\n"
                "━━━━━━━━━━━━━━━━━━\nPlease top up your balance using 💵 Deposit.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("💵 Deposit Funds", callback_data="dep_trc20")]]))
        except InsufficientStock:
            await q.answer()
            return await q.edit_message_text(
                "⚠️ Stock has changed. Please start the purchase again.")
        except Exception:
            log.exception("order_purchase_atomic crashed")
            await q.answer()
            return await q.edit_message_text(
                "⚠️ Order could not be processed. Please try again or contact support.")

        await q.answer()

        newbal = await user_balance(uid)
        try:
            await q.edit_message_text(
                "✅ ORDER CONFIRMED!\n━━━━━━━━━━━━━━━━━━\n"
                f"🌍 Country: {label}\n🧩 Form: {form_label}\n🛍️ Quantity: {qty}\n"
                f"💎 Total Paid: {float(total):.2f} USDT\n"
                f"💳 Remaining Balance: {newbal:.2f} USDT\n"
                "━━━━━━━━━━━━━━━━━━\n⏳ Your order is being processed...")
        except TelegramError as e:
            log.warning("edit failed: %s", e)
        await asyncio.sleep(1.2)

        if form_label == "🔑 OTP":
            lines = ["📦 YOUR ACCOUNTS", "━━━━━━━━━━━━━━━━━━━━"]
            for i, acc in enumerate(purchased, 1):
                lines.append(f"{i}. 📱 Phone: <code>{esc(acc['phone'])}</code>")
            lines.append("━━━━━━━━━━━━━━━━━━━━")
            try:
                await context.bot.send_message(chat_id=q.message.chat_id,
                                               text="\n".join(lines),
                                               parse_mode="HTML", reply_markup=kb_get_otp())
                await order_mark_delivery(order_id, "delivered")
            except TelegramError as e:
                log.warning("OTP-list delivery failed: %s", e)
                await order_mark_delivery(order_id, "failed", f"list send: {e}")
                await _notify_delivery_failure(context, order_id, uid, label,
                                               form_label, qty, total)
            ts = datetime.now(timezone.utc).timestamp()
            for acc in purchased:
                await otp_store(uid, acc["phone"], acc["session"], acc["password"],
                                label, form_label, qty, ts)
        else:
            all_ok = True
            for i, acc in enumerate(purchased, 1):
                bio = make_session_file(acc["session"], acc["phone"])
                try:
                    await context.bot.send_document(
                        chat_id=q.message.chat_id, document=bio,
                        filename=f"{acc['phone'].replace('+', '')}.session",
                        caption=(f"📁 SESSION #{i}\n"
                                 f"📱 Phone: <code>{esc(acc['phone'])}</code>\n"
                                 f"🔐 2FA: <code>{esc(acc['password'])}</code>"),
                        parse_mode="HTML")
                except TelegramError as e:
                    all_ok = False
                    log.warning("session delivery failed: %s", e)
                    try:
                        await context.bot.send_message(q.message.chat_id,
                            f"⚠️ Failed to deliver session for "
                            f"<code>{esc(acc['phone'])}</code>.", parse_mode="HTML")
                    except TelegramError:
                        pass
                finally:
                    try:
                        bio.close()
                    except Exception:
                        pass
            if all_ok:
                await order_mark_delivery(order_id, "delivered")
                await asyncio.sleep(0.8)
                try:
                    await context.bot.send_message(chat_id=q.message.chat_id,
                        text=("✅️ ORDER COMPLETELY ARRIVED\n━━━━━━━━━━━━━━━━━━\n"
                              f"🌍 Country: {label}\n🧩 Form: {form_label}\n"
                              f"🛍️ Quantity: {qty}\n"
                              "━━━━━━━━━━━━━━━━━━\n🤩 Tg store Always Trusted store."),
                        reply_markup=kb_main())
                except TelegramError:
                    pass
            else:
                await order_mark_delivery(order_id, "failed",
                                          "one or more session sends failed")
                await _notify_delivery_failure(context, order_id, uid, label,
                                               form_label, qty, total)

        for k in ("selected_country", "selected_form", "quantity"):
            context.user_data.pop(k, None)
    finally:
        await release_purchase_lock(uid)


async def _notify_delivery_failure(context, order_id, uid, label, form_label, qty, total):
    await send_to_admin(context,
        text=("⚠️ DELIVERY FAILED\n━━━━━━━━━━━━━━━━━━━━━━\n"
              f"🛍️ Order #{order_id}\n👤 User: <code>{uid}</code>\n"
              f"🌍 {esc(label)}\n🧩 {esc(form_label)} | 🛍️ x{qty}\n"
              f"💵 {float(total):.2f} USDT\n"
              "━━━━━━━━━━━━━━━━━━━━━━\n"
              "Stock is reserved for this order. Tap Refund to release it back "
              "and credit the user."),
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("💸 Refund", callback_data=f"refund_{order_id}")]]))


# ═══════════════ Lifecycle ═══════════════
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    log.exception("Handler error", exc_info=context.error)


async def _backup_task():
    try:
        await backup_loop()
    except asyncio.CancelledError:
        log.info("Backup loop stopped.")


async def post_init(app: Application):
    if not SUPER_ADMIN_IDS:
        raise RuntimeError("❌ SUPER_ADMIN_IDS is empty")
    if not API_POOL.apis:
        log.warning("⚠️ No API credentials — adder flow will be disabled")
    await db_init()
    await app.bot.set_my_commands([
        ("start", "Start the bot"),
        ("status", "Admin: bot statistics + API + 2FA pools"),
        ("add", "Admin: add sub-admin"),
        ("adds", "Admin: add account adder"),
        ("set", "Admin: set country (cap=0 removes)"),
        ("refund", "Admin: refund order by id"),
    ])
    app.bot_data["backup_task"] = asyncio.create_task(_backup_task())
    log.info("Bot initialized (v5). Backup every %ss | Rate: %s/s",
             BACKUP_INTERVAL, RATE_LIMIT_RPS)


async def post_shutdown(app: Application):
    task = app.bot_data.get("backup_task")
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    for uid, sess in list(ACTIVE_ADD_SESSIONS.items()):
        client = sess.get("client")
        if client:
            await tg_disconnect(client)
    ACTIVE_ADD_SESSIONS.clear()
    try:
        await db().execute("DELETE FROM pending_purchases")
    except Exception:
        pass
    await db_close()


def main():
    app = (Application.builder().token(BOT_TOKEN)
           .post_init(post_init).post_shutdown(post_shutdown).build())
    app.add_error_handler(on_error)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler("adds", cmd_adds))
    app.add_handler(CommandHandler("set", cmd_set))
    app.add_handler(CommandHandler("refund", cmd_refund))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(CallbackQueryHandler(handle_callback))
    log.info("Bot starting (polling)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=False)


if __name__ == "__main__":
    main()