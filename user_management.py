import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from email.message import EmailMessage
from pathlib import Path

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

class AuthError(Exception):
    pass

class InvalidInput(AuthError):
    pass

class InvalidCode(AuthError):
    pass

class UserExists(AuthError):
    pass

class Mailer:
    def send_code(self, email, code):
        host = os.getenv("SMTP_HOST", "")
        sender = os.getenv("SMTP_FROM", "")
        if not host or not sender:
            raise RuntimeError("SMTP_HOST 和 SMTP_FROM 必须配置后才能发送验证码")
        message = EmailMessage()
        message["Subject"] = "邮箱注册验证码"
        message["From"] = sender
        message["To"] = email
        message.set_content("您好，您的注册验证码是：{}。验证码 10 分钟内有效，请勿转发给他人。".format(code))
        port = int(os.getenv("SMTP_PORT", "587"))
        username = os.getenv("SMTP_USERNAME", "")
        password = os.getenv("SMTP_PASSWORD", "")
        if os.getenv("SMTP_USE_SSL", "false").lower() == "true":
            with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as client:
                if username:
                    client.login(username, password)
                client.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=15) as client:
                client.ehlo()
                if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if username:
                    client.login(username, password)
                client.send_message(message)

class FakeMailer:
    def __init__(self):
        self.sent = []

    def send_code(self, email, code):
        self.sent.append((email, code))

class AuthService:
    CODE_TTL = 600
    CODE_COOLDOWN = 60

    def __init__(self, database, mailer=None, code_factory=None, clock=None):
        self.database = str(database)
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self.mailer = mailer or Mailer()
        self.code_factory = code_factory or (lambda: "{:06d}".format(secrets.randbelow(1_000_000)))
        self.clock = clock or time.time
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS email_codes (
                email TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                sent_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            )""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(email_codes)")}
            if "attempts" not in columns:
                db.execute("ALTER TABLE email_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def normalize_email(email):
        if not isinstance(email, str):
            raise InvalidInput("请输入有效邮箱地址")
        normalized = email.strip().lower()
        if len(normalized) > 254 or not EMAIL_RE.match(normalized):
            raise InvalidInput("请输入有效邮箱地址")
        return normalized

    def _code_hash(self, email, code):
        pepper = os.getenv("APP_SECRET", "development-only-change-me").encode("utf-8")
        return hmac.new(pepper, (email + ":" + code).encode("utf-8"), hashlib.sha256).hexdigest()

    def send_code(self, email):
        email = self.normalize_email(email)
        now = int(self.clock())
        with self._connect() as db:
            existing = db.execute("SELECT sent_at FROM email_codes WHERE email = ?", (email,)).fetchone()
            if existing and now - existing["sent_at"] < self.CODE_COOLDOWN:
                raise InvalidCode("验证码发送过于频繁，请稍后再试")
            if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                raise UserExists("该邮箱已注册")
        code = self.code_factory()
        self.mailer.send_code(email, code)
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO email_codes(email, code_hash, expires_at, sent_at) VALUES (?, ?, ?, ?)",
                       (email, self._code_hash(email, code), now + self.CODE_TTL, now))

    def register(self, email, password, code):
        email = self.normalize_email(email)
        if not isinstance(password, str) or len(password) < 10 or len(password) > 128:
            raise InvalidInput("密码长度须为 10 至 128 位")
        if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
            raise InvalidCode("验证码错误或已过期")
        now = int(self.clock())
        invalid_code = False
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT code_hash, expires_at, attempts FROM email_codes WHERE email = ?", (email,)).fetchone()
            matches = row and row["expires_at"] >= now and row["attempts"] < 5 and hmac.compare_digest(row["code_hash"], self._code_hash(email, code))
            if not matches:
                invalid_code = True
                if row and row["expires_at"] >= now and row["attempts"] < 5:
                    attempts = row["attempts"] + 1
                    if attempts >= 5:
                        db.execute("DELETE FROM email_codes WHERE email = ?", (email,))
                    else:
                        db.execute("UPDATE email_codes SET attempts = ? WHERE email = ?", (attempts, email))
            else:
                salt = secrets.token_bytes(16)
                password_hash = salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000).hex()
                try:
                    cursor = db.execute("INSERT INTO users(email, password_hash, created_at) VALUES (?, ?, ?)", (email, password_hash, now))
                except sqlite3.IntegrityError:
                    raise UserExists("该邮箱已注册")
                db.execute("DELETE FROM email_codes WHERE email = ?", (email,))
                user = {"id": cursor.lastrowid, "email": email, "created_at": now}
        if invalid_code:
            raise InvalidCode("验证码错误或已过期，连续错误 5 次后需重新发送")
        return user

    def authenticate(self, email, password):
        try:
            email = self.normalize_email(email)
        except InvalidInput:
            return None
        if not isinstance(password, str):
            return None
        with self._connect() as db:
            user = db.execute("SELECT id, email, password_hash, created_at FROM users WHERE email = ?", (email,)).fetchone()
        if not user:
            return None
        salt_hex, expected = user["password_hash"].split(":", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310_000).hex()
        if not hmac.compare_digest(actual, expected):
            return None
        return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}

def create_server(host="127.0.0.1", port=8000, database=None):
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
    import json
    from http.cookies import SimpleCookie

    service = AuthService(database or os.getenv("DATABASE_PATH", "data/users.sqlite3"))
    sessions = {}

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(Path(__file__).parent / "web"), **kwargs)

        def log_message(self, fmt, *args):
            if os.getenv("APP_DEBUG", "false").lower() == "true":
                super().log_message(fmt, *args)

        def _json(self, status, payload, headers=None):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 8192:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def _user(self):
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get("session")
            user_id = sessions.get(morsel.value) if morsel else None
            if user_id is None:
                return None
            with service._connect() as db:
                user = db.execute("SELECT id, email, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(user) if user else None

        def do_POST(self):
            try:
                data = self._body()
                if not isinstance(data, dict):
                    raise ValueError("invalid request")
                if self.path == "/api/send-code":
                    service.send_code(data.get("email"))
                    return self._json(200, {"message": "验证码已发送，请查收邮件"})
                if self.path == "/api/register":
                    user = service.register(data.get("email"), data.get("password"), data.get("code"))
                    token = secrets.token_urlsafe(32)
                    sessions[token] = user["id"]
                    cookie = "session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400{}".format(token, "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else "")
                    return self._json(201, {"user": user}, {"Set-Cookie": cookie})
                if self.path == "/api/login":
                    user = service.authenticate(data.get("email"), data.get("password"))
                    if not user:
                        return self._json(401, {"error": "邮箱或密码不正确"})
                    token = secrets.token_urlsafe(32)
                    sessions[token] = user["id"]
                    return self._json(200, {"user": user}, {"Set-Cookie": "session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400".format(token)})
                return self._json(404, {"error": "接口不存在"})
            except UserExists as exc:
                return self._json(409, {"error": str(exc)})
            except InvalidCode as exc:
                return self._json(400, {"error": str(exc)})
            except InvalidInput as exc:
                return self._json(400, {"error": str(exc)})
            except (ValueError, UnicodeDecodeError, TypeError, AttributeError):
                return self._json(400, {"error": "请求内容无效"})
            except Exception as exc:
                if os.getenv("APP_DEBUG", "false").lower() == "true":
                    print("Request failed:", exc)
                return self._json(503, {"error": "服务暂时不可用，请检查邮箱服务配置"})

        def do_GET(self):
            if self.path == "/api/me":
                user = self._user()
                return self._json(200, {"user": user}) if user else self._json(401, {"error": "请先登录"})
            return super().do_GET()

        def do_DELETE(self):
            if self.path != "/api/session":
                return self._json(404, {"error": "接口不存在"})
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get("session")
            if morsel:
                sessions.pop(morsel.value, None)
            return self._json(200, {"message": "已退出登录"}, {"Set-Cookie": "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.auth_service = service
    return server

if __name__ == "__main__":
    server = create_server(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")))
    print("User management is available at http://{}:{}/".format(*server.server_address))
    server.serve_forever()
