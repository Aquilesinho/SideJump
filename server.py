import os
import uuid
import hashlib
import hmac
import secrets
import struct
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form
from fastapi.responses import Response
from pydantic import BaseModel, Field
import psycopg
from psycopg.rows import dict_row

app = FastAPI(title="SideJump Server", version="1.0.0")

MAGIC = b"LVL1"
SUPPORTED_VERSIONS = (1, 2, 3)
MAX_LEVEL_SIZE = 2 * 1024 * 1024
LEVEL_NAME_MAX = 80
TOKEN_DAYS = 30


def db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL não foi definida.")
    return psycopg.connect(url, row_factory=dict_row)


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY,
                username VARCHAR(24) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS levels (
                id UUID PRIMARY KEY,
                name VARCHAR(80) NOT NULL,
                owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                owner_username VARCHAR(24) NOT NULL,
                level_data BYTEA NOT NULL,
                level_version INTEGER NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_levels_updated
            ON levels(updated_at DESC)
        """)
        conn.commit()


@app.on_event("startup")
def startup():
    init_db()


class AccountRequest(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=8, max_length=128)


def hash_password(password):
    salt = secrets.token_bytes(16)
    iterations = 310000
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations
    )
    return "pbkdf2_sha256$" + str(iterations) + "$" + salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt_hex),
            int(iterations)
        )
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except Exception:
        return False


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login necessário.")

    token = authorization[7:].strip()
    with db() as conn:
        row = conn.execute("""
            SELECT u.id, u.username
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = %s AND s.expires_at > NOW()
        """, (token_hash(token),)).fetchone()

    if row is None:
        raise HTTPException(401, "Sessão inválida ou expirada.")
    return row


def validate_level(data):
    if len(data) < 5:
        raise HTTPException(400, "Arquivo .level muito pequeno.")
    if len(data) > MAX_LEVEL_SIZE:
        raise HTTPException(413, "Nível maior que 2 MB.")
    if data[:4] != MAGIC:
        raise HTTPException(400, "Arquivo .level inválido.")

    version = data[4]
    if version not in SUPPORTED_VERSIONS:
        raise HTTPException(400, "Versão do .level não suportada.")

    offset = 5
    if len(data) < offset + 2:
        raise HTTPException(400, "Cabeçalho incompleto.")

    name_size = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if name_size > LEVEL_NAME_MAX * 4 or len(data) < offset + name_size:
        raise HTTPException(400, "Nome interno inválido.")
    try:
        data[offset:offset + name_size].decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "Nome UTF-8 inválido.")
    offset += name_size

    if len(data) < offset + 1:
        raise HTTPException(400, "ID ausente.")
    id_size = data[offset]
    offset += 1
    if len(data) < offset + id_size:
        raise HTTPException(400, "ID inválido.")
    try:
        data[offset:offset + id_size].decode("ascii")
    except UnicodeDecodeError:
        raise HTTPException(400, "ID ASCII inválido.")
    offset += id_size

    if version >= 2:
        if len(data) < offset + 1:
            raise HTTPException(400, "Configuração ausente.")
        offset += 1

    if len(data) < offset + 4:
        raise HTTPException(400, "Quantidade de objetos ausente.")
    count = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    if count > 100000:
        raise HTTPException(400, "Quantidade de objetos inválida.")

    size = 28 if version >= 3 else 24
    if len(data) != offset + count * size:
        raise HTTPException(400, "Estrutura do .level incompatível.")

    return version


@app.get("/")
def root():
    return {"name": "SideJump Server", "status": "online", "version": "1.0.0"}


@app.get("/health")
def health():
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"status": "ok"}


@app.post("/account/register")
def register(request: AccountRequest):
    username = request.username.strip()
    if not all(c.isalnum() or c == "_" for c in username) or not 3 <= len(username) <= 24:
        raise HTTPException(400, "Username deve ter 3-24 caracteres.")
    try:
        user_id = uuid.uuid4()
        with db() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash) VALUES (%s,%s,%s)",
                (user_id, username, hash_password(request.password))
            )
            conn.commit()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Username já existe.")
    return {"success": True, "user_id": str(user_id), "username": username}


@app.post("/account/login")
def login(request: AccountRequest):
    with db() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username=%s",
            (request.username.strip(),)
        ).fetchone()
        if user is None or not verify_password(request.password, user["password_hash"]):
            raise HTTPException(401, "Username ou senha incorretos.")

        token = secrets.token_urlsafe(48)
        expires = datetime.now(timezone.utc) + timedelta(days=TOKEN_DAYS)
        conn.execute(
            "INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (%s,%s,%s)",
            (token_hash(token), user["id"], expires)
        )
        conn.commit()

    return {"token": token, "user_id": str(user["id"]), "username": user["username"]}


@app.post("/account/logout")
def logout(authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=%s", (token_hash(token),))
            conn.commit()
    return {"success": True}


@app.get("/account/me")
def me(user=Depends(current_user)):
    return {"user_id": str(user["id"]), "username": user["username"]}


@app.get("/levels")
def list_levels(limit: int = 50, offset: int = 0):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with db() as conn:
        rows = conn.execute("""
            SELECT id,name,owner_username,level_version,created_at,updated_at
            FROM levels ORDER BY updated_at DESC LIMIT %s OFFSET %s
        """, (limit, offset)).fetchall()
    return {"levels": [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "owner": r["owner_username"],
            "version": r["level_version"],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat()
        } for r in rows
    ]}


@app.get("/levels/mine")
def my_levels(user=Depends(current_user)):
    with db() as conn:
        rows = conn.execute("""
            SELECT id,name,level_version,created_at,updated_at
            FROM levels WHERE owner_id=%s ORDER BY updated_at DESC
        """, (user["id"],)).fetchall()
    return {"levels": [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "version": r["level_version"],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat()
        } for r in rows
    ]}


@app.post("/levels/publish")
async def publish_level(
    file: UploadFile = File(...),
    name: str = Form(...),
    user=Depends(current_user)
):
    clean_name = name.strip()
    if not clean_name or len(clean_name) > LEVEL_NAME_MAX:
        raise HTTPException(400, "Nome de nível inválido.")
    if not file.filename.lower().endswith(".level"):
        raise HTTPException(400, "Envie um arquivo .level.")

    data = await file.read()
    version = validate_level(data)
    level_id = uuid.uuid4()

    with db() as conn:
        conn.execute("""
            INSERT INTO levels
            (id,name,owner_id,owner_username,level_data,level_version)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (level_id, clean_name, user["id"], user["username"], data, version))
        conn.commit()

    return {
        "success": True,
        "level_id": str(level_id),
        "name": clean_name,
        "owner": user["username"],
        "version": version
    }


@app.get("/levels/{level_id}")
def download_level(level_id: str):
    try:
        parsed = uuid.UUID(level_id)
    except ValueError:
        raise HTTPException(400, "ID inválido.")

    with db() as conn:
        row = conn.execute("""
            SELECT name,owner_username,level_data,level_version
            FROM levels WHERE id=%s
        """, (parsed,)).fetchone()

    if row is None:
        raise HTTPException(404, "Nível não encontrado.")

    return Response(
        content=bytes(row["level_data"]),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="level.level"',
            "X-Level-Name": row["name"],
            "X-Level-Owner": row["owner_username"],
            "X-Level-Version": str(row["level_version"])
        }
    )


@app.delete("/levels/{level_id}")
def delete_level(level_id: str, user=Depends(current_user)):
    try:
        parsed = uuid.UUID(level_id)
    except ValueError:
        raise HTTPException(400, "ID inválido.")

    with db() as conn:
        row = conn.execute("SELECT owner_id FROM levels WHERE id=%s", (parsed,)).fetchone()
        if row is None:
            raise HTTPException(404, "Nível não encontrado.")
        if row["owner_id"] != user["id"]:
            raise HTTPException(403, "Você não é o dono deste nível.")
        conn.execute("DELETE FROM levels WHERE id=%s", (parsed,))
        conn.commit()

    return {"success": True}
