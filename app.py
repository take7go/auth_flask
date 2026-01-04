from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import sqlite3
from flask import jsonify
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData, PublicKeyCredentialDescriptor
from fido2.utils import websafe_encode, websafe_decode
import pickle

rp = PublicKeyCredentialRpEntity(
    name="FlaskAuthDemo",
    id="localhost"
)
fido_server = Fido2Server(rp)

DB_PATH = "users.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,

                otp_secret TEXT,
                otp_enabled INTEGER DEFAULT 0,

                fido_credential_id BLOB,
                fido_credential_data BLOB,
                fido_enabled INTEGER DEFAULT 0
            )
        """)

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # 本番では環境変数にする

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT
              username,
              otp_enabled,
              otp_secret,
              fido_enabled
            FROM users
            WHERE username = ?
            """,
            (session["user"],)
        ).fetchone()

    return render_template(
        "index.html",
        user=user["username"],
        otp_enabled=bool(user["otp_enabled"]),
        otp_registered=bool(user["otp_secret"]),
        fido_enabled=bool(user["fido_enabled"])
    )

# ユーザ登録
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO users (username, password_hash)
                    VALUES (?, ?)
                """, (username, password_hash))
        except sqlite3.IntegrityError:
            return "ユーザー名は既に使われています"

        return redirect(url_for("login"))

    return render_template("register.html")

# ログイン画面
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["tmp_user"] = user["username"]
            return redirect(url_for("post_login"))

        return "ログイン失敗"
    return render_template("login.html")

# 認証方式選択画面
@app.route("/post-login")
def post_login():
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute(
            "SELECT otp_enabled, fido_enabled FROM users WHERE username = ?",
            (session["tmp_user"],)
        ).fetchone()

    return render_template(
        "post_login.html",
        otp_enabled=bool(user["otp_enabled"]),
        fido_enabled=bool(user["fido_enabled"])
    )

# 追加認証なし
@app.route("/auth/skip")
def auth_skip():
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    session["user"] = session.pop("tmp_user")
    session["auth_level"] = "password"
    return redirect(url_for("index"))

##
## OTP
##

# OTP認証
@app.route("/otp/auth", methods=["GET", "POST"])
def otp_auth():
    # パスワード認証未完了
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    # ユーザー取得
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["tmp_user"],)
        ).fetchone()
    
    if user is None:
        return redirect(url_for("login"))

    # OTP未登録ユーザーは使えない
    if not user["otp_enabled"] or not user["otp_secret"]:
        return redirect(url_for("post_login"))

    totp = pyotp.TOTP(user["otp_secret"])

    if request.method == "POST":
        code = request.form["code"]

        if totp.verify(code, valid_window=1):
            session["user"] = session.pop("tmp_user")
            session["auth_level"] = "otp"
            return redirect(url_for("index"))

        return render_template(
            "otp.html",
            error="認証コードが正しくありません"
        )

    return render_template("otp_auth.html")

# OTPのセットアップページ表示
@app.route("/otp/setup")
def otp_setup():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["user"],)
        ).fetchone()

    if user["otp_enabled"]:
        return redirect(url_for("index"))

    return render_template("otp_setup.html")

# OTPのQRコード生成
@app.route("/otp/setup/qr")
def otp_setup_qr():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["user"],)
        ).fetchone()

        # 秘密鍵がなければ生成（有効化はまだしない）
        if user["otp_secret"] is None:
            secret = pyotp.random_base32()
            conn.execute(
                "UPDATE users SET otp_secret = ? WHERE username = ?",
                (secret, user["username"])
            )
            user = dict(user)
            user["otp_secret"] = secret

    totp = pyotp.TOTP(user["otp_secret"])
    uri = totp.provisioning_uri(
        name=user["username"],
        issuer_name="FlaskAuthDemo"
    )

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype="image/png")

# OTPのセットアップ時検証用
@app.route("/otp/setup/verify", methods=["POST"])
def otp_setup_verify():
    if "user" not in session:
        return redirect(url_for("login"))

    code = request.form["code"]

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["user"],)
        ).fetchone()

        if not user or not user["otp_secret"]:
            return redirect(url_for("otp_setup"))

        totp = pyotp.TOTP(user["otp_secret"])
        if totp.verify(code, valid_window=1):
            conn.execute(
                "UPDATE users SET otp_enabled = 1 WHERE username = ?",
                (user["username"],)
            )
            return redirect(url_for("index"))

    return "OTP確認失敗"

##
## FIDO
##

# FIDO認証
def encode_if_bytes(value):
    if isinstance(value, bytes):
        return websafe_encode(value)
    return value

@app.route("/fido/setup")
def fido_setup():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("fido_setup.html")

@app.route("/fido/setup/begin")
def fido_setup_begin():
    if "user" not in session:
        return redirect(url_for("login"))

    user = {
        "id": session["user"].encode(), # WebAuthnでは bytes 必須
        "name": session["user"],
        "displayName": session["user"],
    }

    options, state = fido_server.register_begin(
        user=user,
        user_verification="preferred",
    )

    session["fido_state"] = state

    pk = options.public_key

    public_key_options = {
        "challenge": websafe_encode(pk.challenge),
        "rp": pk.rp,
        "user": {
            **pk.user,
            "id": encode_if_bytes(pk.user["id"]),
        },
        "pubKeyCredParams": pk.pub_key_cred_params,
        "timeout": pk.timeout,
        "excludeCredentials": [
            {
                "type": cred.type,
                "id": websafe_encode(cred.id),
            }
            for cred in (pk.exclude_credentials or [])
        ],
        "authenticatorSelection": pk.authenticator_selection,
        "attestation": pk.attestation,
    }

    return jsonify(public_key_options)

@app.route("/fido/setup/complete", methods=["POST"])
def fido_setup_complete():
    if "fido_state" not in session or "user" not in session:
        return "", 400

    data = request.get_json()

    auth_data = fido_server.register_complete(
        session.pop("fido_state"),
        data
    )

    credential_data = auth_data.credential_data  # ← AttestedCredentialData
    print(type(auth_data.credential_data))

    with get_db() as conn:
        conn.execute("""
            UPDATE users SET
                fido_credential_id = ?,
                fido_credential_data = ?,
                fido_enabled = 1
                WHERE username = ?
        """, (
            credential_data.credential_id,
            pickle.dumps(credential_data),
            session["user"]
        ))

    return "", 204

@app.route("/fido/auth")
def fido_auth():
    # パスワード認証未完了
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["tmp_user"],)
        ).fetchone()

    if user is None:
        return redirect(url_for("login"))

    # FIDO未登録ユーザーは使えない
    if not user["fido_enabled"]:
        return redirect(url_for("post_login"))

    return render_template("fido_auth.html")

@app.route("/fido/auth/begin")
def fido_auth_begin():
    # パスワード認証が完了していない場合はログインへ
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    # DBからユーザー取得
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["tmp_user"],)
        ).fetchone()

    if not user or not user["fido_enabled"] or not user["fido_credential_id"]:
        return redirect(url_for("post_login"))

    # PublicKeyCredentialDescriptor を作成（認証開始に必要）
    descriptor = PublicKeyCredentialDescriptor(
        type="public-key",
        id=user["fido_credential_id"]  # bytes
    )

    # FIDO認証開始
    options, state = fido_server.authenticate_begin(
        credentials=[descriptor],
        user_verification="preferred",
    )

    # 認証状態をセッションに保存
    session["fido_state"] = state

    pk = options.public_key

    # クライアントに渡す JSON レスポンス
    response = {
        "challenge": websafe_encode(pk.challenge),
        "timeout": pk.timeout,
        "rpId": pk.rp_id,
        "allowCredentials": [
            {
                "type": cred.type,
                "id": websafe_encode(cred.id),
            }
            for cred in pk.allow_credentials
        ],
        "userVerification": pk.user_verification,
    }

    return jsonify(response)

@app.route("/fido/auth/complete", methods=["POST"])
def fido_auth_complete():
    if "tmp_user" not in session or "fido_state" not in session:
        return "", 403

    data = request.get_json()

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["tmp_user"],)
        ).fetchone()

    if not user or not user["fido_enabled"]:
        return "", 403

    credential_data = pickle.loads(user["fido_credential_data"])

    auth_data = fido_server.authenticate_complete(
        session.pop("fido_state"),
        [credential_data],
        data
    )

    # 認証成功
    session["user"] = session.pop("tmp_user")
    session["auth_level"] = "fido"

    return "", 204

# ログアウト
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
