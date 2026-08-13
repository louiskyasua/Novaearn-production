from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    abort,
)
import sqlite3
import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import config as nova_config
from config import ALLOWED_PAYMENT_PROVIDERS, PAYMENT_ACCOUNTS


app = Flask(__name__)

SECRET_KEY = os.environ.get("NOVA_EARN_SECRET")

if os.environ.get("FLASK_ENV") == "production" and not SECRET_KEY:
    raise RuntimeError("NOVA_EARN_SECRET must be configured in production")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print(
        "WARNING: NOVA_EARN_SECRET is not configured. "
        "A temporary secret was generated for this process."
    )

app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NOVA_COOKIE_SECURE", "0").lower()
    in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

DATA_DIR = os.environ.get("NOVA_DATA_DIR", "instance")
os.makedirs(DATA_DIR, exist_ok=True)
DB = os.environ.get("NOVA_DB_PATH", os.path.join(DATA_DIR, "novaearn.db"))

PLANS = [
    (1, "Starter", 5000, 28, 15000),
    (2, "Bronze", 10000, 28, 30000),
    (3, "Silver", 15000, 14, 45000),
    (4, "Gold", 20000, 14, 60000),
    (5, "Platinum", 25000, 14, 75000),
    (6, "Diamond", 30000, 7, 90000),
]

NIGERIAN_BANKS = [
    {"name": "Access Bank", "code": "044"},
    {"name": "Citibank Nigeria", "code": "023"},
    {"name": "Ecobank Nigeria", "code": "050"},
    {"name": "Fidelity Bank", "code": "070"},
    {"name": "First Bank of Nigeria", "code": "011"},
    {"name": "First City Monument Bank (FCMB)", "code": "214"},
    {"name": "Globus Bank", "code": "103"},
    {"name": "Guaranty Trust Bank (GTBank)", "code": "058"},
    {"name": "Jaiz Bank", "code": "301"},
    {"name": "Keystone Bank", "code": "082"},
    {"name": "Moniepoint Microfinance Bank", "code": "50515"},
    {"name": "Opay", "code": "999992"},
    {"name": "PalmPay", "code": "999991"},
    {"name": "Parallex Bank", "code": "526"},
    {"name": "Polaris Bank", "code": "076"},
    {"name": "PremiumTrust Bank", "code": "105"},
    {"name": "Providus Bank", "code": "101"},
    {"name": "Stanbic IBTC Bank", "code": "221"},
    {"name": "Standard Chartered Bank Nigeria", "code": "068"},
    {"name": "Sterling Bank", "code": "232"},
    {"name": "SunTrust Bank Nigeria", "code": "100"},
    {"name": "Titan Trust Bank", "code": "102"},
    {"name": "Union Bank of Nigeria", "code": "032"},
    {"name": "United Bank for Africa (UBA)", "code": "033"},
    {"name": "Unity Bank", "code": "215"},
    {"name": "Wema Bank", "code": "035"},
    {"name": "Zenith Bank", "code": "057"},
]
BANK_CODES = {bank["code"] for bank in NIGERIAN_BANKS}


def db():
    connection = sqlite3.connect(DB, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def legacy_hash(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_password(password):
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_password, supplied_password):
    if not stored_password:
        return False, False
    if stored_password.startswith(("scrypt:", "pbkdf2:", "argon2:")):
        try:
            return check_password_hash(stored_password, supplied_password), False
        except ValueError:
            return False, False
    if secrets.compare_digest(legacy_hash(supplied_password), stored_password):
        return True, True
    return False, False


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def security_context():
    return {
        "csrf_token": get_csrf_token(),
        "logged": "uid" in session,
        "user_name": session.get("name"),
    }


def validate_csrf():
    supplied = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )
    expected = session.get("_csrf_token")
    if (
        not supplied
        or not expected
        or not secrets.compare_digest(supplied, expected)
    ):
        abort(400, description="Invalid or missing CSRF token.")


@app.before_request
def protect_state_changing_requests():
    if request.method != "POST":
        return
    protected_endpoints = {
        "register",
        "login",
        "invest",
        "deposit",
        "deposit_payment",
        "withdraw",
        "profile",
        "admin_update_deposit",
        "admin_update_withdrawal",
    }
    if request.endpoint in protected_endpoints:
        validate_csrf()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


def init_db():
    c = db()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance INTEGER DEFAULT 0,
            created_at TEXT,
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS investments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_id INTEGER,
            amount INTEGER,
            status TEXT DEFAULT 'active',
            created_at TEXT,
            maturity_at TEXT
        );
        CREATE TABLE IF NOT EXISTS deposits(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER,
            provider TEXT,
            reference TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS withdrawals(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            destination TEXT,
            destination_number TEXT,
            account_name TEXT,
            bank_code TEXT
        );
        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT,
            amount INTEGER,
            note TEXT,
            created_at TEXT
        );
        """
    )

    user_columns = {
        row[1]
        for row in c.execute("PRAGMA table_info(users)").fetchall()
    }
    if "referral_code" not in user_columns:
        c.execute("ALTER TABLE users ADD COLUMN referral_code TEXT")
    if "referred_by" not in user_columns:
        c.execute("ALTER TABLE users ADD COLUMN referred_by INTEGER")
    if "role" not in user_columns:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")

    withdrawal_columns = {
        row[1]
        for row in c.execute("PRAGMA table_info(withdrawals)").fetchall()
    }
    if "bank_code" not in withdrawal_columns:
        c.execute("ALTER TABLE withdrawals ADD COLUMN bank_code TEXT")

    existing = c.execute("SELECT id, name FROM users ORDER BY id").fetchall()
    for position, row in enumerate(existing, start=1):
        clean_name = "".join(
            ch for ch in (row["name"] or "USER").upper() if ch.isalnum()
        )[:12] or "USER"
        c.execute(
            """
            UPDATE users
            SET referral_code=?
            WHERE id=?
            AND (referral_code IS NULL OR referral_code='')
            """,
            (f"{clean_name}{position:03d}", row["id"]),
        )

    admin_email = os.environ.get("NOVA_ADMIN_EMAIL")
    admin_password = os.environ.get("NOVA_ADMIN_PASSWORD")
    if admin_email and admin_password:
        existing_admin = c.execute(
            "SELECT id FROM users WHERE email=?",
            (admin_email,),
        ).fetchone()
        if not existing_admin:
            c.execute(
                """
                INSERT INTO users(name,email,password,created_at,role)
                VALUES(?,?,?,?,?)
                """,
                (
                    "NovaEarn Admin",
                    admin_email,
                    hash_password(admin_password),
                    datetime.now().isoformat(),
                    "admin",
                ),
            )

    c.commit()
    c.close()


def settle_matured_investments(c, user_id=None):
    now = datetime.now().isoformat()
    query = """
        SELECT i.*, u.id AS owner_id
        FROM investments i
        JOIN users u ON u.id=i.user_id
        WHERE i.status='active' AND i.maturity_at<=?
    """
    params = [now]
    if user_id is not None:
        query += " AND i.user_id=?"
        params.append(user_id)

    matured = c.execute(query, params).fetchall()

    for investment in matured:
        plan = next(
            (p for p in PLANS if p[0] == investment["plan_id"]),
            None,
        )
        if not plan:
            continue

        result = c.execute(
            """
            UPDATE investments
            SET status='matured'
            WHERE id=? AND status='active'
            """,
            (investment["id"],),
        )
        if result.rowcount != 1:
            continue

        maturity_value = plan[4]
        c.execute(
            "UPDATE users SET balance=balance+? WHERE id=?",
            (maturity_value, investment["owner_id"]),
        )
        c.execute(
            """
            INSERT INTO transactions(
                user_id, kind, amount, note, created_at
            )
            VALUES(?,?,?,?,?)
            """,
            (
                investment["owner_id"],
                "INVESTMENT_MATURED",
                maturity_value,
                f"{plan[1]} investment matured",
                datetime.now().isoformat(),
            ),
        )


LOGIN_ATTEMPTS = {}
LOGIN_WINDOW = 300
MAX_LOGIN_ATTEMPTS = 8


def login_allowed(identifier):
    now = time.time()
    record = LOGIN_ATTEMPTS.get(identifier)
    if not record:
        return True
    attempts, first_attempt = record
    if now - first_attempt > LOGIN_WINDOW:
        LOGIN_ATTEMPTS.pop(identifier, None)
        return True
    return attempts < MAX_LOGIN_ATTEMPTS


def record_failed_login(identifier):
    now = time.time()
    record = LOGIN_ATTEMPTS.get(identifier)
    if not record or now - record[1] > LOGIN_WINDOW:
        LOGIN_ATTEMPTS[identifier] = (1, now)
        return
    LOGIN_ATTEMPTS[identifier] = (record[0] + 1, record[1])


def clear_login_attempts(identifier):
    LOGIN_ATTEMPTS.pop(identifier, None)


def current():
    uid = session.get("uid")
    if not uid:
        return None
    try:
        user_id = int(uid)
    except (TypeError, ValueError):
        session.clear()
        return None
    c = db()
    u = c.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    c.close()
    if not u:
        session.clear()
        return None
    return u


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        u = current()
        if not u or u["role"] != "admin":
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/healthz")
def healthz():
    c = db()
    c.execute("SELECT 1").fetchone()
    c.close()
    return jsonify({"status": "ok"})


@app.route("/")
def home():
    return render_template("home.html", plans=PLANS)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        incoming_ref = request.args.get("ref", "").strip().upper()
        if incoming_ref:
            session["pending_referral"] = incoming_ref
    if request.method == "POST":
        n = request.form.get("name", "").strip()
        e = request.form.get("email", "").strip().lower()
        p = request.form.get("password", "")
        referral_code = request.form.get(
            "ref", session.get("pending_referral", "")
        ).strip().upper()
        if len(n) < 2 or len(n) > 100:
            flash("Enter a valid name.")
            return redirect(url_for("register"))
        if len(e) < 5 or len(e) > 254 or "@" not in e:
            flash("Enter a valid email address.")
            return redirect(url_for("register"))
        if len(p) < 8 or len(p) > 128:
            flash("Password must be between 8 and 128 characters.")
            return redirect(url_for("register"))
        c = db()
        try:
            referrer = None
            if referral_code:
                referrer = c.execute(
                    "SELECT id FROM users WHERE referral_code=?",
                    (referral_code,),
                ).fetchone()
                if not referrer:
                    flash("Invalid referral code. You can register without one.")
                    referral_code = ""
            position = c.execute(
                "SELECT COALESCE(MAX(id), 0) + 1 FROM users"
            ).fetchone()[0]
            clean_name = "".join(
                ch for ch in n.upper() if ch.isalnum()
            )[:12] or "USER"
            new_code = f"{clean_name}{position:03d}"
            cur = c.execute(
                """
                INSERT INTO users(
                    name,email,password,created_at,
                    referral_code,referred_by,role
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    n,
                    e,
                    hash_password(p),
                    datetime.now().isoformat(),
                    new_code,
                    referrer["id"] if referrer else None,
                    "user",
                ),
            )
            c.commit()
            session.clear()
            session["uid"] = cur.lastrowid
            session["name"] = n
            session["_csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            c.rollback()
            flash("Email already registered.")
        finally:
            c.close()
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        e = request.form.get("email", "").strip().lower()
        p = request.form.get("password", "")
        identifier = f"{request.remote_addr or 'unknown'}:{e}"
        if not login_allowed(identifier):
            flash(
                "Too many login attempts. Please wait a few minutes and try again."
            )
            return redirect(url_for("login"))
        c = db()
        u = c.execute(
            "SELECT * FROM users WHERE email=?",
            (e,),
        ).fetchone()
        if not u:
            c.close()
            record_failed_login(identifier)
            flash("Invalid email or password.")
            return redirect(url_for("login"))
        valid, legacy = verify_password(u["password"], p)
        if not valid:
            c.close()
            record_failed_login(identifier)
            flash("Invalid email or password.")
            return redirect(url_for("login"))
        if legacy:
            c.execute(
                "UPDATE users SET password=? WHERE id=?",
                (hash_password(p), u["id"]),
            )
            c.commit()
        c.close()
        clear_login_attempts(identifier)
        session.clear()
        session["uid"] = u["id"]
        session["name"] = u["name"]
        session["_csrf_token"] = secrets.token_urlsafe(32)
        if u["role"] == "admin":
            return redirect(url_for("admin"))
        return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    u = current()
    c = db()
    settle_matured_investments(c, u["id"])
    c.commit()
    u = c.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    inv = c.execute(
        "SELECT * FROM investments WHERE user_id=? ORDER BY id DESC",
        (u["id"],),
    ).fetchall()
    deps = c.execute(
        "SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 5",
        (u["id"],),
    ).fetchall()
    wd = c.execute(
        "SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 5",
        (u["id"],),
    ).fetchall()
    tx = c.execute(
        "SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 10",
        (u["id"],),
    ).fetchall()
    c.close()
    return render_template(
        "dashboard.html",
        user=u,
        investments=inv,
        deposits=deps,
        withdrawals=wd,
        transactions=tx,
        plans=PLANS,
    )


@app.route("/invest", methods=["POST"])
@login_required
def invest():
    u = current()
    try:
        pid = int(request.form.get("plan_id", ""))
    except (ValueError, TypeError):
        flash("Invalid plan.")
        return redirect(url_for("investments"))
    plan = next((p for p in PLANS if p[0] == pid), None)
    if not plan:
        flash("Invalid plan.")
        return redirect(url_for("investments"))
    amount = plan[2]
    now = datetime.now()
    c = db()
    try:
        settle_matured_investments(c, u["id"])
        result = c.execute(
            """
            UPDATE users
            SET balance=balance-?
            WHERE id=? AND balance>=?
            """,
            (amount, u["id"], amount),
        )
        if result.rowcount != 1:
            c.rollback()
            flash(f"Insufficient balance. You need ₦{amount:,}.")
            return redirect(url_for("investments"))
        c.execute(
            """
            INSERT INTO investments(
                user_id,plan_id,amount,created_at,maturity_at
            )
            VALUES(?,?,?,?,?)
            """,
            (
                u["id"],
                pid,
                amount,
                now.isoformat(),
                (now + timedelta(days=plan[3])).isoformat(),
            ),
        )
        c.execute(
            """
            INSERT INTO transactions(
                user_id,kind,amount,note,created_at
            )
            VALUES(?,?,?,?,?)
            """,
            (
                u["id"],
                "INVESTMENT",
                amount,
                "Investment created",
                now.isoformat(),
            ),
        )
        c.commit()
    except Exception:
        c.rollback()
        flash("Unable to create investment.")
        return redirect(url_for("investments"))
    finally:
        c.close()
    flash("Investment created.")
    return redirect(url_for("investments"))


@app.route("/investments")
@login_required
def investments():
    u = current()
    c = db()
    settle_matured_investments(c, u["id"])
    c.commit()
    items = c.execute(
        "SELECT * FROM investments WHERE user_id=? ORDER BY id DESC",
        (u["id"],),
    ).fetchall()
    c.close()
    return render_template(
        "investments.html",
        user=u,
        items=items,
        plans=PLANS,
    )


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    u = current()
    if request.method == "POST":
        if not PAYMENT_ACCOUNTS:
            flash("Payment accounts are not configured yet.")
            return redirect(url_for("deposit"))
        try:
            amount = int(request.form.get("amount", ""))
        except (ValueError, TypeError):
            flash("Enter a valid deposit amount.")
            return redirect(url_for("deposit"))
        provider = request.form.get("provider", "").strip()
        reference = request.form.get("reference", "").strip()
        configured_providers = {
            account["provider"] for account in PAYMENT_ACCOUNTS
        }
        if provider not in ALLOWED_PAYMENT_PROVIDERS or provider not in configured_providers:
            flash("Invalid payment provider.")
            return redirect(url_for("deposit"))
        if not 5000 <= amount <= 30000:
            flash("Deposit amount must be between ₦5,000 and ₦30,000.")
            return redirect(url_for("deposit"))
        if not reference or len(reference) > 150:
            flash("Enter a valid payment reference.")
            return redirect(url_for("deposit"))
        now = datetime.now()
        c = db()
        try:
            duplicate = c.execute(
                """
                SELECT id FROM deposits
                WHERE provider=? AND reference=?
                LIMIT 1
                """,
                (provider, reference),
            ).fetchone()
            if duplicate:
                c.rollback()
                flash("That payment reference has already been submitted.")
                return redirect(url_for("deposit"))
            c.execute(
                """
                INSERT INTO deposits(
                    user_id,amount,provider,reference,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    u["id"],
                    amount,
                    provider,
                    reference,
                    now.isoformat(),
                ),
            )
            c.execute(
                """
                INSERT INTO transactions(
                    user_id,kind,amount,note,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    u["id"],
                    "DEPOSIT",
                    amount,
                    "Deposit submitted for review",
                    now.isoformat(),
                ),
            )
            c.commit()
        except Exception:
            c.rollback()
            flash("Unable to submit deposit.")
            return redirect(url_for("deposit"))
        finally:
            c.close()
        flash("Deposit submitted.")
        return redirect(url_for("wallet"))
    return render_template("deposit.html", accounts=PAYMENT_ACCOUNTS)


@app.route("/deposit/payment", methods=["POST"])
@login_required
def deposit_payment():
    amount = request.form.get("amount")
    if not amount:
        flash("Please select an amount.")
        return redirect(url_for("deposit"))
    return render_template(
        "deposit_payment.html",
        amount=amount,
        accounts=PAYMENT_ACCOUNTS,
    )


@app.route("/api/banks", methods=["GET"])
def api_banks():
    return jsonify(
        {
            "status": True,
            "banks": NIGERIAN_BANKS,
            "data": NIGERIAN_BANKS,
            "count": len(NIGERIAN_BANKS),
        }
    )


@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    u = current()
    if request.method == "POST":
        try:
            amount = int(request.form.get("amount", ""))
        except (ValueError, TypeError):
            flash("Enter a valid withdrawal amount.")
            return redirect(url_for("withdraw"))
        destination = request.form.get("destination", "").strip()
        destination_number = request.form.get(
            "destination_number", ""
        ).strip()
        account_name = request.form.get("account_name", "").strip()
        bank_code = request.form.get("bank_code", "").strip()
        allowed_destinations = {
            "Bank account",
            "OPay",
            "PalmPay",
            "Moniepoint",
        }
        if not 1500 <= amount <= 800000:
            flash("Withdrawal amount must be between ₦1,500 and ₦800,000.")
            return redirect(url_for("withdraw"))
        if destination not in allowed_destinations:
            flash("Invalid withdrawal destination.")
            return redirect(url_for("withdraw"))
        if not destination_number.isdigit():
            flash("Account number must contain digits only.")
            return redirect(url_for("withdraw"))
        if destination == "Bank account":
            if bank_code not in BANK_CODES:
                flash("Please select a valid bank.")
                return redirect(url_for("withdraw"))
            if len(destination_number) != 10:
                flash("Nigerian bank account numbers must contain 10 digits.")
                return redirect(url_for("withdraw"))
        else:
            if not 10 <= len(destination_number) <= 20:
                flash("Enter a valid wallet number.")
                return redirect(url_for("withdraw"))
            bank_code = ""
        if len(account_name) > 120:
            flash("Account name is too long.")
            return redirect(url_for("withdraw"))
        now = datetime.now()
        c = db()
        try:
            settle_matured_investments(c, u["id"])
            result = c.execute(
                """
                UPDATE users
                SET balance=balance-?
                WHERE id=? AND balance>=?
                """,
                (amount, u["id"], amount),
            )
            if result.rowcount != 1:
                c.rollback()
                flash("Insufficient available balance.")
                return redirect(url_for("withdraw"))
            c.execute(
                """
                INSERT INTO withdrawals(
                    user_id,amount,status,created_at,
                    destination,destination_number,account_name,bank_code
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    u["id"],
                    amount,
                    "pending",
                    now.isoformat(),
                    destination,
                    destination_number,
                    account_name,
                    bank_code,
                ),
            )
            c.execute(
                """
                INSERT INTO transactions(
                    user_id,kind,amount,note,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    u["id"],
                    "WITHDRAWAL",
                    -amount,
                    f"Withdrawal request to {destination}",
                    now.isoformat(),
                ),
            )
            c.commit()
        except Exception:
            c.rollback()
            flash("Unable to submit withdrawal request.")
            return redirect(url_for("withdraw"))
        finally:
            c.close()
        flash("Withdrawal request submitted.")
        return redirect(url_for("wallet"))
    return render_template(
        "withdraw.html",
        user=u,
        banks=NIGERIAN_BANKS,
    )


@app.route("/wallet")
@login_required
def wallet():
    u = current()
    c = db()
    settle_matured_investments(c, u["id"])
    c.commit()
    u = c.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    deps = c.execute(
        "SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC",
        (u["id"],),
    ).fetchall()
    wd = c.execute(
        "SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC",
        (u["id"],),
    ).fetchall()
    c.close()
    return render_template(
        "wallet.html",
        user=u,
        deposits=deps,
        withdrawals=wd,
    )


@app.route("/transactions")
@login_required
def transactions():
    u = current()
    c = db()
    items = c.execute(
        "SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC",
        (u["id"],),
    ).fetchall()
    c.close()
    return render_template("transactions.html", items=items)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    u = current()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not 2 <= len(name) <= 100:
            flash("Enter a valid name.")
            return redirect(url_for("profile"))
        c = db()
        c.execute(
            "UPDATE users SET name=? WHERE id=?",
            (name, u["id"]),
        )
        c.commit()
        c.close()
        session["name"] = name
        flash("Profile updated.")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=u)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/support")
def support():
    return render_template("support.html")


@app.route("/referral")
@login_required
def referral():
    u = current()
    c = db()
    referrals = c.execute(
        """
        SELECT name, email, created_at
        FROM users
        WHERE referred_by=?
        ORDER BY id DESC
        """,
        (u["id"],),
    ).fetchall()
    c.close()
    return render_template(
        "referral.html",
        user=u,
        referral_code=u["referral_code"],
        referrals=referrals,
    )


@app.route("/admin")
@admin_required
def admin():
    c = db()
    users = c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    deps = c.execute(
        """
        SELECT d.*, u.name
        FROM deposits d
        JOIN users u ON u.id=d.user_id
        ORDER BY d.id DESC
        """
    ).fetchall()
    wd = c.execute(
        """
        SELECT w.*, u.name
        FROM withdrawals w
        JOIN users u ON u.id=w.user_id
        ORDER BY w.id DESC
        """
    ).fetchall()
    c.close()
    return render_template(
        "admin.html",
        users=users,
        deposits=deps,
        withdrawals=wd,
    )


@app.route("/admin/payment-accounts")
@admin_required
def payment_accounts():
    return render_template(
        "payment_accounts.html",
        accounts=PAYMENT_ACCOUNTS,
    )


@app.route(
    "/admin/update-deposit/<int:deposit_id>/<action>",
    methods=["POST"],
)
@admin_required
def admin_update_deposit(deposit_id, action):
    if action not in {"approve", "reject"}:
        flash("Invalid deposit action.")
        return redirect(url_for("admin"))
    c = db()
    try:
        dep = c.execute(
            "SELECT * FROM deposits WHERE id=?",
            (deposit_id,),
        ).fetchone()
        if not dep or dep["status"] != "pending":
            c.rollback()
            flash("Deposit is no longer pending.")
            return redirect(url_for("admin"))
        new_status = "approved" if action == "approve" else "rejected"
        result = c.execute(
            """
            UPDATE deposits
            SET status=?
            WHERE id=? AND status='pending'
            """,
            (new_status, deposit_id),
        )
        if result.rowcount != 1:
            c.rollback()
            flash("Deposit is no longer pending.")
            return redirect(url_for("admin"))
        if action == "approve":
            c.execute(
                "UPDATE users SET balance=balance+? WHERE id=?",
                (dep["amount"], dep["user_id"]),
            )
            c.execute(
                """
                INSERT INTO transactions(
                    user_id,kind,amount,note,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    dep["user_id"],
                    "DEPOSIT_APPROVED",
                    dep["amount"],
                    "Deposit approved by admin",
                    datetime.now().isoformat(),
                ),
            )
        else:
            c.execute(
                """
                INSERT INTO transactions(
                    user_id,kind,amount,note,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    dep["user_id"],
                    "DEPOSIT_REJECTED",
                    0,
                    "Deposit rejected by admin",
                    datetime.now().isoformat(),
                ),
            )
        c.commit()
    except Exception:
        c.rollback()
        flash("Unable to update deposit.")
        return redirect(url_for("admin"))
    finally:
        c.close()
    flash(f"Deposit {new_status}.")
    return redirect(url_for("admin"))


@app.route(
    "/admin/update-withdrawal/<int:withdrawal_id>/<action>",
    methods=["POST"],
)
@admin_required
def admin_update_withdrawal(withdrawal_id, action):
    if action not in {"approve", "reject"}:
        flash("Invalid withdrawal action.")
        return redirect(url_for("admin"))
    c = db()
    try:
        wd = c.execute(
            "SELECT * FROM withdrawals WHERE id=?",
            (withdrawal_id,),
        ).fetchone()
        if not wd or wd["status"] != "pending":
            c.rollback()
            flash("Withdrawal is no longer pending.")
            return redirect(url_for("admin"))
        new_status = "approved" if action == "approve" else "rejected"
        result = c.execute(
            """
            UPDATE withdrawals
            SET status=?
            WHERE id=? AND status='pending'
            """,
            (new_status, withdrawal_id),
        )
        if result.rowcount != 1:
            c.rollback()
            flash("Withdrawal is no longer pending.")
            return redirect(url_for("admin"))
        if action == "reject":
            c.execute(
                "UPDATE users SET balance=balance+? WHERE id=?",
                (wd["amount"], wd["user_id"]),
            )
            c.execute(
                """
                INSERT INTO transactions(
                    user_id,kind,amount,note,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    wd["user_id"],
                    "WITHDRAWAL_REFUNDED",
                    wd["amount"],
                    "Withdrawal rejected and balance refunded",
                    datetime.now().isoformat(),
                ),
            )
        else:
            c.execute(
                """
                INSERT INTO transactions(
                    user_id,kind,amount,note,created_at
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    wd["user_id"],
                    "WITHDRAWAL_APPROVED",
                    -wd["amount"],
                    "Withdrawal approved by admin",
                    datetime.now().isoformat(),
                ),
            )
        c.commit()
    except Exception:
        c.rollback()
        flash("Unable to update withdrawal.")
        return redirect(url_for("admin"))
    finally:
        c.close()
    flash(f"Withdrawal {new_status}.")
    return redirect(url_for("admin"))


@app.errorhandler(400)
def bad_request(error):
    return (
        render_template(
            "base.html",
            error_message=getattr(error, "description", "Bad request."),
        ),
        400,
    )


# The admin route function has the same historical name as the payment
# configuration variable. Restore the configured list after route registration.
PAYMENT_ACCOUNTS = nova_config.PAYMENT_ACCOUNTS

init_db()


if __name__ == "__main__":
    debug_mode = (
        os.environ.get("NOVA_DEBUG", "0").lower()
        in {"1", "true", "yes"}
    )
    app.run(debug=debug_mode)
