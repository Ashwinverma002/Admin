import os
import sqlite3
import secrets
import hashlib
import time
from datetime import datetime
from functools import wraps
from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, g, flash)

ADMIN_USER  = "1"
ADMIN_PASS  = "1"
AUTH_SECRET = os.environ.get("PANEL_SECRET", "change_this_secret_string_2025")
GAME_NAME   = os.environ.get("PANEL_GAME",   "bgmi")
DB_PATH     = os.environ.get("PANEL_DB",     "panel.db")

app = Flask(__name__, template_folder="Templates", static_folder="Static")
app.secret_key = os.environ.get("PANEL_SESSION", "change_session_secret_xyz")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS license_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            max_devices INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            banned INTEGER DEFAULT 0,
            banned_reason TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER NOT NULL,
            hwid TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            ip TEXT DEFAULT '',
            FOREIGN KEY(key_id) REFERENCES license_keys(id) ON DELETE CASCADE,
            UNIQUE(key_id, hwid)
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            key_text TEXT DEFAULT '',
            hwid TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            action TEXT NOT NULL,
            message TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_act_key ON activations(key_id);
    """)
    db.commit()
    db.close()

def log_event(action, key_text="", hwid="", ip="", message=""):
    db = get_db()
    db.execute(
        "INSERT INTO logs(ts, key_text, hwid, ip, action, message) VALUES (?,?,?,?,?,?)",
        (int(time.time()), key_text, hwid, ip, action, message)
    )
    db.commit()

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def fmt_ts(ts):
    if not ts: return "—"
    return datetime.fromtimestamp(ts).strftime("%d %b %H:%M")

def fmt_ts_full(ts):
    if not ts: return "—"
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M")

def fmt_date(ts):
    if not ts: return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")

def gen_key():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    parts = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(3)]
    return "BGM-" + "-".join(parts)

def key_status(row):
    if row["banned"]: return "banned"
    if row["expires_at"] < int(time.time()): return "expired"
    return "active"

def human_left(expires_at):
    diff = expires_at - int(time.time())
    if diff <= 0:
        return "expired"
    d = diff // 86400
    h = (diff % 86400) // 3600
    m = (diff % 3600) // 60
    if d > 0: return f"{d}d {h}h left"
    if h > 0: return f"{h}h {m}m left"
    return f"{m}m left"

def client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or ""

@app.context_processor
def inject_globals():
    return {"GAME_NAME": GAME_NAME, "human_left": human_left}

@app.before_request
def _ensure_db():
    init_db()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["admin"] = u
            log_event("admin_login", ip=client_ip(), message=f"user={u}")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    db = get_db()
    now = int(time.time())
    total   = db.execute("SELECT COUNT(*) c FROM license_keys").fetchone()["c"]
    active  = db.execute("SELECT COUNT(*) c FROM license_keys WHERE banned=0 AND expires_at>?", (now,)).fetchone()["c"]
    expired = db.execute("SELECT COUNT(*) c FROM license_keys WHERE banned=0 AND expires_at<=?", (now,)).fetchone()["c"]
    banned  = db.execute("SELECT COUNT(*) c FROM license_keys WHERE banned=1").fetchone()["c"]
    devices = db.execute("SELECT COUNT(DISTINCT hwid) c FROM activations WHERE last_seen>?", (now - 3600,)).fetchone()["c"]
    recent  = db.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT 20").fetchall()
    stats = {"total": total, "active": active, "expired": expired,
             "banned": banned, "devices": devices}
    return render_template("dashboard.html", stats=stats, recent=recent, fmt_ts=fmt_ts)


@app.route("/keys")
@login_required
def keys_list():
    db = get_db()
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    sql = "SELECT * FROM license_keys"
    params = []
    clauses = []

    if q:
        clauses.append("(license_key LIKE ? OR note LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if status_filter == "active":
        clauses.append("banned=0 AND expires_at>?"); params.append(int(time.time()))
    elif status_filter == "expired":
        clauses.append("banned=0 AND expires_at<=?"); params.append(int(time.time()))
    elif status_filter == "banned":
        clauses.append("banned=1")

    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT 500"

    rows = db.execute(sql, params).fetchall()

    keys = []
    for r in rows:
        used = db.execute("SELECT COUNT(*) c FROM activations WHERE key_id=?", (r["id"],)).fetchone()["c"]
        keys.append({
            "id": r["id"], "key": r["license_key"],
            "created": fmt_ts(r["created_at"]), "expires": fmt_ts_full(r["expires_at"]),
            "max_devices": r["max_devices"], "used_devices": used,
            "note": r["note"], "banned": r["banned"],
            "banned_reason": r["banned_reason"], "status": key_status(r),
            "expires_at": r["expires_at"],
        })

    return render_template("keys.html", keys=keys, q=q, status_filter=status_filter)


def _parse_duration(form):
    val = form.get("duration", "").strip()
    unit = form.get("unit", "days").strip()
    if not val:
        return None
    try:
        n = int(val)
    except ValueError:
        return None
    if n <= 0:
        return None
    mult = {"minutes": 60, "hours": 3600, "days": 86400}.get(unit, 86400)
    return n * mult


@app.route("/keys/new", methods=["GET", "POST"])
@login_required
def key_new():
    if request.method == "POST":
        dur = _parse_duration(request.form)
        if dur is None:
            flash("Invalid duration", "error")
            return redirect(url_for("key_new"))
        try:
            max_dev = int(request.form.get("max_devices", "1") or 1)
        except ValueError:
            max_dev = 1
        if max_dev < 1:
            max_dev = 1
        note = request.form.get("note", "").strip()
        custom = request.form.get("custom_key", "").strip()
        k = custom if custom else gen_key()
        expires = int(time.time()) + dur

        db = get_db()
        try:
            db.execute(
                "INSERT INTO license_keys(license_key, created_at, expires_at, max_devices, note) VALUES (?,?,?,?,?)",
                (k, int(time.time()), expires, max_dev, note)
            )
            db.commit()
            log_event("key_create", key_text=k, message=f"dur={dur}s max={max_dev}")
            flash(f"Key created: {k}", "success")
            return redirect(url_for("keys_list"))
        except sqlite3.IntegrityError:
            flash(f"Key already exists: {k}", "error")

    return render_template("key_form.html", mode="new", key=None)


@app.route("/keys/<int:kid>/edit", methods=["GET", "POST"])
@login_required
def key_edit(kid):
    db = get_db()
    row = db.execute("SELECT * FROM license_keys WHERE id=?", (kid,)).fetchone()
    if not row:
        flash("Key not found", "error")
        return redirect(url_for("keys_list"))

    if request.method == "POST":
        try:
            max_dev = int(request.form.get("max_devices", str(row["max_devices"])) or 1)
        except ValueError:
            max_dev = row["max_devices"]
        if max_dev < 1:
            max_dev = 1
        note = request.form.get("note", "").strip()
        dur = _parse_duration(request.form)
        expires = row["expires_at"]
        if dur:
            expires = int(time.time()) + dur
        db.execute("UPDATE license_keys SET max_devices=?, note=?, expires_at=? WHERE id=?",
                   (max_dev, note, expires, kid))
        db.commit()
        log_event("key_edit", key_text=row["license_key"], message=f"max={max_dev}")
        flash("Key updated", "success")
        return redirect(url_for("keys_list"))

    used = db.execute("SELECT * FROM activations WHERE key_id=? ORDER BY last_seen DESC", (kid,)).fetchall()
    return render_template("key_form.html", mode="edit", key=row, used_devices=used, fmt_ts=fmt_ts)


@app.route("/keys/<int:kid>/delete", methods=["POST"])
@login_required
def key_delete(kid):
    db = get_db()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    if row:
        db.execute("DELETE FROM license_keys WHERE id=?", (kid,))
        db.commit()
        log_event("key_delete", key_text=row["license_key"])
        flash(f"Deleted: {row['license_key']}", "success")
    return redirect(url_for("keys_list"))


@app.route("/keys/<int:kid>/ban", methods=["POST"])
@login_required
def key_ban(kid):
    reason = request.form.get("reason", "").strip() or "Banned by admin"
    db = get_db()
    db.execute("UPDATE license_keys SET banned=1, banned_reason=? WHERE id=?", (reason, kid))
    db.commit()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    log_event("key_ban", key_text=row["license_key"] if row else "", message=reason)
    return redirect(url_for("keys_list"))


@app.route("/keys/<int:kid>/unban", methods=["POST"])
@login_required
def key_unban(kid):
    db = get_db()
    db.execute("UPDATE license_keys SET banned=0, banned_reason='' WHERE id=?", (kid,))
    db.commit()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    log_event("key_unban", key_text=row["license_key"] if row else "")
    return redirect(url_for("keys_list"))


@app.route("/keys/<int:kid>/reset", methods=["POST"])
@login_required
def key_reset_devices(kid):
    db = get_db()
    db.execute("DELETE FROM activations WHERE key_id=?", (kid,))
    db.commit()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    log_event("key_reset_hwid", key_text=row["license_key"] if row else "")
    flash("Devices reset", "success")
    return redirect(url_for("key_edit", kid=kid))


@app.route("/logs")
@login_required
def logs_view():
    db = get_db()
    action_filter = request.args.get("action", "").strip()
    sql = "SELECT * FROM logs"
    params = []
    if action_filter:
        sql += " WHERE action LIKE ?"
        params.append(f"%{action_filter}%")
    sql += " ORDER BY ts DESC LIMIT 300"
    rows = db.execute(sql, params).fetchall()
    return render_template("logs.html", logs=rows, fmt_ts=fmt_ts, action_filter=action_filter)


@app.route("/api/auth", methods=["POST"])
def api_auth():
    game     = request.form.get("game", GAME_NAME).strip() or GAME_NAME
    user_key = (request.form.get("user_key") or request.form.get("key") or
                request.form.get("license") or "").strip()
    hwid     = (request.form.get("serial") or request.form.get("hwid") or
                request.form.get("device") or "").strip()
    ip = client_ip()

    if not user_key or not hwid:
        log_event("auth_fail", key_text=user_key, hwid=hwid, ip=ip, message="Bad Parameter")
        return jsonify({"status": False, "reason": "Bad Parameter"})

    db = get_db()
    row = db.execute("SELECT * FROM license_keys WHERE license_key=?", (user_key,)).fetchone()

    if not row:
        log_event("auth_fail", key_text=user_key, hwid=hwid, ip=ip, message="Key not found")
        return jsonify({"status": False, "reason": "Invalid key"})

    if row["banned"]:
        log_event("auth_fail", key_text=user_key, hwid=hwid, ip=ip,
                  message="Banned: " + (row["banned_reason"] or ""))
        return jsonify({"status": False, "reason": "Key banned"})

    if row["expires_at"] < int(time.time()):
        log_event("auth_fail", key_text=user_key, hwid=hwid, ip=ip, message="Expired")
        return jsonify({"status": False, "reason": "Key expired"})

    act = db.execute("SELECT * FROM activations WHERE key_id=? AND hwid=?",
                     (row["id"], hwid)).fetchone()

    if act:
        db.execute("UPDATE activations SET last_seen=?, ip=? WHERE id=?",
                   (int(time.time()), ip, act["id"]))
    else:
        used = db.execute("SELECT COUNT(*) c FROM activations WHERE key_id=?", (row["id"],)).fetchone()["c"]
        if used >= row["max_devices"]:
            log_event("auth_fail", key_text=user_key, hwid=hwid, ip=ip,
                      message=f"Max devices ({used}/{row['max_devices']})")
            return jsonify({"status": False, "reason": "Max devices reached for this key"})
        db.execute("INSERT INTO activations(key_id, hwid, first_seen, last_seen, ip) VALUES (?,?,?,?,?)",
                   (row["id"], hwid, int(time.time()), int(time.time()), ip))

    db.commit()

    token = hashlib.md5(f"{GAME_NAME}-{user_key}-{hwid}-{AUTH_SECRET}".encode()).hexdigest()
    expire_str = fmt_date(row["expires_at"])
    rng = int(time.time())

    log_event("auth_ok", key_text=user_key, hwid=hwid, ip=ip, message=f"exp={expire_str}")

    return jsonify({
        "status": True,
        "data": {"token": token, "EXP": expire_str, "rng": rng},
        "success": True,
        "expire": expire_str,
        "message": "OK",
    })


@app.route("/api/ping")
def api_ping():
    return jsonify({"ok": True, "ts": int(time.time())})


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, msg="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Unhandled error: %s", e)
    return render_template("error.html", code=500, msg="Something went wrong"), 500


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    print(f"[panel] running on http://0.0.0.0:{port}")
    print(f"[panel] admin user: {ADMIN_USER}   pass: {ADMIN_PASS}")
    app.run(host="0.0.0.0", port=port, debug=False)
