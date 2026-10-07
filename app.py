import os
import sqlite3
import secrets
import hashlib
import time
import csv
import io
import json
import threading
import urllib.request
from datetime import datetime
from functools import wraps
from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, g, flash, Response)

ADMIN_USER  = "1"
ADMIN_PASS  = "1"
AUTH_SECRET = os.environ.get("PANEL_SECRET", "change_this_secret_string_2025")
GAME_NAME   = os.environ.get("PANEL_GAME",   "Ashwin")
DB_PATH     = os.environ.get("PANEL_DB",     "panel.db")
AUTO_BAN_IP_THRESHOLD = int(os.environ.get("AUTO_BAN_IPS", "0"))  # 0 = off

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SESSION", "change_session_secret_xyz")


# ============ DB ============
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
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            event TEXT NOT NULL DEFAULT 'all',
            enabled INTEGER DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            duration INTEGER NOT NULL,
            max_devices INTEGER DEFAULT 1,
            category TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_act_key ON activations(key_id);
    """)
    db.commit()
    db.close()


# ============ WEBHOOKS ============
def _send_webhook(event, payload):
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        hooks = db.execute(
            "SELECT * FROM webhooks WHERE enabled=1 AND (event=? OR event='all')",
            (event,)
        ).fetchall()
        db.close()
        for h in hooks:
            try:
                body = json.dumps({"event": event, "ts": int(time.time()), **payload}).encode()
                req = urllib.request.Request(
                    h["url"], data=body,
                    headers={"Content-Type": "application/json",
                             "User-Agent": "AshwinPanel/1.0"}
                )
                urllib.request.urlopen(req, timeout=5).read()
            except Exception as e:
                app.logger.warning(f"[webhook] fail {h['url']}: {e}")
    except Exception as e:
        app.logger.warning(f"[webhook] error: {e}")

def fire_webhook(event, payload):
    threading.Thread(target=_send_webhook, args=(event, payload), daemon=True).start()


# ============ HELPERS ============
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
    return "ASH-" + "-".join(parts)

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


# ============ AUTH ============
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


# ============ DASHBOARD ============
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


@app.route("/api/analytics")
@login_required
def api_analytics():
    db = get_db()
    now = int(time.time())

    today_start = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    days = []
    for i in range(6, -1, -1):
        ds = today_start - i * 86400
        de = ds + 86400
        created = db.execute(
            "SELECT COUNT(*) c FROM license_keys WHERE created_at>=? AND created_at<?",
            (ds, de)).fetchone()["c"]
        activated = db.execute(
            "SELECT COUNT(*) c FROM logs WHERE action='auth_ok' AND ts>=? AND ts<?",
            (ds, de)).fetchone()["c"]
        days.append({
            "label": datetime.fromtimestamp(ds).strftime("%d %b"),
            "created": created,
            "activated": activated,
        })

    active  = db.execute("SELECT COUNT(*) c FROM license_keys WHERE banned=0 AND expires_at>?", (now,)).fetchone()["c"]
    expired = db.execute("SELECT COUNT(*) c FROM license_keys WHERE banned=0 AND expires_at<=?", (now,)).fetchone()["c"]
    banned  = db.execute("SELECT COUNT(*) c FROM license_keys WHERE banned=1").fetchone()["c"]

    top = db.execute("""
        SELECT k.license_key, k.max_devices,
               COUNT(a.id) AS device_count
        FROM license_keys k
        LEFT JOIN activations a ON a.key_id = k.id
        GROUP BY k.id
        ORDER BY device_count DESC, k.id DESC
        LIMIT 5
    """).fetchall()

    return jsonify({
        "days": days,
        "status": {"active": active, "expired": expired, "banned": banned},
        "top": [{"key": r["license_key"], "devices": r["device_count"], "max": r["max_devices"]} for r in top]
    })


# ============ KEYS LIST ============
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


# ============ KEY DETAIL ============
@app.route("/keys/<int:kid>")
@login_required
def key_detail(kid):
    db = get_db()
    row = db.execute("SELECT * FROM license_keys WHERE id=?", (kid,)).fetchone()
    if not row:
        flash("Key not found", "error")
        return redirect(url_for("keys_list"))

    used = db.execute(
        "SELECT * FROM activations WHERE key_id=? ORDER BY last_seen DESC",
        (kid,)).fetchall()
    key_logs = db.execute(
        "SELECT * FROM logs WHERE key_text=? ORDER BY ts DESC LIMIT 50",
        (row["license_key"],)).fetchall()

    return render_template("key_detail.html", key=row, used_devices=used,
                           key_logs=key_logs, fmt_ts=fmt_ts, fmt_ts_full=fmt_ts_full,
                           now=int(time.time()))


# ============ CREATE / EDIT ============
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
    db = get_db()

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

        try:
            db.execute(
                "INSERT INTO license_keys(license_key, created_at, expires_at, max_devices, note) VALUES (?,?,?,?,?)",
                (k, int(time.time()), expires, max_dev, note)
            )
            db.commit()
            log_event("key_create", key_text=k, message=f"dur={dur}s max={max_dev}")
            fire_webhook("key_create", {"key": k, "duration": dur, "max_devices": max_dev, "note": note})
            flash(f"Key created: {k}", "success")
            return redirect(url_for("keys_list"))
        except sqlite3.IntegrityError:
            flash(f"Key already exists: {k}", "error")

    try:
        templates = db.execute("SELECT * FROM key_templates ORDER BY id DESC").fetchall()
    except sqlite3.OperationalError:
        templates = []
    return render_template("key_form.html", mode="new", key=None, templates=templates)


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
        return redirect(url_for("key_detail", kid=kid))

    used = db.execute("SELECT * FROM activations WHERE key_id=? ORDER BY last_seen DESC", (kid,)).fetchall()
    try:
        templates = db.execute("SELECT * FROM key_templates ORDER BY id DESC").fetchall()
    except sqlite3.OperationalError:
        templates = []
    return render_template("key_form.html", mode="edit", key=row, used_devices=used,
                           templates=templates, fmt_ts=fmt_ts)


@app.route("/keys/<int:kid>/delete", methods=["POST"])
@login_required
def key_delete(kid):
    db = get_db()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    if row:
        db.execute("DELETE FROM license_keys WHERE id=?", (kid,))
        db.commit()
        log_event("key_delete", key_text=row["license_key"])
        fire_webhook("key_delete", {"key": row["license_key"]})
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
    k = row["license_key"] if row else ""
    log_event("key_ban", key_text=k, message=reason)
    fire_webhook("key_ban", {"key": k, "reason": reason})
    return redirect(request.referrer or url_for("keys_list"))


@app.route("/keys/<int:kid>/unban", methods=["POST"])
@login_required
def key_unban(kid):
    db = get_db()
    db.execute("UPDATE license_keys SET banned=0, banned_reason='' WHERE id=?", (kid,))
    db.commit()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    k = row["license_key"] if row else ""
    log_event("key_unban", key_text=k)
    fire_webhook("key_unban", {"key": k})
    return redirect(request.referrer or url_for("keys_list"))


@app.route("/keys/<int:kid>/reset", methods=["POST"])
@login_required
def key_reset_devices(kid):
    db = get_db()
    db.execute("DELETE FROM activations WHERE key_id=?", (kid,))
    db.commit()
    row = db.execute("SELECT license_key FROM license_keys WHERE id=?", (kid,)).fetchone()
    log_event("key_reset_hwid", key_text=row["license_key"] if row else "")
    flash("Devices reset", "success")
    return redirect(request.referrer or url_for("keys_list"))


# ============ BULK ============
@app.route("/keys/bulk", methods=["POST"])
@login_required
def keys_bulk():
    action = request.form.get("action", "")
    ids_raw = request.form.getlist("ids")
    ids = []
    for x in ids_raw:
        try:
            ids.append(int(x))
        except ValueError:
            pass

    if not ids:
        flash("No keys selected", "error")
        return redirect(url_for("keys_list"))

    db = get_db()
    placeholders = ",".join("?" * len(ids))

    if action == "delete":
        db.execute(f"DELETE FROM license_keys WHERE id IN ({placeholders})", ids)
        db.commit()
        msg = f"Deleted {len(ids)} key(s)"
        log_event("bulk_delete", message=f"{len(ids)} keys")
    elif action == "ban":
        reason = request.form.get("reason", "").strip() or "Bulk ban by admin"
        db.execute(f"UPDATE license_keys SET banned=1, banned_reason=? WHERE id IN ({placeholders})",
                   [reason] + ids)
        db.commit()
        msg = f"Banned {len(ids)} key(s)"
        log_event("bulk_ban", message=f"{len(ids)} keys")
    elif action == "unban":
        db.execute(f"UPDATE license_keys SET banned=0, banned_reason='' WHERE id IN ({placeholders})", ids)
        db.commit()
        msg = f"Unbanned {len(ids)} key(s)"
        log_event("bulk_unban", message=f"{len(ids)} keys")
    elif action == "extend":
        try:
            days = int(request.form.get("extend_days", "7") or 7)
        except ValueError:
            days = 7
        if days < 1: days = 7
        secs = days * 86400
        now = int(time.time())
        db.execute(f"""
            UPDATE license_keys
            SET expires_at = MAX(expires_at, ?) + ?
            WHERE id IN ({placeholders})
        """, [now, secs] + ids)
        db.commit()
        msg = f"Extended {len(ids)} key(s) by {days} day(s)"
        log_event("bulk_extend", message=f"{len(ids)} keys +{days}d")
    else:
        flash("Unknown action", "error")
        return redirect(url_for("keys_list"))

    flash(msg, "success")
    return redirect(url_for("keys_list"))


# ============ EXPORT / IMPORT ============
@app.route("/keys/export")
@login_required
def keys_export():
    fmt = request.args.get("format", "csv").lower()
    db = get_db()
    rows = db.execute("SELECT * FROM license_keys ORDER BY id DESC").fetchall()

    if fmt == "json":
        data = [{
            "id": r["id"], "license_key": r["license_key"],
            "created_at": r["created_at"], "expires_at": r["expires_at"],
            "max_devices": r["max_devices"], "note": r["note"],
            "banned": r["banned"], "banned_reason": r["banned_reason"],
        } for r in rows]
        return Response(
            json.dumps(data, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=keys_{int(time.time())}.json"}
        )

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["license_key", "created_at", "expires_at", "max_devices", "note", "banned", "banned_reason"])
    for r in rows:
        w.writerow([r["license_key"], r["created_at"], r["expires_at"],
                    r["max_devices"], r["note"], r["banned"], r["banned_reason"]])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=keys_{int(time.time())}.csv"}
    )


@app.route("/keys/import", methods=["POST"])
@login_required
def keys_import():
    f = request.files.get("file")
    if not f:
        flash("No file uploaded", "error")
        return redirect(url_for("keys_list"))

    try:
        default_days = int(request.form.get("default_days", "30") or 30)
    except ValueError:
        default_days = 30
    if default_days < 1: default_days = 30

    try:
        max_dev = int(request.form.get("max_devices", "1") or 1)
    except ValueError:
        max_dev = 1
    if max_dev < 1: max_dev = 1

    content = f.read().decode("utf-8", errors="ignore")
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]

    if lines and lines[0].lower().startswith(("license_key", "key")):
        lines = lines[1:]

    db = get_db()
    now = int(time.time())
    expires = now + default_days * 86400
    added = 0
    skipped = 0

    for ln in lines:
        k = ln.split(",")[0].strip().strip('"')
        if not k:
            continue
        try:
            db.execute(
                "INSERT INTO license_keys(license_key, created_at, expires_at, max_devices, note) VALUES (?,?,?,?,?)",
                (k, now, expires, max_dev, "imported")
            )
            added += 1
        except sqlite3.IntegrityError:
            skipped += 1

    db.commit()
    log_event("keys_import", message=f"added={added} skipped={skipped}")
    flash(f"Imported {added} key(s), {skipped} skipped (duplicates)", "success")
    return redirect(url_for("keys_list"))


# ============ LOGS ============
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


# ============ TEMPLATES ============
@app.route("/templates")
@login_required
def templates_list():
    db = get_db()
    rows = db.execute("SELECT * FROM key_templates ORDER BY id DESC").fetchall()
    return render_template("templates.html", templates=rows)


@app.route("/templates/new", methods=["POST"])
@login_required
def template_new():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Name required", "error")
        return redirect(url_for("templates_list"))

    val = request.form.get("duration", "").strip()
    unit = request.form.get("unit", "days").strip()
    mult = {"minutes": 60, "hours": 3600, "days": 86400}.get(unit, 86400)
    try:
        n = int(val)
        if n <= 0: raise ValueError
    except (ValueError, TypeError):
        flash("Invalid duration", "error")
        return redirect(url_for("templates_list"))
    dur = n * mult

    try:
        max_dev = int(request.form.get("max_devices", "1") or 1)
    except ValueError:
        max_dev = 1
    if max_dev < 1: max_dev = 1

    category = request.form.get("category", "").strip()

    db = get_db()
    db.execute(
        "INSERT INTO key_templates(name, duration, max_devices, category, created_at) VALUES (?,?,?,?,?)",
        (name, dur, max_dev, category, int(time.time()))
    )
    db.commit()
    log_event("template_create", message=name)
    flash(f"Template '{name}' created", "success")
    return redirect(url_for("templates_list"))


@app.route("/templates/<int:tid>/delete", methods=["POST"])
@login_required
def template_delete(tid):
    db = get_db()
    db.execute("DELETE FROM key_templates WHERE id=?", (tid,))
    db.commit()
    flash("Template deleted", "success")
    return redirect(url_for("templates_list"))


# ============ WEBHOOKS ============
@app.route("/webhooks")
@login_required
def webhooks_list():
    db = get_db()
    rows = db.execute("SELECT * FROM webhooks ORDER BY id DESC").fetchall()
    return render_template("webhooks.html", webhooks=rows)


@app.route("/webhooks/new", methods=["POST"])
@login_required
def webhook_new():
    url = request.form.get("url", "").strip()
    event = request.form.get("event", "all").strip() or "all"
    if not url.startswith(("http://", "https://")):
        flash("URL must start with http:// or https://", "error")
        return redirect(url_for("webhooks_list"))

    db = get_db()
    db.execute("INSERT INTO webhooks(url, event, enabled, created_at) VALUES (?,?,1,?)",
               (url, event, int(time.time())))
    db.commit()
    flash("Webhook added", "success")
    return redirect(url_for("webhooks_list"))


@app.route("/webhooks/<int:wid>/delete", methods=["POST"])
@login_required
def webhook_delete(wid):
    db = get_db()
    db.execute("DELETE FROM webhooks WHERE id=?", (wid,))
    db.commit()
    flash("Webhook deleted", "success")
    return redirect(url_for("webhooks_list"))


@app.route("/webhooks/<int:wid>/toggle", methods=["POST"])
@login_required
def webhook_toggle(wid):
    db = get_db()
    db.execute("UPDATE webhooks SET enabled = 1 - enabled WHERE id=?", (wid,))
    db.commit()
    return redirect(url_for("webhooks_list"))


@app.route("/webhooks/<int:wid>/test", methods=["POST"])
@login_required
def webhook_test(wid):
    db = get_db()
    row = db.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
    if not row:
        flash("Webhook not found", "error")
        return redirect(url_for("webhooks_list"))
    fire_webhook("test", {"message": "Test from Ashwin Panel", "url": row["url"]})
    flash("Test sent! Check your endpoint.", "success")
    return redirect(url_for("webhooks_list"))


# ============ API ============
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
        fire_webhook("auth_fail", {"key": user_key, "reason": "Key not found", "hwid": hwid, "ip": ip})
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

    is_new_device = False
    if act:
        db.execute("UPDATE activations SET last_seen=?, ip=? WHERE id=?",
                   (int(time.time()), ip, act["id"]))
    else:
        used = db.execute("SELECT COUNT(*) c FROM activations WHERE key_id=?", (row["id"],)).fetchone()["c"]
        if used >= row["max_devices"]:
            log_event("auth_fail", key_text=user_key, hwid=hwid, ip=ip,
                      message=f"Max devices ({used}/{row['max_devices']})")
            fire_webhook("auth_fail", {"key": user_key, "reason": "Max devices",
                                       "hwid": hwid, "ip": ip})
            return jsonify({"status": False, "reason": "Max devices reached for this key"})
        db.execute("INSERT INTO activations(key_id, hwid, first_seen, last_seen, ip) VALUES (?,?,?,?,?)",
                   (row["id"], hwid, int(time.time()), int(time.time()), ip))
        is_new_device = True

    db.commit()

    # Auto-ban logic
    if AUTO_BAN_IP_THRESHOLD > 0:
        distinct_ips = db.execute(
            "SELECT COUNT(DISTINCT ip) c FROM activations WHERE key_id=? AND ip != ''",
            (row["id"],)
        ).fetchone()["c"]
        if distinct_ips > AUTO_BAN_IP_THRESHOLD:
            db.execute("UPDATE license_keys SET banned=1, banned_reason=? WHERE id=?",
                       (f"Auto-ban: {distinct_ips} unique IPs", row["id"]))
            db.commit()
            log_event("auto_ban", key_text=user_key, hwid=hwid, ip=ip,
                      message=f"{distinct_ips} unique IPs")
            fire_webhook("key_ban", {"key": user_key, "reason": f"Auto-ban ({distinct_ips} IPs)", "auto": True})
            return jsonify({"status": False, "reason": "Key banned"})

    token = hashlib.md5(f"{GAME_NAME}-{user_key}-{hwid}-{AUTH_SECRET}".encode()).hexdigest()
    expire_str = fmt_date(row["expires_at"])
    rng = int(time.time())

    log_event("auth_ok", key_text=user_key, hwid=hwid, ip=ip, message=f"exp={expire_str}")
    if is_new_device:
        fire_webhook("key_activate", {
            "key": user_key, "hwid": hwid, "ip": ip,
            "expires": expire_str, "new_device": True
        })

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


# ============ ERROR HANDLERS ============
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
