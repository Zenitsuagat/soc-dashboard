# ── LOCAL TESTING VERSION ─────────────────────────────────────────────────────
from flask import Flask, render_template, request, redirect, Response, session
import sqlite3, csv, io
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'soc_secret_key_2024'   # needed for session

DB_PATH = "database.db"

# ─── DASHBOARD CREDENTIALS (separate from login page) ─────────────────────────
DASH_USER = "soc_admin"
DASH_PASS = "soc123"


# ─── HELPER ───────────────────────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


# ─── INIT DB ──────────────────────────────────────────────────────────────────
def init_db():
    with get_conn() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            status     TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp  TEXT,
            alert_flag TEXT
        )''')
        conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', '1234')")

init_db()


# ─── DETECT SUSPICIOUS ────────────────────────────────────────────────────────
def detect_suspicious(username, password):
    for pattern in ["'", "OR 1=1", "or 1=1", ";"]:
        if pattern in (username + password):
            return "SQL_INJECTION_ATTEMPT"
    return None


# ─── LOG ATTEMPT ──────────────────────────────────────────────────────────────
def log_attempt(username, status, ip_address, user_agent, alert_flag):
    with get_conn() as conn:
        conn.execute('''
            INSERT INTO logs (username, status, ip_address, user_agent, timestamp, alert_flag)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, status, ip_address, user_agent,
              datetime.now().strftime('%Y-%m-%d %H:%M:%S'), alert_flag or ''))


# ─── BRUTE FORCE CHECK ────────────────────────────────────────────────────────
def is_brute_force(ip_address):
    with get_conn() as conn:
        count = conn.execute("""
            SELECT COUNT(*) FROM logs
            WHERE ip_address=? AND status='FAILED'
              AND timestamp >= datetime('now', '-10 minutes')
        """, (ip_address,)).fetchone()[0]
    return count > 3


# ─── LOGIN (main app) ─────────────────────────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username   = request.form['username']
        password   = request.form['password']
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        alert_flag = detect_suspicious(username, password)

        with get_conn() as conn:
            result = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, password)
            ).fetchone()

        if result:
            log_attempt(username, 'SUCCESS', ip_address, user_agent, alert_flag)
            return redirect('/welcome')
        else:
            if is_brute_force(ip_address):
                alert_flag = "BRUTE_FORCE"
            log_attempt(username, 'FAILED', ip_address, user_agent, alert_flag)
            return render_template('login.html', error="Invalid Credentials ❌")

    return render_template('login.html')


# ─── WELCOME ──────────────────────────────────────────────────────────────────
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


# ─── NEW: DASHBOARD LOGIN ─────────────────────────────────────────────────────
@app.route('/dash-login', methods=['GET', 'POST'])
def dash_login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == DASH_USER and request.form['password'] == DASH_PASS:
            session['dash_auth'] = True
            return redirect('/dashboard')
        else:
            error = "Wrong credentials ❌"
    return render_template('dash_login.html', error=error)


@app.route('/dash-logout')
def dash_logout():
    session.pop('dash_auth', None)
    return redirect('/dash-login')


# ─── DASHBOARD ────────────────────────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    # NEW: protect dashboard with session check
    if not session.get('dash_auth'):
        return redirect('/dash-login')

    with get_conn() as conn:
        success_count = conn.execute("SELECT COUNT(*) FROM logs WHERE status='SUCCESS'").fetchone()[0]
        failed_count  = conn.execute("SELECT COUNT(*) FROM logs WHERE status='FAILED'").fetchone()[0]
        alert_count   = conn.execute("SELECT COUNT(*) FROM logs WHERE alert_flag='SQL_INJECTION_ATTEMPT'").fetchone()[0]
        brute_count   = conn.execute("SELECT COUNT(*) FROM logs WHERE alert_flag='BRUTE_FORCE'").fetchone()[0]

        top_ips = conn.execute("""
            SELECT ip_address, COUNT(*) as attempts
            FROM logs WHERE status='FAILED'
            GROUP BY ip_address ORDER BY attempts DESC LIMIT 5
        """).fetchall()

        # NEW: hourly activity — attempts grouped by hour
        hourly = conn.execute("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM logs GROUP BY hour ORDER BY hour
        """).fetchall()

        # NEW: top targeted usernames
        top_users = conn.execute("""
            SELECT username, COUNT(*) as count
            FROM logs WHERE status='FAILED'
            GROUP BY username ORDER BY count DESC LIMIT 7
        """).fetchall()

        logs = conn.execute("""
            SELECT id, username, status, ip_address, user_agent, timestamp, alert_flag
            FROM logs ORDER BY id DESC LIMIT 50
        """).fetchall()

    # Convert to plain lists for JSON in template
    hourly_labels  = [r[0] + ":00" for r in hourly]
    hourly_data    = [r[1] for r in hourly]
    user_labels    = [r[0] for r in top_users]
    user_data      = [r[1] for r in top_users]

    return render_template(
        'dashboard.html',
        success_count=success_count,
        failed_count=failed_count,
        alert_count=alert_count,
        brute_count=brute_count,
        top_ips=top_ips,
        logs=logs,
        hourly_labels=hourly_labels,
        hourly_data=hourly_data,
        user_labels=user_labels,
        user_data=user_data
    )


# ─── DOWNLOAD CSV ─────────────────────────────────────────────────────────────
@app.route('/download_csv')
def download_csv():
    if not session.get('dash_auth'):
        return redirect('/dash-login')

    with get_conn() as conn:
        logs = conn.execute("""
            SELECT id, username, status, ip_address, user_agent, timestamp, alert_flag
            FROM logs ORDER BY id DESC
        """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Status', 'IP Address', 'User Agent', 'Timestamp', 'Alert Flag'])
    for row in logs:
        writer.writerow(list(row))

    output.seek(0)
    filename = f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={filename}'})


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)