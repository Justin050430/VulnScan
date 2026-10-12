"""
SQLi Attack Lab - a deliberately vulnerable demo application.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!  INTENTIONALLY INSECURE - LOCAL SECURITY TRAINING ONLY.   !!
!!  Runs on 127.0.0.1:5003 with a throwaway in-memory SQLite  !!
!!  database. Never deploy this file and never give it real   !!
!!  data. This is a target range, not a product.              !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Purpose: play the attacker against a tiny fake "ACME Corp" portal so
SQL injection is something you have DONE, not just read about.  Every
action prints the exact SQL statement the server executed, so you can
watch your input rewrite the query in real time.

Three missions (tracked on the home page):
  1. Log in as the administrator WITHOUT knowing the password.
  2. Extract the users table with a UNION query on the product search.
  3. Extract the lab flag from the secrets table.

The deliberately vulnerable lines are marked with:
      # VULNERABLE - string-concatenated SQL
"""
import sqlite3
import threading

from flask import Flask, redirect, request, session, url_for
from markupsafe import escape

app = Flask(__name__)
app.secret_key = "sqli-lab-demo-only"  # lab-only value, not a real secret

PORT = 5003
FLAG = "VULNSCAN{l4b_0wn3d_v1a_un10n_s3l3ct}"

# --------------------------------------------------------------- database
_lock = threading.Lock()
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.row_factory = sqlite3.Row

SEED_SQL = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT NOT NULL,
    secret_note TEXT
);
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    order_ref TEXT NOT NULL,
    customer TEXT NOT NULL,
    card_number TEXT NOT NULL,
    total REAL NOT NULL
);
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    value TEXT NOT NULL
);

INSERT INTO users (id, username, password, role, email, secret_note) VALUES
  (1, 'admin', 'Adm1n$3cret!', 'Administrator', 'admin@acme.lab',  'Vault passphrase: correct-horse-battery'),
  (2, 'alice', 'alice123',    'Customer',      'alice@acme.lab',  NULL),
  (3, 'bob',   'hunter2',     'Customer',      'bob@acme.lab',    NULL),
  (4, 'carol', 'qwerty123',   'Customer',      'carol@acme.lab',  NULL);

INSERT INTO products (id, name, description, price) VALUES
  (1, 'Laptop Pro 15',     '15-inch business laptop with 32 GB RAM',      1299.00),
  (2, 'Wireless Mouse',    'Ergonomic 2.4 GHz mouse',                      29.90),
  (3, 'Mechanical Keyboard','Cherry MX switches, RGB backlight',           99.50),
  (4, '27-inch Monitor',   '4K IPS display for the office',                349.00),
  (5, 'Gaming Headset',    '7.1 surround sound with mute boom',            79.00),
  (6, 'HD Webcam',         '1080p webcam with privacy shutter',            54.25);

INSERT INTO orders (id, order_ref, customer, card_number, total) VALUES
  (1, 'ACME-1001', 'alice', '4111 1111 1111 1111', 1328.90),
  (2, 'ACME-1002', 'bob',   '5500 0000 0000 0004',   29.90),
  (3, 'ACME-1003', 'carol', '3400 000000 00009',     99.50),
  (4, 'ACME-1004', 'alice', '6011 0000 0000 0004',  428.50);

INSERT INTO secrets (id, label, value) VALUES
  (1, 'Lab flag',        '{flag}'),
  (2, 'DB backup key',   'backup-key-8f2c-a91d'),
  (3, 'Deploy API token','sk_fake_51H9x2lmQ0fakeToken');
""".format(flag=FLAG)

STATE = {"query": "", "error": "", "rows": 0, "ran": False}
CHALLENGES = {"login_bypass": False, "union_dump": False, "flag": False}


def reset_db():
    with _lock:
        for table in ("users", "products", "orders", "secrets"):
            _conn.execute(f"DROP TABLE IF EXISTS {table}")
        _conn.executescript(SEED_SQL)
        _conn.commit()
    STATE.update({"query": "", "error": "", "rows": 0, "ran": False})
    for key in CHALLENGES:
        CHALLENGES[key] = False


def run_query(sql):
    """
    Execute one statement and remember it for the on-page console.

    NOTE: this helper is the lab's teaching device, not a safe query
    executor - the SQL it receives was built by concatenating user input.
    """
    with _lock:
        STATE["query"] = sql
        STATE["ran"] = True
        try:
            rows = _conn.execute(sql).fetchall()
        except sqlite3.Error as exc:
            STATE["error"] = (
                f"{type(exc).__module__}.{type(exc).__name__}: {exc}"
            )
            STATE["rows"] = 0
            return []
        STATE["error"] = ""
        STATE["rows"] = len(rows)

    flat = " ".join(str(value) for row in rows for value in row)
    if "union" in sql.lower() and rows:
        CHALLENGES["union_dump"] = True
    if FLAG in flat:
        CHALLENGES["flag"] = True
    return rows


# --------------------------------------------------------------- rendering
CSS = """
:root { --bg:#0a0f1e; --panel:#101830; --border:#1e2a4a; --text:#dbe4ff;
        --muted:#8b9bd0; --green:#34d399; --red:#f87171; --amber:#fbbf24; }
* { box-sizing:border-box; }
body { background:var(--bg); color:var(--text); margin:0;
       font-family:system-ui,'Segoe UI',sans-serif; }
a { color:#7dd3fc; text-decoration:none; }
a:hover { text-decoration:underline; }
header { padding:14px 22px; border-bottom:1px solid var(--border);
         display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
.logo { font-family:Consolas,monospace; font-weight:800; color:var(--green);
        letter-spacing:.5px; }
nav a { margin-right:14px; font-size:14px; }
.user-chip { margin-left:auto; font-size:12.5px; color:var(--muted); }
main { max-width:1000px; margin:22px auto 40px; padding:0 20px; }
h1 { font-size:22px; margin:14px 0 12px; }
h2 { font-size:16px; margin:0 0 10px; }
.card { background:var(--panel); border:1px solid var(--border);
        border-radius:10px; padding:16px 18px; margin-bottom:16px; }
.banner { background:#2a1010; border:1px solid #7f1d1d; color:#fca5a5;
          padding:8px 12px; border-radius:8px; font-size:12.5px; }
form { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin:6px 0; }
input { background:#05080f; border:1px solid var(--border); color:var(--text);
        border-radius:8px; padding:9px 11px; font-family:Consolas,monospace;
        font-size:13.5px; min-width:260px; }
button { background:var(--green); color:#06281c; border:0; border-radius:8px;
         padding:9px 16px; font-weight:700; cursor:pointer; font-size:13.5px; }
button:hover { filter:brightness(1.1); }
table { width:100%; border-collapse:collapse; margin-top:10px; }
th, td { border:1px solid var(--border); padding:6px 9px; font-size:13px;
         text-align:left; vertical-align:top; }
th { background:#0d1530; color:var(--muted); font-weight:600; }
.console { background:#05080f; border:1px solid var(--border);
           border-radius:10px; padding:12px 14px; margin-top:16px;
           font-family:Consolas,monospace; font-size:12.5px;
           white-space:pre-wrap; word-break:break-word; }
.console .lbl { color:var(--muted); }
.console .sql { color:var(--green); margin:4px 0; }
.ok { color:var(--green); } .bad { color:var(--red); }
.chip { display:inline-block; padding:4px 11px; border-radius:999px;
        border:1px solid var(--border); font-size:12.5px; margin:0 6px 6px 0;
        color:var(--muted); }
.chip.done { border-color:var(--green); color:var(--green); }
.muted { color:var(--muted); font-size:12.5px; }
details { margin-top:10px; border:1px dashed var(--border); border-radius:8px;
          padding:10px 12px; }
summary { cursor:pointer; color:var(--amber); font-weight:600; font-size:13.5px; }
code { background:#05080f; padding:1px 6px; border-radius:5px;
       color:var(--green); font-family:Consolas,monospace; font-size:12.5px; }
ol { margin:6px 0 0; padding-left:20px; font-size:13.5px; line-height:1.75; }
footer { text-align:center; color:var(--muted); font-size:12px;
         padding:16px; border-top:1px solid var(--border); }
"""

BANNER = ("⚠ INTENTIONALLY VULNERABLE lab — throwaway in-memory data, "
          "listens on 127.0.0.1 only, never deploy or reuse this code.")


def nav_html():
    links = [("/", "Home"), ("/login", "Login"), ("/search", "Product search"),
             ("/orders", "Order lookup"), ("/reset", "Reset lab")]
    if session.get("role") == "Administrator":
        links.insert(4, ("/admin", "Admin panel"))
    return "".join(f'<a href="{href}">{label}</a>' for href, label in links)


def console_html():
    if not STATE["ran"]:
        return ""
    error = STATE["error"]
    error_html = f'<span class="err bad">{escape(error)}</span>' if error \
        else '<span class="ok">none</span>'
    return f"""
    <div class="console">
      <div class="lbl">▼ SQL statement the server actually executed:</div>
      <div class="sql">{escape(STATE["query"])}</div>
      <div class="lbl">rows returned: {STATE["rows"]} &nbsp;·&nbsp; database error: {error_html}</div>
    </div>"""


def missions_html():
    labels = [
        ("login_bypass", "Mission 1 · Log in without the password"),
        ("union_dump", "Mission 2 · Extract users with UNION"),
        ("flag", "Mission 3 · Steal the lab flag"),
    ]
    chips = "".join(
        f'<span class="chip {"done" if CHALLENGES[key] else ""}">'
        f'{"✔" if CHALLENGES[key] else "○"} {escape(label)}</span>'
        for key, label in labels
    )
    return (f'<div class="card"><h2>Missions</h2><div>{chips}</div>'
            f'<div class="muted" style="margin-top:6px">completed '
            f'{sum(CHALLENGES.values())} / {len(CHALLENGES)}</div></div>')


def user_chip_html():
    if session.get("username"):
        return (f'<span class="user-chip">signed in as '
                f'<b>{escape(session["username"])}</b> '
                f'({escape(session.get("role", ""))})</span>')
    return '<span class="user-chip">not signed in</span>'


def page(title, body, show_console=False):
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>{escape(title)} · SQLi Lab</title><style>{CSS}</style></head>
<body>
<header><span class="logo">acme://sqli-lab</span><nav>{nav_html()}</nav>{user_chip_html()}</header>
<main>
  <div class="banner">{BANNER}</div>
  <h1>{escape(title)}</h1>
  {missions_html()}
  {body}
  {console_html() if show_console else ""}
</main>
<footer>VulnScan FYP training range · the vulnerable lines are marked in app.py</footer>
</body></html>"""


# --------------------------------------------------------------- routes
@app.get("/")
def home():
    body = f"""
    <div class="card">
      <h2>Welcome to the ACME Corp portal (test range)</h2>
      <p class="muted">This portal is built the way real vulnerable code was
      written in the 2000s: user input is stitched straight into SQL strings.
      Your job is to abuse that. The console shows the exact query after every
      action — use it as your feedback loop.</p>
      <ol>
        <li>Go to <a href="/login">Login</a> and get in as <code>admin</code>
            without knowing the password.</li>
        <li>Use <a href="/search?q=laptop">Product search</a> and a
            <code>UNION</code> query to dump the <code>users</code> table.</li>
        <li>Read the <code>secrets</code> table and capture the flag
            (<code>VULNSCAN{{...}}</code>).</li>
      </ol>
    </div>
    <div class="card">
      <h2>Pages</h2>
      <ul>
        <li><a href="/login">/login</a> — POST form · the classic authentication bypass</li>
        <li><a href="/search?q=laptop">/search?q=…</a> — GET · 3 columns · UNION territory</li>
        <li><a href="/orders?ref=ACME-1001">/orders?ref=…</a> — GET · 4 columns · other people's orders</li>
      </ul>
    </div>
    <details>
      <summary>Hint 1 — authentication bypass (click to reveal spoilers)</summary>
      <ol>
        <li>Read the login query the server runs:
            <code>SELECT * FROM users WHERE username = '…' AND password = '…'</code></li>
        <li>What if your username ends the string and comments out the rest?
            SQLite comments start with <code>--</code>.</li>
        <li>Try username <code>admin' --</code> and any password.</li>
        <li>Variation: <code>' OR 1=1 --</code> logs you in as the first row.</li>
      </ol>
    </details>
    <details>
      <summary>Hint 2 — UNION extraction on /search</summary>
      <ol>
        <li>Search a single quote <code>'</code> and read the DB error: it
            tells you the engine is SQLite. Errors you cause are findings too.</li>
        <li>The search selects <b>3 columns</b>. A UNION needs the same count —
            prove it by breaking it first:
            <code>' UNION SELECT 1,2 --</code>.</li>
        <li>Now aim it at a real table:
            <code>' UNION SELECT id, username, password FROM users --</code></li>
        <li>Curious what tables exist?
            <code>' UNION SELECT 1, name, sql FROM sqlite_master --</code></li>
      </ol>
    </details>
    <details>
      <summary>Hint 3 — the flag</summary>
      <ol>
        <li>You already know the trick. <code>secrets</code> has
            <code>id, label, value</code>:
            <code>' UNION SELECT id, label, value FROM secrets --</code></li>
      </ol>
    </details>
    """
    return page("Home", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    result = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE - user input concatenated straight into the SQL string
        sql = (f"SELECT * FROM users WHERE username = '{username}' "
               f"AND password = '{password}'")
        rows = run_query(sql)
        if rows:
            user = rows[0]
            session["username"] = user["username"]
            session["role"] = user["role"]
            if user["password"] != password:
                # the query matched even though the password was wrong
                CHALLENGES["login_bypass"] = True
            result = (f'<div class="card"><span class="ok">Login accepted as '
                      f'<b>{escape(user["username"])}</b> — role: '
                      f'{escape(user["role"])}</span>'
                      + ('<div class="muted" style="margin-top:6px">You were '
                         'let in without the real password. Mission 1 done — '
                         'head to the <a href="/admin">admin panel</a>.</div>'
                         if CHALLENGES["login_bypass"] else "")
                      + "</div>")
        else:
            result = ('<div class="card"><span class="bad">Invalid '
                      'credentials.</span><div class="muted" style="margin-top:6px">'
                      'Look at the SQL below — your input went into it '
                      'verbatim.</div></div>')
    body = f"""
    <div class="card">
      <h2>Sign in</h2>
      <form method="post" action="/login">
        <input name="username" placeholder="username" autocomplete="off"/>
        <input name="password" placeholder="password" type="text" autocomplete="off"/>
        <button type="submit">Sign in</button>
      </form>
      <div class="muted">Hint: usernames live in the users table, e.g.
      <code>alice</code>. The server-side query is printed after every
      attempt.</div>
    </div>
    {result}
    """
    return page("Login", body, show_console=request.method == "POST")


@app.get("/search")
def search():
    q = request.args.get("q")
    result = ""
    if q is not None:
        # VULNERABLE - search term concatenated into the WHERE clause
        sql = (f"SELECT id, name, description FROM products "
               f"WHERE name LIKE '%{q}%'")
        rows = run_query(sql)
        if STATE["error"]:
            result = ('<div class="card"><span class="bad">The database '
                      'rejected the query — read the error in the console.'
                      '</span><div class="muted" style="margin-top:6px">A DB '
                      'error you caused on purpose is a vulnerability finding '
                      'in itself.</div></div>')
        elif rows:
            cells = "".join(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    escape(row[0]), escape(row[1]), escape(row[2]))
                for row in rows
            )
            result = (f'<div class="card"><h2>Results ({len(rows)})</h2>'
                      f'<table><thead><tr><th>id</th><th>name</th>'
                      f'<th>description</th></tr></thead><tbody>{cells}'
                      f'</tbody></table></div>')
        else:
            result = '<div class="card">No products matched.</div>'
    body = f"""
    <div class="card">
      <h2>Product search</h2>
      <form method="get" action="/search">
        <input name="q" value="{escape(q) if q is not None else ''}"
               placeholder="e.g. laptop"/>
        <button type="submit">Search</button>
      </form>
      <div class="muted">Server-side query:
      <code>SELECT id, name, description FROM products WHERE name LIKE
      '%&lt;you&gt;%'</code> — three columns, remember that for UNION.</div>
    </div>
    {result}
    """
    return page("Product search", body, show_console=q is not None)


@app.get("/orders")
def orders():
    ref = request.args.get("ref")
    result = ""
    if ref is not None:
        # VULNERABLE - order reference concatenated into the WHERE clause
        sql = (f"SELECT id, order_ref, customer, card_number FROM orders "
               f"WHERE order_ref = '{ref}'")
        rows = run_query(sql)
        if STATE["error"]:
            result = ('<div class="card"><span class="bad">The database '
                      'rejected the query — check the console.</span></div>')
        elif rows:
            cells = "".join(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    escape(row[0]), escape(row[1]), escape(row[2]),
                    escape(row[3]))
                for row in rows
            )
            result = (f'<div class="card"><h2>Orders ({len(rows)})</h2>'
                      f'<table><thead><tr><th>id</th><th>order_ref</th>'
                      f'<th>customer</th><th>card_number</th></tr></thead>'
                      f'<tbody>{cells}</tbody></table></div>')
        else:
            result = '<div class="card">Order not found.</div>'
    body = f"""
    <div class="card">
      <h2>Order lookup</h2>
      <form method="get" action="/orders">
        <input name="ref" value="{escape(ref) if ref is not None else ''}"
               placeholder="e.g. ACME-1001"/>
        <button type="submit">Look up</button>
      </form>
      <div class="muted">Server-side query:
      <code>SELECT id, order_ref, customer, card_number FROM orders WHERE
      order_ref = '&lt;you&gt;'</code> — four columns this time.</div>
    </div>
    {result}
    <details>
      <summary>Hint — orders</summary>
      <ol>
        <li>No comment needed here: try
            <code>' OR '1'='1</code> and read every order at once.</li>
        <li>Or steal the users table in four columns:
            <code>' UNION SELECT id, 'x', username || ':' || password, '0'
            FROM users --</code></li>
      </ol>
    </details>
    """
    return page("Order lookup", body, show_console=ref is not None)


@app.get("/admin")
def admin():
    if session.get("role") != "Administrator":
        return page("Admin panel",
                    '<div class="card"><span class="bad">Access denied — '
                    'administrators only.</span></div>')
    rows = run_query(
        "SELECT id, username, password, role, email FROM users")
    cells = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(row[0]), escape(row[1]), escape(row[2]),
            escape(row[3]), escape(row[4]))
        for row in rows
    )
    body = f"""
    <div class="card">
      <h2>Admin panel</h2>
      <div class="muted">You are seeing this page because the login form let
      you in without the administrator password.</div>
      <table><thead><tr><th>id</th><th>username</th><th>password</th>
      <th>role</th><th>email</th></tr></thead><tbody>{cells}</tbody></table>
    </div>
    """
    return page("Admin panel", body, show_console=True)


@app.get("/reset")
def reset():
    reset_db()
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    reset_db()
    print()
    print("=" * 66)
    print("  SQLi Attack Lab   ->   http://127.0.0.1:5003/")
    print("  INTENTIONALLY VULNERABLE. Local training only.")
    print("  Missions: login bypass -> UNION extraction -> steal the flag")
    print("=" * 66)
    print()
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
