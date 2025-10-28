Vehicle Theft Complaint System — Interview Cheat Sheet

Overview

- Project: Vehicle Theft Online Complaint System
- Purpose: Allow citizens to register, submit vehicle-theft complaints, and let authorized officers/admins manage and update complaint status.
- Tech stack: Python (Flask), SQLite, Jinja2 templates, HTML/CSS, WTForms, Flask-WTF, Flask-Bcrypt.

Quick file map

- `app.py` — main Flask app, routes, forms, DB helpers, decorators
- `schema.sql` — database schema (users, complaints, indexes)
- `templates/` — HTML templates (home, login, register, dashboards, forms)
- `static/styles.css` — basic styling
- `requirements.txt` — Python dependencies

Important code patterns

Database helpers

- connect_db(): returns sqlite3.Connection with `row_factory=sqlite3.Row` and `PRAGMA foreign_keys = ON`.
- query_db(query, args=(), commit=False, one=False): parameterized queries to prevent SQL injection; commit support + rollback on error.

Auth & sessions

- Sessions store `user_id`, `username`, `is_admin` after successful login.
- `login_required` and `admin_required` decorators protect routes.

Forms & validation

- WTForms classes: `RegistrationForm`, `LoginForm`, `AdminRegistrationForm`, `ComplaintForm`.
- Server-side validation methods `validate_username`, `validate_email` using `query_db`.
- CSRF protection via Flask-WTF.

Security highlights

- Password hashing: bcrypt (use `bcrypt.generate_password_hash` and `bcrypt.check_password_hash`).
- CSRF protection: Flask-WTF automatically provides CSRF tokens in forms.
- Parameterized SQL queries prevent SQL injection.

Potential production hardening

- Use server-side session store (Redis) and set cookie flags: `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`.
- Use HTTPS and enforce HSTS.
- Add rate-limiting and account lockout for login.
- Escape user-submitted content in templates or sanitize before rendering to prevent XSS.

Key SQL

- Create indexes: `idx_complaints_user_id`, `idx_complaints_status`, `idx_users_username`, `idx_users_email`.
- Example: Get user complaints — `SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC`.

Top 15 interview topics to study

1. Flask routing & request lifecycle
2. Sessions and authentication in Flask
3. WTForms and server-side validation
4. SQL schema design and foreign keys
5. SQLite limitations and migration to Postgres
6. Password hashing and authentication best practices
7. CSRF/XSS/SQL Injection mitigations
8. Dockerizing a Flask app and production WSGI servers
9. Pagination and performance for dashboard lists
10. Caching strategies (Redis/memcached)
11. Logging, monitoring, health checks
12. Testing (pytest, Flask test client)
13. Accessibility (a11y) in templates
14. File uploads and secure storage (S3)
15. Role-based access control design

Quick commands (Windows PowerShell)

- Run app locally:

```powershell
python "app.py"
```

- Initialize DB (if script in app.py runs create_tables automatically on first run):

```powershell
python "app.py"
```

- Convert `CHEATSHEET.md` to PDF using Pandoc (if installed):

```powershell
pandoc CHEATSHEET.md -o CHEATSHEET.pdf --from markdown --pdf-engine wkhtmltopdf
```

- Or open `cheatsheet.html` in a browser and print to PDF.

Notes

- Focus on explaining design choices, trade-offs, and how you'd improve the app for production.
- Be ready to write a small code change during interview: e.g., add pagination, add an index, or secure a route.

Good luck — practice aloud and use this sheet as a quick reference!
