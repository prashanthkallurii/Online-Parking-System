"""
Online Parking System (Flask, SQLite, single file)
- Customer + Admin portals
- Role-based auth, booking engine with time-window conflict checks
- Minimal UI (Bootstrap CDN)

How to run (after saving as app.py):
  pip install flask werkzeug
  python app.py
Then open http://127.0.0.1:5000

Default admin login: admin@example.com / admin123
"""

from __future__ import annotations
from flask import Flask, g, render_template_string, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

APP_TITLE = "Online Parking System"
DB_PATH = os.path.join(os.path.dirname(__file__), "parking.db")

app = Flask(__name__)
app.secret_key = "change-this-in-production"

# ---------------------------- DB Helpers ---------------------------- #

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_number INTEGER NOT NULL UNIQUE,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    slot_id INTEGER NOT NULL,
    start_time TEXT NOT NULL, -- ISO format
    end_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'booked', -- booked | cancelled | completed
    amount REAL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(slot_id) REFERENCES slots(id)
);
"""

ADMIN_SEED = {
    "name": "Admin",
    "email": "admin@example.com",
    "password": "admin123",
}


def init_db(seed_slots:int=20):
    db = get_db()
    db.executescript(SCHEMA_SQL)
    # Seed admin if missing
    cur = db.execute("SELECT COUNT(*) AS c FROM users WHERE email=?", (ADMIN_SEED["email"],))
    if cur.fetchone()["c"] == 0:
        db.execute(
            "INSERT INTO users(name,email,password_hash,is_admin) VALUES (?,?,?,1)",
            (ADMIN_SEED["name"], ADMIN_SEED["email"], generate_password_hash(ADMIN_SEED["password"]))
        )
        db.commit()
    # Seed slots if empty
    cur = db.execute("SELECT COUNT(*) AS c FROM slots")
    if cur.fetchone()["c"] == 0:
        for n in range(1, seed_slots+1):
            db.execute("INSERT INTO slots(slot_number,is_active) VALUES (?,1)", (n,))
        db.commit()

# Ensure DB exists before first request
@app.before_first_request
def ensure_db():
    init_db()

# ---------------------------- Auth Utils ---------------------------- #

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return user

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["is_admin"] != 1:
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

# ---------------------------- Templates ---------------------------- #

BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title or app_title }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding-top: 4.5rem; }
    .brand { font-weight: 700; }
    .card { border-radius: 1rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand brand" href="{{ url_for('index') }}">🚗 {{ app_title }}</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarsExample" aria-controls="navbarsExample" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarsExample">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        {% if user %}
          {% if user.is_admin %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_dashboard') }}">Admin Dashboard</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_slots') }}">Manage Slots</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('admin_bookings') }}">All Bookings</a></li>
          {% else %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('customer_search') }}">Find Slot</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('customer_bookings') }}">My Bookings</a></li>
          {% endif %}
        {% endif %}
      </ul>
      <ul class="navbar-nav">
        {% if user %}
          <li class="nav-item"><span class="navbar-text me-2">Hi, {{ user.name }}{% if user.is_admin %} (Admin){% endif %}</span></li>
          <li class="nav-item"><a class="btn btn-outline-light btn-sm" href="{{ url_for('logout') }}">Logout</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
          <li class="nav-item"><a class="btn btn-primary btn-sm" href="{{ url_for('register') }}">Sign up</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<main class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">{{ message }}
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

HOME_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="row g-3">
  <div class="col-lg-7">
    <div class="card p-4 shadow-sm">
      <h3 class="mb-3">Welcome!</h3>
      <p>Book parking slots with time-window based availability. Admins can manage slots and monitor bookings.</p>
      <div class="d-flex gap-2">
        {% if not user %}
          <a class="btn btn-primary" href="{{ url_for('register') }}">Create Customer Account</a>
          <a class="btn btn-outline-secondary" href="{{ url_for('login') }}">Log in</a>
        {% else %}
          {% if user.is_admin %}
            <a class="btn btn-primary" href="{{ url_for('admin_dashboard') }}">Go to Admin Dashboard</a>
          {% else %}
            <a class="btn btn-primary" href="{{ url_for('customer_search') }}">Find a Slot</a>
          {% endif %}
        {% endif %}
      </div>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card p-4 shadow-sm">
      <h5 class="mb-3">Quick Stats</h5>
      <ul class="list-group">
        <li class="list-group-item d-flex justify-content-between"><span>Active Slots</span><span class="badge bg-success">{{ stats.active_slots }}</span></li>
        <li class="list-group-item d-flex justify-content-between"><span>Total Bookings</span><span class="badge bg-primary">{{ stats.total_bookings }}</span></li>
        <li class="list-group-item d-flex justify-content-between"><span>Upcoming Bookings</span><span class="badge bg-info">{{ stats.upcoming }}</span></li>
      </ul>
    </div>
  </div>
</div>
{% endblock %}
"""

AUTH_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card p-4 shadow-sm">
      <h3 class="mb-3">{{ heading }}</h3>
      <form method="post">
        {% if register %}
        <div class="mb-3">
          <label class="form-label">Name</label>
          <input name="name" class="form-control" required>
        </div>
        {% endif %}
        <div class="mb-3">
          <label class="form-label">Email</label>
          <input type="email" name="email" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <button class="btn btn-primary w-100">{{ cta }}</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""

CUSTOMER_SEARCH_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="card p-4 shadow-sm">
  <h3 class="mb-3">Find Available Slots</h3>
  <form class="row g-3" method="get">
    <div class="col-md-4">
      <label class="form-label">Start Time</label>
      <input class="form-control" type="datetime-local" name="start" value="{{ request.args.get('start','') }}" required>
    </div>
    <div class="col-md-4">
      <label class="form-label">End Time</label>
      <input class="form-control" type="datetime-local" name="end" value="{{ request.args.get('end','') }}" required>
    </div>
    <div class="col-md-4 align-self-end">
      <button class="btn btn-primary">Search</button>
    </div>
  </form>

  {% if slots is not none %}
    <hr>
    <h5>Available Slots ({{ slots|length }})</h5>
    <div class="table-responsive">
      <table class="table table-striped align-middle">
        <thead><tr><th>#</th><th>Status</th><th></th></tr></thead>
        <tbody>
          {% for s in slots %}
          <tr>
            <td>Slot {{ s.slot_number }}</td>
            <td>{% if s.is_active %}<span class="badge bg-success">Active</span>{% else %}<span class="badge bg-secondary">Inactive</span>{% endif %}</td>
            <td>
              {% if s.is_active %}
                <a class="btn btn-sm btn-primary" href="{{ url_for('customer_book', slot_id=s.id, start=request.args.get('start'), end=request.args.get('end')) }}">Book</a>
              {% else %}
                <button class="btn btn-sm btn-secondary" disabled>Unavailable</button>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  {% endif %}
</div>
{% endblock %}
"""

CUSTOMER_BOOKINGS_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="card p-4 shadow-sm">
  <h3 class="mb-3">My Bookings</h3>
  <div class="table-responsive">
    <table class="table table-striped align-middle">
      <thead><tr><th>ID</th><th>Slot</th><th>Start</th><th>End</th><th>Status</th><th>Amount</th><th></th></tr></thead>
      <tbody>
        {% for b in bookings %}
        <tr>
          <td>{{ b.id }}</td>
          <td>{{ b.slot_number }}</td>
          <td>{{ b.start_time }}</td>
          <td>{{ b.end_time }}</td>
          <td><span class="badge {% if b.status=='booked' %}bg-primary{% elif b.status=='cancelled' %}bg-secondary{% else %}bg-success{% endif %}">{{ b.status }}</span></td>
          <td>₹{{ '%.2f'|format(b.amount or 0) }}</td>
          <td>
            {% if b.status=='booked' %}
              <a class="btn btn-sm btn-outline-danger" href="{{ url_for('customer_cancel', booking_id=b.id) }}">Cancel</a>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

ADMIN_DASHBOARD_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="row g-3">
  <div class="col-md-6">
    <div class="card p-4 shadow-sm">
      <h4 class="mb-3">Overview</h4>
      <ul class="list-group">
        <li class="list-group-item d-flex justify-content-between"><span>Total Slots</span><span class="badge bg-dark">{{ stats.total_slots }}</span></li>
        <li class="list-group-item d-flex justify-content-between"><span>Active Slots</span><span class="badge bg-success">{{ stats.active_slots }}</span></li>
        <li class="list-group-item d-flex justify-content-between"><span>Total Users</span><span class="badge bg-secondary">{{ stats.users }}</span></li>
        <li class="list-group-item d-flex justify-content-between"><span>Total Bookings</span><span class="badge bg-primary">{{ stats.total_bookings }}</span></li>
      </ul>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card p-4 shadow-sm">
      <h4 class="mb-3">Quick Actions</h4>
      <form method="post" action="{{ url_for('admin_set_slots') }}" class="row g-3">
        <div class="col-8">
          <label class="form-label">Reset number of slots (recreates slots 1..N)</label>
          <input class="form-control" type="number" name="count" min="1" value="{{ stats.total_slots or 20 }}" required>
        </div>
        <div class="col-4 align-self-end">
          <button class="btn btn-warning w-100">Apply</button>
        </div>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""

ADMIN_SLOTS_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="card p-4 shadow-sm">
  <h3 class="mb-3">Manage Slots</h3>
  <div class="table-responsive">
    <table class="table table-striped align-middle">
      <thead><tr><th>#</th><th>Active</th><th></th></tr></thead>
      <tbody>
        {% for s in slots %}
        <tr>
          <td>Slot {{ s.slot_number }}</td>
          <td>{% if s.is_active %}<span class="badge bg-success">Yes</span>{% else %}<span class="badge bg-secondary">No</span>{% endif %}</td>
          <td>
            {% if s.is_active %}
              <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('admin_toggle_slot', slot_id=s.id) }}">Deactivate</a>
            {% else %}
              <a class="btn btn-sm btn-outline-success" href="{{ url_for('admin_toggle_slot', slot_id=s.id) }}">Activate</a>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

ADMIN_BOOKINGS_HTML = """
{% extends 'base.html' %}
{% block content %}
<div class="card p-4 shadow-sm">
  <h3 class="mb-3">All Bookings</h3>
  <div class="table-responsive">
    <table class="table table-striped align-middle">
      <thead><tr><th>ID</th><th>User</th><th>Slot</th><th>Start</th><th>End</th><th>Status</th><th>Amount</th></tr></thead>
      <tbody>
        {% for b in bookings %}
        <tr>
          <td>{{ b.id }}</td>
          <td>{{ b.user_name }} ({{ b.user_email }})</td>
          <td>{{ b.slot_number }}</td>
          <td>{{ b.start_time }}</td>
          <td>{{ b.end_time }}</td>
          <td>{{ b.status }}</td>
          <td>₹{{ '%.2f'|format(b.amount or 0) }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

# ---------------------------- Utility Logic ---------------------------- #

def iso(dt:datetime) -> str:
    return dt.strftime('%Y-%m-%d %H:%M')

@app.context_processor
def inject_globals():
    u = current_user()
    # Cast sqlite Row to a simple object with attribute access for Jinja convenience
    class U: pass
    user_obj = None
    if u:
        user_obj = type("UserObj", (), dict(u))
    return dict(app_title=APP_TITLE, user=user_obj)

# ---------------------------- Routes ---------------------------- #

@app.route('/')
def index():
    db = get_db()
    stats = {
        "active_slots": db.execute("SELECT COUNT(*) c FROM slots WHERE is_active=1").fetchone()["c"],
        "total_bookings": db.execute("SELECT COUNT(*) c FROM bookings").fetchone()["c"],
        "upcoming": db.execute("SELECT COUNT(*) c FROM bookings WHERE status='booked' AND end_time >= ?", (iso(datetime.now()),)).fetchone()["c"],
    }
    return render_template_string(HOME_HTML, stats=stats)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        pw = request.form['password']
        db = get_db()
        try:
            db.execute("INSERT INTO users(name,email,password_hash) VALUES (?,?,?)", (name, email, generate_password_hash(pw)))
            db.commit()
            flash("Registered! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "danger")
    return render_template_string(AUTH_HTML, heading="Create Account", cta="Sign up", register=True)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        pw = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user['password_hash'], pw):
            session['user_id'] = user['id']
            flash("Welcome back!", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials.", "danger")
    return render_template_string(AUTH_HTML, heading="Log in", cta="Log in", register=False)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('index'))

# ---------------------------- Customer ---------------------------- #

@app.route('/customer/search')
@login_required
def customer_search():
    user = current_user()
    if user['is_admin']:
        flash("Admins cannot book. Use a customer account.", "warning")
        return redirect(url_for('index'))

    slots = None
    start = request.args.get('start')
    end = request.args.get('end')
    if start and end:
        try:
            start_dt = datetime.fromisoformat(start)
            end_dt = datetime.fromisoformat(end)
            if end_dt <= start_dt:
                raise ValueError("End time must be after start time")
            db = get_db()
            # Find slots that are active and NOT overlapping with existing booked bookings
            slots = db.execute(
                """
                SELECT s.* FROM slots s
                WHERE s.is_active=1 AND NOT EXISTS (
                    SELECT 1 FROM bookings b
                    WHERE b.slot_id = s.id AND b.status='booked'
                      AND NOT (b.end_time <= ? OR b.start_time >= ?)
                )
                ORDER BY s.slot_number
                """,
                (start, end)
            ).fetchall()
        except Exception as e:
            flash(f"Invalid date/time: {e}", "danger")
    return render_template_string(CUSTOMER_SEARCH_HTML, slots=slots)

@app.route('/customer/book/<int:slot_id>')
@login_required
def customer_book(slot_id:int):
    user = current_user()
    if user['is_admin']:
        flash("Admins cannot book.", "warning")
        return redirect(url_for('index'))

    start = request.args.get('start')
    end = request.args.get('end')
    if not (start and end):
        flash("Provide start and end time via search.", "warning")
        return redirect(url_for('customer_search'))

    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
        if end_dt <= start_dt:
            raise ValueError("End must be after start")
    except Exception as e:
        flash(f"Invalid date/time: {e}", "danger")
        return redirect(url_for('customer_search'))

    db = get_db()
    # Check slot exists & active
    s = db.execute("SELECT * FROM slots WHERE id=?", (slot_id,)).fetchone()
    if not s or s['is_active'] != 1:
        flash("Slot not available.", "danger")
        return redirect(url_for('customer_search', start=start, end=end))

    # Check conflicts
    conflict = db.execute(
        """
        SELECT 1 FROM bookings b
        WHERE b.slot_id=? AND b.status='booked'
          AND NOT (b.end_time <= ? OR b.start_time >= ?)
        LIMIT 1
        """,
        (slot_id, start, end)
    ).fetchone()
    if conflict:
        flash("Sorry, this slot was just booked.", "warning")
        return redirect(url_for('customer_search', start=start, end=end))

    # Simple pricing: ₹20 per hour, rounded up to next hour
    duration_hours = max(1, int(((end_dt - start_dt).total_seconds() + 3599)//3600))
    amount = 20 * duration_hours

    db.execute(
        "INSERT INTO bookings(user_id,slot_id,start_time,end_time,status,amount,created_at) VALUES (?,?,?,?,?,?,?)",
        (user['id'], slot_id, start, end, 'booked', amount, iso(datetime.now()))
    )
    db.commit()
    flash(f"Booked Slot {s['slot_number']} for ₹{amount}.", "success")
    return redirect(url_for('customer_bookings'))

@app.route('/customer/bookings')
@login_required
def customer_bookings():
    user = current_user()
    db = get_db()
    bookings = db.execute(
        """
        SELECT b.*, s.slot_number FROM bookings b
        JOIN slots s ON s.id=b.slot_id
        WHERE b.user_id=?
        ORDER BY b.created_at DESC
        """,
        (user['id'],)
    ).fetchall()
    return render_template_string(CUSTOMER_BOOKINGS_HTML, bookings=bookings)

@app.route('/customer/cancel/<int:booking_id>')
@login_required
def customer_cancel(booking_id:int):
    user = current_user()
    db = get_db()
    b = db.execute("SELECT * FROM bookings WHERE id=? AND user_id=?", (booking_id, user['id'])).fetchone()
    if not b:
        flash("Booking not found.", "danger")
        return redirect(url_for('customer_bookings'))
    if b['status'] != 'booked':
        flash("Only active bookings can be cancelled.", "warning")
        return redirect(url_for('customer_bookings'))
    db.execute("UPDATE bookings SET status='cancelled' WHERE id=?", (booking_id,))
    db.commit()
    flash("Booking cancelled.", "info")
    return redirect(url_for('customer_bookings'))

# ---------------------------- Admin ---------------------------- #

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        "total_slots": db.execute("SELECT COUNT(*) c FROM slots").fetchone()["c"],
        "active_slots": db.execute("SELECT COUNT(*) c FROM slots WHERE is_active=1").fetchone()["c"],
        "users": db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "total_bookings": db.execute("SELECT COUNT(*) c FROM bookings").fetchone()["c"],
    }
    return render_template_string(ADMIN_DASHBOARD_HTML, stats=stats)

@app.route('/admin/slots')
@admin_required
def admin_slots():
    db = get_db()
    slots = db.execute("SELECT * FROM slots ORDER BY slot_number").fetchall()
    return render_template_string(ADMIN_SLOTS_HTML, slots=slots)

@app.route('/admin/slots/toggle/<int:slot_id>')
@admin_required
def admin_toggle_slot(slot_id:int):
    db = get_db()
    s = db.execute("SELECT * FROM slots WHERE id=?", (slot_id,)).fetchone()
    if not s:
        flash("Slot not found.", "danger")
        return redirect(url_for('admin_slots'))
    new = 0 if s['is_active'] == 1 else 1
    db.execute("UPDATE slots SET is_active=? WHERE id=?", (new, slot_id))
    db.commit()
    flash(f"Slot {s['slot_number']} set to {'Active' if new==1 else 'Inactive'}.", "info")
    return redirect(url_for('admin_slots'))

@app.route('/admin/bookings')
@admin_required
def admin_bookings():
    db = get_db()
    bookings = db.execute(
        """
        SELECT b.*, s.slot_number, u.name AS user_name, u.email AS user_email
        FROM bookings b
        JOIN slots s ON s.id=b.slot_id
        JOIN users u ON u.id=b.user_id
        ORDER BY b.created_at DESC
        """
    ).fetchall()
    return render_template_string(ADMIN_BOOKINGS_HTML, bookings=bookings)

@app.route('/admin/set-slots', methods=['POST'])
@admin_required
def admin_set_slots():
    try:
        count = int(request.form.get('count', '0'))
        if count < 1 or count > 10000:
            raise ValueError("Count must be between 1 and 10000")
    except Exception as e:
        flash(f"Invalid count: {e}", "danger")
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute("DELETE FROM slots")
    db.execute("DELETE FROM sqlite_sequence WHERE name='slots'")
    for n in range(1, count+1):
        db.execute("INSERT INTO slots(slot_number,is_active) VALUES (?,1)", (n,))
    db.commit()
    flash(f"Recreated {count} slots.", "success")
    return redirect(url_for('admin_slots'))

# ---------------------------- Template Loader ---------------------------- #
# Serve our inline strings as if they were templates
from jinja2 import DictLoader
app.jinja_loader = DictLoader({
    'base.html': BASE_HTML,
    'home.html': HOME_HTML,
})

# Root route uses render_template_string already; others too.

if __name__ == '__main__':
    app.run(debug=True)
