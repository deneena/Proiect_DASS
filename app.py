from datetime import datetime, timezone, timedelta
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db, close_db, init_db, log_action
import re
from flask_wtf import CSRFProtect
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SECURE = False, #pentru ca rulez local
    SESSION_COOKIE_SAMESITE = 'Lax',
    PERMANENT_SESSION_LIFETIME = timedelta(minutes = 10)
)

@app.cli.command("init-db")
def init_db_command():
    init_db()
    log_action(0, "initialized database", "database", 1)
    print("Initialized the database.")

@app.cli.command("migrate-db")
def migrate_db():
    db = get_db()
    try:
        db.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    except Exception as e:
        print("failed_attempts:", e)
    try:
        db.execute("ALTER TABLE users ADD COLUMN reset_token STRING")
    except Exception as e:
        print("reset_token:", e)
    try:
        db.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
    except Exception as e:
        print("reset_token_expiry:", e)
    db.commit()
    print("Migration done!")

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

@app.context_processor
def inject_now():
    return {
        "now": datetime.now(timezone.utc)
    }

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def login_required():
    if not session.get("user_id"):
        abort(401)

#verific daca parola e destul de sigura ca sa nu isi puna userii parole tip 1234 usor de ghicit
def password_complexity(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }

@app.get("/")
def home():
    user = current_user()
    if user:
        return redirect(url_for("profile"))
    return redirect(url_for("register"))

def is_manager(user):
    return user["role"].upper() == "MANAGER"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password1") or ""
        password2 = request.form.get("password2") or ""
        role = request.form.get("role") or ""

        if not email or not password or not password2 or not role:
            flash("Email, password and role are required.")
            return render_template("register.html")

        if password != password2:
            flash("Passwords must match.")
            return render_template("register.html")

        pw_check = password_complexity(password)
        if not pw_check["password_ok"]:
            flash("Password is too weak! Must have at least 8 characters, one digit, one symbol, one upper and one lower character.")
            return render_template("register.html")
        pw_hash = generate_password_hash(password)

        db = get_db()
        try:
            cursor = db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, pw_hash, role),
            )
            userid = cursor.lastrowid
            db.commit()
            log_action(userid, "new user added", "user", userid)
        except sqlite3.IntegrityError as e:
            flash(f"Unexpected error occurred.")
            return render_template("register.html")
        except Exception as e:
            flash(f"Unexpected error occurred.")
            return render_template("register.html")

        flash("Account created. Proceed to login.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email") or ""
        password = request.form.get("password") or ""

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user:
            flash("Incorrect credentials.")
            return render_template("login.html")

        if user["locked"]:
            flash("Account is locked.")
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            db.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                (user["id"],)
            )
            if user["failed_attempts"] + 1 >= 5:
                db.execute(
                    "UPDATE users SET locked = 1 WHERE id = ?",
                    (user["id"],)
                )
                flash("Account is locked after too many failed attempts.")
            else:
                flash("Incorrect credentials.")
            db.commit()
            return render_template("login.html")

        db.execute(
            "UPDATE users SET failed_attempts = 0  WHERE id = ?",
            (user["id"],)
        )
        db.commit()

        #in contextul acesta un user real ar trebui sa ceara de la un support sa ii fie deblocat contul
        #m-am gandit sa pun un timestamp pentru deblocare in users dar desi the average atacator nu ar incerca
        #sa atace un cont cu 5 incercari pe ora (sa zicem ca s-ar debloca dupa o ora), nu este exclus ca un user
        #sa fie targeted de cineva si mi se pare mai firesc sa apeleze la support ca sa isi schimbe parola

        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        flash(f"Logged in as: {user['email']}")
        log_action(user["id"], "login", "user", user["id"])
        return redirect(url_for("profile"))

    return render_template("login.html")

@app.route("/resetpw", methods=["GET", "POST"])
def resetpw():
    if request.method == "POST":
        email = request.form.get("email") or ""

        if not email:
            flash("Email is required.")
            return render_template("resetpw.html")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user:
            flash("Incorrect email.")
            return render_template("resetpw.html")

        token = secrets.token_urlsafe(32)
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        db.execute(
            "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
            (token, expiry, email)
        )
        db.commit()

        #intr-o aplicatie reala ar fi un mail cu un tokenm de resetare, eventual un link cu redirect
        flash(f"Your reset token is: {token}")
        return redirect(url_for("confirm_reset"))

    return render_template("resetpw.html")

@app.route("/confirm-reset", methods=["GET", "POST"])
def confirm_reset():
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        password1 = request.form.get("password1") or ""
        password2 = request.form.get("password2") or ""

        db = get_db()

        # if token != session.get("reset_token"):
        #     flash("Invalid token.")
        #     return render_template("confirmreset.html")

        if password1 != password2:
            flash("Passwords do not match.")
            return render_template("confirmreset.html")

        user = db.execute(
            "SELECT * FROM users WHERE reset_token = ?",
            (token,)
        ).fetchone()
        if not user:
            flash("Invalid token.")
            return render_template("confirmreset.html")
        expiry = datetime.fromisoformat(user["reset_token_expiry"])
        if expiry < datetime.now(timezone.utc):
            flash("Token expired.")
            return render_template("confirmreset.html")

        email = user["email"]
        userid = user["id"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user:
            flash("User not found.")
            return redirect(url_for("resetpw"))

        userid = user["id"]

        pw_check = password_complexity(password1)
        if not pw_check["password_ok"]:
            flash("Password is too weak!")
            return render_template("confirmreset.html")
        pw_hash = generate_password_hash(password1)

        db.execute(
            """
            UPDATE users 
            SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL
            WHERE id = ?
            """,
            (pw_hash, userid)
        )
        db.commit()
        log_action(userid, "reset pw", "user", userid)

        session.pop("reset_token", None)
        session.pop("reset_email", None)

        flash("Password successfully changed.")
        return redirect(url_for("login"))

    return render_template("confirmreset.html")

@app.route("/tickets/create", methods=["GET", "POST"])
def create_ticket():
    login_required()
    user = current_user()

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        severity = request.form.get("severity")

        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO tickets (title, description, severity, status, owner_id)
            VALUES (?, ?, ?, 'OPEN', ?)
            """,
            (title, description, severity, user["id"])
        )
        ticket_id = cursor.lastrowid
        db.commit()

        log_action(user["id"], "created ticket", "ticket", ticket_id)
        return redirect(url_for("list_tickets"))

    return render_template("createticket.html")

@app.route("/tickets")
def list_tickets():
    login_required()
    user = current_user()
    db = get_db()

    search = request.args.get("search", "")
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")

    query = """
    SELECT tickets.*, users.email AS owner_email
    FROM tickets
    JOIN users ON tickets.owner_id = users.id
    WHERE 1=1
    """
    params = []

    if not is_manager(user):
        query += " AND owner_id = ?"
        params.append(user["id"])

    if search:
        query += " AND (title LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if status:
        query += " AND status = ?"
        params.append(status)

    tickets = db.execute(query, params).fetchall()
    return render_template("tickets.html", tickets=tickets)

@app.route("/tickets/<int:id>/edit", methods=["GET", "POST"])
def edit_ticket(id):
    login_required()
    user = current_user()
    db = get_db()

    ticket = db.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (id,)
    ).fetchone()

    if not ticket:
        abort(404)

    if not is_manager(user) and ticket["owner_id"] != user["id"]:
        abort(403)

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        severity = request.form.get("severity")

        if is_manager(user):
            status = request.form.get("status")
            db.execute(
                """
                UPDATE tickets
                SET title=?, description=?, severity=?, status=?
                WHERE id=?
                """,
                (title, description, severity, status, id)
            )
        else:
            db.execute(
                """
                UPDATE tickets
                SET title=?, description=?, severity=?
                WHERE id=?
                """,
                (title, description, severity, id)
            )

        db.commit()
        log_action(user["id"], "edited ticket", "ticket", id)

        return redirect(url_for("list_tickets"))
    return render_template("editticket.html", ticket=ticket, user=user)

@app.route("/audit")
def audit_logs():
    login_required()
    user = current_user()

    if not is_manager(user):
        abort(403)

    db = get_db()
    logs = db.execute("SELECT * FROM audit_logs").fetchall()

    return render_template("auditlogs.html", logs=logs)

@app.post("/logout")
def logout():
    user = current_user()
    if user:
        log_action(user["id"], "logout", "user", user["id"])
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()
    return render_template("profile.html", user=user)

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    #in productie nu ar trebui sa fie cu unsafe inline dar nu reusesc sa fac scriptul sa treaca deb csp
    #si practic pot sa il fac safe daca elimin scriptul adica scot butonul de show password
    #dar ca sa fie mai clar demoul cu parolele il voi pastra, merge bine cu csp safe atata ca nu imi incarca scriptul
    return response

if __name__ == '__main__':
    app.run()
