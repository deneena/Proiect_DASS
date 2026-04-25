from datetime import datetime, timezone
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db, close_db, init_db, log_action

app = Flask(__name__)
app.config["SECRET_KEY"] = "miau"

@app.cli.command("init-db")
def init_db_command():
    init_db()
    log_action(0, "initialized database", "database", 1)
    print("Initialized the database.")

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def login_required():
    if not session.get("user_id"):
        abort(401)

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
        password = request.form.get("password") or ""
        role = request.form.get("role") or ""

        if not email or not password or not role:
            flash("Email, password and role are required.")
            return render_template("register.html")

        pw_hash = password
        #pw_hash = generate_password_hash(password)

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
            flash(f"DB integrity error: {e}")
            return render_template("register.html")
        except Exception as e:
            flash(f"Unexpected error: {e}")
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

        query = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{password}'"
        print("LOGIN QUERY:", query)
        user = db.execute(query).fetchone()

        query_user = f"SELECT * FROM users WHERE email = '{email}'"
        print("LOGIN QUERY:", query_user)
        email_query = db.execute(query_user).fetchone()

        if not email_query:
            flash("Incorrect email..")
            return render_template("login.html")
        elif email_query and not user:
            flash("Incorrect password.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
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

        token = "1234"

        session["reset_email"] = email
        session["reset_token"] = token

        flash(f"Your token is: {token}")
        return redirect(url_for("confirm_reset"))

    return render_template("resetpw.html")

@app.route("/confirm-reset", methods=["GET", "POST"])
def confirm_reset():
    if request.method == "POST":
        token = request.form.get("token") or ""
        password1 = request.form.get("password1") or ""
        password2 = request.form.get("password2") or ""

        if token != session.get("reset_token"):
            flash("Invalid token.")
            return render_template("confirmreset.html")

        if password1 != password2:
            flash("Passwords do not match.")
            return render_template("confirmreset.html")

        email = session.get("reset_email")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user:
            flash("User not found.")
            return redirect(url_for("resetpw"))

        userid = user["id"]

        pw_hash = password1

        db.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (pw_hash, email)
        )
        db.commit()

        log_action(userid, "RESET_PASSWORD", "user", userid)

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
    user_id = user["id"]
    log_action(user_id, "logout", "user", user_id)
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()
    return render_template("profile.html", user=user)

if __name__ == '__main__':
    app.run()
