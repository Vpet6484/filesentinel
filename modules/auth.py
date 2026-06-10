from flask import Blueprint, render_template, request, redirect, session
from datetime import date, datetime
import bcrypt

from extensions import mysql, socketio
from config import Config

auth_bp = Blueprint("auth", __name__)


# =========================
# REALTIME HELPERS (FIXED)
# =========================

def emit_log(user_id, event, result, action, ip):

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT username FROM users WHERE user_id=%s",
        (user_id,)
    )

    row = cursor.fetchone()
    username = row[0] if row else "Unknown"

    socketio.emit(
        "log_event",
        {
            "user": username,
            "event": event,
            "result": result,
            "action": action,
            "ip": ip,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        namespace="/admin"   # ✅ IMPORTANT
    )


def emit_alert(user_id, severity, message):

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT username FROM users WHERE user_id=%s",
        (user_id,)
    )

    row = cursor.fetchone()
    username = row[0] if row else "Unknown"

    socketio.emit(
        "alert_event",
        {
            "user": username,
            "severity": severity,
            "message": message,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        namespace="/admin"   # ✅ IMPORTANT
    )


# =========================
# CLIENT IP
# =========================

def get_client_ip(request):

    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()

    return request.remote_addr


# =========================
# LOGIN PAGE
# =========================

@auth_bp.route("/")
def index():
    return render_template("public/index.html")


# =========================
# LOGIN LOGIC
# =========================

@auth_bp.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    ip = get_client_ip(request)

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()


    # =========================
    # USER NOT FOUND
    # =========================

    if not user:

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (NULL,NULL,'LOGIN','FAIL','Invalid username',%s)
        """, (ip,))

        db.commit()

        return render_template(
            "public/index.html",
            error="Invalid username or password"
        )


    user_id = user[0]
    password_hash = user[2]
    role = user[3]
    status = user[4]
    failed_attempts = user[5]
    last_failed_date = user[6]


    # =========================
    # TERMINATED ACCOUNT (NEW)
    # =========================

    if status == "terminated":

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,NULL,'LOGIN','DENIED',
            'Terminated account login attempt',%s)
        """, (user_id, ip))

        db.commit()

        emit_log(
            user_id,
            "LOGIN",
            "DENIED",
            "Terminated account login attempt",
            ip
        )

        return render_template(
            "public/index.html",
            error="Your account has been terminated. Contact admin."
        )


    # =========================
    # ACCOUNT BLOCKED
    # =========================

    if status == "blocked":

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,NULL,'LOGIN','BLOCKED','Blocked account login attempt',%s)
        """, (user_id, ip))

        db.commit()

        emit_log(
            user_id,
            "LOGIN",
            "BLOCKED",
            "Blocked account login attempt",
            ip
        )

        return render_template(
            "public/index.html",
            error="Your account is blocked. Contact admin."
        )


    today = date.today()


    # =========================
    # WRONG PASSWORD
    # =========================

    if not bcrypt.checkpw(password.encode(), password_hash.encode()):

        if last_failed_date != today:
            failed_attempts = 0

        failed_attempts += 1

        cursor.execute("""
            UPDATE users
            SET failed_attempts=%s, last_failed_date=%s
            WHERE user_id=%s
        """, (failed_attempts, today, user_id))


        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,NULL,'LOGIN','FAIL','Incorrect password attempt',%s)
        """, (user_id, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)
            VALUES (%s,'WARNING','Incorrect password entered',NULL)
        """, (user_id,))

        db.commit()


        emit_log(
            user_id,
            "LOGIN",
            "FAIL",
            "Incorrect password attempt",
            ip
        )

        emit_alert(
            user_id,
            "WARNING",
            "Incorrect password entered"
        )


        # =========================
        # BLOCK AFTER 3 FAILURES
        # =========================

        if failed_attempts >= 3 and role == "employee":

            cursor.execute("""
                UPDATE users
                SET status='blocked'
                WHERE user_id=%s
            """, (user_id,))

            cursor.execute("""
                INSERT INTO alerts
                (user_id, severity, message, session_id)
                VALUES (%s,'CRITICAL',
                'Employee blocked after 3 failed login attempts',NULL)
            """, (user_id,))

            db.commit()

            emit_alert(
                user_id,
                "CRITICAL",
                "Employee blocked after 3 failed login attempts"
            )


        return render_template(
            "public/index.html",
            error="Incorrect password"
        )


    # =========================
    # SUCCESS LOGIN
    # =========================

    cursor.execute("""
        UPDATE users
        SET failed_attempts=0
        WHERE user_id=%s
    """, (user_id,))


    cursor.execute("""
        INSERT INTO user_sessions
        (user_id, role, login_result, ip_address)
        VALUES (%s,%s,'SUCCESS',%s)
    """, (user_id, role, ip))

    session_id = cursor.lastrowid

    db.commit()


    session["user_id"] = user_id
    session["role"] = role
    session["session_id"] = session_id


    now = datetime.now().time()


    # =========================
    # WORK HOURS CHECK
    # =========================

    if Config.WORK_START <= now <= Config.WORK_END:

        action = "Login during working hours"

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'LOGIN','SUCCESS',%s,%s)
        """, (user_id, session_id, action, ip))

        db.commit()

        emit_log(user_id, "LOGIN", "SUCCESS", action, ip)


    else:

        action = "Login outside working hours"

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'LOGIN','SUCCESS',%s,%s)
        """, (user_id, session_id, action, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)
            VALUES (%s,'WARNING','Login outside working hours',%s)
        """, (user_id, session_id))

        db.commit()


        emit_log(user_id, "LOGIN", "SUCCESS", action, ip)

        emit_alert(
            user_id,
            "WARNING",
            "Login outside working hours"
        )


    return redirect(
        "/admin/home" if role == "admin" else "/employee/home"
    )



# =========================
# LOGOUT
# =========================

@auth_bp.route("/logout")
def logout():

    user_id = session.get("user_id")
    session_id = session.get("session_id")

    ip = get_client_ip(request)

    if user_id and session_id:

        db = mysql.get_db()
        cursor = db.cursor()


        cursor.execute("""
            UPDATE user_sessions
            SET logout_time=NOW()
            WHERE session_id=%s
        """, (session_id,))


        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'LOGOUT','SUCCESS','User logged out',%s)
        """, (user_id, session_id, ip))

        db.commit()


        emit_log(
            user_id,
            "LOGOUT",
            "SUCCESS",
            "User logged out",
            ip
        )


    session.clear()

    return redirect("/")
