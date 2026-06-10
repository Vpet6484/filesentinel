from flask import (
    Blueprint, render_template, session,
    redirect, send_file, request, current_app
)
import json   # add at top

from modules.file_converter import convert_to_pdf

from modules.virus_scan import scan_file
from modules.file_watermark import watermark_file
from modules.watermark import generate_watermark, hash_watermark


from extensions import mysql, socketio

from datetime import datetime, timedelta

import os
import uuid


# =========================
# BLUEPRINT
# =========================

employee_bp = Blueprint(
    "employee",
    __name__,
    url_prefix="/employee"
)


# =========================
# FILE VALIDATION
# =========================

ALLOWED_EXTENSIONS = {
    "pdf",
    "docx",
    "xlsx"
}



def allowed_file(filename):

    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# =========================
# REALTIME HELPERS (FIXED ✅)
# =========================

def get_username(user_id):

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT username FROM users WHERE user_id=%s",
        (user_id,)
    )

    row = cursor.fetchone()

    return row[0] if row else "Unknown"


def emit_log(user_id, event, result, action, ip):

    username = get_username(user_id)

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
        namespace="/admin"   # ✅ REQUIRED
    )


def emit_alert(user_id, severity, message):

    username = get_username(user_id)

    socketio.emit(
        "alert_event",
        {
            "user": username,
            "severity": severity,
            "message": message,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        namespace="/admin"   # ✅ REQUIRED
    )


# =========================
# CLIENT IP
# =========================

def get_client_ip():

    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()

    return request.remote_addr


# =========================
# EMPLOYEE SECURITY
# =========================

@employee_bp.before_request
def employee_security_guard():

    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "employee":
        session.clear()
        return redirect("/")

    db = mysql.get_db()
    cursor = db.cursor()

    # Only check status now (no terminated column)
    cursor.execute(
        "SELECT status FROM users WHERE user_id=%s",
        (session["user_id"],)
    )

    row = cursor.fetchone()

    if not row:
        session.clear()
        return redirect("/")

    status = row[0]

    # Kick blocked or terminated user immediately
    if status in ("blocked", "terminated"):
        session.clear()
        return redirect("/")



def block_and_logout(message):

    safe_msg = json.dumps(message)

    return f"""
    <script>
        alert({safe_msg});
        window.location.href = "/logout";
    </script>
    """


# =========================
# INSIDER DETECTION
# =========================
INSIDER_RULES = {
    "read": {
        "limit": 5,
        "minutes": 5,
        "message": "Insider threat: Excessive file reads"
    },
    "download": {
        "limit": 3,
        "minutes": 5,
        "message": "Insider threat: Excessive downloads"
    },
    "delete": {
        "limit": 3,
        "minutes": 5,
        "message": "Insider threat: Suspicious deletions"
    }
}
ACTION_ALERTS = {
    "read": {
        "normal": ("INFO", "File read"),
        "critical": "Insider threat: Excessive file reads"
    },
    "download": {
        "normal": ("WARNING", "File downloaded"),
        "critical": "Insider threat: Excessive downloads"
    },
    "delete": {
        "normal": ("WARNING", "File deleted"),
        "critical": "Insider threat: Suspicious deletions"
    }
}

def track_and_check_insider(user_id, action, session_id):
    rule = INSIDER_RULES.get(action)
    if not rule:
        return False

    db = mysql.get_db()
    cursor = db.cursor()

    # Insert activity
    cursor.execute("""
        INSERT INTO activity_tracker (user_id, action)
        VALUES (%s, %s)
    """, (user_id, action))

    window_start = datetime.now() - timedelta(minutes=rule["minutes"])

    cursor.execute("""
        SELECT COUNT(*)
        FROM activity_tracker
        WHERE user_id=%s
          AND action=%s
          AND timestamp >= %s
    """, (user_id, action, window_start))

    count = cursor.fetchone()[0]

    if count >= rule["limit"]:
        # BLOCK USER
        cursor.execute("""
            UPDATE users
            SET status='blocked'
            WHERE user_id=%s
        """, (user_id,))

        cursor.execute("""
            INSERT INTO alerts (user_id, severity, message, session_id)
            VALUES (%s, 'CRITICAL', %s, %s)
        """, (user_id, rule["message"], session_id))

        

        db.commit()
        return True

    db.commit()
    return False

def enforce_insider_policy(user_id, action, session_id):

    config = ACTION_ALERTS.get(action)
    if not config:
        return False

    db = mysql.get_db()
    cursor = db.cursor()

    # NORMAL ALERT
    level, message = config["normal"]

    cursor.execute("""
        INSERT INTO alerts (user_id, severity, message, session_id)
        VALUES (%s,%s,%s,%s)
    """, (user_id, level, message, session_id))

    db.commit()
    emit_alert(user_id, level, message)

    # INSIDER CHECK
    if track_and_check_insider(user_id, action, session_id):

        critical_msg = config["critical"]

        cursor.execute("""
            INSERT INTO alerts (user_id, severity, message, session_id)
            VALUES (%s,'CRITICAL',%s,%s)
        """, (user_id, critical_msg, session_id))

        db.commit()
        emit_alert(user_id, "CRITICAL", critical_msg)

        session.clear()
        return True

    return False



# =========================
# HOME
# =========================

@employee_bp.route("/home")
def employee_home():
    return render_template("employee/home.html")


# =========================
# FILE LIST
# =========================

@employee_bp.route("/files")
def employee_files():

    user_id = session["user_id"]
    sid = session.get("session_id")
    ip = get_client_ip()

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            f.file_token,
            f.filename,
            p.can_read,
            p.can_download,
            p.can_delete
        FROM files f
        JOIN file_permissions p ON f.file_id = p.file_id
        WHERE p.user_id=%s AND f.is_deleted=0
    """, (user_id,))

    files = cursor.fetchall()

    action = f"view_file_list by_user={user_id}"


    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'VIEW','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    db.commit()

    emit_log(user_id, "VIEW", "SUCCESS", action, ip)

    return render_template("employee/files.html", files=files)




# =========================
# READ FILE
# =========================

@employee_bp.route("/read/<string:token>")
def read_file(token):

    user_id = session["user_id"]
    sid = session.get("session_id")
    ip = get_client_ip()

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            f.filename,
            f.stored_path,
            p.can_read
        FROM files f
        JOIN file_permissions p ON f.file_id = p.file_id
        WHERE f.file_token=%s
          AND p.user_id=%s
          AND f.is_deleted=0
    """, (token, user_id))

    row = cursor.fetchone()

    if not row or not row[2]:

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'READ','DENIED','Read denied',%s)
        """, (user_id, sid, ip))

        db.commit()
        return "Read access denied", 403

    filename, file_path, _ = row
    ext = filename.rsplit(".", 1)[-1].lower()

    action = f"read file_token={token} name={filename} by_user={user_id}"

    # PDF
    if ext == "pdf":

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'READ','SUCCESS',%s,%s)
        """, (user_id, sid, action, ip))

        db.commit()
        emit_log(user_id, "READ", "SUCCESS", action, ip)

        if enforce_insider_policy(user_id, "read", sid):
            return block_and_logout(
                "Your account was blocked due to excessive file reads."
            )


        return send_file(file_path, as_attachment=False, download_name=filename)

    # DOCX / XLSX
    if ext in ["docx", "xlsx"]:

        temp_dir = current_app.config["TEMP_STORAGE"]
        os.makedirs(temp_dir, exist_ok=True)

        try:
            pdf_path = convert_to_pdf(file_path, temp_dir)
        except Exception:
            return "Preview not available", 500

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'READ','SUCCESS',%s,%s)
        """, (user_id, sid, action, ip))

        db.commit()
        emit_log(user_id, "READ", "SUCCESS", action, ip)

        if enforce_insider_policy(user_id, "read", sid):
            return block_and_logout(
                "Your account was blocked due to excessive file reads."
            )

        return send_file(pdf_path, as_attachment=False,
                         download_name=os.path.basename(pdf_path))

    # FALLBACK

    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'READ','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    db.commit()
    emit_log(user_id, "READ", "SUCCESS", action, ip)

    if enforce_insider_policy(user_id, "read", sid):
            return block_and_logout(
                "Your account was blocked due to excessive file reads."
            )

    return send_file(file_path, as_attachment=True, download_name=filename)


# =========================
# DOWNLOAD FILE
# =========================

@employee_bp.route("/download/<string:token>")
def download_file(token):

    user_id = session["user_id"]
    sid = session.get("session_id")
    ip = get_client_ip()

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            f.file_id,
            f.filename,
            f.stored_path,
            p.can_download
        FROM files f
        JOIN file_permissions p ON f.file_id = p.file_id
        WHERE f.file_token=%s
          AND p.user_id=%s
          AND f.is_deleted=0
    """, (token, user_id))

    row = cursor.fetchone()

    if not row or not row[3]:

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'DOWNLOAD','DENIED','Download denied',%s)
        """, (user_id, sid, ip))

        db.commit()
        return "Download access denied", 403

    file_id, filename, src_path, _ = row

    wm_token = generate_watermark(file_id, user_id, sid)
    wm_hash = hash_watermark(wm_token)

    try:
        temp_path = watermark_file(src_path, wm_token)
    except Exception:
        temp_path = src_path

    cursor.execute("""
        INSERT INTO download_watermarks
        (file_id, user_id, session_id, watermark_hash)
        VALUES (%s,%s,%s,%s)
    """, (file_id, user_id, sid, wm_hash))

    action = f"download file_id={file_id} name={filename} by_user={user_id}"

    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'DOWNLOAD','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    db.commit()

    emit_log(user_id, "DOWNLOAD", "SUCCESS", action, ip)

    if enforce_insider_policy(user_id, "download", sid):
        return block_and_logout(
            "Your account was blocked due to excessive downloads."
        )


    return send_file(temp_path, as_attachment=True, download_name=filename)


# =========================
# DELETE FILE
# =========================

@employee_bp.route("/delete/<string:token>")
def delete_file(token):

    user_id = session["user_id"]
    sid = session.get("session_id")
    ip = get_client_ip()

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            f.file_id,
            f.filename,
            p.can_delete
        FROM files f
        JOIN file_permissions p ON f.file_id = p.file_id
        WHERE f.file_token=%s
          AND p.user_id=%s
          AND f.is_deleted=0
    """, (token, user_id))

    row = cursor.fetchone()

    if not row or not row[2]:

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'DELETE','DENIED','Delete denied',%s)
        """, (user_id, sid, ip))

        db.commit()
        return "Delete access denied", 403

    file_id, filename, _ = row

    cursor.execute("""
        UPDATE files
        SET is_deleted=1
        WHERE file_id=%s
    """, (file_id,))

    action = f"delete file_id={file_id} name={filename} by_user={user_id}"

    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'DELETE','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    db.commit()

    emit_log(user_id, "DELETE", "SUCCESS", action, ip)

    if enforce_insider_policy(user_id, "delete", sid):
        return block_and_logout(
            "Your account was blocked due to suspicious deletions."
        )


    return redirect("/employee/files")

# =========================
# UPLOAD REQUEST
# =========================

@employee_bp.route("/upload", methods=["GET", "POST"])
def employee_upload():

    if request.method == "POST":

        file = request.files.get("file")

        if not file or file.filename == "":
            return "No file selected", 400

        if not allowed_file(file.filename):
            return "Unsupported file type", 400

        user_id = session["user_id"]
        sid = session.get("session_id")
        ip = get_client_ip()

        filename = file.filename

        temp_filename = f"{uuid.uuid4().hex}_{filename}"

        pending_dir = current_app.config["PENDING_STORAGE"]

        os.makedirs(pending_dir, exist_ok=True)

        temp_path = os.path.join(pending_dir, temp_filename)

        file.save(temp_path)


        db = mysql.get_db()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO upload_requests
            (user_id, filename, temp_path)
            VALUES (%s,%s,%s)
        """, (user_id, filename, temp_path))


        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)
            VALUES (%s,'INFO',
            'Employee upload request pending approval',%s)
        """, (user_id, sid))


        action = f"upload_request name={filename} by_user={user_id}"


        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'UPLOAD_REQUEST','PENDING',%s,%s)
        """, (user_id, sid, action, ip))


        db.commit()

        emit_log(user_id, "UPLOAD_REQUEST", "PENDING", action, ip)

        emit_alert(
            user_id,
            "INFO",
            "Employee upload request pending approval"
        )

        return redirect("/employee/home")

    return render_template("employee/upload.html")


# =========================
# VIEW REQUESTS
# =========================

@employee_bp.route("/requests")
def employee_requests():

    user_id = session["user_id"]

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT filename, status, requested_at
        FROM upload_requests
        WHERE user_id=%s
        ORDER BY requested_at DESC
    """, (user_id,))

    requests = cursor.fetchall()

    return render_template("employee/requests.html", requests=requests)

# =========================
# SEND FEEDBACK
# =========================

@employee_bp.route("/feedback", methods=["GET", "POST"])
def employee_feedback():

    user_id = session["user_id"]
    sid = session.get("session_id")
    ip = get_client_ip()

    db = mysql.get_db()
    cursor = db.cursor()

    # SUBMIT FEEDBACK
    if request.method == "POST":

        subject = request.form.get("subject")
        message = request.form.get("message")

        if not subject or not message:
            return "Subject and message required", 400

        # Insert feedback
        cursor.execute("""
            INSERT INTO feedback
            (sender_id, subject, message)
            VALUES (%s,%s,%s)
        """, (user_id, subject, message))

        feedback_id = cursor.lastrowid

        # Log
        action = f"submitted feedback id={feedback_id}"

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'FEEDBACK','SUCCESS',%s,%s)
        """, (user_id, sid, action, ip))

        # Alert Admin (Assume admin = role admin)
# Alert employee (audit + session timeline)
        cursor.execute("""
            INSERT INTO alerts (user_id, severity, message, session_id)
            VALUES (%s, 'INFO', 'You submitted feedback successfully', %s)
        """, (user_id, sid))



        db.commit()

        # Realtime
        emit_log(user_id, "FEEDBACK", "SUCCESS", action, ip)

        emit_alert(
            user_id,
            "INFO",
            "New feedback sent to admin"
        )

        return redirect("/employee/home")


    # VIEW OWN FEEDBACK
    cursor.execute("""
        SELECT
            subject,
            message,
            reply,
            status,
            created_at,
            replied_at
        FROM feedback
        WHERE sender_id=%s
        ORDER BY created_at DESC
    """, (user_id,))

    feedbacks = cursor.fetchall()

    return render_template(
        "employee/feedback.html",
        feedbacks=feedbacks
    )
