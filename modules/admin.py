from flask import (
    Blueprint, render_template, session,
    redirect, request, current_app, send_file
)

from modules.file_converter import convert_to_pdf
from modules.virus_scan import scan_file
from modules.file_watermark import watermark_file
from modules.watermark import generate_watermark, hash_watermark
from modules.leak_analyzer import analyze_file


import bcrypt

from extensions import mysql, socketio

import os
import hashlib
import uuid

from cryptography.fernet import Fernet

from datetime import datetime, timedelta



# =========================
# BLUEPRINT
# =========================

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin"
)


# =========================
# REALTIME HELPERS (FIXED)
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
        namespace="/admin"   # ✅ IMPORTANT
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
        namespace="/admin"   # ✅ IMPORTANT
    )


# =========================
# CLIENT IP
# =========================

def get_client_ip():

    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()

    return request.remote_addr


# =========================
# FILE TYPE VALIDATION
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
# ADMIN SECURITY
# =========================

@admin_bp.before_request
def admin_guard():

    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "admin":
        session.clear()
        return redirect("/")

# =========================
# ADMIN BEHAVIOR MONITORING
# =========================

ADMIN_INSIDER_RULES = {
    "read": {
        "limit": 20,
        "minutes": 10,
        "message": "Admin excessive file reads"
    },
    "download": {
        "limit": 10,
        "minutes": 10,
        "message": "Admin excessive downloads"
    },
    "delete": {
        "limit": 5,
        "minutes": 10,
        "message": "Admin suspicious deletions"
    }
}
def track_admin_activity(user_id, action, session_id):

    rule = ADMIN_INSIDER_RULES.get(action)

    if not rule:
        return False

    db = mysql.get_db()
    cursor = db.cursor()

    # Insert activity
    cursor.execute("""
        INSERT INTO activity_tracker (user_id, action)
        VALUES (%s,%s)
    """, (user_id, action))


    window = datetime.now() - timedelta(minutes=rule["minutes"])


    cursor.execute("""
        SELECT COUNT(*)
        FROM activity_tracker
        WHERE user_id=%s
          AND action=%s
          AND timestamp >= %s
    """, (user_id, action, window))


    count = cursor.fetchone()[0]


    # Threshold reached → Alert only
    if count >= rule["limit"]:

        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)
            VALUES (%s,'WARNING',%s,%s)
        """, (user_id, rule["message"], session_id))


        



        db.commit()

        emit_alert(user_id, "WARNING", rule["message"])

        return True


    db.commit()
    return False

# =========================
# HOME
# =========================

@admin_bp.route("/home")
def admin_home():
    return render_template("admin/home.html")


# =========================
# FILES
# =========================

@admin_bp.route("/files")
def admin_files():

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            f.file_id,
            f.filename,
            u.username,
            f.is_deleted,
            f.uploaded_at
        FROM files f
        LEFT JOIN users u ON f.owner_id = u.user_id
        ORDER BY f.uploaded_at DESC
    """)

    files = cursor.fetchall()

    return render_template("admin/files.html", files=files)


# =========================
# READ FILE
# =========================

@admin_bp.route("/read/<int:file_id>")
def admin_read(file_id):

    db = mysql.get_db()
    cursor = db.cursor()

    user_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # =========================
    # GET FILE
    # =========================
    cursor.execute("""
        SELECT filename, stored_path
        FROM files
        WHERE file_id=%s AND is_deleted=0
    """, (file_id,))

    row = cursor.fetchone()
    if not row:
        return "File not found", 404

    filename, file_path = row
    ext = filename.rsplit(".", 1)[-1].lower()

    # =========================
    # PERMISSION CHECK
    # =========================
    cursor.execute("""
        SELECT can_read
        FROM file_permissions
        WHERE file_id=%s AND user_id=%s
    """, (file_id, user_id))

    perm = cursor.fetchone()
    if not perm or perm[0] == 0:
        return "Access Denied", 403

    action = f"read file_id={file_id} name={filename} by_user={user_id}"

    # =========================
    # PDF → DIRECT PREVIEW
    # =========================
    if ext == "pdf":

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'READ','SUCCESS',%s,%s)
        """, (user_id, sid, action, ip))

        db.commit()
        emit_log(user_id, "READ", "SUCCESS", action, ip)
        track_admin_activity(user_id, "read", sid)

        return send_file(
            file_path,
            as_attachment=False,
            download_name=filename
        )

    # =========================
    # DOCX / XLSX → CONVERT TO PDF
    # =========================
    if ext in ["docx", "xlsx"]:

        temp_dir = current_app.config["TEMP_STORAGE"]
        os.makedirs(temp_dir, exist_ok=True)

        try:
            pdf_path = convert_to_pdf(file_path, temp_dir)
        except Exception as e:
            print("PDF conversion failed:", e)
            return "Preview not available", 500

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'READ','SUCCESS',%s,%s)
        """, (user_id, sid, action, ip))

        db.commit()
        emit_log(user_id, "READ", "SUCCESS", action, ip)
        track_admin_activity(user_id, "read", sid)

        return send_file(
            pdf_path,
            as_attachment=False,
            download_name=os.path.basename(pdf_path)
        )

    # =========================
    # FALLBACK (DOWNLOAD)
    # =========================


    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'READ','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    db.commit()

    emit_log(user_id, "READ", "SUCCESS", action, ip)
    track_admin_activity(user_id, "read", sid)

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename
    )



# =========================
# DOWNLOAD
# =========================

@admin_bp.route("/download/<int:file_id>")
def admin_download(file_id):

    db = mysql.get_db()
    cursor = db.cursor()

    user_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # ============================
    # GET FILE
    # ============================

    cursor.execute("""
        SELECT file_id, filename, stored_path
        FROM files
        WHERE file_id=%s AND is_deleted=0
    """, (file_id,))

    row = cursor.fetchone()

    if not row:
        return "File not found", 404

    file_id, filename, src_path = row


    # ============================
    # GENERATE WATERMARK
    # ============================

    wm_token = generate_watermark(file_id, user_id, sid)
    wm_hash = hash_watermark(wm_token)


    # ============================
    # CREATE WATERMARKED COPY
    # ============================

    try:
        temp_path = watermark_file(src_path, wm_token)
    except Exception as e:
        print("Watermark error:", e)
        temp_path = src_path   # fallback (no watermark)


    # ============================
    # SAVE WATERMARK PROOF
    # ============================

    cursor.execute("""
        INSERT INTO download_watermarks
        (file_id, user_id, session_id, watermark_hash)
        VALUES (%s,%s,%s,%s)
    """, (file_id, user_id, sid, wm_hash))


    # ============================
    # LOG (UNCHANGED)
    # ============================

    action = f"download file_id={file_id} name={filename} by_user={user_id}"



    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'DOWNLOAD','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))


    db.commit()

    emit_log(user_id, "DOWNLOAD", "SUCCESS", action, ip)
    track_admin_activity(user_id, "download", sid)


    # ============================
    # SEND FILE
    # ============================

    return send_file(
        temp_path,
        as_attachment=True,
        download_name=filename
    )



# =========================
# DELETE
# =========================

@admin_bp.route("/delete/<int:file_id>")
def admin_delete(file_id):

    db = mysql.get_db()
    cursor = db.cursor()

    user_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    cursor.execute("""
    SELECT filename FROM files WHERE file_id=%s
""", (file_id,))

    row = cursor.fetchone()

    filename = row[0] if row else "Unknown"

    cursor.execute("""
        UPDATE files SET is_deleted=1 WHERE file_id=%s
    """, (file_id,))


    action = f"delete file_id={file_id} name={filename} by_user={user_id}"



    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'DELETE','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'WARNING','Admin deleted a file',%s)
    """, (user_id, sid))

    db.commit()

    emit_log(user_id, "DELETE", "SUCCESS", action, ip)
    track_admin_activity(user_id, "delete", sid)

    emit_alert(user_id, "WARNING", "Admin deleted a file")

    return redirect("/admin/files")


# =========================
# RECOVER FILE
# =========================

@admin_bp.route("/recover/<int:file_id>")
def admin_recover(file_id):

    db = mysql.get_db()
    cursor = db.cursor()

    user_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # Get filename
    cursor.execute("""
        SELECT filename
        FROM files
        WHERE file_id=%s
    """, (file_id,))

    row = cursor.fetchone()

    filename = row[0] if row else "Unknown"

    # Recover file
    cursor.execute("""
        UPDATE files
        SET is_deleted=0
        WHERE file_id=%s
    """, (file_id,))

    action = f"recover file_id={file_id} name={filename} by_user={user_id}"

    # Log
    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'RECOVER','SUCCESS',%s,%s)
    """, (user_id, sid, action, ip))

    # Alert
    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'INFO','File recovered by admin',%s)
    """, (user_id, sid))

    db.commit()

    emit_log(user_id, "RECOVER", "SUCCESS", action, ip)

    emit_alert(user_id, "INFO", "File recovered by admin")

    return redirect("/admin/files")

# =========================
# UPLOAD
# =========================

@admin_bp.route("/upload", methods=["GET", "POST"])
def upload_file():

    # Clear old pending scan (safety)
    session.pop("pending_file", None)

    if request.method == "POST":

        file = request.files.get("file")

        if not file or file.filename == "":
            return "No file selected", 400

        if not allowed_file(file.filename):
            return "Unsupported type", 400


        # Session data
        user_id = session["user_id"]
        sid = session["session_id"]
        ip = get_client_ip()


        name = file.filename
        token = uuid.uuid4().hex

        stored = f"{token}_{name}"

        live = os.path.join(
            current_app.config["FILE_STORAGE"],
            stored
        )

        backup = os.path.join(
            current_app.config["BACKUP_STORAGE"],
            stored + ".enc"
        )


        # Save file
        file.save(live)


        # =========================
        # VIRUS SCAN
        # =========================
        status, virus = scan_file(live)


        # =========================
        # IF INFECTED → ASK ADMIN
        # =========================
        if status == "infected":

            session["pending_file"] = {
                "path": live,
                "name": name,
                "token": token,
                "backup": backup,
                "user_id": user_id,
                "sid": sid,
                "ip": ip
            }

            return render_template(
                "admin/virus_confirm.html",
                filename=name,
                virus=virus
            )


        # =========================
        # CLEAN FILE → CONTINUE
        # =========================

        with open(live, "rb") as f:
            data = f.read()

        file_hash = hashlib.sha256(data).hexdigest()


        cipher = Fernet(current_app.config["ENCRYPTION_KEY"])


        with open(backup, "wb") as bf:
            bf.write(cipher.encrypt(data))


        db = mysql.get_db()
        cursor = db.cursor()


        cursor.execute("""
            INSERT INTO files
            (filename,stored_path,owner_id,file_token)
            VALUES(%s,%s,%s,%s)
        """, (name, live, user_id, token))


        fid = cursor.lastrowid


        cursor.execute("""
            INSERT INTO file_permissions
            VALUES(%s,%s,1,1,1)
        """, (fid, user_id))


        action = f"upload file_id={fid} name={name} sha256={file_hash} by_user={user_id}"



        cursor.execute("""
            INSERT INTO logs
            (user_id,session_id,event_type,result,action,ip_address)
            VALUES(%s,%s,'UPLOAD','SUCCESS',%s,%s)
        """, (user_id, sid, action, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id,severity,message,session_id)
            VALUES(%s,'INFO','File uploaded successfully',%s)
        """, (user_id, sid))


        db.commit()


        emit_log(user_id, "UPLOAD", "SUCCESS", action, ip)


        return redirect("/admin/home")


    return render_template("admin/upload.html")

@admin_bp.route("/virus-decision", methods=["POST"])
def virus_decision():

    decision = request.form.get("action")

    data = session.get("pending_file")

    if not data:
        return redirect("/admin/home")


    path = data["path"]
    name = data["name"]
    token = data["token"]
    backup = data["backup"]
    user_id = data["user_id"]
    sid = data["sid"]
    ip = data["ip"]


    db = mysql.get_db()
    cursor = db.cursor()


    # =========================
    # REJECT FILE
    # =========================
    if decision == "reject":

        if os.path.exists(path):
            os.remove(path)

        if os.path.exists(backup):
            os.remove(backup)


        cursor.execute("""
            INSERT INTO logs
            (user_id,session_id,event_type,result,action,ip_address)
            VALUES(%s,%s,'UPLOAD','REJECTED','Upload rejected (virus)',%s)
        """, (user_id, sid, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id,severity,message,session_id)
            VALUES(%s,'WARNING','Upload rejected due to virus',%s)
        """, (user_id, sid))


        db.commit()


        emit_log(
            user_id,
            "UPLOAD",
            "REJECTED",
            "Upload rejected (virus)",
            ip
        )


        emit_alert(
            user_id,
            "WARNING",
            "Upload rejected due to virus"
        )


        session.pop("pending_file", None)


        return redirect("/admin/home")


    # =========================
    # ACCEPT FILE (OVERRIDE)
    # =========================
    if decision == "accept":

        with open(path, "rb") as f:
            data_bytes = f.read()


        file_hash = hashlib.sha256(data_bytes).hexdigest()


        cipher = Fernet(current_app.config["ENCRYPTION_KEY"])


        with open(backup, "wb") as bf:
            bf.write(cipher.encrypt(data_bytes))


        cursor.execute("""
            INSERT INTO files
            (filename,stored_path,owner_id,file_token)
            VALUES(%s,%s,%s,%s)
        """, (name, path, user_id, token))


        fid = cursor.lastrowid


        cursor.execute("""
            INSERT INTO file_permissions
            VALUES(%s,%s,1,1,1)
        """, (fid, user_id))


        action = f"Uploaded infected file: {name} | SHA256:{file_hash}"


        cursor.execute("""
            INSERT INTO logs
            (user_id,session_id,event_type,result,action,ip_address)
            VALUES(%s,%s,'UPLOAD','WARNING',%s,%s)
        """, (user_id, sid, action, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id,severity,message,session_id)
            VALUES(%s,'WARNING','Infected file approved by admin',%s)
        """, (user_id, sid))


        db.commit()


        emit_log(
            user_id,
            "UPLOAD",
            "WARNING",
            action,
            ip
        )


        emit_alert(
            user_id,
            "WARNING",
            "Infected file approved by admin"
        )


        session.pop("pending_file", None)


        return redirect("/admin/home")



# =========================
# MONITOR
# =========================

@admin_bp.route("/monitor")
def admin_monitor():
    return render_template("admin/monitor.html")


# =========================
# API LOGS
# =========================

@admin_bp.route("/api/logs")
def api_logs():

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            u.username,
            l.event_type,
            l.result,
            l.action,
            l.ip_address,
            l.timestamp
        FROM logs l
        LEFT JOIN users u ON l.user_id=u.user_id
        ORDER BY l.timestamp DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()

    return {
        "logs": [
            {
                "user": r[0],
                "event": r[1],
                "result": r[2],
                "action": r[3],
                "ip": r[4],
                "time": r[5].strftime("%Y-%m-%d %H:%M:%S")
            } for r in rows
        ]
    }


# =========================
# API ALERTS
# =========================

@admin_bp.route("/api/alerts")
def api_alerts():

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            u.username,
            a.severity,
            a.message,
            a.timestamp
        FROM alerts a
        LEFT JOIN users u ON a.user_id=u.user_id
        ORDER BY a.timestamp DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()

    return {
        "alerts": [
            {
                "user": r[0],
                "severity": r[1],
                "message": r[2],
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S")
            } for r in rows
        ]
    }


# =========================
# UPLOAD REQUESTS
# =========================

@admin_bp.route("/requests")
def admin_requests():

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            ur.request_id,
            u.username,
            ur.filename,
            ur.requested_at
        FROM upload_requests ur
        JOIN users u ON ur.user_id = u.user_id
        WHERE ur.status='pending'
        ORDER BY ur.requested_at DESC
    """)

    requests = cursor.fetchall()

    return render_template("admin/requests.html", requests=requests)


# =========================
# APPROVE REQUEST
# =========================

@admin_bp.route("/approve/<int:req_id>")
def approve_request(req_id):

    # clear any old pending employee scan
    session.pop("pending_employee_file", None)

    db = mysql.get_db()
    cursor = db.cursor()

    admin_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # =========================
    # 1. Get request details
    # =========================
    cursor.execute("""
        SELECT user_id, filename, temp_path
        FROM upload_requests
        WHERE request_id=%s AND status='pending'
    """, (req_id,))

    row = cursor.fetchone()

    if not row:
        return "Request not found", 404

    employee_id, filename, temp_path = row


    # =========================
    # 2. VIRUS SCAN FIRST
    # =========================
    status, virus = scan_file(temp_path)


    # =========================
    # IF INFECTED → ASK ADMIN
    # =========================
    if status == "infected":

        session["pending_employee_file"] = {
            "req_id": req_id,
            "employee_id": employee_id,
            "filename": filename,
            "temp_path": temp_path,
            "admin_id": admin_id,
            "sid": sid,
            "ip": ip
        }

        return render_template(
            "admin/virus_confirm_employee.html",
            filename=filename,
            virus=virus
        )


    # =========================
    # CLEAN FILE → APPROVE
    # =========================
    return finalize_employee_upload(
        req_id,
        employee_id,
        filename,
        temp_path,
        admin_id,
        sid,
        ip
    )

def finalize_employee_upload(req_id, employee_id, filename,
                             temp_path, admin_id, sid, ip):

    db = mysql.get_db()
    cursor = db.cursor()

    # Move file to storage
    token = uuid.uuid4().hex
    stored_name = f"{token}_{filename}"

    live_path = os.path.join(
        current_app.config["FILE_STORAGE"],
        stored_name
    )

    os.rename(temp_path, live_path)


    # Insert into files table
    cursor.execute("""
        INSERT INTO files
        (filename, stored_path, owner_id, file_token)
        VALUES (%s,%s,%s,%s)
    """, (filename, live_path, employee_id, token))

    file_id = cursor.lastrowid


    # Give permission
    cursor.execute("""
        INSERT INTO file_permissions
        VALUES (%s,%s,1,1,1)
    """, (file_id, employee_id))


    # Mark request approved
    cursor.execute("""
        UPDATE upload_requests
        SET status='approved'
        WHERE request_id=%s
    """, (req_id,))


    # Log
    action = f"approve_upload file={filename} employee_id={employee_id} by_user={admin_id}"


    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'REQUEST','APPROVED',%s,%s)
    """, (admin_id, sid, action, ip))


    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'INFO','Upload approved by admin',%s)
    """, (employee_id, sid))


    db.commit()


    emit_log(admin_id, "REQUEST", "APPROVED", action, ip)
    emit_alert(employee_id, "INFO", "Upload approved by admin")

    return redirect("/admin/requests")
@admin_bp.route("/virus-decision-employee", methods=["POST"])
def virus_decision_employee():

    decision = request.form.get("action")
    data = session.get("pending_employee_file")

    if not data:
        return redirect("/admin/requests")

    req_id = data["req_id"]
    employee_id = data["employee_id"]
    filename = data["filename"]
    temp_path = data["temp_path"]
    admin_id = data["admin_id"]
    sid = data["sid"]
    ip = data["ip"]

    db = mysql.get_db()
    cursor = db.cursor()


    # =========================
    # REJECT
    # =========================
    if decision == "reject":

        if os.path.exists(temp_path):
            os.remove(temp_path)

        cursor.execute("""
            UPDATE upload_requests
            SET status='rejected'
            WHERE request_id=%s
        """, (req_id,))


        cursor.execute("""
            INSERT INTO logs
            (user_id,session_id,event_type,result,action,ip_address)
            VALUES (%s,%s,'REQUEST','REJECTED',
            'Rejected (virus detected)',%s)
        """, (admin_id, sid, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id,severity,message,session_id)
            VALUES (%s,'WARNING','Upload rejected (virus)',%s)
        """, (employee_id, sid))


        db.commit()

        emit_log(
            admin_id,
            "REQUEST",
            "REJECTED",
            "Rejected (virus detected)",
            ip
        )

        emit_alert(
            employee_id,
            "WARNING",
            "Upload rejected (virus)"
        )

        session.pop("pending_employee_file", None)
        return redirect("/admin/requests")


    # =========================
    # ACCEPT (OVERRIDE)
    # =========================
    if decision == "accept":

        session.pop("pending_employee_file", None)

        return finalize_employee_upload(
            req_id,
            employee_id,
            filename,
            temp_path,
            admin_id,
            sid,
            ip
        )



# =========================
# REJECT REQUEST
# =========================

@admin_bp.route("/reject/<int:req_id>")
def reject_request(req_id):

    db = mysql.get_db()
    cursor = db.cursor()

    user_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    cursor.execute("""
        UPDATE upload_requests
        SET status='rejected'
        WHERE request_id=%s
    """, (req_id,))

    action = f"Rejected upload request ID: {req_id}"

    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'REQUEST','REJECTED',%s,%s)
    """, (user_id, sid, action, ip))

    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'WARNING','Upload request rejected',%s)
    """, (user_id, sid))

    db.commit()

    emit_log(user_id, "REQUEST", "REJECTED", action, ip)
    emit_alert(user_id, "WARNING", "Upload request rejected")

    return redirect("/admin/requests")

# =========================
# LOGS PAGE (TABLE VIEW)
# =========================

# =========================
# LOGS PAGE
# =========================
@admin_bp.route("/logs")
def admin_logs():

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            u.username,
            l.event_type,
            l.result,
            l.action,
            l.ip_address,
            l.timestamp
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.user_id
        ORDER BY l.timestamp DESC
        LIMIT 100
    """)

    logs = cursor.fetchall()

    return render_template("admin/logs.html", logs=logs)


# =========================
# ALERTS PAGE
# =========================
@admin_bp.route("/alerts")
def admin_alerts():

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            u.username,
            a.severity,
            a.message,
            a.timestamp
        FROM alerts a
        LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.timestamp DESC
        LIMIT 100
    """)

    alerts = cursor.fetchall()

    return render_template("admin/alerts.html", alerts=alerts)

# ============================
# VIEW EMPLOYEES
# ============================

# ============================
# VIEW EMPLOYEES
# ============================

# ============================
# EMPLOYEE MANAGEMENT
# ============================

# ============================
# EMPLOYEE MANAGEMENT
# ============================

@admin_bp.route("/employees")
def manage_employees():

    if session.get("role") != "admin":
        return redirect("/login")

    db = mysql.get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT 
            user_id,
            username,
            role,
            status,
            photo_path,
            terminated_at
        FROM users
        WHERE role='employee'
    """)

    employees = cursor.fetchall()

    return render_template(
        "admin/employees.html",
        employees=employees
    )


# ============================
# BLOCK USER
# ============================

@admin_bp.route("/block/<int:user_id>")
def block_user(user_id):

    if session.get("role") != "admin":
        return redirect("/login")

    db = mysql.get_db()
    cursor = db.cursor()

    admin_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # Block only if not terminated
    cursor.execute("""
        UPDATE users
        SET status='blocked'
        WHERE user_id=%s AND status!='terminated'
    """, (user_id,))

    # Force logout all sessions
    cursor.execute("""
        UPDATE user_sessions
        SET logout_time=NOW()
        WHERE user_id=%s AND logout_time IS NULL
    """, (user_id,))

    action = f"Admin blocked employee ID {user_id}"

    # Log
    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'ADMIN','SUCCESS',%s,%s)
    """, (admin_id, sid, action, ip))

    # Alert
    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'WARNING','Your account has been blocked',%s)
    """, (user_id, sid))

    db.commit()

    emit_log(admin_id, "ADMIN", "SUCCESS", action, ip)
    emit_alert(user_id, "WARNING", "Your account has been blocked")

    # Realtime logout
    socketio.emit(
        "force_logout",
        {"user_id": user_id},
        namespace="/admin"
    )

    return redirect("/admin/employees")


# ============================
# UNBLOCK USER
# ============================

@admin_bp.route("/unblock/<int:user_id>")
def unblock_user(user_id):

    if session.get("role") != "admin":
        return redirect("/login")

    db = mysql.get_db()
    cursor = db.cursor()

    admin_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # Unblock only if not terminated
    cursor.execute("""
        UPDATE users
        SET status='active'
        WHERE user_id=%s AND status!='terminated'
    """, (user_id,))

    action = f"Admin unblocked employee ID {user_id}"

    # Log
    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'ADMIN','SUCCESS',%s,%s)
    """, (admin_id, sid, action, ip))

    # Alert
    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'INFO','Your account has been unblocked',%s)
    """, (user_id, sid))

    db.commit()

    emit_log(admin_id, "ADMIN", "SUCCESS", action, ip)
    emit_alert(user_id, "INFO", "Your account has been unblocked")

    return redirect("/admin/employees")


# ============================
# TERMINATE USER
# ============================

@admin_bp.route("/terminate/<int:user_id>")
def terminate_user(user_id):

    if session.get("role") != "admin":
        return redirect("/login")

    db = mysql.get_db()
    cursor = db.cursor()

    admin_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()

    # Set terminated
    cursor.execute("""
        UPDATE users
        SET status='terminated',
            terminated_at=NOW()
        WHERE user_id=%s
    """, (user_id,))

    # Force logout all sessions
    cursor.execute("""
        UPDATE user_sessions
        SET logout_time=NOW()
        WHERE user_id=%s AND logout_time IS NULL
    """, (user_id,))

    action = f"Admin terminated employee ID {user_id}"

    # Log
    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'ADMIN','SUCCESS',%s,%s)
    """, (admin_id, sid, action, ip))

    # Alert
    cursor.execute("""
        INSERT INTO alerts
        (user_id,severity,message,session_id)
        VALUES (%s,'CRITICAL','Your account has been terminated',%s)
    """, (user_id, sid))

    db.commit()

    emit_log(admin_id, "ADMIN", "SUCCESS", action, ip)
    emit_alert(user_id, "CRITICAL", "Your account has been terminated")

    # Realtime logout
    socketio.emit(
        "force_logout",
        {"user_id": user_id},
        namespace="/admin"
    )

    return redirect("/admin/employees")

# ============================
# REGISTER EMPLOYEE (WITH PHOTO)
# ============================

import bcrypt
from werkzeug.utils import secure_filename


# ============================
# IMAGE VALIDATION (NEW)
# ============================

ALLOWED_IMAGE_EXT = {"jpg", "jpeg"}


def allowed_profile_image(filename):

    if "." not in filename:
        return False

    ext = filename.rsplit(".", 1)[1].lower()

    return ext in ALLOWED_IMAGE_EXT


# ============================
# REGISTER EMPLOYEE
# ============================

from PIL import Image
import uuid
import os
from werkzeug.utils import secure_filename


@admin_bp.route("/register", methods=["GET", "POST"])
def register_employee():

    if session.get("role") != "admin":
        return redirect("/login")


    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        photo = request.files.get("photo")

        admin_id = session["user_id"]
        sid = session["session_id"]
        ip = get_client_ip()

        db = mysql.get_db()
        cursor = db.cursor()


        # ============================
        # CHECK USER EXISTS
        # ============================

        cursor.execute(
            "SELECT user_id FROM users WHERE username=%s",
            (username,)
        )

        if cursor.fetchone():

            return render_template(
                "admin/register.html",
                error="Username already exists"
            )


        # ============================
        # PASSWORD HASH
        # ============================

        hashed = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        ).decode()


        # ============================
        # PHOTO UPLOAD
        # ============================

        photo_path = None

        if photo and photo.filename != "":

            # Validate extension
            if not allowed_profile_image(photo.filename):

                return render_template(
                    "admin/register.html",
                    error="Only JPG / JPEG images allowed"
                )


            filename = secure_filename(photo.filename)

            unique = uuid.uuid4().hex[:12]

            new_name = f"{unique}_{filename}"

            upload_dir = current_app.config["PROFILE_STORAGE"]

            os.makedirs(upload_dir, exist_ok=True)

            full_path = os.path.join(upload_dir, new_name)


            try:
                # Convert to RGB (fix PNG/P mode error)
                img = Image.open(photo)
                img = img.convert("RGB")

                # Force save as JPEG
                img.save(
                    full_path,
                    "JPEG",
                    quality=90,
                    optimize=True
                )

            except Exception as e:

                print("Image error:", e)

                return render_template(
                    "admin/register.html",
                    error="Invalid image file"
                )


            # Path stored in DB (for frontend use)
            photo_path = f"static/images/profiles/{new_name}"


        # ============================
        # INSERT USER
        # ============================

        cursor.execute("""
            INSERT INTO users
            (username,password_hash,role,status,photo_path)
            VALUES (%s,%s,'employee','active',%s)
        """, (username, hashed, photo_path))


        new_uid = cursor.lastrowid


        # ============================
        # LOG
        # ============================

        action = f"create_employee new_id={new_uid} name={username} by_user={admin_id}"


        cursor.execute("""
            INSERT INTO logs
            (user_id,session_id,event_type,result,action,ip_address)
            VALUES (%s,%s,'ADMIN','SUCCESS',%s,%s)
        """, (admin_id, sid, action, ip))


        # ============================
        # ALERT
        # ============================

        alert_msg = f"Account created by user_id={admin_id}"


        cursor.execute("""
            INSERT INTO alerts
            (user_id,severity,message,session_id)
            VALUES (%s,'INFO',%s,%s)
        """, (new_uid, alert_msg, sid))


        db.commit()


        # ============================
        # REALTIME EVENTS
        # ============================

        emit_log(
            admin_id,
            "ADMIN",
            "SUCCESS",
            action,
            ip
        )

        emit_alert(
            new_uid,
            "INFO",
            alert_msg
        )


        return redirect("/admin/employees")


    # ============================
    # GET PAGE
    # ============================

    return render_template("admin/register.html")


@admin_bp.route("/leak-analyzer", methods=["GET", "POST"])
def leak_analyzer():

    if request.method == "POST":

        file = request.files.get("file")

        # =========================
        # VALIDATE
        # =========================
        if not file or file.filename == "":
            return render_template(
                "admin/leak_analyzer.html",
                error="No file selected"
            )

        # =========================
        # SAVE TEMP FILE
        # =========================
        temp_dir = current_app.config["PENDING_STORAGE"]
        os.makedirs(temp_dir, exist_ok=True)

        temp_path = os.path.join(
            temp_dir,
            uuid.uuid4().hex + "_" + file.filename
        )

        file.save(temp_path)

        # =========================
        # ANALYZE WATERMARK
        # =========================
        try:
            result = analyze_file(temp_path)
        except Exception as e:
            print("Analyze error:", e)
            result = None
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # =========================
        # NO WATERMARK FOUND
        # =========================
        if not result:
            return render_template(
                "admin/leak_analyzer.html",
                error="No valid watermark found"
            )

        # =========================
        # GET USER DETAILS
        # =========================
        db = mysql.get_db()
        cursor = db.cursor()

        cursor.execute(
            "SELECT username FROM users WHERE user_id=%s",
            (result["user_id"],)
        )

        row = cursor.fetchone()
        username = row[0] if row else "Unknown"

        # =========================
        # FORMAT TIME
        # =========================
        leak_time = result.get("timestamp", "Unknown")

        admin_id = session["user_id"]
        admin_sid = session.get("session_id")
        ip = get_client_ip()

        # =========================
        # STRUCTURED ACTION (IMPORTANT)
        # =========================
        action = (
            f"leak_detected "
            f"file_id={result['file_id']} "
            f"by_user={result['user_id']} "
            f"session_id={result['session_id']} "
            f"time={leak_time}"
        )

        # =========================
        # 1️⃣ LOG — ATTRIBUTED TO LEAKER (CRITICAL)
        # =========================
        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'LEAK','CONFIRMED',%s,%s)
        """, (
            result["user_id"],
            result["session_id"],
            action,
            ip
        ))

        # =========================
        # 2️⃣ OPTIONAL ADMIN AUDIT LOG
        # =========================
        admin_action = (
            f"confirmed leak "
            f"user_id={result['user_id']} "
            f"file_id={result['file_id']}"
        )

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'LEAK','AUDIT',%s,%s)
        """, (
            admin_id,
            admin_sid,
            admin_action,
            ip
        ))

        # =========================
        # ALERT TO LEAKER
        # =========================
        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)
            VALUES (%s,'CRITICAL',
            'Data leak detected from your account (watermark confirmed)',%s)
        """, (
            result["user_id"],
            result["session_id"]
        ))

        db.commit()

        # =========================
        # REALTIME EVENTS
        # =========================
        emit_log(
            result["user_id"],
            "LEAK",
            "CONFIRMED",
            action,
            ip
        )

        emit_alert(
            result["user_id"],
            "CRITICAL",
            "Data leak detected from your account"
        )

        # =========================
        # SHOW RESULT
        # =========================
        return render_template(
            "admin/leak_analyzer.html",
            result=result,
            username=username
        )

    return render_template("admin/leak_analyzer.html")

@admin_bp.route("/permissions/<int:file_id>", methods=["GET", "POST"])
def manage_permissions(file_id):

    # Only admin
    if session.get("role") != "admin":
        return redirect("/login")

    db = mysql.get_db()
    cursor = db.cursor()

    admin_id = session["user_id"]
    sid = session["session_id"]
    ip = get_client_ip()


    # ============================
    # GET FILE
    # ============================

    cursor.execute("""
        SELECT file_id, filename
        FROM files
        WHERE file_id=%s AND is_deleted=0
    """, (file_id,))

    file = cursor.fetchone()

    if not file:
        return "File not found", 404


    # ============================
    # GET EMPLOYEES
    # ============================

    cursor.execute("""
        SELECT user_id, username
        FROM users
        WHERE role='employee'
          AND status='active'
    """)

    users = cursor.fetchall()


    # ============================
    # CURRENT PERMISSIONS
    # ============================

    cursor.execute("""
        SELECT user_id, can_read, can_download, can_delete
        FROM file_permissions
        WHERE file_id=%s
    """, (file_id,))

    permissions = {
        r[0]: {
            "can_read": r[1],
            "can_download": r[2],
            "can_delete": r[3]
        }
        for r in cursor.fetchall()
    }


    # ============================
    # ENSURE ALL USERS EXIST
    # ============================

    for u in users:

        uid = u[0]

        if uid not in permissions:

            permissions[uid] = {
                "can_read": 0,
                "can_download": 0,
                "can_delete": 0
            }


    # ============================
    # SAVE UPDATE
    # ============================

    if request.method == "POST":

        for u in users:

            uid = u[0]

            can_read = 1 if request.form.get(f"read_{uid}") else 0
            can_download = 1 if request.form.get(f"download_{uid}") else 0
            can_delete = 1 if request.form.get(f"delete_{uid}") else 0


            cursor.execute("""
                INSERT INTO file_permissions
                (file_id, user_id, can_read, can_download, can_delete)

                VALUES (%s,%s,%s,%s,%s)

                ON DUPLICATE KEY UPDATE
                    can_read=VALUES(can_read),
                    can_download=VALUES(can_download),
                    can_delete=VALUES(can_delete)
            """, (
                file_id,
                uid,
                can_read,
                can_download,
                can_delete
            ))


        # ============================
        # LOG
        # ============================

        action = f"updated_permissions file_id={file_id} by_admin={admin_id}"


        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)

            VALUES (%s,%s,'PERMISSION','SUCCESS',%s,%s)
        """, (admin_id, sid, action, ip))


        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)

            VALUES (%s,'INFO','File permissions updated',%s)
        """, (admin_id, sid))


        db.commit()


        emit_log(
            admin_id,
            "PERMISSION",
            "SUCCESS",
            action,
            ip
        )

        emit_alert(
            admin_id,
            "INFO",
            "File permissions updated"
        )


        return redirect("/admin/files")


    # ============================
    # VIEW
    # ============================

    return render_template(
        "admin/permissions.html",

        file={
            "id": file[0],
            "filename": file[1]
        },

        users=[
            {"id": u[0], "username": u[1]}
            for u in users
        ],

        permissions=permissions
    )

# ============================
# INSPECT EMPLOYEE (FORENSIC DASHBOARD)
# ============================

@admin_bp.route("/inspect/<int:user_id>")
def inspect_employee(user_id):

    if session.get("role") != "admin":
        return redirect("/login")

    db = mysql.get_db()
    cursor = db.cursor()

    # ============================
    # 1. GET USER INFO
    # ============================

    cursor.execute("""
        SELECT
            user_id,
            username,
            role,
            status,
            created_at,
            photo_path
        FROM users
        WHERE user_id=%s
    """, (user_id,))

    user = cursor.fetchone()

    if not user:
        return "User not found", 404


    user_data = {
        "id": user[0],
        "username": user[1],
        "role": user[2],
        "status": user[3],
        "created_at": user[4],
        "photo": user[5]
    }


    # ============================
    # 2. GET ALL SESSIONS
    # ============================

    cursor.execute("""
        SELECT
            session_id,
            login_time,
            logout_time,
            login_result,
            ip_address,
            user_agent
        FROM user_sessions
        WHERE user_id=%s
        ORDER BY login_time DESC
    """, (user_id,))

    sessions_raw = cursor.fetchall()

    sessions = []


    # ============================
    # GLOBAL COUNTERS
    # ============================

    total_reads = 0
    total_downloads = 0
    total_deletes = 0
    total_alerts = 0
    total_leaks = 0
    critical_alerts = 0


    # ============================
    # 3. PROCESS EACH SESSION
    # ============================

    for s in sessions_raw:

        sid = s[0]

        session_obj = {
            "id": sid,
            "login_time": s[1],
            "logout_time": s[2],
            "result": s[3],
            "ip": s[4],
            "agent": s[5],
            "logs": [],
            "alerts": [],
            "summary": {},
            "risk": "LOW"
        }


        # ============================
        # GET LOGS (PER SESSION)
        # ============================

        cursor.execute("""
            SELECT
                event_type,
                result,
                action,
                ip_address,
                timestamp
            FROM logs
            WHERE user_id=%s
              AND session_id=%s
            ORDER BY timestamp ASC
        """, (user_id, sid))

        logs = cursor.fetchall()


        reads = 0
        downloads = 0
        deletes = 0
        leaks = 0


        for l in logs:

            log_obj = {
                "event": l[0],
                "result": l[1],
                "action": l[2],
                "ip": l[3],
                "time": l[4]
            }

            session_obj["logs"].append(log_obj)


            # Count activity
            if l[0] == "READ":
                reads += 1
                total_reads += 1

            if l[0] == "DOWNLOAD":
                downloads += 1
                total_downloads += 1

            if l[0] == "DELETE":
                deletes += 1
                total_deletes += 1

            if l[0] == "LEAK":
                leaks += 1
                total_leaks += 1


        # ============================
        # GET ALERTS (PER SESSION)
        # ============================

        cursor.execute("""
            SELECT
                severity,
                message,
                timestamp
            FROM alerts
            WHERE user_id=%s
              AND session_id=%s
            ORDER BY timestamp ASC
        """, (user_id, sid))

        alerts = cursor.fetchall()


        info = 0
        warning = 0
        critical = 0


        for a in alerts:

            alert_obj = {
                "severity": a[0],
                "message": a[1],
                "time": a[2]
            }

            session_obj["alerts"].append(alert_obj)

            total_alerts += 1


            if a[0] == "INFO":
                info += 1

            if a[0] == "WARNING":
                warning += 1

            if a[0] == "CRITICAL":
                critical += 1
                critical_alerts += 1


        # ============================
        # SESSION SUMMARY
        # ============================

        session_obj["summary"] = {
            "reads": reads,
            "downloads": downloads,
            "deletes": deletes,
            "leaks": leaks,
            "info": info,
            "warning": warning,
            "critical": critical
        }


        # ============================
        # SESSION RISK ENGINE
        # ============================

        risk = "LOW"

        if leaks > 0:
            risk = "HIGH"

        elif critical > 0 or downloads >= 5:
            risk = "MEDIUM"

        session_obj["risk"] = risk


        sessions.append(session_obj)


    # ============================
    # GLOBAL RISK ENGINE
    # ============================

    global_risk = "LOW"

    if total_leaks > 0:
        global_risk = "HIGH"

    elif critical_alerts > 2 or total_downloads > 10:
        global_risk = "MEDIUM"


    # ============================
    # GLOBAL SUMMARY
    # ============================

    summary = {
        "sessions": len(sessions),
        "reads": total_reads,
        "downloads": total_downloads,
        "deletes": total_deletes,
        "alerts": total_alerts,
        "leaks": total_leaks,
        "critical": critical_alerts,
        "risk": global_risk
    }

    
    # ============================
    # LOG ADMIN INSPECTION
    # ============================

    admin_id = session["user_id"]
    sid_admin = session.get("session_id")
    ip = get_client_ip()

    action = f"inspect employee user_id={user_id} by_admin={admin_id}"

    cursor.execute("""
        INSERT INTO logs
        (user_id, session_id, event_type, result, action, ip_address)
        VALUES (%s,%s,'ADMIN','SUCCESS',%s,%s)
    """, (admin_id, sid_admin, action, ip))

    db.commit()

    emit_log(admin_id, "ADMIN", "SUCCESS", action, ip)


    # ============================
    # RENDER DASHBOARD
    # ============================

    return render_template(
        "admin/inspect_employee.html",
        user=user_data,
        sessions=sessions,
        summary=summary
    )
# =========================
# VIEW & REPLY FEEDBACK (ADMIN)
# =========================

@admin_bp.route("/feedback", methods=["GET", "POST"])
def admin_feedback():

    if session.get("role") != "admin":
        return redirect("/")

    db = mysql.get_db()
    cursor = db.cursor()

    admin_id = session["user_id"]
    sid = session.get("session_id")
    ip = get_client_ip()


    # =========================
    # HANDLE REPLY
    # =========================
    if request.method == "POST":

        fid = request.form.get("feedback_id")
        reply = request.form.get("reply")

        if not fid or not reply:
            return "Invalid request", 400

        if len(reply) > 950:
            return "Reply too long (max 950)", 400


        # Update feedback
        cursor.execute("""
            UPDATE feedback
            SET
                responder_id=%s,
                reply=%s,
                status='replied',
                replied_at=NOW()
            WHERE feedback_id=%s
        """, (admin_id, reply, fid))


        # Get employee id
        cursor.execute("""
            SELECT sender_id
            FROM feedback
            WHERE feedback_id=%s
        """, (fid,))

        row = cursor.fetchone()

        if not row:
            return "Feedback not found", 404

        employee_id = row[0]


        # =========================
        # LOG
        # =========================

        action = f"replied feedback id={fid}"

        cursor.execute("""
            INSERT INTO logs
            (user_id, session_id, event_type, result, action, ip_address)
            VALUES (%s,%s,'FEEDBACK_REPLY','SUCCESS',%s,%s)
        """, (admin_id, sid, action, ip))


        # =========================
        # ALERT EMPLOYEE
        # =========================

        cursor.execute("""
            INSERT INTO alerts
            (user_id, severity, message, session_id)
            VALUES (%s,'INFO','Admin replied to your feedback',%s)
        """, (employee_id, sid))


        db.commit()


        # =========================
        # REALTIME
        # =========================

        emit_log(admin_id, "FEEDBACK_REPLY", "SUCCESS", action, ip)

        emit_alert(
            employee_id,
            "INFO",
            "Admin replied to your feedback"
        )


        return redirect("/admin/feedback")


    # =========================
    # VIEW FEEDBACK
    # =========================

    cursor.execute("""
        SELECT
            f.feedback_id,
            u.username,
            f.subject,
            f.message,
            f.reply,
            f.status,
            f.created_at,
            f.replied_at
        FROM feedback f
        JOIN users u ON f.sender_id = u.user_id
        ORDER BY f.created_at DESC
    """)

    feedbacks = cursor.fetchall()


    return render_template(
        "admin/feedback.html",
        feedbacks=feedbacks
    )
