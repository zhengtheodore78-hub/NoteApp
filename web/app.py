"""NotesApp - a small grades application.

Deliberately insecure teaching app for the EPITA Computer Security course.
Do not deploy this anywhere real.
"""
import os
import csv
import io
import json
import hmac
import time
import base64
import hashlib
import subprocess
import ipaddress

import psycopg2
import psycopg2.extras
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, Response, jsonify, abort,
)

# Import encryption utilities for AES-GCM comment encryption
from encryption import encrypt_comment, decrypt_comment

# Import HMAC utilities for grade export integrity protection
from hmac_utils import add_hmac_to_csv, verify_csv_integrity

# Import Argon2 password utilities for secure password storage (Class 5 Lab 2)
from password_utils import hash_password, verify_password, is_argon2_hash, needs_rehash

# --- Configuration ------------------------------------------------------------
# All configuration comes from the environment (set in docker-compose.yml).
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "notesapp")
DB_USER = os.environ.get("DB_USER", "notesapp")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024")
JWT_SECRET = os.environ.get("JWT_SECRET", "s3cr3t")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-session-key")

app = Flask(__name__)
app.secret_key = SECRET_KEY

LOG_FILE = os.environ.get("NOTESAPP_LOG", "/var/log/notesapp/app.log")


def log(msg):
    """Very small access log. No rotation, no policy (see flaw #14)."""
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


def valid_ping_host(host):
    """Validate host parameter - only accept IP addresses or simple hostnames."""
    if not host:
        return False
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Check if it's a simple hostname (alphanumeric + hyphens + dots)
    import re
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?$', host):
        return True
    return False


def can_read_note(ident, note):
    """Check if the current user has permission to read this note."""
    role = ident.get("role")
    user_id = ident.get("user_id")
    
    if role == "student":
        return note["student_id"] == user_id
    if role == "teacher":
        return note["teacher_id"] == user_id
    if role == "admin":
        return True
    return False


# --- Database -----------------------------------------------------------------
def get_db():
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    conn.autocommit = True
    return conn


# --- Minimal JWT (deliberately weak) ------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_jwt(token: str):
    """Decode and verify a JWT. Only HS256 with a valid signature is accepted.

    Fixed (flaw #4): "alg":"none" is rejected and the algorithm is pinned to
    HS256, so a token without a valid signature is refused.
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "").lower()
    # Fixed (flaw #4): reject "alg":"none" and pin the algorithm to HS256 so the
    # signature is ALWAYS verified. A forged token can no longer bypass auth.
    if alg != "hs256":
        return None
    signing_input = f"{h_b64}.{p_b64}".encode()
    expected = _b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
    if hmac.compare_digest(expected, sig_b64):
        return payload
    return None


def current_identity():
    """Return the acting identity from a Bearer JWT if present, else the session."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verify_jwt(auth[7:].strip())
        if payload:
            return payload
    if "user_id" in session:
        return {"user_id": session["user_id"], "username": session.get("username"),
                "role": session.get("role")}
    return None


# --- Auth helpers -------------------------------------------------------------
def login_required(role=None):
    if "user_id" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


# --- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        role = session.get("role")
        if role == "student":
            return redirect(url_for("dashboard"))
        if role == "teacher":
            return redirect(url_for("teacher"))
        if role == "admin":
            return redirect(url_for("admin"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        conn = get_db()
        cur = conn.cursor()
        try:
            # Get user with password hash
            cur.execute(
                "SELECT id, username, role, password FROM users "
                "WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
        except Exception as e:
            log(f"login query error: {e}")
            error = "Login failed."
            row = None
        
        if row:
            stored_password = row["password"]
            
            # Check password type and verify accordingly
            if is_argon2_hash(stored_password):
                # Argon2 hash - verify properly
                if verify_password(stored_password, password):
                    # Check if rehash needed (parameters updated)
                    if needs_rehash(stored_password):
                        new_hash = hash_password(password)
                        cur.execute(
                            "UPDATE users SET password = %s WHERE id = %s",
                            (new_hash, row["id"]),
                        )
                        conn.commit()
                        log(f"password rehashed for user={row['username']}")
                    # Login successful
                    pass
                else:
                    row = None  # Invalid password
            else:
                # Legacy plaintext or MD5 - verify directly, then upgrade
                if stored_password == password:
                    # Plaintext match - upgrade to Argon2
                    new_hash = hash_password(password)
                    cur.execute(
                        "UPDATE users SET password = %s WHERE id = %s",
                        (new_hash, row["id"]),
                    )
                    conn.commit()
                    log(f"password upgraded from plaintext for user={row['username']}")
                else:
                    row = None  # Invalid password
        
        conn.close()
        
        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["token"] = make_jwt({
                "user_id": row["id"], "username": row["username"], "role": row["role"],
            })
            log(f"login success user={row['username']} role={row['role']}")
            return redirect(url_for("index"))
        if not error:
            error = "Invalid credentials."
        log(f"login failure username={username!r}")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, c.name AS class_name "
        "FROM notes n JOIN classes c ON c.id = n.class_id "
        "WHERE n.student_id = %s ORDER BY c.name",
        (session["user_id"],),
    )
    notes = cur.fetchall()
    conn.close()
    
    # Decrypt comments before displaying to students
    for note in notes:
        note["comment"] = decrypt_comment(note["comment"])
    
    return render_template("dashboard.html", notes=notes, token=session.get("token"))


@app.route("/api/notes/<int:note_id>")
def api_notes(note_id):
    ident = current_identity()
    if not ident:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    # Fixed: Check note ownership before returning (prevent IDOR)
    cur.execute(
        "SELECT n.id, n.student_id, n.class_id, n.grade, n.comment, "
        "u.username AS student, c.name AS class_name, c.teacher_id "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id WHERE n.id = %s",
        (note_id,),
    )
    note = cur.fetchone()
    conn.close()
    if not note or not can_read_note(ident, note):
        return jsonify({"error": "not found"}), 404
    note["grade"] = float(note["grade"]) if note["grade"] is not None else None
    # Decrypt comment before returning via API
    note["comment"] = decrypt_comment(note["comment"])
    return jsonify(note)


@app.route("/teacher")
def teacher():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    # A teacher sees every class (no owner scoping - broken access control).
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY name")
    classes = cur.fetchall()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, n.student_id, n.class_id, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
    )
    notes = cur.fetchall()
    
    # Decrypt comments before displaying to teachers
    for note in notes:
        note["comment"] = decrypt_comment(note["comment"])
    
    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
    students = cur.fetchall()
    conn.close()
    return render_template("teacher.html", classes=classes, notes=notes, students=students)


@app.route("/grades", methods=["POST"])
def grades():
    # Fixed: Check CSRF and ownership before modifying grades
    if not login_required("teacher"):
        return redirect(url_for("login"))
    note_id = request.form.get("note_id", "").strip()
    student_id = request.form.get("student_id")
    class_id = request.form.get("class_id")
    grade = request.form.get("grade")
    comment = request.form.get("comment", "")

    # Encrypt the comment before storing in database (AES-GCM)
    encrypted_comment = encrypt_comment(comment)

    conn = get_db()
    cur = conn.cursor()
    
    if note_id:
        # Fixed: Check if this note belongs to teacher's class before updating
        cur.execute(
            "SELECT n.student_id, n.class_id, c.teacher_id "
            "FROM notes n JOIN classes c ON c.id = n.class_id "
            "WHERE n.id = %s",
            (note_id,),
        )
        row = cur.fetchone()
        if not row or row["teacher_id"] != session["user_id"]:
            conn.close()
            abort(403)
        
        cur.execute(
            "UPDATE notes SET grade = %s, comment = %s WHERE id = %s",
            (grade, encrypted_comment, note_id),
        )
    else:
        # Fixed: Check if teacher owns this class before inserting
        cur.execute(
            "SELECT teacher_id FROM classes WHERE id = %s",
            (class_id,),
        )
        row = cur.fetchone()
        if not row or row["teacher_id"] != session["user_id"]:
            conn.close()
            abort(403)
        
        cur.execute(
            "INSERT INTO notes (student_id, class_id, grade, comment) "
            "VALUES (%s, %s, %s, %s)",
            (student_id, class_id, grade, encrypted_comment),
        )
    
    conn.close()
    log(f"grade write by {session.get('username')} note_id={note_id or 'new'}")
    return redirect(url_for("teacher"))


@app.route("/export.csv")
def export_csv():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    class_id = request.args.get("class_id")
    conn = get_db()
    cur = conn.cursor()
    if class_id:
        cur.execute(
            "SELECT u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id WHERE n.class_id = %s "
            "ORDER BY u.username",
            (class_id,),
        )
    else:
        cur.execute(
            "SELECT u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
        )
    rows = cur.fetchall()
    conn.close()

    # Decrypt comments before exporting to CSV
    for row in rows:
        row["comment"] = decrypt_comment(row["comment"])

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["student", "class", "grade", "comment"])
    for r in rows:
        writer.writerow([r["student"], r["class"], r["grade"], r["comment"]])
    
    # Get raw CSV content
    csv_content = buf.getvalue()
    
    # Add HMAC for integrity protection (Class 4 requirement)
    csv_with_hmac = add_hmac_to_csv(csv_content)
    
    return Response(
        csv_with_hmac, mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=grades.csv"},
    )


@app.route("/verify-hmac", methods=["POST"])
def verify_hmac_upload():
    """
    Verify the integrity of an uploaded grades CSV file.
    
    This endpoint checks if the HMAC in the uploaded file matches
    the computed HMAC, detecting any tampering.
    """
    if not login_required("teacher"):
        return jsonify({"error": "unauthorized"}), 401
    
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "empty filename"}), 400
    
    # Read uploaded file content
    csv_content = file.read().decode("utf-8")
    
    # Verify HMAC integrity
    is_valid = verify_csv_integrity(csv_content)
    
    if is_valid:
        return jsonify({
            "status": "success",
            "message": "HMAC verification passed - file integrity confirmed",
            "valid": True
        })
    else:
        return jsonify({
            "status": "failed",
            "message": "HMAC verification failed - file may have been tampered!",
            "valid": False
        }), 403


@app.route("/admin")
def admin():
    if not login_required("admin"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    users = cur.fetchall()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    classes = cur.fetchall()
    conn.close()
    return render_template("admin.html", users=users, classes=classes,
                           ping_result=request.args.get("ping_result"))


@app.route("/admin/ping", methods=["POST"])
def admin_ping():
    # Fixed: Validate host parameter and use parameterized subprocess (no shell)
    if not login_required("admin"):
        return redirect(url_for("login"))
    host = request.form.get("host", "").strip()
    
    if not valid_ping_host(host):
        output = "Invalid host."
    else:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", host],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)
    
    log(f"admin ping host={host!r}")
    return render_template("admin.html", users=_all_users(), classes=_all_classes(),
                           ping_result=output)


def _all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


def _all_classes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


@app.route("/admin/users", methods=["POST"])
def admin_users():
    if not login_required("admin"):
        return redirect(url_for("login"))
    action = request.form.get("action")
    conn = get_db()
    cur = conn.cursor()
    if action == "create":
        cur.execute(
            "INSERT INTO users (username, password, role, teacher_id) "
            "VALUES (%s, %s, %s, %s)",
            (request.form.get("username"), request.form.get("password"),
            request.form.get("role", "student"), None),
        )
    elif action == "delete":
        cur.execute("DELETE FROM users WHERE id = %s", (request.form.get("user_id"),))
    conn.close()
    return redirect(url_for("admin"))


@app.route("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.close()
        return "ok", 200
    except Exception as e:
        return f"db error: {e}", 500


if __name__ == "__main__":
    # Plain HTTP on purpose (flaw #3). Nginx + TLS is added in a later lab.
    app.run(host="0.0.0.0", port=5000, debug=True)
