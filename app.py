import os
import csv
import sqlite3
import datetime
import qrcode
import re

from flask import (
    Flask, render_template, request,
    redirect, session, url_for,
    send_file, flash
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = "Brainydecsecretkey"

DB = "database.db"
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "csv"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= DATABASE =================
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        full_name TEXT,
        matric_no TEXT UNIQUE,
        department TEXT,
        level TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS units (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS officers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        unit_id INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS clearance_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        unit_id INTEGER,
        status TEXT,
        remark TEXT,
        updated_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        unit_id INTEGER,
        file_path TEXT,
        uploaded_at TEXT
    )
    """)

    conn.commit()
    conn.close()


def seed_units():
    units = ["Hostel", "Library"]
    conn = get_db()
    cur = conn.cursor()
    for u in units:
        cur.execute("INSERT OR IGNORE INTO units (name) VALUES (?)", (u,))
    conn.commit()
    conn.close()


# ================= HELPERS =================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Matric number pattern: fuku/sci/21/com/number or fuku/sci/21b/com/number
MATRIC_RE = re.compile(r'^fuku/sci/\d{2}b?/com/\d+$', re.IGNORECASE)


def login_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "role" not in session or session["role"] != role:
                return redirect("/")
            return f(*args, **kwargs)
        return decorated
    return wrapper


# ================= QR + PDF =================
def generate_qr(student_id):
    url = url_for("verify", student_id=student_id, _external=True)
    qr = qrcode.make(url)
    path = f"static/qr_{student_id}.png"
    qr.save(path)
    return path


def generate_clearance_pdf(student_id):
    conn = get_db()

    student = conn.execute(
        "SELECT * FROM students WHERE id=?",
        (student_id,)
    ).fetchone()

    statuses = conn.execute("""
        SELECT units.name, clearance_status.status
        FROM clearance_status
        JOIN units ON clearance_status.unit_id = units.id
        WHERE clearance_status.student_id=?
    """, (student_id,)).fetchall()

    conn.close()

    pdf_path = f"static/clearance_{student_id}.pdf"
    qr_path = generate_qr(student_id)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    # Add school logo on the left
    sch_logo_path = "static/images/sch.jpg"
    if os.path.exists(sch_logo_path):
        c.drawImage(sch_logo_path, 50, height - 100, width=80, height=80)
    
    # Add NAC logo on the right
    nac_logo_path = "static/images/nac.jpeg"
    if os.path.exists(nac_logo_path):
        c.drawImage(nac_logo_path, width - 130, height - 100, width=80, height=80)

    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width / 2, height - 50, "STUDENT CLEARANCE SLIP")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 140, f"Name: {student['full_name']}")
    c.drawString(50, height - 160, f"Matric No: {student['matric_no']}")
    c.drawString(50, height - 180, f"Department: {student['department']}")
    c.drawString(50, height - 200, f"Level: {student['level']}")

    y = height - 250
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Clearance Status")
    y -= 20

    c.setFont("Helvetica", 11)
    for s in statuses:
        c.drawString(70, y, f"{s['name']}: {s['status'].upper()}")
        y -= 18

    c.drawImage(qr_path, width - 170, 100, width=120, height=120)
    c.showPage()
    c.save()

    return pdf_path


# ================= AUTH =================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(f"/{user['role']}/dashboard")

        flash("Invalid login", "danger")

    return render_template("auth/login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ================= CHANGE PASSWORD =================
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/")
    
    if request.method == "POST":
        user_id = session["user_id"]
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not old_password or not new_password or not confirm_password:
            flash("All fields are required", "danger")
            return redirect("/change-password")
        
        if new_password != confirm_password:
            flash("New passwords do not match", "danger")
            return redirect("/change-password")
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        
        if not user or not check_password_hash(user["password_hash"], old_password):
            flash("Old password is incorrect", "danger")
            conn.close()
            return redirect("/change-password")
        
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(new_password), user_id)
        )
        conn.commit()
        conn.close()
        
        flash("Password changed successfully", "success")
        return redirect(f"/{session['role']}/dashboard")
    
    return render_template("auth/change_password.html")


# ================= ADMIN =================
@app.route("/admin/dashboard")
@login_required("admin")
def admin_dashboard():
    conn = get_db()

    students = conn.execute("""
        SELECT students.id AS student_id,
               students.full_name,
               students.matric_no,
               students.department,
               students.level,
               users.id AS user_id,
               users.username
        FROM students
        JOIN users ON students.user_id = users.id
    """).fetchall()

    officers = conn.execute("""
        SELECT officers.id AS officer_id,
               users.id AS user_id,
               users.username,
               units.name AS unit
        FROM officers
        JOIN users ON officers.user_id = users.id
        JOIN units ON officers.unit_id = units.id
    """).fetchall()

    conn.close()
    return render_template("admin/dashboard.html", students=students, officers=officers)


# ---------- VIEW STUDENT STATUS ----------
@app.route("/admin/student-status/<int:student_id>")
@login_required("admin")
def admin_view_student_status(student_id):
    conn = get_db()
    
    # Get student details
    student = conn.execute(
        "SELECT * FROM students WHERE id = ?",
        (student_id,)
    ).fetchone()
    
    if not student:
        conn.close()
        return "Student not found", 404
    
    # Get clearance statuses for all units
    statuses = conn.execute("""
        SELECT units.id AS unit_id, units.name, clearance_status.status, clearance_status.remark, clearance_status.updated_at
        FROM clearance_status
        JOIN units ON clearance_status.unit_id = units.id
        WHERE clearance_status.student_id = ?
        ORDER BY units.name
    """, (student_id,)).fetchall()
    
    conn.close()
    
    student_dict = dict(student) if student else {}
    return render_template("admin/view_student_status.html", student=student_dict, statuses=statuses)


# ================= OFFICER =================
@app.route("/officer/dashboard")
@login_required("officer")
def officer_dashboard():
    conn = get_db()
    
    # Get officer and their assigned unit
    officer = conn.execute("""
        SELECT officers.unit_id, units.name AS unit
        FROM officers
        JOIN users ON officers.user_id = users.id
        JOIN units ON officers.unit_id = units.id
        WHERE users.id = ?
    """, (session.get("user_id"),)).fetchone()
    
    if not officer:
        conn.close()
        return redirect("/logout")
    
    # Get all students with their clearance status for this unit
    students = conn.execute("""
        SELECT students.id,
               students.full_name,
               students.matric_no,
               students.department,
               students.level,
               clearance_status.status,
               clearance_status.remark
        FROM students
        JOIN clearance_status ON students.id = clearance_status.student_id
        WHERE clearance_status.unit_id = ?
        ORDER BY students.full_name
    """, (officer["unit_id"],)).fetchall()
    
    conn.close()
    return render_template("officer/dashboard.html", unit=officer["unit"], students=students)


# ---------- REVIEW STUDENT ----------
@app.route("/officer/review/<int:student_id>")
@login_required("officer")
def review_student_page(student_id):
    conn = get_db()
    
    # Verify officer is assigned to a unit
    officer = conn.execute("""
        SELECT officers.unit_id
        FROM officers
        JOIN users ON officers.user_id = users.id
        WHERE users.id = ?
    """, (session.get("user_id"),)).fetchone()
    
    if not officer:
        conn.close()
        return redirect("/logout")
    
    # Get student details
    student = conn.execute(
        "SELECT * FROM students WHERE id = ?",
        (student_id,)
    ).fetchone()
    
    if not student:
        conn.close()
        return "Student not found", 404
    
    # Get clearance status for this officer's unit
    clearance = conn.execute("""
        SELECT * FROM clearance_status
        WHERE student_id = ? AND unit_id = ?
    """, (student_id, officer["unit_id"])).fetchone()
    
    # Get uploaded documents for this student's unit
    uploads = conn.execute("""
        SELECT * FROM uploads
        WHERE student_id = ? AND unit_id = ?
    """, (student_id, officer["unit_id"])).fetchall()
    
    conn.close()
    
    student_dict = dict(student)
    if clearance:
        student_dict["status"] = clearance["status"]
        student_dict["remark"] = clearance["remark"]
    
    return render_template("officer/review_student.html", 
                         student=student_dict, 
                         uploads=uploads)


@app.route("/officer/review/<int:student_id>/submit", methods=["POST"])
@login_required("officer")
def review_student_submit(student_id):
    conn = get_db()
    
    # Verify officer is assigned to a unit
    officer = conn.execute("""
        SELECT officers.unit_id
        FROM officers
        JOIN users ON officers.user_id = users.id
        WHERE users.id = ?
    """, (session.get("user_id"),)).fetchone()
    
    if not officer:
        conn.close()
        return redirect("/logout")
    
    status = request.form.get("status")
    remark = request.form.get("remark", "")
    
    if status not in ["approved", "rejected", "pending"]:
        conn.close()
        return "Invalid status", 400
    
    cur = conn.cursor()
    cur.execute("""
        UPDATE clearance_status
        SET status = ?, remark = ?, updated_at = ?
        WHERE student_id = ? AND unit_id = ?
    """, (status, remark, datetime.datetime.now(), student_id, officer["unit_id"]))
    
    conn.commit()
    conn.close()
    
    return redirect("/officer/dashboard")


# ================= STUDENT =================
@app.route("/student/dashboard")
@login_required("student")
def student_dashboard():
    conn = get_db()
    
    # Get logged-in student
    student = conn.execute("""
        SELECT students.id, students.full_name, students.matric_no,
               students.department, students.level
        FROM students
        JOIN users ON students.user_id = users.id
        WHERE users.id = ?
    """, (session.get("user_id"),)).fetchone()
    
    if not student:
        conn.close()
        return redirect("/logout")
    
    # Get clearance statuses for all units
    statuses = conn.execute("""
        SELECT units.id AS unit_id, units.name, clearance_status.status, clearance_status.remark
        FROM clearance_status
        JOIN units ON clearance_status.unit_id = units.id
        WHERE clearance_status.student_id = ?
        ORDER BY units.name
    """, (student["id"],)).fetchall()
    
    # Check if all clearances are approved
    cleared = all(s["status"] == "approved" for s in statuses)
    
    conn.close()
    return render_template("student/dashboard.html", student=student, statuses=statuses, cleared=cleared)


# ---------- DOWNLOAD CLEARANCE ----------
@app.route("/student/download-clearance")
@login_required("student")
def download_clearance():
    conn = get_db()

    student = conn.execute("""
        SELECT students.id, students.full_name, students.matric_no
        FROM students
        JOIN users ON students.user_id = users.id
        WHERE users.id = ?
    """, (session.get("user_id"),)).fetchone()

    if not student:
        conn.close()
        return redirect("/logout")

    statuses = conn.execute("""
        SELECT clearance_status.status
        FROM clearance_status
        WHERE clearance_status.student_id = ?
    """, (student["id"],)).fetchall()

    cleared = all(s["status"] == "approved" for s in statuses)
    conn.close()

    if not cleared:
        flash("Clearance not complete yet.", "warning")
        return redirect("/student/dashboard")

    pdf_path = generate_clearance_pdf(student["id"])
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"clearance_{student['matric_no']}.pdf",
        mimetype="application/pdf",
    )


# ---------- VERIFY CLEARANCE ----------
@app.route("/verify/<int:student_id>")
def verify(student_id):
    conn = get_db()
    student = conn.execute(
        "SELECT * FROM students WHERE id = ?",
        (student_id,)
    ).fetchone()

    if not student:
        conn.close()
        return "Student not found", 404

    statuses = conn.execute("""
        SELECT clearance_status.status
        FROM clearance_status
        WHERE clearance_status.student_id = ?
    """, (student_id,)).fetchall()

    conn.close()

    cleared = all(s["status"] == "approved" for s in statuses)
    state = "CLEARED" if cleared else "NOT CLEARED"

    return f"Student: {student['full_name']} ({student['matric_no']}) - {state}"


# ---------- UPLOAD DOCUMENT ----------
@app.route("/student/upload/<int:unit_id>", methods=["POST"])
@login_required("student")
def upload_document(unit_id):
    file = request.files.get("file")
    if not file or not allowed_file(file.filename):
        flash("Invalid file or no file provided", "danger")
        return redirect("/student/dashboard")
    
    conn = get_db()
    
    # Get the logged-in student
    student = conn.execute("""
        SELECT students.id FROM students
        JOIN users ON students.user_id = users.id
        WHERE users.id = ?
    """, (session.get("user_id"),)).fetchone()
    
    if not student:
        conn.close()
        return redirect("/logout")
    
    # Save the file
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, f"{student['id']}_{unit_id}_{filename}")
    file.save(file_path)
    
    # Record in database
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO uploads (student_id, unit_id, file_path, uploaded_at)
        VALUES (?, ?, ?, ?)
    """, (student["id"], unit_id, file_path, datetime.datetime.now()))
    
    conn.commit()
    conn.close()
    
    flash("Document uploaded successfully", "success")
    return redirect("/student/dashboard")


# ---------- ADD STUDENT ----------
@app.route("/admin/add-student", methods=["GET", "POST"])
@login_required("admin")
def add_student():
    if request.method == "POST":
        full_name = request.form["full_name"]
        matric = request.form["matric"]
        # validate matric format
        if not MATRIC_RE.match(matric.strip()):
            flash("Matric number must follow fuku/sci/21/com/number or fuku/sci/21b/com/number", "danger")
            return redirect(url_for('add_student'))
        password = request.form.get("password", "").strip() or "12345678"
        # Use matric number as the student's username for login
        username = matric


        department = "Computer Science"
        level = "400"
        faculty = "Science"  # logical default

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, 'student', ?)
        """, (username, generate_password_hash(password), datetime.datetime.now()))
        user_id = cur.lastrowid

        cur.execute("""
            INSERT INTO students (user_id, full_name, matric_no, department, level)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, full_name, matric, department, level))
        student_id = cur.lastrowid

        units = cur.execute("SELECT id FROM units").fetchall()
        for u in units:
            cur.execute("""
                INSERT INTO clearance_status
                (student_id, unit_id, status, remark, updated_at)
                VALUES (?, ?, 'pending', '', ?)
            """, (student_id, u["id"], datetime.datetime.now()))

        conn.commit()
        conn.close()
        return redirect("/admin/dashboard")

    return render_template("admin/add_student.html")


# ---------- BULK ADD ----------
@app.route("/admin/bulk-add-students", methods=["POST"])
@login_required("admin")
def bulk_add_students():
    file = request.files.get("file")
    if not file or not allowed_file(file.filename):
        flash("Invalid file or no file provided", "danger")
        return redirect("/admin/dashboard")
    try:
        reader = csv.DictReader(file.read().decode("utf-8").splitlines())
        conn = get_db()
        cur = conn.cursor()
        units = cur.execute("SELECT id FROM units").fetchall()
        
        added = 0
        failed = 0

        def find_val(row, *names):
            if not row:
                return None
            for key in row.keys():
                if not key:
                    continue
                norm = key.strip().lower().replace(" ", "").replace("_", "")
                for n in names:
                    if norm == n.strip().lower().replace(" ", "").replace("_", ""):
                        return row[key]
            return None

        for row_num, row in enumerate(reader, start=2):
            try:
                full_name = find_val(row, "fullname", "full_name")
                matric_no = find_val(row, "matric number", "matric_no", "matric", "matricno")
                password = find_val(row, "password") or "12345678"

                if not full_name or not matric_no:
                    failed += 1
                    continue

                # validate matric format
                if not MATRIC_RE.match(matric_no.strip()):
                    failed += 1
                    continue


                # Use matric_no as username
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, created_at)
                    VALUES (?, ?, 'student', ?)
                """, (
                    matric_no.strip(),
                    generate_password_hash(password),
                    datetime.datetime.now()
                ))
                user_id = cur.lastrowid

                cur.execute("""
                    INSERT INTO students (user_id, full_name, matric_no, department, level)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    user_id,
                    full_name.strip(),
                    matric_no.strip(),
                    "Computer Science",
                    "400"
                ))
                student_id = cur.lastrowid

                for u in units:
                    cur.execute("""
                        INSERT INTO clearance_status
                        (student_id, unit_id, status, remark, updated_at)
                        VALUES (?, ?, 'pending', '', ?)
                    """, (student_id, u["id"], datetime.datetime.now()))
                
                added += 1

            except (sqlite3.IntegrityError, KeyError, ValueError) as e:
                failed += 1
                continue

        conn.commit()
        conn.close()
        
        flash(f"Bulk add complete: {added} added, {failed} failed", "info")

    except Exception as e:
        flash(f"Error processing file: {str(e)}", "danger")
    
    return redirect("/admin/dashboard")


@app.route("/admin/bulk-add-students-form")
@login_required("admin")
def bulk_add_students_form():
    return render_template("admin/bulk_add_students.html")

# ---------- FORM-BASED BULK ADD ----------
@app.route("/admin/form-bulk-add-students", methods=["GET", "POST"])
@login_required("admin")
def form_bulk_add_students():
    if request.method == "POST":
        # Get the number of rows submitted
        num_rows = int(request.form.get("num_rows", 1))
        
        conn = get_db()
        cur = conn.cursor()
        units = cur.execute("SELECT id FROM units").fetchall()
        
        added = 0
        failed = 0
        errors = []
        
        for i in range(num_rows):
            try:
                full_name = request.form.get(f"full_name_{i}", "").strip()
                matric_no = request.form.get(f"matric_no_{i}", "").strip()
                password = request.form.get(f"password_{i}", "").strip() or "12345678"
                
                # Skip empty rows
                if not full_name or not matric_no:
                    continue
                
                # Validate matric format
                if not MATRIC_RE.match(matric_no):
                    errors.append(f"Row {i+1}: Invalid matric format for {matric_no}")
                    failed += 1
                    continue
                
                # Create user
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, created_at)
                    VALUES (?, ?, 'student', ?)
                """, (matric_no, generate_password_hash(password), datetime.datetime.now()))
                user_id = cur.lastrowid
                
                # Create student
                cur.execute("""
                    INSERT INTO students (user_id, full_name, matric_no, department, level)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, full_name, matric_no, "Computer Science", "400"))
                student_id = cur.lastrowid
                
                # Create clearance status records
                for u in units:
                    cur.execute("""
                        INSERT INTO clearance_status
                        (student_id, unit_id, status, remark, updated_at)
                        VALUES (?, ?, 'pending', '', ?)
                    """, (student_id, u["id"], datetime.datetime.now()))
                
                added += 1
                
            except sqlite3.IntegrityError as e:
                errors.append(f"Row {i+1}: Student already exists or database error")
                failed += 1
            except Exception as e:
                errors.append(f"Row {i+1}: {str(e)}")
                failed += 1
        
        conn.commit()
        conn.close()
        
        if errors:
            for error in errors:
                flash(error, "warning")
        
        flash(f"Bulk add complete: {added} added, {failed} failed", "info")
        return redirect("/admin/dashboard")
    
    return render_template("admin/form_bulk_add_students.html")

# ---------------- ADMIN: ADD OFFICER ----------------
@app.route("/admin/add-officer", methods=["GET", "POST"])
@login_required("admin")
def add_officer():
    conn = get_db()
    units = conn.execute("SELECT * FROM units").fetchall()

    if request.method == "POST":
        username = request.form["username"]
        password = request.form.get("password", "").strip() or "12345678"
        unit_id = request.form["unit_id"]

        cur = conn.cursor()

        # create officer user
        cur.execute("""
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, 'officer', ?)
        """, (
            username,
            generate_password_hash(password),
            datetime.datetime.now()
        ))
        user_id = cur.lastrowid

        # assign officer to unit
        cur.execute("""
            INSERT INTO officers (user_id, unit_id)
            VALUES (?, ?)
        """, (user_id, unit_id))

        conn.commit()
        conn.close()
        return redirect("/admin/dashboard")

    conn.close()
    return render_template("admin/add_officer.html", units=units)
# ---------------- ADMIN: RESET PASSWORD ----------------
@app.route("/admin/reset-password", methods=["POST"])
@login_required("admin")
def admin_reset_password():
    user_id = request.form.get("user_id")
    new_password = request.form.get("new_password")

    if not user_id or not new_password:
        return "Invalid request", 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET password_hash=?
        WHERE id=?
    """, (generate_password_hash(new_password), user_id))

    conn.commit()
    conn.close()
    return redirect("/admin/dashboard")
# ---------------- ADMIN: DELETE USER ----------------
@app.route("/admin/delete-user", methods=["POST"])
@login_required("admin")
def admin_delete_user():
    user_id = request.form.get("user_id")
    role = request.form.get("role")

    if not user_id or not role:
        return "Invalid request", 400

    conn = get_db()
    cur = conn.cursor()

    if role == "student":
        student = cur.execute(
            "SELECT id FROM students WHERE user_id=?",
            (user_id,)
        ).fetchone()

        if student:
            student_id = student["id"]

            # delete dependent data first
            cur.execute("DELETE FROM uploads WHERE student_id=?", (student_id,))
            cur.execute("DELETE FROM clearance_status WHERE student_id=?", (student_id,))
            cur.execute("DELETE FROM students WHERE id=?", (student_id,))

    elif role == "officer":
        cur.execute(
            "DELETE FROM officers WHERE user_id=?",
            (user_id,)
        )

    # finally remove login account
    cur.execute(
        "DELETE FROM users WHERE id=?",
        (user_id,)
    )

    conn.commit()
    conn.close()
    return redirect("/admin/dashboard")

# ================= RUN =================
if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
        seed_units()

        conn = get_db()
        conn.execute("""
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES ('admin', ?, 'admin', ?)
        """, (generate_password_hash("admin123"), datetime.datetime.now()))
        conn.commit()
        conn.close()

    app.run(host="0.0.0.0", port=5000, debug=True)
