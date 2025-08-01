import os
import hashlib
import psycopg2
import psycopg2.extras
from flask import Flask, request, render_template, redirect, session, url_for, flash, abort
from contextlib import contextmanager
from datetime import date
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from dotenv import load_dotenv
from datetime import datetime
from collections import defaultdict

# 📦 Load .env variables
if os.getenv("FLASK_ENV") != "production":
    from dotenv import load_dotenv
    load_dotenv()


# 🛠️ Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key'

# 🗃️ Database config using SQLAlchemy
from sqlalchemy.engine.url import URL

DATABASE = {
    'drivername': 'postgresql',
    'username': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASSWORD"),
    'host': os.getenv("DB_HOST"),
    'port': os.getenv("DB_PORT"),
    'database': os.getenv("DB_NAME"),
}

engine = create_engine(
    URL.create(**DATABASE),
    pool_size=10,
    max_overflow=5,
    pool_timeout=30,
    pool_recycle=1800,
    echo=False
)

db_session = scoped_session(sessionmaker(bind=engine))

# 🔄 Context manager for DB access
@contextmanager
def get_db():
    conn = engine.raw_connection()
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()


# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize tables
def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT,
                email TEXT UNIQUE,
                password TEXT,
                role TEXT,
                semester TEXT,
                branch TEXT,
                roll_number TEXT
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS subjects (
                id SERIAL PRIMARY KEY,
                name TEXT,
                code TEXT,
                semester TEXT,
                branch TEXT,
                faculty_id INTEGER
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id SERIAL PRIMARY KEY,
                student_id INTEGER,
                subject_id INTEGER,
                date DATE,
                hour INTEGER,
                present BOOLEAN,
                UNIQUE(student_id, subject_id, date, hour)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
               id SERIAL PRIMARY KEY,
               email TEXT NOT NULL,
               role TEXT CHECK(role IN ('student', 'faculty'))
        )
        ''')

        # Default admin setup
        admin_email = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@example.com")
        admin_pass = os.environ.get("DEFAULT_ADMIN_PASS", "admin123")
        hashed = hash_password(admin_pass)

        db.execute("SELECT * FROM users WHERE email = %s AND role = %s", (admin_email, 'admin'))
        exists = db.fetchone()
        if not exists:
            db.execute('''
                INSERT INTO users (name, email, password, role)
                VALUES (%s, %s, %s, %s)
            ''', ("Admin", admin_email, hashed, 'admin'))
            print(f"✅ Admin created: {admin_email}")

init_db()

# 🏠 Home route
@app.route('/')
def home():
    return render_template('home.html')

# ---------------------
# 🔐 WHITELIST HELPERS
# ---------------------
def load_whitelist(role):
    with get_db() as db:
        db.execute("SELECT email FROM whitelist WHERE role = %s", (role,))
        return [row['email'] for row in db.fetchall()]

def is_whitelisted(email, role):
    whitelist = load_whitelist(role)
    return any(email == w or email.endswith(w) for w in whitelist)

def save_whitelist(role, emails):
    with get_db() as db:
        db.execute("DELETE FROM whitelist WHERE role = %s", (role,))
        for email in emails:
            db.execute("INSERT INTO whitelist (email, role) VALUES (%s, %s)", (email.strip(), role))

# ----------------------
# 👨‍🎓 Student Registration
# ----------------------
@app.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        semester = request.form['semester']
        branch = request.form['branch']
        roll_number = request.form['roll_number']

        if not is_whitelisted(email, 'student'):
            flash('❌ This email is not authorized to register as student.', 'danger')
            return redirect(request.url)

        if password != confirm_password:
            flash("❌ Passwords do not match", "danger")
            return redirect(request.url)

        hashed = hash_password(password)

        try:
            with get_db() as db:
                db.execute('''
                    INSERT INTO users (name, email, password, role, semester, branch, roll_number)
                    VALUES (%s, %s, %s, 'student', %s, %s, %s)
                ''', (name, email, hashed, semester, branch, roll_number))
            flash("✅ Student registered successfully", "success")
            return redirect(url_for('home'))
        except psycopg2.IntegrityError:
            flash("⚠️ Email already exists. Please use another.", "warning")
            return redirect(request.url)

    return render_template('student_register.html')


# ----------------------
# 👨‍🏫 Faculty Registration
# ----------------------
@app.route('/register/faculty', methods=['GET', 'POST'])
def register_faculty():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not is_whitelisted(email, 'faculty'):
            flash('❌ This email is not authorized to register as faculty.', 'danger')
            return redirect(request.url)

        if password != confirm_password:
            flash("❌ Passwords do not match", "danger")
            return redirect(request.url)

        hashed = hash_password(password)

        try:
            with get_db() as db:
                db.execute('''
                    INSERT INTO users (name, email, password, role)
                    VALUES (%s, %s, %s, 'faculty')
                ''', (name, email, hashed))
            flash("✅ Faculty registered successfully", "success")
            return redirect(url_for('home'))
        except psycopg2.IntegrityError:
            flash("⚠️ Email already exists. Please use another.", "warning")
            return redirect(request.url)

    return render_template('faculty_register.html')


# ----------------------
# 🔑 Login (Student + Faculty)
# ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])

        with get_db() as db:
            db.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, password))
            user = db.fetchone()

        if user:
            if user['role'] == 'admin':
                flash('⚠️ Admins must log in from the Admin Login page.', 'warning')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            session['role'] = user['role']
            session['name'] = user['name']
            flash('✅ Login successful!', 'success')

            if user['role'] == 'faculty':
                return redirect(url_for('faculty_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('❌ Invalid email or password.', 'danger')

    return render_template('login.html')


# ----------------------
# 🔓 Logout
# ----------------------
@app.route('/logout')
def logout():
    session.clear()
    flash('🔓 Logged out successfully!', 'success')
    return redirect(url_for('home'))
# ----------------------
# 🎓 Faculty Dashboard
# ----------------------
@app.route('/faculty/dashboard')
def faculty_dashboard():
    if session.get('role') != 'faculty':
        return redirect(url_for('login'))
    return render_template('faculty_dashboard.html', name=session['name'])
@app.route('/student/dashboard')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('login'))

    student_id = session['user_id']
    with get_db() as db:
        db.execute('''
            SELECT s.id AS subject_id, s.name AS subject_name, s.code AS subject_code,
                   COUNT(a.id) AS total,
                   SUM(a.present::int) AS present
            FROM attendance a
            JOIN subjects s ON a.subject_id = s.id
            WHERE a.student_id = %s
            GROUP BY s.id
        ''', (student_id,))
        records = db.fetchall()

    # Add percentage calculation
    for rec in records:
        total = rec['total']
        present = rec['present'] or 0
        rec['percentage'] = round((present / total) * 100, 2) if total > 0 else 0

    return render_template(
        'student_dashboard.html',
        name=session['name'],
        attendance_summary=records  # 🔁 match template variable
    )





# ----------------------
# ➕ Add Subject
# ----------------------
@app.route('/faculty/add_subject', methods=['GET', 'POST'])
def add_subject():
    if session.get('role') != 'faculty':
        flash('⚠️ Unauthorized access.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        semester = request.form['semester']
        branch = request.form['branch']
        faculty_id = session['user_id']

        with get_db() as db:
            db.execute('''
                INSERT INTO subjects (name, code, semester, branch, faculty_id)
                VALUES (%s, %s, %s, %s, %s)
            ''', (name, code, semester, branch, faculty_id))

        flash('📘 Subject added successfully!', 'success')
        return redirect(url_for('faculty_dashboard'))

    return render_template('add_subject.html')


# ----------------------
# 📚 Faculty View Subjects
# ----------------------
@app.route('/faculty/subjects')
def faculty_subjects():
    if session.get('role') != 'faculty':
        return redirect(url_for('login'))

    with get_db() as db:
        db.execute('SELECT * FROM subjects WHERE faculty_id = %s', (session['user_id'],))
        subjects = db.fetchall()
    return render_template('faculty_subjects.html', subjects=subjects)


# ----------------------
# 🗑️ Delete Subject
# ----------------------
@app.route('/faculty/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if session.get('role') != 'faculty':
        abort(403)

    with get_db() as db:
        db.execute("DELETE FROM attendance WHERE subject_id = %s", (subject_id,))
        db.execute("DELETE FROM subjects WHERE id = %s", (subject_id,))

    flash("Subject and related attendance deleted successfully", "success")
    return redirect(url_for('faculty_subjects'))


# ----------------------
# 📅 Select Subject + Date + Hour for Attendance
# ----------------------
@app.route('/faculty/select_subject_for_attendance', methods=['GET', 'POST'])
def mark_attendance_select_subject():
    if session.get('role') != 'faculty':
        flash('⚠️ Unauthorized access.', 'warning')
        return redirect(url_for('login'))

    with get_db() as db:
        faculty_id = session['user_id']
        db.execute('SELECT * FROM subjects WHERE faculty_id = %s', (faculty_id,))
        subjects = db.fetchall()

    from datetime import date
    current_date = date.today().isoformat()

    if request.method == 'POST':
        subject_id = request.form['subject_id']
        date_val = request.form['date']
        hour = request.form['hour']

        # ✅ Check if attendance already exists
        with get_db() as db:
            db.execute('''
                SELECT 1 FROM attendance
                WHERE subject_id = %s AND date = %s AND hour = %s
                LIMIT 1
            ''', (subject_id, date_val, hour))
            exists = db.fetchone()

        if exists:
            flash("⚠️ Attendance already marked for this subject, date, and hour.", "warning")
            return redirect(url_for('mark_attendance_select_subject'))

        return redirect(url_for('mark_attendance', subject_id=subject_id, date=date_val, hour=hour))


    return render_template('select_subject_for_attendance.html', subjects=subjects, current_date=current_date)


# ----------------------
# ✅ Mark Attendance
# ----------------------
@app.route('/faculty/mark/<int:subject_id>/<date>/<int:hour>', methods=['GET', 'POST'])
def mark_attendance(subject_id, date, hour):
    if session.get('role') != 'faculty':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    # Convert date string to datetime object
    try:
        date_obj = datetime.strptime(date, "%Y-%m-%d").date()  # Assuming format is YYYY-MM-DD
    except ValueError:
        flash("Invalid date format", "danger")
        return redirect(url_for('faculty_dashboard'))  # Adjust redirect as needed

    with get_db() as db:
        db.execute("SELECT * FROM subjects WHERE id = %s", (subject_id,))
        subject = db.fetchone()

        db.execute('''
            SELECT * FROM users
            WHERE role = 'student' AND semester = %s AND branch = %s
            ORDER BY roll_number::int       
        ''', (subject['semester'], subject['branch']))
        students = db.fetchall()

    if request.method == 'POST':
        absentees = []
        present_status = {}

        for student in students:
            student_id = int(student['id'])
            present = 1 if f"present_{student_id}" in request.form else 0
            present_status[str(student['id'])] = present

            if not present:
                absentees.append(student['roll_number'])

        session['attendance_temp'] = {
            'subject_id': subject_id,
            'date': date,
            'hour': hour,
            'status': present_status
        }

        return render_template(
            'attendance_preview.html',
            absentees=absentees,
            subject=subject,
            date=date_obj,
            hour=hour
        )

    return render_template('mark_attendance.html', students=students, subject=subject, date=date_obj, hour=hour)





# ----------------------
# 📝 Confirm Attendance
# ----------------------
@app.route('/faculty/mark/confirm', methods=['POST'])
def confirm_attendance():
    if 'attendance_temp' not in session:
        flash("No attendance to confirm", "warning")
        return redirect(url_for('faculty_dashboard'))

    data = session.pop('attendance_temp')

    with get_db() as cursor:
        cursor.execute('''
            SELECT * FROM users
            WHERE role = 'student' AND semester = (
                SELECT semester FROM subjects WHERE id = %s
            ) AND branch = (
                SELECT branch FROM subjects WHERE id = %s
            )
        ''', (data['subject_id'], data['subject_id']))
        students = cursor.fetchall()

        for student in students:
            present = data['status'].get(str(student['id']), 0) == 1
            print(f"✅ Saving for {student['name']} ({student['id']}): {present} Raw Status: {data['status']}")

            cursor.execute('''
                INSERT INTO attendance (student_id, subject_id, date, hour, present)
                VALUES (%s, %s, %s, %s, %s)
            ''', (student['id'], data['subject_id'], data['date'], data['hour'], present))

    flash("✅ Attendance successfully saved!", "success")
    return redirect(url_for('faculty_dashboard'))



# ----------------------
# 🔐 Admin Login
# ----------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])

        with get_db() as db:
            db.execute("SELECT * FROM users WHERE email = %s AND password = %s AND role = 'admin'", (email, password))
            user = db.fetchone()

        if user:
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            flash('✅ Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials", "danger")

    return render_template('admin_login.html')


# ----------------------
# 🧑‍💼 Admin Dashboard
# ----------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')


# Helper
def is_admin():
    return session.get('role') == 'admin'


# ----------------------
# 👥 Admin: Manage Users
# ----------------------
@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if not is_admin(): abort(403)
    filters = {}
    query = "SELECT * FROM users WHERE 1=1"
    params = []

    if request.method == 'POST':
        role = request.form.get('role')
        semester = request.form.get('semester')
        branch = request.form.get('branch')

        if role:
            query += " AND role = %s"
            params.append(role)
            filters['role'] = role
        if semester:
            query += " AND semester = %s"
            params.append(semester)
            filters['semester'] = semester
        if branch:
            query += " AND branch = %s"
            params.append(branch)
            filters['branch'] = branch

    with get_db() as db:
        db.execute(query, params)
        users = db.fetchall()

    return render_template("admin_users.html", users=users, filters=filters)


@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not is_admin(): abort(403)

    with get_db() as db:
        db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = db.fetchone()

        if not user:
            flash("User not found", "danger")
            return redirect(url_for('admin_users'))

        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            role = request.form['role']

            semester = request.form.get('semester') if role == 'student' else None
            branch = request.form.get('branch') if role == 'student' else None
            roll_number = request.form.get('roll_number') if role == 'student' else None

            db.execute('''
                UPDATE users SET name=%s, email=%s, role=%s, semester=%s, branch=%s, roll_number=%s
                WHERE id=%s
            ''', (name, email, role, semester, branch, roll_number, user_id))

            flash("✅ User updated successfully", "success")
            return redirect(url_for('admin_users'))

    return render_template('edit_user.html', user=user)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin(): abort(403)
    with get_db() as db:
        db.execute('DELETE FROM users WHERE id = %s', (user_id,))
    flash('User deleted.', 'info')
    return redirect(url_for('admin_users'))
# ----------------------
# 📚 Admin: Subjects
# ----------------------
@app.route('/admin/subjects', methods=['GET', 'POST'])
def admin_subjects():
    if not is_admin():
        abort(403)

    filters = {'keyword': '', 'semester': '', 'branch': ''}
    query = "SELECT * FROM subjects WHERE 1=1"
    args = []

    if request.method == 'POST':
        filters['keyword'] = request.form.get('keyword', '').strip()
        filters['semester'] = request.form.get('semester', '')
        filters['branch'] = request.form.get('branch', '')

        if filters['keyword']:
            query += " AND (name ILIKE %s OR code ILIKE %s)"
            args.extend([f"%{filters['keyword']}%", f"%{filters['keyword']}%"])
        if filters['semester']:
            query += " AND semester = %s"
            args.append(filters['semester'])
        if filters['branch']:
            query += " AND branch = %s"
            args.append(filters['branch'])

    with get_db() as db:
        db.execute(query, args)
        subjects = db.fetchall()

    return render_template('admin_subjects.html', subjects=subjects, filters=filters)


@app.route('/admin/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if not is_admin(): abort(403)

    with get_db() as db:
        db.execute("SELECT * FROM subjects WHERE id = %s", (subject_id,))
        subject = db.fetchone()

        if not subject:
            flash("Subject not found", "danger")
            return redirect(url_for('admin_subjects'))

        if request.method == 'POST':
            name = request.form['name']
            code = request.form['code']
            semester = request.form['semester']
            branch = request.form['branch']
            faculty_id = request.form.get('faculty_id') or None

            db.execute('''
                UPDATE subjects SET name=%s, code=%s, semester=%s, branch=%s, faculty_id=%s
                WHERE id=%s
            ''', (name, code, semester, branch, faculty_id, subject_id))

            flash("✅ Subject updated successfully", "success")
            return redirect(url_for('admin_subjects'))

    return render_template('edit_subject.html', subject=subject)


@app.route('/admin/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject_admin(subject_id):
    if not is_admin():
        abort(403)

    with get_db() as db:
        db.execute('DELETE FROM attendance WHERE subject_id = %s', (subject_id,))
        db.execute('DELETE FROM subjects WHERE id = %s', (subject_id,))

    flash('🗑️ Subject and related attendance deleted.', 'info')
    return redirect(url_for('admin_subjects'))


# ----------------------
# 🗓️ Admin: Attendance Records
# ----------------------
@app.route('/admin/attendance')
def admin_attendance():
    if not is_admin():
        abort(403)

    with get_db() as db:
        db.execute('''
            SELECT a.date, a.hour, a.present,
                   u.name as student_name, u.roll_number,
                   s.name as subject_name, s.code
            FROM attendance a
            JOIN users u ON a.student_id = u.id
            JOIN subjects s ON a.subject_id = s.id
            ORDER BY date DESC, hour DESC
        ''')
        records = db.fetchall()

    return render_template('admin_attendance.html', records=records)


@app.route('/admin/student-attendance', methods=['GET', 'POST'])
def admin_view_student_attendance():
    if not is_admin():
        abort(403)

    student = records = None
    if request.method == 'POST':
        semester = request.form.get('semester')
        branch = request.form.get('branch')
        roll_number = request.form.get('roll_number')

        with get_db() as db:
            db.execute(
                "SELECT * FROM users WHERE role='student' AND semester=%s AND branch=%s AND roll_number=%s",
                (semester, branch, roll_number)
            )
            student = db.fetchone()

            if student:
                db.execute('''
                    SELECT s.id AS subject_id, s.name AS subject_name, s.code AS subject_code,
                           COUNT(a.id) AS total,
                           SUM(a.present::int) AS present
                    FROM attendance a
                    JOIN subjects s ON a.subject_id = s.id
                    WHERE a.student_id = %s
                    GROUP BY s.id
                ''', (student['id'],))
                records = db.fetchall()

    return render_template('admin_view_student_attendance.html', student=student, records=records)


# ----------------------
# 📋 Admin: Whitelist
# ----------------------
def save_whitelist(role, emails):
    with get_db() as db:
        db.execute("DELETE FROM whitelist WHERE role = %s", (role,))
        for email in emails:
            db.execute("INSERT INTO whitelist (email, role) VALUES (%s, %s)", (email.strip(), role))


@app.route('/admin/whitelist/<role>', methods=['GET', 'POST'])
def manage_whitelist(role):
    if not is_admin():
        abort(403)

    if role not in ['student', 'faculty']:
        abort(400)

    emails = load_whitelist(role)

    if request.method == 'POST':
        new_emails = request.form.get('emails', '')
        updated_list = new_emails.strip().splitlines()
        save_whitelist(role, updated_list)
        flash(f'✅ {role.capitalize()} whitelist updated successfully.', 'success')
        return redirect(url_for('manage_whitelist', role=role))

    return render_template('admin_whitelist.html', emails="\n".join(emails), role=role)


@app.route('/admin/whitelist-options')
def manage_whitelist_options():
    if not is_admin():
        abort(403)
    return render_template('manage_whitelist_options.html')
# -----------------------------------------
# 📄 View Attendance Detail (Student View)
# -----------------------------------------
@app.route('/student/attendance/<int:subject_id>')
def view_attendance_detail(subject_id):
    student_id = session.get('user_id')
    if is_admin() and request.args.get('student_id'):
        student_id = request.args.get('student_id')

    with get_db() as db:
        db.execute("SELECT * FROM subjects WHERE id = %s", (subject_id,))
        subject = db.fetchone()

        db.execute('''
            SELECT * FROM attendance
            WHERE subject_id = %s AND student_id = %s
            ORDER BY date, hour
        ''', (subject_id, student_id))
        records = db.fetchall()

    return render_template('student_attendance_detail.html', subject=subject, records=records)


# -----------------------------------------
# 🧑‍🏫 Faculty View of Subject Attendance
# -----------------------------------------
@app.route('/faculty/subject/<int:subject_id>/attendance')
def view_attendance_detail_faculty(subject_id):
    if 'user_id' not in session or session['role'] != 'faculty':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    with get_db() as db:
        db.execute("SELECT * FROM subjects WHERE id = %s AND faculty_id = %s",
                   (subject_id, session['user_id']))
        subject = db.fetchone()

        if not subject:
            flash("Subject not found or not authorized", "danger")
            return redirect(url_for('faculty_dashboard'))

        db.execute('''
         SELECT u.name AS student_name, u.roll_number,
           COUNT(a.id) AS total_classes,
           SUM(a.present::int) AS present_count
          FROM attendance a
    JOIN users u ON a.student_id = u.id
    WHERE a.subject_id = %s
    GROUP BY u.id
    ORDER BY u.roll_number
''', (subject_id,))
        records = db.fetchall()

    return render_template('faculty_attendance_detail.html', subject=subject, records=records)


# -----------------------------------------
# 🔁 Basic Health Check Route
# -----------------------------------------
@app.route('/ping')
def ping():
    return "pong"


# -----------------------------------------
# ❌ Disable Browser Caching
# -----------------------------------------
@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store'
    return response
@app.route('/debug/attendance')
def debug_attendance_table():
    with get_db() as db:
        db.execute("SELECT * FROM attendance ORDER BY id DESC LIMIT 20")
        records = db.fetchall()
    return render_template('debug_attendance.html', records=records)

@app.route('/faculty/subject/<int:subject_id>/edit/<student_roll>', methods=['GET', 'POST'])
def edit_attendance(subject_id, student_roll):
    
    if 'user_id' not in session or session['role'] != 'faculty':
        abort(403)

    with get_db() as db:
        # Get subject info
        db.execute("SELECT * FROM subjects WHERE id = %s AND faculty_id = %s", (subject_id, session['user_id']))
        subject = db.fetchone()
        if not subject:
            flash("Subject not found or not authorized", "danger")
            return redirect(url_for('faculty_dashboard'))

        # Get student info
        db.execute("SELECT * FROM users WHERE roll_number = %s AND semester = %s AND branch = %s",
                   (student_roll, subject['semester'], subject['branch']))
        student = db.fetchone()
        if not student:
            flash("Student not found in this subject", "danger")
            return redirect(url_for('faculty_dashboard'))

        # Handle form
        if request.method == 'POST':
            date_val = request.form['date']
            hour = int(request.form['hour'])
            new_status = request.form['present'] == '1'

            db.execute('''
                UPDATE attendance
                SET present = %s
                WHERE subject_id = %s AND student_id = %s AND date = %s AND hour = %s
            ''', (new_status, subject_id, student['id'], date_val, hour))

            flash("✅ Attendance updated successfully", "success")
            return redirect(url_for('view_attendance_detail_faculty', subject_id=subject_id))

        # Load previous attendance records for the student in this subject
        db.execute('''
            SELECT date, hour, present
            FROM attendance
            WHERE subject_id = %s AND student_id = %s
            ORDER BY date DESC, hour DESC
        ''', (subject_id, student['id']))
        records = db.fetchall()
        unique_dates = sorted({r['date'] for r in records}, reverse=True)
        unique_hours = sorted({r['hour'] for r in records})

           
          

    # Group hours by date for dynamic dropdown
    date_to_hours = defaultdict(list)
    for r in records:
     date_to_hours[str(r['date'])].append(r['hour'])

# Remove duplicates and sort
    for date in date_to_hours:
     date_to_hours[date] = sorted(set(date_to_hours[date]))

    return render_template('edit_attendance.html',
                       subject=subject,
                       student=student,
                       records=records,
                       unique_dates=unique_dates,
                       date_to_hours=date_to_hours)



# -----------------------------------------
# 🚀 Run App
# -----------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

