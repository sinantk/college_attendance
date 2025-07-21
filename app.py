# 1. All imports and setup
import os
from flask import Flask, request, render_template, redirect, session, url_for, flash
import sqlite3
import hashlib
from contextlib import contextmanager

@contextmanager
def get_db():
    conn = sqlite3.connect('database.db', timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


app = Flask(__name__)
app.secret_key = 'your-secret-key'



def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                code TEXT,
                semester TEXT,
                branch TEXT,
                faculty_id INTEGER
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER,
                subject_id INTEGER,
                date TEXT,
                hour INTEGER,
                present INTEGER
            )
        ''')
        admin_email = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@example.com")
        admin_pass = os.environ.get("DEFAULT_ADMIN_PASS", "admin123")
        hashed = hash_password(admin_pass)

        exists = db.execute("SELECT * FROM users WHERE email = ? AND role = 'admin'", (admin_email,)).fetchone()
        if not exists:
            db.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')",
                       ("Admin", admin_email, hashed))
            print(f"✅ Admin created: {admin_email}")

init_db()

# 3. Routes (HOME + STUDENT + FACULTY)
@app.route('/')
def home():
    return render_template('home.html')
def load_whitelist(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def is_whitelisted(email, role):
    filename = 'student_whitelist.txt' if role == 'student' else 'faculty_whitelist.txt'
    whitelist = load_whitelist(filename)
    return any(email == w or email.endswith(w) for w in whitelist)



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
                    VALUES (?, ?, ?, 'student', ?, ?, ?)
                ''', (name, email, hashed, semester, branch, roll_number))
            flash("✅ Student registered successfully", "success")
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash("⚠️ Email already exists. Please use another.", "warning")
            return redirect(request.url)

    return render_template('student_register.html')


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
                    VALUES (?, ?, ?, 'faculty')
                ''', (name, email, hashed))
            flash("✅ Faculty registered successfully", "success")
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash("⚠️ Email already exists. Please use another.", "warning")
            return redirect(request.url)

    return render_template('faculty_register.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password)).fetchone()

        if user:
            if user['role'] == 'admin':
                flash('⚠️ Admins must log in from the Admin Login page.', 'warning')
                return redirect(url_for('login'))

            # proceed with normal user login
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



@app.route('/faculty/dashboard')
def faculty_dashboard():
    if session.get('role') != 'faculty':
        return redirect(url_for('login'))
    return render_template('faculty_dashboard.html', name=session['name'])


@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))

    student_id = session['user_id']
    db = get_db()
    
    # Get all subjects for this student
    subjects = db.execute('''
        SELECT * FROM subjects WHERE semester = (
            SELECT semester FROM users WHERE id = ?
        ) AND branch = (
            SELECT branch FROM users WHERE id = ?
        )
    ''', (student_id, student_id)).fetchall()
    
    attendance_summary = []
    for subject in subjects:
        total_hours = db.execute('''
            SELECT COUNT(*) FROM attendance
            WHERE subject_id = ? AND student_id = ?
        ''', (subject['id'], student_id)).fetchone()[0]

        present_hours = db.execute('''
            SELECT COUNT(*) FROM attendance
            WHERE subject_id = ? AND student_id = ? AND present = 1
        ''', (subject['id'], student_id)).fetchone()[0]

        percentage = (present_hours / total_hours * 100) if total_hours > 0 else 0
        attendance_summary.append({
    'subject_name': subject['name'],
    'subject_code': subject['code'],  # Add this line
    'subject_id': subject['id'],
    'total': total_hours,
    'present': present_hours,
    'percentage': round(percentage, 2)
})


    return render_template(
        'student_dashboard.html',
        name=session['name'],
        attendance_summary=attendance_summary
    )


@app.route('/faculty/add_subject', methods=['GET', 'POST'])
def add_subject():
    if 'user_id' not in session or session.get('role') != 'faculty':
        flash('⚠️ Unauthorized access. Please log in as faculty.', 'warning')
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
                VALUES (?, ?, ?, ?, ?)
            ''', (name, code, semester, branch, faculty_id))

        flash('📘 Subject added successfully!', 'success')
        return redirect(url_for('faculty_dashboard'))

    return render_template('add_subject.html')


@app.route('/faculty/subjects')
def faculty_subjects():
    if session.get('role') != 'faculty':
        return redirect(url_for('login'))

    db = get_db()
    subjects = db.execute('SELECT * FROM subjects WHERE faculty_id = ?', (session['user_id'],)).fetchall()
    return render_template('faculty_subjects.html', subjects=subjects)
@app.route('/logout')
def logout():
    session.clear()
    flash('🔓 Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/faculty/mark/<int:subject_id>/<date>/<int:hour>', methods=['GET', 'POST'])
def mark_attendance(subject_id, date, hour):
    if 'user_id' not in session or session['role'] != 'faculty':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    db = get_db()
    subject = db.execute("SELECT * FROM subjects WHERE id = ?", (subject_id,)).fetchone()

    students = db.execute('''
        SELECT * FROM users WHERE role = 'student' AND semester = ? AND branch = ?
    ''', (subject['semester'], subject['branch'])).fetchall()

    if request.method == 'POST':
        # Step 1: Preview absentees before saving
        absentees = []
        present_status = {}
        for student in students:
            present = 1 if f"present_{student['id']}" in request.form else 0
            present_status[student['id']] = present
            if not present:
                absentees.append(student['roll_number'])

        # Store temporarily in session
        session['attendance_temp'] = {
            'subject_id': subject_id,
            'date': date,
            'hour': hour,
            'status': present_status
        }

        return render_template('attendance_preview.html', absentees=absentees, subject=subject, date=date, hour=hour)

    return render_template('mark_attendance.html', students=students, subject=subject, date=date, hour=hour)

@app.route('/faculty/mark/confirm', methods=['POST'])
def confirm_attendance():
    if 'attendance_temp' not in session:
        flash("No attendance to confirm", "warning")
        return redirect(url_for('faculty_dashboard'))

    data = session.pop('attendance_temp')

    with get_db() as db:
        students = db.execute('''
            SELECT * FROM users WHERE role = 'student' AND semester = (
                SELECT semester FROM subjects WHERE id = ?
            ) AND branch = (
                SELECT branch FROM subjects WHERE id = ?
            )
        ''', (data['subject_id'], data['subject_id'])).fetchall()

        for student in students:
            present = data['status'].get(str(student['id']), 0)
            db.execute('''
                INSERT INTO attendance (student_id, subject_id, date, hour, present)
                VALUES (?, ?, ?, ?, ?)
            ''', (student['id'], data['subject_id'], data['date'], data['hour'], present))

    flash("✅ Attendance successfully saved!", "success")
    return redirect(url_for('faculty_dashboard'))



@app.route('/faculty/mark_attendance/<int:subject_id>/<date>/<int:hour>', methods=['GET', 'POST'])
def mark_attendance_form(subject_id, date, hour):
    if session.get('role') != 'faculty':
        return redirect(url_for('login'))

    db = get_db()
    subject = db.execute('SELECT * FROM subjects WHERE id = ?', (subject_id,)).fetchone()

    students = db.execute('''
        SELECT * FROM users
        WHERE role = 'student' AND semester = ? AND branch = ?
    ''', (subject['semester'], subject['branch'])).fetchall()

    if request.method == 'POST':
        for student in students:
            present = 1 if request.form.get(str(student['id'])) == 'on' else 0
            db.execute('''
                INSERT INTO attendance (student_id, subject_id, date, hour, present)
                VALUES (?, ?, ?, ?, ?)
            ''', (student['id'], subject_id, date, hour, present))
        db.commit()
        return redirect(url_for('faculty_dashboard'))

    return render_template('mark_attendance.html', students=students, subject=subject, date=date, hour=hour)


@app.route('/faculty/select_subject_for_attendance', methods=['GET', 'POST'])
def mark_attendance_select_subject():
    if 'user_id' not in session or session.get('role') != 'faculty':
        flash('⚠️ Unauthorized access.', 'warning')
        return redirect(url_for('login'))

    db = get_db()
    faculty_id = session['user_id']
    subjects = db.execute('SELECT * FROM subjects WHERE faculty_id = ?', (faculty_id,)).fetchall()

    if request.method == 'POST':
        subject_id = request.form['subject_id']
        date = request.form['date']
        hour = request.form['hour']
        return redirect(url_for('mark_attendance', subject_id=subject_id, date=date, hour=hour))

    from datetime import date
    current_date = date.today().isoformat()

    return render_template('select_subject_for_attendance.html', subjects=subjects, current_date=current_date)


@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store'
    return response
@app.route('/student/attendance/<int:subject_id>')
def view_attendance_detail(subject_id):
    student_id = session.get('user_id')

    # Allow admin to pass student_id manually
    if is_admin() and request.args.get('student_id'):
        student_id = request.args.get('student_id')

    db = get_db()
    subject = db.execute("SELECT * FROM subjects WHERE id = ?", (subject_id,)).fetchone()
    records = db.execute('''
        SELECT * FROM attendance
        WHERE subject_id = ? AND student_id = ?
        ORDER BY date, hour
    ''', (subject_id, student_id)).fetchall()

    return render_template('student_attendance_detail.html', subject=subject, records=records)

@app.route('/faculty/subject/<int:subject_id>/attendance')
def view_attendance_detail_faculty(subject_id):
    # Ensure logged in faculty
    if 'user_id' not in session or session['role'] != 'faculty':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    db = get_db()

    # Verify subject belongs to this faculty
    subject = db.execute(
        "SELECT * FROM subjects WHERE id = ? AND faculty_id = ?",
        (subject_id, session['user_id'])
    ).fetchone()

    if not subject:
        flash("Subject not found or not authorized", "danger")
        return redirect(url_for('faculty_dashboard'))

    # Fetch attendance stats grouped by student
    records = db.execute('''
        SELECT 
            u.name AS student_name,
            u.roll_number,
            COUNT(a.id) AS total_classes,
            SUM(a.present) AS present_count
        FROM attendance a
        JOIN users u ON u.id = a.student_id
        WHERE a.subject_id = ?
        GROUP BY a.student_id
        ORDER BY u.roll_number
    ''', (subject_id,)).fetchall()

    return render_template('faculty_attendance_detail.html', subject=subject, records=records)

@app.route('/faculty/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if session.get('role') != 'faculty':
        abort(403)

    with get_db() as db:
        # First delete related attendance records
        db.execute("DELETE FROM attendance WHERE subject_id = ?", (subject_id,))
        
        # Then delete the subject itself
        db.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))

    flash("Subject and related attendance deleted successfully", "success")
    return redirect(url_for('faculty_subjects'))


# Admin Login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ? AND password = ? AND role = "admin"', 
                          (email, password)).fetchone()

        if user:
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            flash('✅ Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials", "danger")

    return render_template('admin_login.html')

# Middleware


from flask import abort

# Helper to restrict access to admin
def is_admin():
    return session.get('role') == 'admin'

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if not is_admin(): abort(403)
    db = get_db()

    filters = {}
    query = "SELECT * FROM users WHERE 1=1"
    params = []

    if request.method == 'POST':
        role = request.form.get('role')
        semester = request.form.get('semester')
        branch = request.form.get('branch')

        if role:
            query += " AND role = ?"
            params.append(role)
            filters['role'] = role
        if semester:
            query += " AND semester = ?"
            params.append(semester)
            filters['semester'] = semester
        if branch:
            query += " AND branch = ?"
            params.append(branch)
            filters['branch'] = branch

    users = db.execute(query, params).fetchall()
    return render_template("admin_users.html", users=users, filters=filters)


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
            query += " AND (name LIKE ? OR code LIKE ?)"
            args.extend([f"%{filters['keyword']}%", f"%{filters['keyword']}%"])
        if filters['semester']:
            query += " AND semester = ?"
            args.append(filters['semester'])
        if filters['branch']:
            query += " AND branch = ?"
            args.append(filters['branch'])

    db = get_db()
    subjects = db.execute(query, args).fetchall()
    return render_template('admin_subjects.html', subjects=subjects, filters=filters)

@app.route('/admin/attendance')
def admin_attendance():
    if not is_admin(): abort(403)
    db = get_db()
    records = db.execute('''
        SELECT a.date, a.hour, a.present,
               u.name as student_name, u.roll_number,
               s.name as subject_name, s.code
        FROM attendance a
        JOIN users u ON a.student_id = u.id
        JOIN subjects s ON a.subject_id = s.id
        ORDER BY date DESC, hour DESC
    ''').fetchall()
    return render_template('admin_attendance.html', records=records)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin():
        abort(403)
    
    with get_db() as db:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))

    flash('User deleted.', 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject_admin(subject_id):
    if not is_admin():
        abort(403)

    with get_db() as db:
        # First delete attendance records linked to the subject
        db.execute('DELETE FROM attendance WHERE subject_id = ?', (subject_id,))
        
        # Then delete the subject itself
        db.execute('DELETE FROM subjects WHERE id = ?', (subject_id,))

    flash('🗑️ Subject and related attendance deleted.', 'info')
    return redirect(url_for('admin_subjects'))




@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('home'))  # or show 403
    return render_template('admin_dashboard.html')
@app.route('/admin/student-attendance', methods=['GET', 'POST'])
def admin_view_student_attendance():
    if not is_admin(): abort(403)
    db = get_db()
    records = None
    student = None

    if request.method == 'POST':
        semester = request.form.get('semester')
        branch = request.form.get('branch')
        roll_number = request.form.get('roll_number')

        student = db.execute(
            "SELECT * FROM users WHERE role='student' AND semester=? AND branch=? AND roll_number=?",
            (semester, branch, roll_number)
        ).fetchone()

        if student:
            records = db.execute('''
                SELECT s.id AS subject_id, s.name AS subject_name, s.code AS subject_code,
                       COUNT(a.id) AS total,
                       SUM(a.present) AS present
                FROM attendance a
                JOIN subjects s ON a.subject_id = s.id
                WHERE a.student_id = ?
                GROUP BY s.id
            ''', (student['id'],)).fetchall()

    return render_template('admin_view_student_attendance.html', student=student, records=records)


def save_whitelist(filename, emails):
    with open(filename, 'w') as f:
        for email in emails:
            f.write(email.strip() + '\n')

@app.route('/admin/whitelist/<role>', methods=['GET', 'POST'])
def manage_whitelist(role):
    if not is_admin():
        abort(403)

    if role not in ['student', 'faculty']:
        abort(400)

    filename = f"{role}_whitelist.txt"
    emails = load_whitelist(filename)

    if request.method == 'POST':
        new_emails = request.form.get('emails', '')
        updated_list = new_emails.strip().splitlines()
        save_whitelist(filename, updated_list)
        flash(f'✅ {role.capitalize()} whitelist updated successfully.', 'success')
        return redirect(url_for('manage_whitelist', role=role))  # Redirect to avoid resubmission

    return render_template('admin_whitelist.html', emails="\n".join(emails), role=role)


@app.route('/admin/whitelist-options')
def manage_whitelist_options():
    if not is_admin():
        abort(403)
    return render_template('manage_whitelist_options.html')


@app.route('/ping')
def ping():
    return "pong"

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not is_admin():
        abort(403)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        role = request.form['role']

        # Handle student-specific fields
        if role == 'student':
            semester = request.form.get('semester') or None
            branch = request.form.get('branch') or None
            roll_number = request.form.get('roll_number') or None
        else:
            semester = branch = roll_number = None

        db.execute('''
            UPDATE users 
            SET name=?, email=?, role=?, semester=?, branch=?, roll_number=? 
            WHERE id=?
        ''', (name, email, role, semester, branch, roll_number, user_id))
        db.commit()

        flash("✅ User updated successfully", "success")
        return redirect(url_for('admin_users'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if not is_admin():
        abort(403)

    db = get_db()
    subject = db.execute("SELECT * FROM subjects WHERE id = ?", (subject_id,)).fetchone()

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
            UPDATE subjects SET name=?, code=?, semester=?, branch=?, faculty_id=? WHERE id=?
        ''', (name, code, semester, branch, faculty_id, subject_id))
        db.commit()

        flash("✅ Subject updated successfully", "success")
        return redirect(url_for('admin_subjects'))

    return render_template('edit_subject.html', subject=subject)





# 4. Place app.run() at the END
if __name__ == '__main__':
    app.run(debug=True)

