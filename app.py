# 1. All imports and setup
from flask import Flask, request, render_template, redirect, session, url_for, flash
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# 2. DB functions
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

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

init_db()

# 3. Routes (HOME + STUDENT + FACULTY)
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = hash_password(request.form['password'])
        semester = request.form['semester']
        branch = request.form['branch']
        roll_number = request.form['roll_number']

        try:
            db = get_db()
            db.execute('''
                INSERT INTO users (name, email, password, role, semester, branch, roll_number)
                VALUES (?, ?, ?, 'student', ?, ?, ?)
            ''', (name, email, password, semester, branch, roll_number))
            db.commit()
            db.close()
            flash('✅ Student registered successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('⚠️ Email already exists. Please use another.', 'danger')
            db.close()  # ✅ Important: always close DB
            return render_template('student_register.html')

    return render_template('student_register.html')



@app.route('/register/faculty', methods=['GET', 'POST'])
def register_faculty():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = hash_password(request.form['password'])

        try:
            db = get_db()
            db.execute('''
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, 'faculty')
            ''', (name, email, password))
            db.commit()
            db.close()
            flash('✅ Faculty registered successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('⚠️ Email already exists. Please use another.', 'danger')
            db.close()  # ✅ Always close DB
            return render_template('faculty_register.html')

    return render_template('faculty_register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password)).fetchone()

        if user:
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
            return render_template('login.html')  # 🟢 Re-render without redirect

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

        db = get_db()
        db.execute('''
            INSERT INTO subjects (name, code, semester, branch, faculty_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, code, semester, branch, faculty_id))
        db.commit()
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
    db = get_db()

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

    db.commit()
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
    if 'user_id' not in session or session.get('role') != 'student':
        flash("⚠️ Please log in first.", "warning")
        return redirect(url_for('login'))

    db = get_db()
    student_id = session['user_id']

    subject = db.execute('SELECT * FROM subjects WHERE id = ?', (subject_id,)).fetchone()
    records = db.execute('''
        SELECT date, hour, present FROM attendance
        WHERE student_id = ? AND subject_id = ?
        ORDER BY date, hour
    ''', (student_id, subject_id)).fetchall()

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
    db = get_db()
    db.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
    db.commit()
    flash("Subject deleted successfully", "success")
    return redirect(url_for('faculty_subjects'))

# 4. Place app.run() at the END
if __name__ == '__main__':
    app.run(debug=True)
