from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from dotenv import load_dotenv
import secrets
import sqlite3
import os
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

socketio = SocketIO(app, cors_allowed_origins="*")

ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY')
TRAINER_SECRET_KEY = os.getenv('TRAINER_SECRET_KEY')

DATABASE = 'videomeet.db'

# -------------------- DATABASE SETUP --------------------

def get_db_cursor():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn, conn.cursor()

def initialize_db():
    try:
        conn, cursor = get_db_cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS meetings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id TEXT UNIQUE NOT NULL,
                meeting_name TEXT NOT NULL,
                meeting_date TEXT NOT NULL,
                meeting_time TEXT NOT NULL,
                meeting_duration TEXT NOT NULL,
                meeting_description TEXT,
                email TEXT NOT NULL,
                status TEXT DEFAULT 'scheduled'
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

initialize_db()

# -------------------- ROLE-BASED ACCESS DECORATOR --------------------

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in allowed_roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# -------------------- ROUTES --------------------

@app.route('/')
def home():
    return render_template('home.html')

# -------------------- USER DASHBOARD --------------------

@app.route('/user_dashboard')
def user_dashboard():
    if 'user' in session:
        return render_template('user_dashboard.html', user=session['user_name'])
    else:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

# -------------------- CREATE MEETING --------------------

@app.route('/create_meeting', methods=['GET', 'POST'])
@role_required(['admin', 'trainer'])
def create_meeting():
    if request.method == 'POST':
        meeting_name = request.form.get('meeting_name', '').strip()
        meeting_date = request.form.get('meeting_date', '').strip()
        meeting_time = request.form.get('meeting_time', '').strip()
        meeting_duration = request.form.get('meeting_duration', '').strip()
        meeting_description = request.form.get('meeting_description', '').strip()

        # Validate inputs
        if not all([meeting_name, meeting_date, meeting_time, meeting_duration]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('trainer_dashboard'))

        try:
            meeting_datetime = datetime.strptime(f"{meeting_date} {meeting_time}", '%Y-%m-%d %H:%M')
            if meeting_datetime < datetime.now():
                flash('Meeting date and time cannot be in the past.', 'danger')
                return redirect(url_for('trainer_dashboard'))
        except ValueError:
            flash('Invalid date or time format.', 'danger')
            return redirect(url_for('trainer_dashboard'))

        meeting_id = secrets.token_hex(8)
        email = session.get('user')

        conn, cursor = get_db_cursor()
        try:
            cursor.execute(
                '''INSERT INTO meetings (meeting_id, meeting_name, meeting_date, meeting_time, meeting_duration, meeting_description, email)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (meeting_id, meeting_name, meeting_date, meeting_time, meeting_duration, meeting_description, email)
            )
            conn.commit()
            flash('Meeting created successfully!', 'success')
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
            conn.rollback()
        finally:
            conn.close()

        return redirect(url_for('trainer_dashboard'))

    return render_template('create_meeting.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        if not all([name, email, password, role]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('home'))

        conn, cursor = get_db_cursor()
        try:
            cursor.execute(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                (name, email, password, role)
            )
            conn.commit()
            flash('Signup successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'danger')
        finally:
            conn.close()

    return render_template('signup.html')
@app.route('/start_meeting/<string:meeting_id>', methods=['GET', 'POST'])
def start_meeting(meeting_id):
    conn, cursor = get_db_cursor()
    cursor.execute("SELECT * FROM meetings WHERE id = ?", (meeting_id,))
    meeting = cursor.fetchone()
    conn.close()
    
    if not meeting:
        flash('Meeting not found', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Example logic to start the meeting
    flash(f"Meeting {meeting['title']} has started!", 'success')
    
    return redirect(url_for('admin_dashboard'))


# -------------------- ADMIN DASHBOARD --------------------

@app.route('/admin_dashboard')
@role_required(['admin'])
def admin_dashboard():
    if 'user' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    conn, cursor = get_db_cursor()
    try:
        cursor.execute("SELECT * FROM meetings")
        meetings = cursor.fetchall()
    finally:
        conn.close()

    return render_template('admin_dashboard.html', meetings=meetings)

# -------------------- TRAINER DASHBOARD --------------------

@app.route('/trainer_dashboard')
@role_required(['admin', 'trainer'])
def trainer_dashboard():
    email = session.get('user')
    if not email:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    conn, cursor = get_db_cursor()
    try:
        cursor.execute("SELECT * FROM meetings WHERE email = ?", (email,))
        meetings = cursor.fetchall()
    finally:
        conn.close()

    return render_template('trainer_dashboard.html', meetings=meetings)

# -------------------- LOGIN --------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('login'))

        conn, cursor = get_db_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
            user = cursor.fetchone()
            if user:
                session['user'] = user['email']
                session['user_name'] = user['name']
                session['role'] = user['role']

                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'trainer':
                    return redirect(url_for('trainer_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        finally:
            conn.close()

    return render_template('home.html')

# -------------------- LOGOUT --------------------

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# -------------------- SOCKET.IO --------------------

@socketio.on('chat_message')
def handle_chat(data):
    emit('chat_message', data, broadcast=True)

# -------------------- RUN APP --------------------

if __name__ == '__main__':
    socketio.run(app, debug=True)
