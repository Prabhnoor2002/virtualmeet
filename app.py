from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from dotenv import load_dotenv
import secrets
import sqlite3
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE = 'videomeet.db'
ACTIVE_USERS = {}

# -------------------- DATABASE SETUP --------------------

def get_db_cursor():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn, conn.cursor()

def initialize_db():
    try:
        conn, cursor = get_db_cursor()

        # Create 'users' table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')

        # Create 'meetings' table
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
    flash('Please log in first.', 'danger')
    return redirect(url_for('login'))

# -------------------- CREATE MEETING --------------------

@app.route('/create_meeting', methods=['GET', 'POST'])
@role_required(['admin', 'trainer'])
def create_meeting():
    if request.method == 'POST':
        meeting_name = request.form['meeting_name']
        meeting_date = request.form['meeting_date']
        meeting_time = request.form['meeting_time']
        meeting_duration = request.form['meeting_duration']
        meeting_description = request.form['meeting_description']
        meeting_id = secrets.token_hex(8)  # Generates 16 characters
        email = session.get('user')

        try:
            meeting_datetime = datetime.strptime(f"{meeting_date} {meeting_time}", '%Y-%m-%d %H:%M')
            if meeting_datetime < datetime.now():
                flash('Meeting date and time cannot be in the past.', 'danger')
                return redirect(url_for('trainer_dashboard'))

            conn, cursor = get_db_cursor()
            sql = """INSERT INTO meetings 
                     (meeting_id, meeting_name, meeting_date, meeting_time, meeting_duration, meeting_description, email)
                     VALUES (?, ?, ?, ?, ?, ?, ?)"""
            cursor.execute(sql, (meeting_id, meeting_name, meeting_date, meeting_time, meeting_duration, meeting_description, email))
            conn.commit()
            flash('Meeting created successfully!', 'success')
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
        finally:
            conn.close()

        return redirect(url_for('trainer_dashboard'))

    return render_template('create_meeting.html')

# -------------------- JOIN MEETING --------------------

@app.route('/join_meeting', methods=['POST'])
def join_meeting():
    meeting_input = request.form['meeting_id'].strip()
    meeting_id = meeting_input.split('meeting_room/')[-1].split('?')[0]

    if len(meeting_id) != 16:
        flash("Invalid meeting ID or link.", "danger")
        return redirect(url_for('home'))

    conn, cursor = get_db_cursor()
    try:
        cursor.execute("SELECT * FROM meetings WHERE meeting_id = ?", (meeting_id,))
        meeting = cursor.fetchone()
        if meeting:
            flash(f"Joined meeting '{meeting['meeting_name']}' successfully!", "success")
            return redirect(url_for('meeting_room', meeting_id=meeting_id))
        flash("Meeting not found.", "danger")
    finally:
        conn.close()

    return redirect(url_for('home'))

# -------------------- LOGIN --------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn, cursor = get_db_cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user'] = user['email']
                session['user_name'] = user['name']
                session['role'] = user['role']

                ACTIVE_USERS[email] = user['name']

                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'trainer':
                    return redirect(url_for('trainer_dashboard'))
                return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        finally:
            conn.close()

    return render_template('home.html')

# -------------------- CHAT SYSTEM --------------------

@socketio.on('chat_message')
def handle_chat(data):
    if session.get('user'):
        emit('chat_message', data, broadcast=True)

@socketio.on('user_connected')
def handle_user_connected(data):
    ACTIVE_USERS[data['email']] = data['name']
    emit('update_users', list(ACTIVE_USERS.values()), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    user = session.get('user')
    if user in ACTIVE_USERS:
        del ACTIVE_USERS[user]
        emit('update_users', list(ACTIVE_USERS.values()), broadcast=True)

# -------------------- RUN APP --------------------

if __name__ == '__main__':
    socketio.run(app, debug=True)
