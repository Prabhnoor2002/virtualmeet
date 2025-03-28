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
# filepath: c:\Users\Dell\OneDrive\Desktop\virtualmeet\app.py
@app.route('/join_meeting', methods=['POST'])
def join_meeting():
    meeting_id = request.form.get('meeting_id', '').strip()
    print(f"Received Meeting ID: {meeting_id}")  # Debugging log

    # Extract meeting_id if it's a full URL
    if "http" in meeting_id:
        meeting_id = meeting_id.split("/")[-1]  # Extract the last part of the URL
        print(f"Extracted Meeting ID: {meeting_id}")  # Debugging log

    if not meeting_id:
        flash('Meeting ID or link is required.', 'danger')
        return redirect(url_for('user_dashboard'))

    conn, cursor = get_db_cursor()
    try:
        cursor.execute("SELECT * FROM meetings WHERE meeting_id = ?", (meeting_id,))
        meeting = cursor.fetchone()
        print(f"Query Result: {meeting}")  # Debugging log

        if meeting:
            print(f"Meeting Found: {meeting['meeting_name']}")  # Debugging log
            return redirect(url_for('meeting_room', meeting_id=meeting_id))
        else:
            print("Meeting not found.")  # Debugging log
            flash('Meeting not found. Please check the Meeting ID or link.', 'danger')
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Debugging log
        flash('An error occurred while accessing the database.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('user_dashboard'))
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
@app.route('/delete_meeting/<meeting_id>', methods=['DELETE'])
@role_required(['admin', 'trainer'])
def delete_meeting(meeting_id):
    user_role = session.get('role')  # Get the role of the logged-in user
    user_email = session.get('user')  # Get the email of the logged-in user

    conn, cursor = get_db_cursor()
    try:
        # If the user is a trainer, ensure they can only delete their own meetings
        if user_role == 'trainer':
            cursor.execute("SELECT * FROM meetings WHERE meeting_id = ? AND email = ?", (meeting_id, user_email))
            meeting = cursor.fetchone()
            if not meeting:
                return jsonify({'error': 'Unauthorized: Trainers can only delete their own meetings.'}), 401

        # Admins can delete any meeting
        cursor.execute("DELETE FROM meetings WHERE meeting_id = ?", (meeting_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({'error': 'Meeting not found'}), 404
        return '', 204  # No Content
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()
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

    return render_template('home.html')
@app.route('/start_meeting/<meeting_id>')
def start_meeting(meeting_id):
    meeting_link = url_for('meeting_room', meeting_id=meeting_id, _external=True)
    flash(f'Meeting started! Share this link: {meeting_link}', 'success')
    return redirect(url_for('meeting_room', meeting_id=meeting_id))
@app.route('/meeting_room/<meeting_id>')
def meeting_room(meeting_id):
    return render_template('meeting_room.html', meeting_id=meeting_id)


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
@app.route('/reset_password/<reset_token>', methods=['GET', 'POST'])
def reset_password(reset_token):
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not new_password or not confirm_password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('reset_password', reset_token=reset_token))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', reset_token=reset_token))

        conn, cursor = get_db_cursor()
        try:
            # Verify the reset token
            cursor.execute("SELECT * FROM users WHERE reset_token = ?", (reset_token,))
            user = cursor.fetchone()
            if not user:
                flash('Invalid or expired reset token.', 'danger')
                return redirect(url_for('reset_password_request'))

            # Update the password and clear the reset token
            cursor.execute("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?", (new_password, reset_token))
            conn.commit()

            flash('Password reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash('An error occurred while resetting your password.', 'danger')
        finally:
            conn.close()

    return render_template('reset_password.html', reset_token=reset_token)
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('reset_password_request'))

        conn, cursor = get_db_cursor()
        try:
            # Check if the email exists in the database
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if not user:
                flash('Email not found.', 'danger')
                return redirect(url_for('reset_password_request'))

            # Generate a unique reset token
            reset_token = secrets.token_hex(16)

            # Save the token in the database (optional: add an expiration time)
            cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
            conn.commit()

            # Send the reset link to the user's email
            reset_link = f"{request.url_root}reset_password/{reset_token}"
            print(f"Reset link (for testing): {reset_link}")  # Replace with actual email sending logic

            flash('A reset link has been sent to your email.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash('An error occurred while processing your request.', 'danger')
        finally:
            conn.close()

    return render_template('reset_password_req.html')
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
