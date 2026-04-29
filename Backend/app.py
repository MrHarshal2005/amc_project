import os
import random
import string
import sqlite3
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, g
from flask_session import Session

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # change for production!
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# ---------- Database helper ----------
DATABASE = 'amc_portal.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=(), commit=True):
    db = get_db()
    cur = db.execute(query, args)
    if commit:
        db.commit()
    cur.close()

# ---------- Automatic table creation (runs once at startup) ----------
def init_database():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # citizens table
        cursor.execute('''CREATE TABLE IF NOT EXISTS citizens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            mobile TEXT UNIQUE NOT NULL,
            address TEXT,
            password_hash TEXT NOT NULL,
            photo TEXT,
            created_at TIMESTAMP
        )''')

        # officials table
        cursor.execute('''CREATE TABLE IF NOT EXISTS officials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            department TEXT,
            email TEXT,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP
        )''')

        # appointments table
        cursor.execute('''CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            citizen_id INTEGER,
            leader_name TEXT NOT NULL,
            leader_aadhaar TEXT,
            mobile TEXT,
            people_count INTEGER DEFAULT 1,
            member_names TEXT,
            department TEXT,
            date TEXT,
            time TEXT,
            reason TEXT,
            status TEXT DEFAULT 'Pending PA Review',
            rejection_reason TEXT,
            reschedule_reason TEXT,
            rescheduled_date TEXT,
            rescheduled_time TEXT,
            forwarded_to TEXT,
            photo TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            FOREIGN KEY(citizen_id) REFERENCES citizens(id)
        )''')

        # feedback table
        cursor.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            category TEXT,
            message TEXT,
            submitted_at TIMESTAMP
        )''')

        # password resets table
        cursor.execute('''CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            token TEXT,
            expires_at TIMESTAMP
        )''')

        # Insert default System Manager if none exists (password: admin123)
        cursor.execute("SELECT id FROM officials WHERE role = 'system_manager' LIMIT 1")
        if not cursor.fetchone():
            hashed = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode('utf-8')
            cursor.execute('''INSERT INTO officials (name, username, role, password_hash, created_at)
                              VALUES (?, ?, ?, ?, ?)''',
                           ('System Manager', 'sysmgr', 'system_manager', hashed, datetime.now()))
            print("✅ Default System Manager created (username: sysmgr, password: admin123).")

        db.commit()
        print("✅ Database tables verified/created.")

# Run database initialisation
init_database()

# ---------- Helper functions ----------
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_token():
    date_str = datetime.now().strftime('%Y%m%d')
    rand = str(random.randint(1000, 9999))
    return f"AMC{date_str}{rand}"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('user_type') != 'official':
                return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            if session.get('role') not in allowed_roles:
                return jsonify({'success': False, 'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------- Page routes ----------
@app.route('/')
def home():
    return render_template('main_home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/citizen_register', methods=['GET', 'POST'])
def citizen_register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        address = request.form.get('address')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        
        if not name or not email or not mobile or not password:
            flash('All fields marked with * are required', 'danger')
            return redirect(url_for('citizen_register'))
        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('citizen_register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('citizen_register'))
        if not mobile.isdigit() or len(mobile) != 10:
            flash('Mobile number must be 10 digits', 'danger')
            return redirect(url_for('citizen_register'))
        
        existing = query_db('SELECT id FROM citizens WHERE mobile = ?', [mobile], one=True)
        if existing:
            flash('Mobile number already registered. Please login.', 'danger')
            return redirect(url_for('citizen_register'))
        
        hashed = hash_password(password)
        execute_db('''INSERT INTO citizens (name, email, mobile, address, password_hash, created_at)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                   [name, email, mobile, address, hashed, datetime.now()])
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('home'))
    return render_template('citizen_register.html')

@app.route('/register', methods=['GET', 'POST'])
def register_official():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        emp_id = request.form.get('emp_id')
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        
        if not full_name or not emp_id or not email or not role or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('register_official'))
        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register_official'))
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('register_official'))
        
        existing = query_db('SELECT id FROM officials WHERE username = ?', [emp_id], one=True)
        if existing:
            flash('Employee ID already exists', 'danger')
            return redirect(url_for('register_official'))
        
        hashed = hash_password(password)
        execute_db('''INSERT INTO officials (name, username, role, email, password_hash, created_at)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                   [full_name, emp_id, role, email, hashed, datetime.now()])
        flash('Official account created! They can now log in.', 'success')
        return redirect(url_for('home'))
    return render_template('create_account_all.html')

# Dashboard routes
@app.route('/people-dashboard')
def people_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'citizen':
        return redirect(url_for('home'))
    return render_template('people_dashboard.html')

@app.route('/commissioner-dashboard')
def commissioner_dashboard():
    if session.get('role') != 'commissioner':
        return redirect(url_for('home'))
    return render_template('commissioner_dashboard.html')

@app.route('/deputy-commissioner-dashboard')
def deputy_commissioner_dashboard():
    if session.get('role') != 'deputy_commissioner':
        return redirect(url_for('home'))
    return render_template('deputy_commissioner_dashboard.html')

@app.route('/assistant-commissioner-dashboard')
def assistant_commissioner_dashboard():
    if session.get('role') != 'assistant_commissioner':
        return redirect(url_for('home'))
    return render_template('assistant_commissioner_dashboard.html')

@app.route('/hod-dashboard')
def hod_dashboard():
    if session.get('role') != 'hod':
        return redirect(url_for('home'))
    return render_template('hod_dashboard.html')

@app.route('/pa-dashboard')
def pa_dashboard():
    if session.get('role') != 'pa':
        return redirect(url_for('home'))
    return render_template('pa_dashboard.html')

@app.route('/system-manager')
def system_manager():
    if session.get('role') != 'system_manager':
        return redirect(url_for('home'))
    return render_template('system_manager.html')

# ---------- Authentication APIs ----------
@app.route('/citizen-login', methods=['POST'])
def citizen_login():
    data = request.json
    mobile = data.get('mobile')
    password = data.get('password')
    if not mobile or not password:
        return jsonify({'success': False, 'message': 'Missing credentials'})
    
    user = query_db('SELECT * FROM citizens WHERE mobile = ?', [mobile], one=True)
    if not user or not check_password(password, user['password_hash']):
        return jsonify({'success': False, 'message': 'Invalid mobile or password'})
    
    session['user_id'] = user['id']
    session['user_type'] = 'citizen'
    session['name'] = user['name']
    return jsonify({'success': True, 'redirect': url_for('people_dashboard')})

@app.route('/official-login', methods=['POST'])
def official_login():
    data = request.json
    role = data.get('role')
    emp_id = data.get('emp_id')
    password = data.get('password')
    
    official = query_db('SELECT * FROM officials WHERE username = ? AND role = ?', [emp_id, role], one=True)
    if not official or not check_password(password, official['password_hash']):
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    session['user_id'] = official['id']
    session['user_type'] = 'official'
    session['role'] = official['role']
    session['name'] = official['name']
    session['department'] = official['department']
    
    redirect_map = {
        'commissioner': 'commissioner_dashboard',
        'deputy_commissioner': 'deputy_commissioner_dashboard',
        'assistant_commissioner': 'assistant_commissioner_dashboard',
        'hod': 'hod_dashboard',
        'pa': 'pa_dashboard',
        'system_manager': 'system_manager'
    }
    return jsonify({'success': True, 'redirect': url_for(redirect_map.get(role, 'home'))})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ---------- Citizen APIs ----------
@app.route('/api/citizen/profile', methods=['GET'])
@login_required
def citizen_profile():
    if session.get('user_type') != 'citizen':
        return jsonify({'error': 'Unauthorized'}), 403
    citizen = query_db('SELECT id, name, email, mobile, address, photo FROM citizens WHERE id = ?', [session['user_id']], one=True)
    return jsonify(dict(citizen) if citizen else {})

@app.route('/api/citizen/book', methods=['POST'])
@login_required
def citizen_book():
    if session.get('user_type') != 'citizen':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.json
    token = generate_token()
    while query_db('SELECT id FROM appointments WHERE token = ?', [token], one=True):
        token = generate_token()
    
    member_names = data.get('memberNames', [])
    member_str = ','.join(member_names) if member_names else ''
    
    execute_db('''INSERT INTO appointments
        (token, citizen_id, leader_name, leader_aadhaar, mobile, people_count, member_names,
         department, date, time, reason, status, photo, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        [token, session['user_id'], data['name'], data['leaderAadhaar'], data['mobile'],
         data['people'], member_str, 'Municipal Commissioner', data['date'], data['time'],
         data['reason'], 'Pending PA Review', data['photo'], datetime.now(), datetime.now()])
    return jsonify({'success': True, 'token': token})

@app.route('/api/citizen/appointments', methods=['GET'])
@login_required
def citizen_appointments():
    if session.get('user_type') != 'citizen':
        return jsonify([])
    # Alias leader_name as name for frontend
    rows = query_db('SELECT *, leader_name as name FROM appointments WHERE citizen_id = ? ORDER BY created_at DESC', [session['user_id']])
    return jsonify([dict(row) for row in rows])

# ---------- PA APIs ----------
@app.route('/api/pa/appointments', methods=['GET'])
@role_required(['pa'])
def pa_appointments():
    # Alias leader_name as name for frontend
    rows = query_db('SELECT *, leader_name as name FROM appointments ORDER BY created_at DESC')
    return jsonify([dict(row) for row in rows])

@app.route('/api/pa/update', methods=['POST'])
@role_required(['pa'])
def pa_update():
    data = request.json
    appt_id = data.get('id')
    new_status = data.get('status')
    if not appt_id or not new_status:
        return jsonify({'success': False, 'message': 'Missing fields'})
    
    update_fields = {'status': new_status, 'updated_at': datetime.now()}
    if new_status == 'Rejected':
        update_fields['rejection_reason'] = data.get('rejectionReason', '')
    elif new_status == 'Rescheduled':
        update_fields['rescheduled_date'] = data.get('date')
        update_fields['rescheduled_time'] = data.get('time')
        update_fields['reschedule_reason'] = data.get('rescheduleReason', '')
        update_fields['date'] = data.get('date')
        update_fields['time'] = data.get('time')
    
    set_clause = ', '.join([f"{k} = ?" for k in update_fields])
    values = list(update_fields.values()) + [appt_id]
    execute_db(f"UPDATE appointments SET {set_clause} WHERE id = ?", values)
    return jsonify({'success': True})

@app.route('/api/pa/profile', methods=['GET'])
@role_required(['pa'])
def pa_profile():
    official = query_db('SELECT name, email, photo FROM officials WHERE id = ?', [session['user_id']], one=True)
    return jsonify({'name': official['name'], 'email': official['email'], 'photo': ''})

# ---------- Commissioner APIs ----------
@app.route('/api/commissioner/stats', methods=['GET'])
@role_required(['commissioner'])
def commissioner_stats():
    # Alias leader_name as name for frontend
    appointments = query_db('SELECT *, leader_name as name FROM appointments')
    total = len(appointments)
    accepted = sum(1 for a in appointments if a['status'] in ('Confirmed', 'Completed'))
    rejected = sum(1 for a in appointments if a['status'] in ('Rejected', 'Cancelled'))
    
    dept_counts = {}
    for a in appointments:
        d = a['department'] or 'Other'
        dept_counts[d] = dept_counts.get(d, 0) + 1
    
    pending_apps = [a for a in appointments if a['status'] == 'Pending PA Review']
    aging = {'0-1': 0, '2-3': 0, '4+': 0}
    for a in pending_apps:
        created = datetime.fromisoformat(a['created_at'])
        days = (datetime.now() - created).days
        if days <= 1:
            aging['0-1'] += 1
        elif days <= 3:
            aging['2-3'] += 1
        else:
            aging['4+'] += 1
    
    analytics = {
        'rates': {'approvalRate': (accepted/total*100) if total else 0,
                  'rejectionRate': (rejected/total*100) if total else 0,
                  'acceptedCount': accepted, 'rejectedCount': rejected},
        'pendingAging': {'d0_1': aging['0-1'], 'd2_3': aging['2-3'], 'd4_plus': aging['4+'], 'total': len(pending_apps)},
        'avgDecision': {'label': 'N/A'},
        'sla': {'breachedCount': 0},
        'backlogByDepartment': [{'department': d, 'pending': dept_counts[d]} for d in dept_counts],
        'slotUtilization': [],
        'rescheduleReasons': [],
        'trends': {'daily': []},
        'generatedAt': datetime.now().isoformat()
    }
    return jsonify({'appointments': [dict(a) for a in appointments], 'analytics': analytics})

@app.route('/api/commissioner/tokens', methods=['GET'])
@role_required(['commissioner'])
def commissioner_tokens():
    # Alias leader_name as name for frontend
    confirmed = query_db("SELECT *, leader_name as name FROM appointments WHERE status IN ('Confirmed', 'Completed')")
    rescheduled = query_db("SELECT *, leader_name as name FROM appointments WHERE status = 'Rescheduled'")
    pending = query_db("SELECT *, leader_name as name FROM appointments WHERE status = 'Pending PA Review'")
    rejected = query_db("SELECT *, leader_name as name FROM appointments WHERE status IN ('Rejected', 'Cancelled')")
    return jsonify({
        'confirmed': [dict(r) for r in confirmed],
        'rescheduled': [dict(r) for r in rescheduled],
        'pending': [dict(r) for r in pending],
        'rejected': [dict(r) for r in rejected]
    })

@app.route('/api/forward_item', methods=['POST'])
@role_required(['commissioner'])
def forward_item():
    data = request.json
    appt_id = data.get('id')
    new_dept = data.get('dept')
    if not appt_id or not new_dept:
        return jsonify({'success': False, 'message': 'Missing data'})
    execute_db("UPDATE appointments SET department = ?, forwarded_to = ?, status = 'Forwarded' WHERE id = ?",
               [new_dept, new_dept, appt_id])
    return jsonify({'success': True})

# ---------- Deputy Commissioner APIs ----------
@app.route('/api/dc/stats', methods=['GET'])
@role_required(['deputy_commissioner'])
def dc_stats():
    all_appts = query_db('SELECT *, leader_name as name FROM appointments')
    total = len(all_appts)
    pending = sum(1 for a in all_appts if a['status'] == 'Pending PA Review')
    confirmed = sum(1 for a in all_appts if a['status'] in ('Confirmed', 'Completed'))
    rejected = sum(1 for a in all_appts if a['status'] in ('Rejected', 'Cancelled'))
    rescheduled = sum(1 for a in all_appts if a['status'] == 'Rescheduled')
    return jsonify({'total': total, 'pending': pending, 'confirmed': confirmed, 'rejected': rejected, 'rescheduled': rescheduled})

@app.route('/api/dc/appointments', methods=['GET'])
@role_required(['deputy_commissioner'])
def dc_appointments():
    rows = query_db('SELECT *, leader_name as name FROM appointments ORDER BY created_at DESC')
    return jsonify([dict(r) for r in rows])

# ---------- Assistant Commissioner & HOD (Tasks) ----------
@app.route('/api/tasks', methods=['GET'])
@login_required
def get_tasks():
    if session.get('user_type') != 'official':
        return jsonify([])
    role = session.get('role')
    department = session.get('department')
    if role == 'assistant_commissioner':
        rows = query_db('SELECT *, leader_name as name FROM appointments WHERE department = ? OR forwarded_to = ?', [department, department])
    elif role == 'hod':
        rows = query_db('SELECT *, leader_name as name FROM appointments WHERE department = ?', [department])
    else:
        rows = []
    return jsonify([dict(r) for r in rows])

@app.route('/api/task/complete', methods=['POST'])
@login_required
def task_complete():
    data = request.json
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'success': False, 'message': 'No IDs provided'})
    placeholders = ','.join('?' for _ in ids)
    execute_db(f"UPDATE appointments SET status = 'Completed', updated_at = ? WHERE id IN ({placeholders})",
               [datetime.now()] + ids)
    return jsonify({'success': True})

# ---------- HOD Profile ----------
@app.route('/api/profile', methods=['GET'])
@role_required(['hod'])
def hod_profile():
    off = query_db('SELECT name, email FROM officials WHERE id = ?', [session['user_id']], one=True)
    return jsonify({'name': off['name'], 'email': off['email'], 'photo': ''})

@app.route('/api/profile/update', methods=['POST'])
@role_required(['hod'])
def hod_profile_update():
    data = request.json
    execute_db("UPDATE officials SET name = ?, email = ? WHERE id = ?", [data.get('name'), data.get('email'), session['user_id']])
    session['name'] = data.get('name')
    return jsonify({'success': True})

# ---------- System Manager APIs ----------
@app.route('/api/system/officials', methods=['GET'])
@role_required(['system_manager'])
def list_officials():
    rows = query_db('SELECT id, name, username, role, department, email FROM officials')
    return jsonify({'officials': [dict(r) for r in rows]})

@app.route('/api/system/officials/create', methods=['POST'])
@role_required(['system_manager'])
def create_official():
    data = request.json
    exist = query_db('SELECT id FROM officials WHERE username = ?', [data['username']], one=True)
    if exist:
        return jsonify({'success': False, 'msg': 'Username already exists'})
    hashed = hash_password(data['password'])
    execute_db('''INSERT INTO officials (name, username, role, department, email, password_hash, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
               [data['name'], data['username'], data['role'], data.get('department', ''),
                data.get('email', ''), hashed, datetime.now()])
    return jsonify({'success': True})

@app.route('/api/system/officials/update', methods=['POST'])
@role_required(['system_manager'])
def update_official():
    data = request.json
    execute_db('''UPDATE officials SET name = ?, username = ?, role = ?, department = ?, email = ?
                 WHERE id = ?''',
               [data['name'], data['username'], data['role'], data.get('department', ''),
                data.get('email', ''), data['id']])
    return jsonify({'success': True})

@app.route('/api/system/officials/delete', methods=['POST'])
@role_required(['system_manager'])
def delete_official():
    data = request.json
    if data['id'] == session['user_id']:
        return jsonify({'success': False, 'msg': 'Cannot delete own account'})
    execute_db('DELETE FROM officials WHERE id = ?', [data['id']])
    return jsonify({'success': True})

@app.route('/api/system/reset-password', methods=['POST'])
@role_required(['system_manager'])
def system_reset_password():
    data = request.json
    new_hash = hash_password(data['password'])
    execute_db('UPDATE officials SET password_hash = ? WHERE id = ? OR username = ?',
               [new_hash, data.get('id'), data.get('username')])
    return jsonify({'success': True})

# ---------- Feedback ----------
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    name = request.form.get('name')
    email = request.form.get('email')
    category = request.form.get('category')
    message = request.form.get('message')
    execute_db('INSERT INTO feedback (name, email, category, message, submitted_at) VALUES (?, ?, ?, ?, ?)',
               [name, email, category, message, datetime.now()])
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('feedback'))

# ---------- Forgot Password ----------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        citizen = query_db('SELECT id FROM citizens WHERE email = ?', [email], one=True)
        if not citizen:
            flash('No account found with that email', 'danger')
            return redirect(url_for('forgot_password'))
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        expires = datetime.now() + timedelta(hours=1)
        execute_db('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
                   [email, token, expires])
        reset_link = url_for('reset_password_page', token=token, _external=True)
        print(f"Password reset link: {reset_link}")
        flash('Password reset link sent to your email (check console).', 'info')
        return redirect(url_for('home'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_page(token):
    reset = query_db('SELECT * FROM password_resets WHERE token = ? AND expires_at > ?', [token, datetime.now()], one=True)
    if not reset:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password_page', token=token))
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('reset_password_page', token=token))
        hashed = hash_password(password)
        execute_db('UPDATE citizens SET password_hash = ? WHERE email = ?', [hashed, reset['email']])
        execute_db('DELETE FROM password_resets WHERE token = ?', [token])
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('home'))
    return render_template('reset_password.html', token=token)

# ---------- Run ----------
if __name__ == '__main__':
    app.run(debug=True)