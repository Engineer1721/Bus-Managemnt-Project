from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
from flask import make_response
from xhtml2pdf import pisa
from pyzbar.pyzbar import decode
from PIL import Image
import qrcode
import base64
import io
import flask
g = flask.g

import os
print(os.path.abspath('bus.db'))

app = Flask(__name__)
app.secret_key = 'secret123'

#------------------------tables--------------------------
def init_db():
    conn = sqlite3.connect('bus.db', timeout=10)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS assignments")
    cursor.execute("DROP TABLE IF EXISTS notifications")
    cursor.execute("DROP TABLE IF EXISTS students")
    cursor.execute("DROP TABLE IF EXISTS drivers")
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS buses")
    cursor.execute("DROP TABLE IF EXISTS routes")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS routes (
        route_code TEXT PRIMARY KEY,
        start TEXT NOT NULL,
        end TEXT NOT NULL,
        stops TEXT,
        fare REAL NOT NULL,
        map TEXT
    );
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS students (
        registration_number TEXT PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        fee_status TEXT,
        bus_id INTEGER,
        seat_number TEXT,
        route_code TEXT,
        driver_registration TEXT,
        FOREIGN KEY (bus_id) REFERENCES buses(id),
        FOREIGN KEY (route_code) REFERENCES routes(route_code),
        FOREIGN KEY (driver_registration) REFERENCES drivers(registration_number)
    );
''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    );
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS buses (
        id INTEGER PRIMARY KEY,
        number TEXT NOT NULL UNIQUE,
        capacity INTEGER NOT NULL,
        driver_registration TEXT,
        route_code TEXT,
        FOREIGN KEY (driver_registration) REFERENCES drivers(registration_number),
        FOREIGN KEY (route_code) REFERENCES routes(route_code)
    );
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS drivers (
    registration_number TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    bus_id INTEGER,
    working_days TEXT,
    shift TEXT,
    is_active INTEGER DEFAULT 1,
    route_code TEXT,
    FOREIGN KEY (route_code) REFERENCES routes(route_code)
);
''')                   

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    role TEXT,
    days TEXT,  -- New column to specify days like "Monday,Wednesday,Friday"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''')

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO users (name, email, password, role) VALUES
        ('Admin', 'admin@bus.com', 'admin123', 'admin'),
        ('Driver1', 'driver@bus.com', 'driver123', 'driver'),
        ('Student1', 'student@bus.com', 'student123', 'student');
        """)

    conn.commit()
    conn.close()

#----------------------make databse----------------------------
def get_db_connection():
    conn = sqlite3.connect('bus.db')
    conn.row_factory = sqlite3.Row
    return conn
#-----------------home route----------------------------------
@app.route('/')
def home():
    return render_template('login.html')

#----------------login----------------------------------------

@app.route('/login', methods=['POST'])
def login():
    email    = request.form['email']
    password = request.form['password']
    role     = request.form['role']

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, name, password, role FROM users WHERE email = ? AND role = ?",
        (email, role)
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("No user found with this email and role.", "danger")
        return render_template('login.html')

    if user['password'] != password and not check_password_hash(user['password'], password):
        conn.close()
        flash("Incorrect password.", "danger")
        return render_template('login.html')
    session_user = {
        'id': user['id'],
        'name': user['name'],
        'email': email,
        'role': role
    }

    if role == 'student':
        cursor.execute("SELECT registration_number FROM students WHERE email = ?", (email,))
        result = cursor.fetchone()
        if not result:
            flash("Student record not found.", "danger")
            conn.close()
            return render_template('login.html')
        session_user['registration_number'] = result['registration_number']

    elif role == 'driver':
        cursor.execute("SELECT registration_number FROM drivers WHERE email = ?", (email,))
        result = cursor.fetchone()
        if not result:
            flash("Driver record not found.", "danger")
            conn.close()
            return render_template('login.html')
        session_user['registration_number'] = result['registration_number']

    session['user'] = session_user
    conn.close()

    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'driver':
        return redirect(url_for('driver_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    else:
        flash("Unknown user role.", "danger")
        return render_template('login.html')


#----------------------------dashboard------------------------------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('home'))
    
    role = session['user']['role']
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    elif role == 'driver':
        return redirect(url_for('driver_dashboard'))
    else:
        session.clear()
        return redirect(url_for('home'))
    
#----------------------------admin dashboard------------------------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('home'))

    user = session['user']
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS cnt FROM buses")
    total_buses = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) AS cnt FROM students")
    total_students = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) AS cnt FROM drivers")
    total_drivers = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) AS cnt FROM routes")
    active_routes = cursor.fetchone()['cnt']

    seat_availability = 0
    cursor.execute("SELECT id, capacity FROM buses")
    for bus in cursor.fetchall():
        cursor.execute("SELECT COUNT(*) AS assigned FROM students WHERE bus_id = ?", (bus['id'],))
        assigned = cursor.fetchone()['assigned']
        seat_availability += bus['capacity'] - assigned

    drivers = cursor.execute("SELECT registration_number, name FROM drivers").fetchall()
    students = cursor.execute("SELECT registration_number, name FROM students").fetchall()
    buses = cursor.execute("SELECT id, number FROM buses").fetchall()

    cursor.execute("SELECT message FROM notifications WHERE role='admin' OR role='all'")
    notifications = [row['message'] for row in cursor.fetchall()]

    conn.close()
    return render_template('admin_dashboard.html',
                           user=user,
                           notifications=notifications,
                           total_buses=total_buses,
                           total_students=total_students,
                           total_drivers=total_drivers,
                           active_routes=active_routes,
                           seat_availability=seat_availability,
                           drivers=drivers,
                           students=students,
                           buses=buses)

#----------------------------student dashboard------------------------------------
@app.route('/student/dashboard')
def student_dashboard():
    if 'user' not in session or session['user']['role'] != 'student':
        return redirect(url_for('home'))

    user  = session['user']
    regno = user['registration_number']

    conn = get_db_connection()
    c    = conn.cursor()

    c.execute("SELECT * FROM students WHERE registration_number = ?", (regno,))
    student = c.fetchone()
    if not student:
        conn.close()
        flash("Student record not found.", "danger")
        return redirect(url_for('home'))

    if student['fee_status'] != 'Paid':
        conn.close()
        flash("You must clear your fees before accessing the dashboard.", "warning")
        return redirect(url_for('home'))
    student_info = {
        'registration_number': student['registration_number'],
        'name':                student['name'],
        'email':               student['email'],
        'fee_status':          student['fee_status'],
        'seat_number':         student['seat_number']
    }
    bus_info    = {}
    route_info  = {}
    driver_info = {}

    if student['bus_id']:
        c.execute("SELECT number, capacity FROM buses WHERE id = ?", (student['bus_id'],))
        b = c.fetchone()
        if b:
            bus_info = {'number': b['number'], 'capacity': b['capacity']}
    if student['route_code']:
        c.execute("""
            SELECT start, end, fare, stops, map
              FROM routes
             WHERE route_code = ?
        """, (student['route_code'],))
        r = c.fetchone()
        if r:
            route_info = {
                'start': r['start'],
                'end':   r['end'],
                'fare':  r['fare'],
                'stops': r['stops'],
                'map':   r['map']
            }
    if student['driver_registration']:
        c.execute("""
            SELECT name, working_days, shift, is_active
              FROM drivers
             WHERE registration_number = ?
        """, (student['driver_registration'],))
        d = c.fetchone()
        if d:
            driver_info = {
                'name':         d['name'],
                'working_days': d['working_days'],
                'shift':        d['shift'],
                'status':       'Active' if d['is_active'] else 'Inactive'
            }
    c.execute("""
        SELECT message, days, created_at
          FROM notifications
         WHERE role IN ('student','all')
         ORDER BY created_at DESC
    """)
    notifications = [
        {
          'message':    row['message'],
          'days':       row['days'],
          'created_at': row['created_at']
        }
        for row in c.fetchall()
    ]

    conn.close()
    return render_template(
        'student_dashboard.html',
        user=user,
        student_info=student_info,
        bus_info=bus_info,
        route_info=route_info,
        driver_info=driver_info,
        notifications=notifications
    )
#----------------------------driver dashboard------------------------------------
@app.route('/driver/dashboard')
def driver_dashboard():
    if 'user' not in session or session['user']['role'] != 'driver':
        return redirect(url_for('home'))

    user = session['user']
    regno = user.get('registration_number')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM drivers WHERE registration_number = ?", (regno,))
    driver = cursor.fetchone()

    driver_info = {}
    bus_info = {}
    route_info = {}

    if driver:
        driver_info = {
            'registration_number': driver['registration_number'],
            'name': driver['name'],
            'email': driver['email'],
            'working_days': driver['working_days'],
            'shift': driver['shift'],
            'is_active': 'Active' if driver['is_active'] else 'Inactive'
        }

        if driver['route_code']:
            cursor.execute("""
                SELECT start, end, fare, stops, map
                FROM routes
                WHERE route_code = ?
            """, (driver['route_code'],))
            route = cursor.fetchone()
            if route:
                route_info = {
                    'start': route['start'],
                    'end': route['end'],
                    'fare': route['fare'],
                    'stops': route['stops'],
                    'map': route['map'] if 'map' in route.keys() else None
                }

                # Get bus info based on route_code
                cursor.execute("""
                    SELECT number, capacity
                    FROM buses
                    WHERE route_code = ?
                """, (driver['route_code'],))
                bus = cursor.fetchone()
                if bus:
                    bus_info = {
                        'number': bus['number'],
                        'capacity': bus['capacity']
                    }
    cursor.execute("""
        SELECT message, days, created_at
        FROM notifications
        WHERE role IN ('driver', 'all')
        ORDER BY created_at DESC
    """)
    notifications = [
        {
            'message': row['message'],
            'days': row['days'],
            'created_at': row['created_at']
        }
        for row in cursor.fetchall()
    ]

    conn.close()

    return render_template(
        'driver_dashboard.html',
        user=user,
        driver_info=driver_info,
        bus_info=bus_info,
        route_info=route_info,
        notifications=notifications
    )


#----------------------------send notification------------------------------------
@app.route('/notifications', methods=['GET', 'POST'])
def notifications():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'POST':
        message = request.form['message']
        role = request.form['role']
        selected_days = request.form.getlist('days')
        days = ','.join(selected_days)

        cursor.execute(
            'INSERT INTO notifications (message, role, days) VALUES (?, ?, ?)',
            (message, role, days)
        )
        conn.commit()
        flash("Notification added successfully!", "success")
        return redirect(url_for('notifications'))
    cursor.execute('SELECT * FROM notifications ORDER BY created_at DESC')
    notifications = cursor.fetchall()
    conn.close()
    return render_template('notifications.html', notifications=notifications)

#----------------------------Delete notification-------------------------------
@app.route('/delete_notification/<int:id>', methods=['POST'])
def delete_notification(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM notifications WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash("Notification deleted successfully!", "success")
    return redirect(url_for('notifications'))

#----------------------------Add Route----------------------------------------
@app.route('/add-route', methods=['GET', 'POST'])
def add_route():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('home'))
    conn = get_db_connection()
    cursor = conn.cursor()
    route_to_edit = None
    route_code_param = request.args.get('route_code')
    search_query = request.args.get('search', '')
    if request.method == 'POST':
        route_code = request.form.get('route_code')
        start = request.form.get('start')
        end = request.form.get('end')
        stops = request.form.get('stops')
        fare = request.form.get('fare')
        map_url = request.form.get('map')

        if not route_code or not start or not end or not fare:
            flash("Route Code, Start, End, and Fare are required.", "danger")
            return redirect(url_for('add_route'))

        cursor.execute("SELECT * FROM routes WHERE route_code = ?", (route_code,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute('''UPDATE routes 
                              SET start=?, end=?, stops=?, fare=?, map=? 
                              WHERE route_code=?''',
                           (start, end, stops, fare, map_url, route_code))
            flash("Route updated successfully!", "success")
        else:
            cursor.execute('''INSERT INTO routes (route_code, start, end, stops, fare, map) 
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (route_code, start, end, stops, fare, map_url))
            flash("Route added successfully!", "success")
        conn.commit()
        return redirect(url_for('add_route'))
    if route_code_param:
        cursor.execute("SELECT * FROM routes WHERE route_code = ?", (route_code_param,))
        route_to_edit = cursor.fetchone()
    if search_query:
        query = f"%{search_query}%"
        cursor.execute("SELECT * FROM routes WHERE route_code LIKE ? OR start LIKE ? OR end LIKE ?",
                       (query, query, query))
    else:
        cursor.execute("SELECT * FROM routes")
    routes = cursor.fetchall()
    conn.close()

    return render_template('add_route.html', routes=routes, route_to_edit=route_to_edit)

#----------------------------Delete Route-------------------------------------
@app.route('/delete-route/<route_code>', methods=['GET', 'POST'])
def delete_route(route_code):
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('home'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM routes WHERE route_code=?", (route_code,))
    conn.commit()
    conn.close()
    flash("Route deleted successfully!", "success")
    return redirect(url_for('add_route'))

# --- ----------------------Add Driver ------------------------------------
@app.route('/admin/add-driver', methods=['GET', 'POST'])
def add_driver():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor()

    driver_to_edit = None
    rn_param       = request.args.get('registration_number', '').strip()
    search_query   = request.args.get('search', '').strip()
    cursor.execute("SELECT * FROM routes")
    routes = cursor.fetchall()

    if request.method == 'POST':
        rn         = request.form['registration_number']
        name       = request.form['name']
        email      = request.form['email']
        pwd        = request.form['password']
        days       = request.form['working_days']
        shift      = request.form['shift']
        route_code = request.form['route_code']
        is_active  = 1 if request.form.get('is_active') else 0

 
        if not (rn and name and email and days and shift and route_code):
            flash("All fields except password are required.", "danger")
            return redirect(url_for('add_driver'))
        hpwd = generate_password_hash(pwd) if pwd else None
        cursor.execute("SELECT 1 FROM drivers WHERE registration_number = ?", (rn,))
        exists = cursor.fetchone()

        if exists:
            if hpwd:
                cursor.execute('''
                    UPDATE drivers
                       SET name=?, email=?, password=?, working_days=?, shift=?, route_code=?, is_active=?
                     WHERE registration_number=?
                ''', (name, email, hpwd, days, shift, route_code, is_active, rn))
            else:
                cursor.execute('''
                    UPDATE drivers
                       SET name=?, email=?, working_days=?, shift=?, route_code=?, is_active=?
                     WHERE registration_number=?
                ''', (name, email, days, shift, route_code, is_active, rn))
            flash("Driver updated successfully!", "success")
        else:
            cursor.execute('''
                INSERT INTO drivers
                  (registration_number, name, email, password, working_days, shift, route_code, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (rn, name, email, hpwd, days, shift, route_code, is_active))
            flash("Driver added successfully!", "success")
        cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            if hpwd:
                cursor.execute('''
                    UPDATE users
                       SET name=?, password=?, role='driver'
                     WHERE email=?
                ''', (name, hpwd, email))
            else:
                cursor.execute('''
                    UPDATE users
                       SET name=?, role='driver'
                     WHERE email=?
                ''', (name, email))
        else:
            cursor.execute('''
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, 'driver')
            ''', (name, email, hpwd))

        conn.commit()
        conn.close()
        return redirect(url_for('add_driver'))
    if rn_param:
        cursor.execute("SELECT * FROM drivers WHERE registration_number = ?", (rn_param,))
        driver_to_edit = cursor.fetchone()
        if not driver_to_edit:
            flash(f"No driver found with registration number '{rn_param}'.", "warning")
    if search_query:
        q = f"%{search_query}%"
        cursor.execute('''
            SELECT * FROM drivers
             WHERE registration_number LIKE ? OR name LIKE ? OR email LIKE ?
        ''', (q, q, q))
    else:
        cursor.execute("SELECT * FROM drivers")

    drivers = cursor.fetchall()
    conn.close()
    return render_template('add_driver.html',
                           drivers=drivers,
                           driver_to_edit=driver_to_edit,
                           routes=routes)

#-------------------------Delete Driver--------------------------------------
@app.route('/admin/delete-driver/<registration_number>', methods=['POST'])
def delete_driver(registration_number):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM drivers WHERE registration_number = ?', (registration_number,))
        conn.commit()
        flash('Driver deleted successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error deleting driver: ' + str(e), 'error')
    finally:
        conn.close()
    return redirect(url_for('add_driver'))

#--------------------------Add buses-------------------------------------------
def get_bus_by_number(bus_number):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM buses WHERE number = ?", (bus_number,))
    bus = cursor.fetchone()  
    conn.close()
    return bus
@app.route('/add_bus', methods=['GET', 'POST'])
def add_bus():
    search_q = request.args.get('q', '').strip()
    bus_to_edit = None
    edit_bus_number = request.args.get('edit')
    if edit_bus_number:
        bus_to_edit = get_bus_by_number(edit_bus_number)  

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routes")
    routes = cursor.fetchall()
    cursor.execute("SELECT * FROM drivers")
    drivers = cursor.fetchall()

    route_driver_map = {}
    for driver in drivers:
        route_driver_map.setdefault(driver['route_code'], []).append({
            'registration_number': driver['registration_number'],
            'name': driver['name']
        })

    if request.method == 'POST':
        bus_number = request.form['number']
        capacity = request.form['capacity']
        route_code = request.form['route_code']
        driver_registration = request.form['driver_registration']
        cursor.execute("SELECT * FROM buses WHERE number = ?", (bus_number,))
        existing_bus = cursor.fetchone()
        if bus_to_edit: 
            if bus_number != bus_to_edit['number'] and existing_bus:
                error = "Bus number already exists! Please choose a different number."
                conn.close()
                return render_template('add_bus.html', buses=[], routes=routes, route_driver_map=route_driver_map, bus_to_edit=bus_to_edit, search_query=search_q, error=error)
            cursor.execute(''' 
                UPDATE buses 
                SET number = ?, capacity = ?, route_code = ?, driver_registration = ? 
                WHERE number = ?
            ''', (bus_number, capacity, route_code, driver_registration, bus_to_edit['number']))
        else:  
            if existing_bus:
                error = "Bus number already exists! Please choose a different number."
                conn.close()
                return render_template('add_bus.html', buses=[], routes=routes, route_driver_map=route_driver_map, bus_to_edit=None, search_query=search_q, error=error)

            cursor.execute('''
                INSERT INTO buses (number, capacity, route_code, driver_registration)
                VALUES (?, ?, ?, ?)
            ''', (bus_number, capacity, route_code, driver_registration))

        conn.commit()
        conn.close()
        return redirect(url_for('add_bus'))
    if search_q:
        like_q = f"%{search_q}%"
        cursor.execute(""" 
            SELECT * FROM buses 
            WHERE number LIKE ? OR CAST(capacity AS TEXT) LIKE ? OR route_code LIKE ? OR driver_registration LIKE ? 
            ORDER BY ROWID ASC 
        """, (like_q, like_q, like_q, like_q))
    else:
        cursor.execute("""
            SELECT * FROM buses ORDER BY ROWID ASC
        """)
    buses = cursor.fetchall()
    conn.close()
    return render_template('add_bus.html', buses=buses, routes=routes, route_driver_map=route_driver_map, bus_to_edit=bus_to_edit, search_query=search_q)

#------------------------Delete bus----------------------------------
@app.route('/admin/delete-bus/<int:id>', methods=['GET', 'POST'])
def delete_bus(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT number FROM buses WHERE id = ?", (id,))  
        bus = cursor.fetchone()
        if bus:
            cursor.execute("DELETE FROM buses WHERE id = ?", (id,))
            conn.commit()
            flash(f"Bus {bus['number']} deleted successfully.", "success") 
        else:
            flash(f"Bus with ID {id} not found.", "danger")
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error deleting bus: {e}")
        flash("Error deleting bus.", "danger")
    finally:
        conn.close()
    return redirect(url_for('add_bus'))

#-------------------------Add Student--------------------------------------
@app.route('/add-student', methods=['GET', 'POST'])
def add_student():
    orig_reg = request.form.get('original_registration')
    if request.method == 'POST':
        reg_no      = request.form['registration_number']
        name        = request.form['name']
        email       = request.form['email']
        password    = request.form['password']
        fee_status  = request.form['fee_status']
        seat_number = request.form['seat_number']
        route_code  = request.form['route_code']
        driver_reg  = request.form['driver_registration']

        conn = get_db_connection()
        cursor = conn.cursor()
        print(f"Route code from form: {route_code}")
        cursor.execute("SELECT id FROM buses WHERE route_code = ?", (route_code,))
        bus_row = cursor.fetchone()
        print(f"Bus row found: {bus_row}")

        bus_id = bus_row['id'] if bus_row else None
        print(f"bus_id assigned: {bus_id}")

        try:
            if orig_reg:
                cursor.execute(''' 
                    UPDATE students 
                    SET registration_number = ?, name = ?, email = ?, password = ?,
                        fee_status = ?, seat_number = ?, route_code = ?, bus_id = ?, driver_registration = ?
                    WHERE registration_number = ?
                ''', (reg_no, name, email, password, fee_status, seat_number, route_code, bus_id, driver_reg, orig_reg))
                flash(f"Student {orig_reg} updated to {reg_no}.", "success")
                cursor.execute('''UPDATE users 
                                  SET name=?, email=?, password=?, role=? 
                                  WHERE email=?''',
                               (name, email, password, 'student', email))

            else:
                cursor.execute(
                    "SELECT 1 FROM students WHERE registration_number = ?",
                    (reg_no,)
                )
                if cursor.fetchone():
                    flash(f"Registration #{reg_no} already exists.", "danger")
                else:
                    cursor.execute(''' 
                        INSERT INTO students
                          (registration_number, name, email, password,
                           fee_status, seat_number, route_code, bus_id, driver_registration)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (reg_no, name, email, password, fee_status, seat_number, route_code, bus_id, driver_reg))
                    cursor.execute('''INSERT INTO users (name, email, password, role)
                                      VALUES (?, ?, ?, ?)''',
                                   (name, email, password, 'student'))
                    flash("Student added successfully!", "success")
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            action = "updating" if orig_reg else "adding"
            print(f"Error {action} student:", e)
            flash(f"Error {action} student.", "danger")
        finally:
            conn.close()
        return redirect(url_for('add_student'))
    search_q = request.args.get('q', '').strip()
    edit_reg = request.args.get('edit')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routes")
    routes = cursor.fetchall()
    cursor.execute("SELECT * FROM drivers")
    drivers = cursor.fetchall()
    route_driver_map = {}
    for d in drivers:
        route_driver_map.setdefault(d['route_code'], []).append({
            'registration_number': d['registration_number'],
            'name': d['name']
        })
    if search_q:
        like_q = f"%{search_q}%"
        cursor.execute("""
        SELECT * 
          FROM students 
         WHERE name LIKE ? OR registration_number LIKE ? 
         ORDER BY ROWID ASC
        """, (like_q, like_q))
    else:
        cursor.execute("""
        SELECT * 
          FROM students 
         ORDER BY ROWID ASC
        """)

    students = cursor.fetchall()
    student_to_edit = None
    if edit_reg:
        cursor.execute(
            "SELECT * FROM students WHERE registration_number = ?",
            (edit_reg,)
        )
        student_to_edit = cursor.fetchone()

    conn.close()

    return render_template(
        'add_student.html',
        routes=routes,
        route_driver_map=route_driver_map,
        students=students,
        search_query=search_q,
        student_to_edit=student_to_edit
    )

#--------------------------delete student-------------------------------
@app.route('/delete-student/<string:registration_number>', methods=['POST'])
def delete_student(registration_number):
    try:
        conn = sqlite3.connect('bus.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM students WHERE registration_number = ?',
            (registration_number,)
        )
        conn.commit()
        conn.close()
        flash(f"Student {registration_number} deleted successfully.", "success")
    except sqlite3.Error as e:
        print(f"An error occurred while deleting the student: {e}")
        flash("An error occurred while deleting the student.", "danger")
    return redirect(url_for('add_student'))

#--------------------------print database----------------------------
@app.route('/print-database')
def print_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    tables = ["routes", "students", "users", "buses", "drivers", "notifications"]
    data = {}
    for table in tables:
        cursor.execute(f"SELECT * FROM {table}")
        rows = cursor.fetchall()
        data[table] = [dict(row) for row in rows]
    conn.close()
    output_format = request.args.get('format', 'html')
    if output_format == 'pdf':
        html = render_template("print_database_pdf.html", data=data)
        result = io.BytesIO()
        pisa_status = pisa.CreatePDF(io.StringIO(html), dest=result)
        if pisa_status.err:
            return "PDF generation error", 500
        response = make_response(result.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "inline; filename=database.pdf"
        return response
    else:
        return render_template("print_database.html", data=data)

#--------------------------Scanning--------------------------------------
@app.route('/qr-form')
def qr_form():
    print("Session:", session)
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('qr_form.html')
@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    registration_number = request.form.get('registration_number')
    if not registration_number:
        return redirect(url_for('qr_form'))

    qr_img = qrcode.make(registration_number)
    buffered = io.BytesIO()
    qr_img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('ascii')

    return render_template('show_qr.html', qr_code=img_str, registration_number=registration_number)

DATABASE = 'bus.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()
        del g.db

def query_student_by_registration(registration_number):
    db = get_db()
    cursor = db.execute('SELECT * FROM students WHERE registration_number = ?', (registration_number,))
    return cursor.fetchone()

@app.route('/scan_registration', methods=['GET', 'POST'])
def scan_registration():
    registration_number = None
    student = None
    error = None

    if request.method == 'POST':
        registration_number = request.form.get('registration_number', '').strip()
        if not registration_number:
            error = "Please enter a registration number."
        else:
            student = query_student_by_registration(registration_number)
            if student is None:
                error = f"No student found with registration number '{registration_number}'."

    return render_template('scan_registration.html',
                           registration_number=registration_number,
                           student=student,
                           error=error)
#----------------------------Log Out---------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

#-------------------------------Main-----------------------------------------
if __name__ == '__main__':
    db_path = os.path.abspath('bus.db')
    if not os.path.exists(db_path):
        init_db()      
    app.run(debug=True)

