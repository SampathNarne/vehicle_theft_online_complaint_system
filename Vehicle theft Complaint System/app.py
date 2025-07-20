from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key for session management

# Database connection
def connect_db():
    conn = sqlite3.connect('data.db')  # Make sure to replace 'data.db' with the actual database file
    conn.row_factory = sqlite3.Row  # To fetch rows as dictionaries
    return conn

# Function to add 'phone_number' column if it does not exist
def add_phone_number_column_if_not_exists():
    conn = connect_db()
    cursor = conn.cursor()
    
    # Check if the 'phone_number' column already exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]  # Get all column names
    
    if "phone_number" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN phone_number TEXT")
        conn.commit()
    
    conn.close()

# Create tables if they don't exist
def create_tables():
    conn = connect_db()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        dob TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        mobile TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 1,
        phone_number TEXT,
        officer_type TEXT,
        id_number TEXT,
        date_of_joining TEXT
    )''')

    # Create complaints table
    cursor.execute('''CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        vehicle_type TEXT,
        vehicle_model TEXT,
        registration_number TEXT,
        theft_date TEXT,
        theft_location TEXT,
        contact_number TEXT,
        status TEXT DEFAULT 'Pending'
    )''')

    conn.commit()
    conn.close()

# Check user credentials (for both users and admins)
def check_user(username, password):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

# Check if the user is an admin
def check_admin(username, password):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ? AND is_admin = 1', (username, password))
    admin = cursor.fetchone()
    conn.close()
    return admin

# Home page using home.html
@app.route('/')
def home():
    return render_template('home.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = check_user(username, password)
        
        if user:
            # Set session variables for logged-in user
            session['username'] = username
            session['is_admin'] = user['is_admin'] == 1  # True if user is an admin, False otherwise
            
            # Debugging print statement to check role
            print(f"Logged in as: {username}, is_admin: {session['is_admin']}")
            
            # Redirect based on the is_admin flag
            if session['is_admin']:  
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            error_message = 'Invalid username or password'
    
    return render_template('login.html', error_message=error_message)

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None
    if request.method == 'POST':
        first_name = request.form['f_name']
        last_name = request.form['l_name']
        dob = request.form['dob']
        email = request.form['email']
        mobile = request.form['mobile']
        username = request.form['username']
        password = request.form['password']
        conn = connect_db()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (first_name, last_name, dob, email, mobile, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                           (first_name, last_name, dob, email, mobile, username, password))
            conn.commit()
            flash('Registration completed successfully.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error_message = 'Username or Email already exists'
        finally:
            conn.close()
    return render_template('register.html', error_message=error_message)

# Admin Register page
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone_number = request.form['phone_number']
        officer_type = request.form['officer_type']
        id_number = request.form['id_number']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        date_of_joining = request.form['date_of_joining']

        # Validate passwords match
        if password != confirm_password:
            error_message = 'Passwords do not match.'
        else:
            conn = connect_db()
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT INTO users (username, email, phone_number, officer_type, id_number, password, date_of_joining, is_admin) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, 1)''',
                       (username, email, phone_number, officer_type, id_number, password, date_of_joining))
                conn.commit()

                # Flash a success message after successful registration
                flash('Registration successful!', 'success')
                return redirect(url_for('admin_login'))  # Redirect to admin login page after successful registration
            except sqlite3.IntegrityError:
                error_message = 'Username or Email already exists.'
            finally:
                conn.close()

    return render_template('admin_register.html', error_message=error_message)

# Admin login page
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = check_admin(username, password)  # Check if the user is an admin
        if admin:
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            error_message = 'Invalid admin credentials'
    return render_template('admin_login.html', error_message=error_message)

# Admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    # Only allow access if the user is logged in as an admin
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('admin_login'))
    
    # Fetch complaints data for admin view
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM complaints')
    complaints = cursor.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', complaints=complaints)

# Admin update status route (for updating complaint status)
@app.route('/admin/update_status/<int:complaint_id>', methods=['GET', 'POST'])
def admin_update_status(complaint_id):
    # Only allow access if the user is logged in as an admin
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('admin_login'))
    
    # Fetch the complaint based on the complaint_id
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM complaints WHERE id = ?', (complaint_id,))
    complaint = cursor.fetchone()

    if request.method == 'POST':
        status = request.form['status']  # Status submitted by the admin
        cursor.execute('UPDATE complaints SET status = ? WHERE id = ?', (status, complaint_id))
        conn.commit()
        conn.close()
        flash('Complaint status updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    conn.close()
    return render_template('admin_update_status.html', complaint=complaint)

# User Dashboard
@app.route('/dashboard')
def user_dashboard():
    # Only allow access if the user is logged in and not an admin
    if 'username' not in session or session.get('is_admin', False):
        return redirect(url_for('login'))
    
    # Fetch complaints data for the logged-in user
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM complaints WHERE user_id = (SELECT id FROM users WHERE username = ?)', (session['username'],))
    complaints = cursor.fetchall()
    conn.close()
    return render_template('user_dashboard.html', complaints=complaints)

# Submit Complaint page
@app.route('/submit_complaint', methods=['GET', 'POST'])
def submit_complaint():
    if 'username' not in session:
        return redirect(url_for('login'))

    error_message = None
    if request.method == 'POST':
        vehicle_type = request.form['vehicle_type']
        vehicle_model = request.form['vehicle_model']
        registration_number = request.form['registration_number']
        theft_date = request.form['theft_date']
        theft_location = request.form['theft_location']
        contact_number = request.form['contact_number']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO complaints (user_id, vehicle_type, vehicle_model, registration_number, theft_date, theft_location, contact_number) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                       (session['username'], vehicle_type, vehicle_model, registration_number, theft_date, theft_location, contact_number))
        conn.commit()
        conn.close()
        flash('Complaint submitted successfully', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('submit_complaint.html', error_message=error_message)

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))  # Redirect to the login page

# Run the application
if __name__ == '__main__':
    create_tables()
    add_phone_number_column_if_not_exists()
    app.run(debug=True)
