import os
import sqlite3
from contextlib import closing
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, DateField, TelField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

DB_FILE = "data.db"

# Database helper functions
def connect_db():
    """Create database connection with foreign keys enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # CRITICAL: Enable foreign key constraints
    return conn

def query_db(query, args=(), commit=False, one=False):
    """Execute param to prevent SQL injection."""
    with closing(connect_db()) as conn:
        try:
            cur = conn.execute(query, args)
            if commit:
                conn.commit()
            rv = cur.fetchone() if one else cur.fetchall()
            return rv
        except Exception as e:
            if commit:
                conn.rollback()
            raise e

def create_tables():
    """Initialize database tables with proper schema."""
    schema = """
    PRAGMA foreign_keys = ON;
    
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        dob TEXT,
        email TEXT UNIQUE NOT NULL,
        mobile TEXT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        phone_number TEXT,
        officer_type TEXT,
        id_number TEXT,
        date_of_joining TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        vehicle_type TEXT NOT NULL,
        vehicle_model TEXT NOT NULL,
        registration_number TEXT NOT NULL,
        theft_date TEXT NOT NULL,
        theft_location TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Solved', 'Rejected')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    -- Create indexes for better performance
    CREATE INDEX IF NOT EXISTS idx_complaints_user_id ON complaints(user_id);
    CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    """
    
    with closing(connect_db()) as conn:
        conn.executescript(schema)
        conn.commit()

# Authentication decorators
def login_required(f):
    """Decorator to require user login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# WTForms for validation and CSRF protection
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobile = TelField('Mobile Number', validators=[DataRequired(), Length(min=10, max=15)])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = query_db("SELECT id FROM users WHERE username = ?", (username.data,), one=True)
        if user:
            raise ValidationError('Username already exists. Choose a different one.')

    def validate_email(self, email):
        user = query_db("SELECT id FROM users WHERE email = ?", (email.data,), one=True)
        if user:
            raise ValidationError('Email already registered. Choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = TelField('Phone Number', validators=[DataRequired()])
    officer_type = SelectField('Officer Type', choices=[
        ('police', 'Police Officer'),
        ('detective', 'Detective'),
        ('supervisor', 'Supervisor')
    ], validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    date_of_joining = DateField('Date of Joining', validators=[DataRequired()])
    submit = SubmitField('Register Admin')

class ComplaintForm(FlaskForm):
    vehicle_type = SelectField('Vehicle Type', choices=[
        ('car', 'Car'),
        ('motorcycle', 'Motorcycle'),
        ('truck', 'Truck'),
        ('bicycle', 'Bicycle'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    vehicle_model = StringField('Vehicle Model', validators=[DataRequired(), Length(max=100)])
    registration_number = StringField('Registration Number', validators=[DataRequired(), Length(max=20)])
    theft_date = DateField('Date of Theft', validators=[DataRequired()])
    theft_location = StringField('Location of Theft', validators=[DataRequired(), Length(max=200)])
    contact_number = TelField('Contact Number', validators=[DataRequired()])
    description = TextAreaField('Additional Details', validators=[Length(max=500)])
    submit = SubmitField('Submit Complaint')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash password securely using bcrypt
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        query_db("""INSERT INTO users 
                    (first_name, last_name, dob, email, mobile, username, password_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (form.first_name.data, form.last_name.data, form.dob.data,
                 form.email.data, form.mobile.data, form.username.data, password_hash),
                commit=True)
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = query_db("SELECT * FROM users WHERE username = ? AND is_admin = 0",
                       (form.username.data,), one=True)
        
        if user and bcrypt.check_password_hash(user['password_hash'], form.password.data):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = False
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        # Hash password securely using bcrypt
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        query_db("""INSERT INTO users 
                    (username, email, phone_number, officer_type, id_number, 
                     password_hash, date_of_joining, is_admin)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (form.username.data, form.email.data, form.phone_number.data,
                 form.officer_type.data, form.id_number.data, password_hash,
                 form.date_of_joining.data), commit=True)
        
        flash('Admin registration successful!', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_register.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        admin = query_db("SELECT * FROM users WHERE username = ? AND is_admin = 1",
                        (form.username.data,), one=True)
        
        if admin and bcrypt.check_password_hash(admin['password_hash'], form.password.data):
            session.clear()
            session['user_id'] = admin['id']
            session['username'] = admin['username']
            session['is_admin'] = True
            flash(f'Welcome, Admin {admin["username"]}!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    
    return render_template('admin_login.html', form=form)

@app.route('/dashboard')
@login_required
def user_dashboard():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    complaints = query_db("SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC",
                         (session['user_id'],))
    
    stats = {
        'total': len(complaints),
        'pending': len([c for c in complaints if c['status'] == 'Pending']),
        'solved': len([c for c in complaints if c['status'] == 'Solved'])
    }
    
    return render_template('user_dashboard.html', complaints=complaints, stats=stats)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    complaints = query_db("""SELECT c.*, u.username, u.email, u.mobile
                            FROM complaints c
                            JOIN users u ON c.user_id = u.id
                            ORDER BY c.created_at DESC""")
    
    stats = {
        'total': len(complaints),
        'pending': len([c for c in complaints if c['status'] == 'Pending']),
        'solved': len([c for c in complaints if c['status'] == 'Solved'])
    }
    
    return render_template('admin_dashboard.html', complaints=complaints, stats=stats)

@app.route('/submit_complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    if session.get('is_admin'):
        flash('Admins cannot submit complaints.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    form = ComplaintForm()
    if form.validate_on_submit():
        # Insert complaint with proper user_id (not username!)
        query_db("""INSERT INTO complaints 
                    (user_id, vehicle_type, vehicle_model, registration_number,
                     theft_date, theft_location, contact_number, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session['user_id'], form.vehicle_type.data, form.vehicle_model.data,
                 form.registration_number.data, form.theft_date.data,
                 form.theft_location.data, form.contact_number.data,
                 form.description.data), commit=True)
        
        flash('Complaint submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('submit_complaint.html', form=form)

@app.route('/admin/update_status/<int:complaint_id>', methods=['GET', 'POST'])
@admin_required
def admin_update_status(complaint_id):
    complaint = query_db("""SELECT c.*, u.username, u.email
                           FROM complaints c
                           JOIN users u ON c.user_id = u.id
                           WHERE c.id = ?""", (complaint_id,), one=True)
    
    if not complaint:
        flash('Complaint not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        new_status = request.form.get('status')
        if new_status in ['Pending', 'Solved', 'Rejected']:
            query_db("UPDATE complaints SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (new_status, complaint_id), commit=True)
            flash('Complaint status updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid status value.', 'danger')
    
    return render_template('admin_update_status.html', complaint=complaint)

@app.route('/complaint/<int:complaint_id>')
@login_required
def view_complaint(complaint_id):
    """View individual complaint details for users."""
    complaint = query_db("""SELECT * FROM complaints
                           WHERE id = ? AND user_id = ?""",
                        (complaint_id, session['user_id']), one=True)
    if not complaint:
        flash('Complaint not found.', 'danger')
        return redirect(url_for('user_dashboard'))
    return render_template('update_status.html', complaint=complaint)

@app.route('/complaint/success/<int:complaint_id>')
@login_required
def complaint_success(complaint_id):
    """Success page after complaint submission."""
    complaint = query_db("""SELECT * FROM complaints
                           WHERE id = ? AND user_id = ?""",
                        (complaint_id, session['user_id']), one=True)
    if not complaint:
        flash('Complaint not found.', 'danger')
        return redirect(url_for('user_dashboard'))
    return render_template('complaint_success.html', complaint=complaint)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    if not os.path.exists(DB_FILE):
        create_tables()
        print("Database initialized successfully!")
    app.run(debug=True, host='127.0.0.1', port=5000)
