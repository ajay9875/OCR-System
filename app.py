from flask import Flask, render_template, request, session, flash, redirect, url_for, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3
import pytz
import os
import uuid
from dotenv import load_dotenv
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Session cookie settings
app.config["SESSION_COOKIE_SECURE"] = True  # Ensures cookies are sent over HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Protects cookies from JavaScript access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protects against CSRF in cross-site contexts

# Prevent denial-of-service (DoS) attacks by limiting the size of incoming requests
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

@app.route('/insert_courses')
def insert_courses():
    with app.app_context():
        db = get_allcourses_db()
        cursor = db.cursor()
        
        # Combined list of all courses (original + new)
        courses = [
            # Original courses (30)
            ("PCC-CSM101", "Artificial Intelligence", 12, 34),
            ("PCC-CSM104", "Cloud Computing", 20, 10),
            ("PCC-CSM105", "Cyber Security", 18, 30),
            ("PCC-CSM106", "Python for Data Science", 10, 30),
            ("PCC-CSM107", "Java for Web Development", 14, 30),
            ("PCC-CSM108", "Blockchain Development", 18, 30),
            ("PCC-CSM109", "DevOps Engineering", 16, 30),
            ("PCC-CSM110", "UI/UX Design", 12, 30),
            ("PCC-CSM111", "Game Development", 20, 30),
            ("PCC-CSM112", "Internet of Things (IoT)", 14, 30),
            ("PCC-CSM113", "Software Testing", 12, 30),
            ("PCC-CSM114", "Big Data Analytics", 18, 30),
            ("PCC-CSM115", "Quantum Computing", 22, 30),
            ("PCC-CSM116", "Digital Marketing", 14, 30),
            ("PCC-CSM117", "Mobile App Development", 12, 30),
            ("PCC-CSM119", "Robotics and Automation", 18, 30),
            ("PCC-CSM120", "Network Administration", 14, 30),
            ("PCC-CSM121", "Game AI Development", 16, 30),
            ("PCC-CSM122", "Data Engineering", 18, 30),
            ("PCC-CSM123", "Cloud Security", 16, 30),
            ("PCC-CSM125", "Artificial Intelligence for Robotics", 20, 30),
            ("PCC-CSM126", "Blockchain for Supply Chain", 14, 30),
            ("PCC-CSM127", "Python for Automation", 10, 30),
            ("PCC-CSM128", "Natural Language Processing (NLP)", 18, 30),
            ("PCC-CSM129", "Enterprise Resource Planning (ERP)", 16, 30),
            ("PCC-CSM130", "Introduction to Quantum Computing", 12, 30),
            ("PCC-CSM131", "Cybersecurity Risk Management", 18, 30),
            ("PCC-CSM132", "DevOps for Developers", 14, 30),
            ("PCC-CSM134", "Machine Learning", 20, 30),
            ("PCC-CSM201", "ML", 5, 10),
            
            # New courses (70)
            ("PCC-CSM202", "Advanced Algorithms", 16, 25),
            ("PCC-CSM203", "Computer Graphics", 14, 20),
            ("PCC-CSM204", "Distributed Systems", 18, 30),
            ("PCC-CSM205", "Computer Vision", 16, 25),
            ("PCC-CSM206", "Embedded Systems", 14, 20),
            ("PCC-CSM207", "Wireless Networks", 12, 30),
            ("PCC-CSM208", "Database Administration", 16, 25),
            ("PCC-CSM209", "Software Architecture", 18, 20),
            ("PCC-CSM210", "Mobile Security", 14, 25),
            ("PCC-CSM211", "Ethical Hacking", 16, 30),
            ("PCC-CSM212", "Digital Forensics", 14, 20),
            ("PCC-CSM213", "Network Security", 16, 25),
            ("PCC-CSM214", "Cryptography", 18, 20),
            ("PCC-CSM215", "Penetration Testing", 14, 25),
            ("PCC-CSM216", "Secure Coding", 12, 30),
            ("PCC-CSM217", "Cloud Architecture", 16, 25),
            ("PCC-CSM218", "Serverless Computing", 14, 20),
            ("PCC-CSM219", "Microservices", 18, 25),
            ("PCC-CSM220", "Containerization", 16, 30),
            ("PCC-CSM221", "Data Mining", 14, 25),
            ("PCC-CSM222", "Data Visualization", 12, 30),
            ("PCC-CSM223", "Business Intelligence", 16, 25),
            ("PCC-CSM224", "Predictive Analytics", 18, 20),
            ("PCC-CSM225", "Time Series Analysis", 14, 25),
            ("PCC-CSM226", "Deep Learning", 16, 30),
            ("PCC-CSM227", "Reinforcement Learning", 18, 20),
            ("PCC-CSM228", "Neural Networks", 14, 25),
            ("PCC-CSM229", "Computer Organization", 12, 30),
            ("PCC-CSM230", "Operating Systems", 16, 25),
            ("PCC-CSM231", "Compiler Design", 18, 20),
            ("PCC-CSM232", "Parallel Computing", 14, 25),
            ("PCC-CSM233", "Quantum Algorithms", 16, 30),
            ("PCC-CSM234", "Bioinformatics", 18, 20),
            ("PCC-CSM235", "Computational Biology", 14, 25),
            ("PCC-CSM236", "Health Informatics", 12, 30),
            ("PCC-CSM237", "Augmented Reality", 16, 25),
            ("PCC-CSM238", "Virtual Reality", 18, 20),
            ("PCC-CSM239", "Mixed Reality", 14, 25),
            ("PCC-CSM240", "Game Design", 16, 30),
            ("PCC-CSM241", "Game Physics", 18, 20),
            ("PCC-CSM242", "3D Modeling", 14, 25),
            ("PCC-CSM243", "Animation Techniques", 12, 30),
            ("PCC-CSM244", "Digital Signal Processing", 16, 25),
            ("PCC-CSM245", "Image Processing", 18, 20),
            ("PCC-CSM246", "Audio Processing", 14, 25),
            ("PCC-CSM247", "Video Processing", 16, 30),
            ("PCC-CSM248", "Natural Language Generation", 18, 20),
            ("PCC-CSM249", "Speech Recognition", 14, 25),
            ("PCC-CSM250", "Chatbot Development", 12, 30),
            ("PCC-CSM251", "Recommendation Systems", 16, 25),
            ("PCC-CSM252", "Fraud Detection", 18, 20),
            ("PCC-CSM253", "Anomaly Detection", 14, 25),
            ("PCC-CSM254", "Edge Computing", 16, 30),
            ("PCC-CSM255", "Fog Computing", 18, 20),
            ("PCC-CSM256", "Green Computing", 14, 25),
            ("PCC-CSM257", "Sustainable IT", 12, 30),
            ("PCC-CSM258", "IT Project Management", 16, 25),
            ("PCC-CSM259", "Agile Methodologies", 18, 20),
            ("PCC-CSM260", "Scrum Master", 14, 25),
            ("PCC-CSM261", "DevOps Culture", 16, 30),
            ("PCC-CSM262", "Site Reliability Engineering", 18, 20),
            ("PCC-CSM263", "Infrastructure as Code", 14, 25),
            ("PCC-CSM264", "Continuous Integration", 12, 30),
            ("PCC-CSM265", "Continuous Deployment", 16, 25),
            ("PCC-CSM266", "Test Automation", 18, 20),
            ("PCC-CSM267", "Performance Engineering", 14, 25),
            ("PCC-CSM268", "Load Testing", 16, 30),
            ("PCC-CSM269", "Chaos Engineering", 18, 20),
            ("PCC-CSM270", "Observability", 14, 25),
            ("PCC-CSM271", "Monitoring Systems", 12, 30),
            ("PCC-CSM272", "Log Management", 16, 25),
            ("PCC-CSM273", "Incident Management", 18, 20),
            ("PCC-CSM274", "IT Service Management", 14, 25),
            ("PCC-CSM275", "Cloud Cost Optimization", 16, 30)
        ]
        
        try:
            cursor.execute("SELECT COUNT(*) AS total_courses FROM allcourses")
            result = cursor.fetchone()
            if result[0] >= 100:
                return f"{result[0]} courses already exists!"

            # Insert all courses in a single transaction
            cursor.executemany("""
                INSERT OR IGNORE INTO allcourses 
                (course_code, course_name, course_unit, seat_limit) 
                VALUES (?, ?, ?, ?)
            """, courses)
            
            db.commit()
            print(f"Successfully inserted {cursor.rowcount} courses.")
            return f"Successfully inserted {cursor.rowcount} courses."
        
        except Exception as e:
            db.rollback()
            print(f"Error inserting courses: {str(e)}")
            return "Courses could not insert!"
        finally:
            cursor.close()

# For development only
@app.route('/init_admin')
def init_admin():
    try:
        admin_name = os.getenv("ADMIN_NAME")
        admin_email = os.getenv("ADMIN_EMAIL")
        admin_phone = os.getenv("ADMIN_PHONE")
        # Hash the password and the security pin using the default PBKDF2 method
        hashed_password = generate_password_hash(os.getenv("ADMIN_PASSWORD"))  # Uses PBKDF2 by default
        hashed_security_pin = generate_password_hash(os.getenv("SECURITY_PIN"))  # Uses PBKDF2 by default

        # Open database connection to admins database
        db = get_admin_db()
        cursor = db.cursor()

        # Check if the admin user already exists in the admins table
        cursor.execute("SELECT COUNT(*) FROM admins WHERE username = ?", (admin_name,))
        result = cursor.fetchone()

        if result[0] >= 1:
            return f"Admin user '{admin_name}' already exists in admins table!"

        # Insert admin into the admins table
        cursor.execute(''' 
            INSERT INTO admins (username, email, phone_number, password, securityPin, profile_pic)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (admin_name, admin_email, admin_phone, hashed_password, hashed_security_pin, None)
        )
        db.commit()

        # Handle users table separately
        db1 = get_db()  # User database connection
        cursor1 = db1.cursor()

        # Check if the admin user already exists in the users table
        cursor1.execute("SELECT COUNT(*) FROM users WHERE username = ?", (admin_name,))
        result1 = cursor1.fetchone()

        if result1[0] >= 1:
            return f"User '{admin_name}' already exists in users table!"

        # Insert into the users table as well (for login purposes)
        now = datetime.now()
        cursor1.execute('''
            INSERT INTO users (username, email, phone_number, created_at, password)
            VALUES (?, ?, ?, ?, ?)
        ''', (admin_name, admin_email, admin_phone, now, hashed_password))
        db1.commit()

        print("Admin user created and inserted into both admins and users tables.")
        return "Admin user created and inserted into both admins and users tables."

    except Exception as e:
        return f"Admin user could not be created! Error: {str(e)}"
    
@app.before_request
def validate_admin_session():
    if 'admin_id' in session:
        try:
            admin_id = session['admin_id']
            db = get_admin_db()
            cursor = db.cursor()
            cursor.execute("SELECT id FROM admins WHERE id = ?", (admin_id,))
            admin = cursor.fetchone()

            if not admin:
                session.pop('admin_id', None)
                flash("Your account has been deleted. Please contact support.", "error")
                return redirect(url_for("adminLogin"))

        except Exception as e:
            session.pop('admin_id', None)
            session.pop('admin_name', None)
            flash(f"Session error: {str(e)}", "error")
            return redirect(url_for("adminLogin"))

@app.before_request
def validate_user_session():
    if 'user_id' in session:
        try:
            user_id = session['user_id']
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
            user = cursor.fetchone()

            if not user:
                session.pop('user_id', None)
                session.pop('username', None)
                flash("Your account has been deleted. Please contact support.", "error")
                return redirect(url_for("login"))

        except Exception as e:
            session.pop('user_id', None)
            session.pop('username', None)
            flash(f"Session error: {str(e)}", "error")
            return redirect(url_for("login"))

# Create the database folder if it doesn't exist
db_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

#------ All functions to create database using sqlite3 ------
import time

# Database file paths - Ensure they are full paths inside the 'database' folder
USERS_DB = os.path.join(db_folder, "users.db")
RESERVED_COURSES_DB = os.path.join(db_folder, "reservedcourses.db")
ADMIN_DB = os.path.join(db_folder, "admins.db")
ALLCOURSES_DB = os.path.join(db_folder, "allcourses.db")
SESSIONS_DB = os.path.join(db_folder, "sessions.db")

# Function to get the users database connection
def get_db():
    """Returns a database connection to the users database."""
    if not hasattr(g, 'users_db'):
        g.users_db = sqlite3.connect(USERS_DB)
        g.users_db.row_factory = sqlite3.Row
    return g.users_db

# Function to get the reserved courses database connection
def get_reserved_courses_db():
    """Returns a database connection to the courses database."""
    if not hasattr(g, 'reservedcourses_db'):
        g.reservedcourses_db = sqlite3.connect(RESERVED_COURSES_DB)
        g.reservedcourses_db.row_factory = sqlite3.Row
    return g.reservedcourses_db

# Function to get the admin database connection
def get_admin_db():
    """Returns a database connection to the admins database."""
    if not hasattr(g, 'admin_db'):
        g.admin_db = sqlite3.connect(ADMIN_DB)
        g.admin_db.row_factory = sqlite3.Row
    return g.admin_db

# Function to get the allcourses database connection
def get_allcourses_db():
    """Returns a database connection to the allcourses database."""
    if not hasattr(g, 'courses_db'):
        g.courses_db = sqlite3.connect(ALLCOURSES_DB)
        g.courses_db.row_factory = sqlite3.Row
    return g.courses_db

# Function to get the sessions database connection
def get_sessions_db():
    """Returns a database connection to the sessions database."""
    if not hasattr(g, 'sessions_db'):
        g.sessions_db = sqlite3.connect(SESSIONS_DB)
        g.sessions_db.row_factory = sqlite3.Row
    return g.sessions_db

from flask import g

@app.teardown_appcontext
def close_db(error=None):
    """Closes all database connections at the end of the request."""
    dbs = [get_db, get_reserved_courses_db, get_admin_db, get_allcourses_db, get_sessions_db]
    
    for get_db_func in dbs:
        # Access the database connection using the name of the function
        db_name = get_db_func.__name__.replace('get_', '').replace('_db', '')  # Get the db name part
        db = getattr(g, db_name + '_db', None)  # Get the db connection from g
        if db is not None:
            db.close()

# Functions to create the databases (tables) if they don't exist

# Create the 'users' table
def create_users_database():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                phone_number TEXT,
                created_at TEXT NOT NULL,
                password TEXT NOT NULL,
                profile_pic TEXT
            )
        """)
        db.commit()

# Create the 'reservedcourses' table
def create_reserved_courses_database():
    with app.app_context():
        db = get_reserved_courses_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reservedcourses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                course_code TEXT NOT NULL,
                course_name TEXT NOT NULL,
                course_unit INTEGER NOT NULL,
                seat_limit INTEGER NOT NULL,
                enrolled_at CURRENT_TIMESTAMP
            )
        """)
        db.commit()

# Create the 'admins' table
def create_admin_database():
    with app.app_context():
        db = get_admin_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                phone_number TEXT,
                password TEXT NOT NULL,
                securityPin TEXT NOT NULL,
                profile_pic TEXT
            )
        """)
        db.commit()

# Create the 'allcourses' table
def create_allcourses_database():
    with app.app_context():
        db = get_allcourses_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS allcourses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_code TEXT UNIQUE NOT NULL,
                course_name TEXT UNIQUE NOT NULL,
                seat_limit INTEGER NOT NULL,
                course_unit INTEGER NOT NULL
            )
        """)
        db.commit()

# Create the 'sessions' table
def create_sessions_database():
    with app.app_context():
        db = get_sessions_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT,
                admin_name TEXT,
                IP_address TEXT NOT NULL,
                logged_in BOOLEAN,
                login_time TEXT NOT NULL,
                logout_time TEXT,
                active_time TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        db.commit()

# Call to create databases (tables)
create_users_database()
create_reserved_courses_database()
create_admin_database()
create_allcourses_database()
create_sessions_database()

# Close connections properly
@app.teardown_appcontext
def close_connection(exception=None):
    """Closes database connections at the end of each request."""
    for db_name in ['admins_db', 'users_db', 'allcourses_db', 'enrollments_db', 'sessions_db']:
        db = getattr(g, db_name, None)
        if db is not None:
            db.close()

def execute_with_retry(db, query, params=(), retries=3, delay=0.1):
    for attempt in range(retries):
        try:
            cursor = db.cursor()
            cursor.execute(query, params)
            db.commit()
            return True
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                time.sleep(delay)
            else:
                raise
    raise Exception("Max retries exceeded for database operation.")

#------------- Handle All function for ADMIN with their Route -----------------
# Admin Dashboard (Only Accessible by Logged-In Admins)
@app.route('/adminDashboard')
def adminDashboard():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    
    # To retrieve All users data
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users')
    allusers = cursor.fetchall()

    # To retrieve All courses data
    db1 = get_allcourses_db()
    cursor = db1.cursor()
    cursor.execute('SELECT * FROM allcourses')
    allcourses = cursor.fetchall()
   
    # To retrieve All sessions data
    db2 = get_sessions_db()
    cursor = db2.cursor()
    cursor.execute('SELECT * FROM sessions')
    allsessions = cursor.fetchall()
    
    # Fetch all reserved courses for admin
    db3 = get_reserved_courses_db()
    cursor = db3.cursor()
    cursor.execute("SELECT * FROM reservedcourses")
    allenrolledcourses = cursor.fetchall()
    
    # To retrieve All admins data
    with get_admin_db() as db4:
        cursor = db4.cursor()
        cursor.execute('SELECT * FROM admins')
        alladmins = cursor.fetchall()
    
    # Check if any session has 'logged_in' == True
    active = 0
    for sessions in allsessions:
        if sessions['logged_in'] == 1:  # Access 'logged_in' as a key
            active = 1

    adminName = session.get('admin_name')
    response = make_response(
        render_template(
            'adminDashboard.html',
            adminName = adminName,
            alladmins = alladmins,
            allcourses = allcourses,
            allusers = allusers,
            allsessions = allsessions,
            active = active,
            allenrolledcourses = allenrolledcourses
        )
    )
    
    # Prevent caching of the admindashboard page
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

# Login route for admin
# Login route for admin
@app.route('/adminLogin', methods=['GET', 'POST'])
def adminLogin():
    if request.method == 'POST':
        admin_name = request.form.get('username')
        password = request.form.get('password')
        securityPin = request.form.get('securityPin')

        admin_db = get_admin_db()  # Get the database connection from `g`
        cursor = admin_db.cursor()
        cursor.execute("SELECT id, username, password, securityPin FROM admins WHERE username = ?", (admin_name,))
        admin = cursor.fetchone()

        # Check if the admin is found and credentials match
        if admin and check_password_hash(admin[2], password) and check_password_hash(admin[3], securityPin):
            session.permanent = True  # Keep session active
            session_id = str(uuid.uuid4())  # Generate unique session ID
            admin_ip = request.remote_addr  # Capture user's IP dynamically

            # Store session details
            session["admin_id"] = admin[0]
            session['admin_name'] = admin[1]
            session['session_id'] = session_id
            session['admin_ip'] = admin_ip

            # Get the current time in India (IST) and format it
            india_timezone = pytz.timezone('Asia/Kolkata')
            india_time = datetime.now(india_timezone)
            login_time = india_time.strftime('%Y-%m-%d %H:%M:%S')

            logged_in = True

            # Handle session details in the session database
            with get_sessions_db() as db1:  # Use context manager for session database
                cursor = db1.cursor()

                # Check if admin session already exists
                cursor.execute("SELECT admin_name FROM sessions WHERE admin_name = ?", (admin_name,))
                admin_session = cursor.fetchone()

                if admin_session:
                    cursor.execute('''UPDATE sessions SET IP_address = ?, logged_in = ?, login_time = ? WHERE admin_name = ?''',
                                    (admin_ip, logged_in, login_time, admin_name))
                else:
                    cursor.execute('''INSERT INTO sessions (session_id, user_id, IP_address, admin_name, logged_in, login_time)
                                        VALUES (?, ?, ?, ?, ?, ?)''',
                                    (session_id, admin[0], admin_ip, admin_name, logged_in, login_time))

                db1.commit()  # Commit changes to the session database

            flash('Login successful!', 'success')
            return redirect(url_for('adminDashboard'))

        else:
            flash('Invalid Credentials!', 'error')

    return render_template('adminLogin.html')


# Registration page for admin
@app.route('/registerAdmin', methods=['GET', 'POST'])
def registerAdmin():
    if 'admin_id' not in session:
        flash("Please login again!", "error")
        return redirect(url_for("adminLogin"))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('newpassword')
        confirmpassword = request.form.get('confirmpassword')
        securityPin = request.form.get('securityPin')

        if password != confirmpassword:
            return render_template('adminDashboard.html', error_message="Passwords do not match")

        hashed_password = generate_password_hash(password)
        hashed_pin = generate_password_hash(securityPin)
        now = datetime.now()

        try:
            db = get_admin_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO admins (username, email, phone_number, password, securityPin) VALUES (?, ?, ?, ?, ?)",
                           (username, email, phone_number, hashed_password, hashed_pin))
            db.commit()

            # Handle users table separately
            db1 = get_db()
            cursor1 = db1.cursor()
            cursor1.execute("INSERT INTO users (username, email, phone_number, created_at, password) VALUES (?, ?, ?, ?, ?)",
                            (username, email, phone_number, now, hashed_password))
            db1.commit()

            flash("Admin registered successfully!", 'success')
            return redirect(url_for("adminDashboard"))

        except sqlite3.IntegrityError:
            flash("Admin already exists!", 'error')
            return redirect(url_for("adminDashboard"))

        except Exception as e:
            flash(f"Error registering admin")
            return redirect(url_for("adminDashboard"))
        
# Delete Admin by admin
@app.route('/deleteAdmin', methods=['POST'])
def deleteAdmin():
    if 'admin_id' not in session:
        return redirect(url_for("adminLogin"))

    if request.method == 'POST':
        admin_id = request.form.get('admin_id')
        admin_email = request.form.get('admin_email')

        if admin_id and admin_email:
            try:
                # Delete from 'admins' table
                db = get_admin_db()
                cursor = db.cursor()
                cursor.execute('DELETE FROM admins WHERE id = ?', (admin_id,))
                db.commit()

                # Delete associated user from 'users' table
                db1 = get_db()
                cursor1 = db1.cursor()
                cursor1.execute('DELETE FROM users WHERE email = ?', (admin_email,))
                db1.commit()

                # Delete admin's session from 'sessions' table
                db_sessions = get_sessions_db()
                cursor_sessions = db_sessions.cursor()
                cursor_sessions.execute('DELETE FROM sessions WHERE user_id = ?', (admin_id,))
                # Commit all changes
                db_sessions.commit()

                # Check if the admin is deleting themselves
                if str(session.get('admin_id')) == str(admin_id):
                    session.pop('admin_id', None)
                    flash("Your account was deleted. You have been logged out.", 'info')
                    return redirect(url_for("adminLogin"))
                else:
                    flash("Admin, related user, and session deleted successfully!", 'success')
            
            except Exception as e:
                flash(f"Error deleting admin, user, or session: {str(e)}", 'error')

            return redirect(url_for("adminDashboard"))
        else:
            flash("Admin ID or Admin Email is missing!", 'error')
            return redirect(url_for("adminDashboard"))

    return redirect(url_for("adminDashboard"))

# Logout Route for Admin
@app.route('/adminLogout')
def adminLogout():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))

    admin_id = session['admin_id']
    india_timezone = pytz.timezone('Asia/Kolkata')
    logout_time = datetime.now(india_timezone)

    try:
        logged_in = False
        db_sessions = get_sessions_db()
        cursor = db_sessions.cursor()

        # Get the login time from the session
        cursor.execute('SELECT login_time FROM sessions WHERE user_id = ?', (admin_id,))
        data = cursor.fetchone()

        if data:
            # Parse login time and calculate active duration
            login_time = datetime.strptime(data[0], '%Y-%m-%d %H:%M:%S.%f')
            active_time = str(logout_time - login_time)

            # Update session logout details
            cursor.execute('''
                UPDATE sessions 
                SET logged_in = ?, logout_time = ?, active_time = ? 
                WHERE user_id = ?
            ''', (logged_in, logout_time.strftime('%Y-%m-%d %H:%M:%S.%f'), active_time, admin_id))
            db_sessions.commit()

    except Exception as e:
        print(f"Admin logout session update failed")
        # Optionally log to file using `logging` if needed

    # Always end session and redirect
    session.pop('admin_id', None)
    flash("You have been logged out!", 'info')
    return redirect(url_for('adminLogin'))

# Route and handle forget password for admin 
@app.route('/forgetAdminPass', methods=['GET', 'POST'])
def forgetAdminPass():
    if request.method == 'POST':
        admin_name = request.form.get('admin_name')
        email = request.form.get('email')
        securityPin = request.form.get('securityPin')
        newpassword = request.form.get('newpassword')
        confirmpassword = request.form.get('confirmpassword')

        if not (admin_name and email and securityPin and newpassword):
            flash("All fields are required!", "error")
            return redirect(url_for('forgetAdminPass'))

        if len(newpassword) < 6:
            flash("Passwords must be at least 6 characters long!", "error")
            return redirect(url_for('forgetAdminPass'))

        if newpassword != confirmpassword:
            flash("Passwords do not match!", "error")
            return redirect(url_for('forgetAdminPass'))

        with app.app_context():
            db = get_admin_db()
            cursor = db.cursor()
            # Check if admin exists
            cursor.execute('''SELECT username, email, securityPin
                           FROM admins WHERE username = ?''', (admin_name,))
            admin = cursor.fetchone()

        if admin and email == str(admin[1]) and securityPin == str(admin[2]):
            # Update password
            hashed_password = generate_password_hash(newpassword)
            cursor.execute('''UPDATE admins
                                SET password = ?
                                WHERE username = ?''', (hashed_password, admin_name))
            db.commit()
            flash("Password updated successfully!", "success")
            return redirect(url_for('adminLogin'))
        else:
            flash("Invalid Admin name or email or security pin!", "error")
            return redirect(url_for('forgetAdminPass'))

    return render_template('forgetAdminPass.html')

# Forget Admin Name for admin
@app.route('/forgetAdminName', methods=['GET', 'POST'])
def forgetAdminName():
    if request.method == 'POST':
        # Retrieve form data
        email = request.form.get('email')
        securityPin = request.form.get('securityPin')
        password = request.form.get('password')
        admin_name = request.form.get('admin_name')

        # Validate input fields
        if not (email and securityPin and password and admin_name):
            flash("All fields are required!", "error")
            return redirect(url_for('forgetAdminName'))

        # Connect to the database
        with app.app_context():
            db = get_admin_db()
            cursor = db.cursor()
            # Check if admin exists
            cursor.execute('''SELECT email, securityPin, password FROM admins WHERE email = ?''', (email,))
            admin = cursor.fetchone()
 
        if admin and securityPin == str(admin[1]) and check_password_hash(admin[2],password):
            cursor.execute('''UPDATE admins SET username = ? WHERE email = ?''', (admin_name, email))
            db.commit()
            flash("Admin Name updated successfully!", "success")
            return redirect(url_for('adminLogin'))
        else:
            flash("Invalid email or phone number or password!", "error")
            return redirect(url_for('forgetAdminName'))

    return render_template('forgetAdminName.html')

# Forget security pin for Admin
@app.route('/forgetSecurityPin', methods=['GET','POST'])
def forgetSecurityPin():
    if request.method == 'POST':
        admin_name = request.form.get('admin_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        newsecurityPin = request.form.get('securityPin')

        # Validate input fields
        if not (admin_name and email and phone_number and password and newsecurityPin):
            flash("All fields are required!", "error")
            return redirect(url_for('forgetSecurityPin'))
        
        if len(newsecurityPin) < 6:
            flash("Security pin must be at least 6 characters long!", "error")
            return redirect(url_for('forgetSecurityPin'))
        
        # Connect to the database
        with app.app_context():
            db = get_admin_db()
            cursor = db.cursor()

            # Check if admin exists
            cursor.execute('''SELECT username, email, phone_number, password  FROM admins 
                            WHERE username = ?''', (admin_name,))
            admin = cursor.fetchone()

        if admin and email == admin[1] and phone_number == str(admin[2]) and check_password_hash(admin[3],password):
            hashed_pin = generate_password_hash(newsecurityPin)
            cursor.execute('''UPDATE admins
                                SET securityPin = ?
                                WHERE username = ?''', (hashed_pin, admin_name))
            db.commit()
            flash("Security Pin updated successfully!", "success")
            return redirect(url_for('adminLogin'))
        else:
            flash("Invalid admin name or email or phone number or password!", "error")
            return redirect(url_for('forgetSecurityPin'))

    return render_template('forgetSecurityPin.html')
    
# Adding new user by admin
@app.route('/newUser', methods=['POST'])
def newUser():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('newpassword')
        
        if not username or not email or not password:
            flash("Missing fields!","error")
            return redirect(url_for("adminDashboard"))
        
        now = datetime.now()
        hashed_password = generate_password_hash(password)

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, email, phone_number, created_at, password) VALUES (?, ?, ?, ?, ?)",
                        (username, email, phone_number, now, hashed_password))
        db.commit()
        flash("New user registered successfully!","success")
        return redirect(url_for("adminDashboard"))
    else:
        return redirect(url_for('adminLogin'))
 
# Update user by Admin 
@app.route('/updateUser',methods=['POST'])
def updateUser():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    elif request.method == 'POST':
        user_id = request.form['user_id']
        
        if not user_id:
            flash('User id not found!','error')
            return redirect(url_for('adminDashboard'))
        else:
            username = request.form.get('username')
            email = request.form.get('email')
            phone_number = request.form.get('phone_number')
            password = request.form.get('password')
            
            hashed_password = generate_password_hash(password)
            
            db = get_db()
            cursor = db.cursor()
            
            # Update User information
            cursor.execute('''UPDATE users 
                           SET username = ?, email = ?, phone_number = ?, password = ? WHERE user_id = ? ''',
                           (username, email, phone_number, hashed_password, user_id))
            db.commit()
            
            flash('User updated successfully!','success')
            return redirect(url_for('adminDashboard'))        
            
# Delete user by Admin
@app.route('/deleteUser', methods=['POST'])
def deleteUser():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    
    user_id = request.form.get('user_id')

    if not user_id:
        flash("Invalid user ID.", "error")
        return redirect(url_for('adminDashboard'))

    try:
        # Delete from users table
        db = get_db()
        cursor = db.cursor()

        cursor.execute('SELECT * FROM users WHERE user_id=?', (user_id,))
        user = cursor.fetchone()

        if user:
            cursor.execute('DELETE FROM users WHERE user_id=?', (user_id,))
            cursor.execute('SELECT COUNT(*) FROM users')
            count = cursor.fetchone()[0]
            if count == 0:
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")
            db.commit()
        else:
            flash("User not found!", "error")
            return redirect(url_for('adminDashboard'))
        
        # Delete user session (if stored in sessions table)
        db_sessions = get_sessions_db()
        cursor = db_sessions.cursor()
        cursor.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
        db_sessions.commit()
        db_sessions.close()
        
        session.pop(user_id, None)
        flash("User and their session deleted successfully!", "success")

    except Exception as e:
        print(f"[ERROR] Failed to delete user and session: {e}")
        flash("An error occurred while deleting the user.", "error")

    return redirect(url_for('adminDashboard'))

# Route to add new course by Admin
@app.route('/addnewCourse', methods=['POST'])
def addnewCourse():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    else:
        if request.method == 'POST':
            course_code = request.form['course_code']
            course_name = request.form['course_name']
            course_unit = request.form['course_unit']
            seat_limit = request.form['seat_limit']

            if not (course_code and course_name and course_unit and seat_limit):
                flash('Missing fields!, please check.','error')
                return redirect(url_for('adminDashboard'))
            
            db = get_allcourses_db()
            cursor = db.cursor()
            
            cursor.execute('''SELECT * FROM allcourses 
                                    WHERE course_code= ? OR course_name= ?''',
                                    (course_code, course_name))
            course = cursor.fetchone()
            if course:
                flash('Course already present!, please check it out.','success')
                return redirect(url_for('adminDashboard'))
            
            else:
                cursor.execute('''INSERT INTO allcourses
                        (course_code, course_name, course_unit, seat_limit)
                            VALUES (?, ?, ?, ?)''',
                            (course_code, course_name, course_unit, seat_limit))
            
                db.commit()
                flash('New course added successfully!.','success')
                return redirect(url_for('adminDashboard'))
        
# Update Courses by Admin
@app.route('/updateCourse', methods=['POST'])
def updateCourse():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    
    else:
        if request.method == 'POST':
            course_id = request.form.get('course_id')
            course_code = request.form.get('course_code')
            course_name = request.form.get('course_name')
            seat_limit = request.form.get('seat_limit')
            course_unit = request.form.get('course_unit')

            # Check if any required field is missing
            if not all([course_id, course_code, course_name, seat_limit, course_unit]):
                flash("Please fill all fields", "error")
                return redirect(url_for('adminDashboard'))
            
            db = get_allcourses_db()
            cursor = db.cursor()

            # Update course information
            cursor.execute('''
                UPDATE allcourses 
                SET course_code = ?, course_name = ?, seat_limit = ?, course_unit = ?
                WHERE id = ?
            ''', (course_code, course_name, seat_limit, course_unit, course_id))

            db.commit()
            
            flash("Course updated successfully!", "success")
            return redirect(url_for('adminDashboard'))

# Route to delete courses by Admin
@app.route('/deleteCourse',methods=['POST'])
def deleteCourse():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    
    elif request.method == 'POST':
        course_id = request.form.get('course_id')
        
        if not course_id:
            flash('Course id not found!','error')
            return redirect(url_for('adminDashboard'))
        db = get_allcourses_db()
        cursor = db.cursor()
        
        cursor.execute('DELETE FROM allcourses WHERE id = ?',(course_id,))
        db.commit()
        
        flash('Course deleted successfully!','success')
        return redirect(url_for('adminDashboard'))


# Delete enrolled courses by admin
@app.route('/deleteEnrolledCourse', methods=['POST'])
def deleteEnrolledCourse():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    
    if request.method == 'POST':
        id = request.form.get('id')
        db = get_reserved_courses_db()
        cursor = db.cursor()
        
        if id:   
            cursor.execute('DELETE FROM reservedcourses WHERE id= ?',(id,))
            db.commit()
            flash('Selected enrolled course deleted successfully!','success')
            return redirect(url_for('adminDashboard'))
        else:
            flash('Id not found for selected course!','success')
            return redirect(url_for('adminDashboard'))
    else:
        return None
    
# Route to foce logout by admin
@app.route('/forceLogout',methods=['POST'])
def forceLogout():
    if 'admin_id' not in session:
        flash('You must log in as an admin to perform this action.', 'error')
        return redirect(url_for('adminLogin'))
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        if user_id:
            db = get_sessions_db()
            cursor = db.cursor()
            cursor.execute('''DELETE FROM sessions
                            WHERE user_id = ?
                            ''',(user_id,))
            db.commit()
            session.pop('user_id', None)  # Remove username from session
            flash('User logged out successfully!','success')
            return redirect(url_for('adminDashboard'))
        flash('User id not found!','error')
        return redirect(url_for('adminDashboard'))
    return None

#----------- Handle all login credentials or login information for Users -----------
#To register, login,logout, forgot username and password route and their handling functions at dashboard page --------

# Function to check whether an eamil is valid or not
def check_email(email):
    try:
      # validate and get info
        v = validate_email(email) 
        # replace with normalized form
        email = v["email"]
        result = True  
        return result
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        result = str(e)
        return result

# To route a registration page and checking all sytax of username,number,email and password
@app.route('/register', methods=['POST', 'GET'])
def register():
    """Handles user registration with validations."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('newpassword')
        confirmpassword = request.form.get('confirmpassword')
        
        now = datetime.now()

        # Check for missing fields
        if not username or not email or not password or not phone_number:
            return render_template('signup.html', error_message="All fields are required!")

        # Validate username length
        if len(username) < 4 or len(username) > 20:
            return render_template('signup.html', error_message="Username must be between 3 and 30 characters.")

        # Validate phone number (10 digits for standard formats)
        if not phone_number.isdigit() or len(phone_number) > 10:
            return render_template('signup.html', error_message="Phone number must be lesser or equal to 10 digits long.")

        # email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        result = check_email(email)
        if  result != True:
            return render_template('signup.html', error_message=result)

        # Validate password length
        if len(password) < 6 or len(password) > 16:
            return render_template('signup.html', error_message="Password must be at least 6 characters long.")

        # Validation of password types
        if not(password.isalnum()):
            return render_template('signup.html', error_message="Password must contain alphabet and number.")
        
        # Confirm passwords match
        if password != confirmpassword:
            return render_template('signup.html', error_message="Passwords do not match.")

        # Hash the password
        hashed_password = generate_password_hash(password)

        try:
            # Use a context manager to ensure the connection is properly closed after the operation
            with get_db() as db:  # Assuming get_db() returns the connection
                cursor = db.cursor()
                cursor.execute("INSERT INTO users (username, email, phone_number, created_at, password) VALUES (?, ?, ?, ?, ?)",
                               (username, email, phone_number, now, hashed_password))
                db.commit()
                flash("Registered successfully!", 'success')
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template('signup.html', error_message="Username or email already exists.")
    else:
        return render_template('signup.html')


# Get user IP address 
def get_ip_address():
    """Helper function to capture the user's IP address."""
    user_ip = request.remote_addr
    if 'X-Forwarded-For' in request.headers:
        user_ip = request.headers['X-Forwarded-For'].split(',')[0]
    return user_ip
# Handle login credentials
@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Step 1: Validate credentials
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT user_id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            # Step 2: Store session
            session.permanent = True
            session_id = str(uuid.uuid4())
            user_ip = get_ip_address()

            session['user_id'] = user[0]
            session['username'] = user[1]
            session['session_id'] = session_id
            session['ip_address'] = user_ip

            login_time = datetime.now()
            logged_in = True

            # Step 3: Insert or update session info
            db1 = get_sessions_db()
            cursor = db1.cursor()

            cursor.execute("SELECT user_name FROM sessions WHERE user_name = ?", (username,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute(
                    "UPDATE sessions SET IP_address = ?, logged_in = ?, login_time = ? WHERE user_name = ?",
                    (user_ip, logged_in, login_time, username)
                )
            else:
                cursor.execute(
                    '''INSERT INTO sessions (session_id, user_id, IP_address, user_name, logged_in, login_time)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                    (session_id, user[0], user_ip, username, logged_in, login_time)
                )

            db1.commit()

            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid Credentials!', 'error')
    
    return render_template('dashboard.html')  # Make sure this is your login template

#Route for checking the details related to forget password
@app.route('/forgetpass', methods=['GET', 'POST'])
def forgetpass():
    if request.method == 'POST':
        username = request.form.get('username')
        phone_number = request.form.get('phone_number')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND phone_number = ?", (username, phone_number))
        user = cursor.fetchone()

        if user:
            session['reset_user'] = user['username']
            return render_template('createpassword.html')
        return render_template('forgetpass.html', error_message="Invalid username or email or phone number")
    return render_template('forgetpass.html')

#Route for creating new password after forgot password page
@app.route('/createpassword', methods=['POST', 'GET'])
def create_password():
    if request.method == 'POST':
        new_password = request.form.get('newpassword')
        confirm_password = request.form.get('confirmpassword')
        username = session.get('reset_user')

        if not new_password or new_password != confirm_password:
            flash("Passwords do not match or are invalid.")
            return render_template('createpassword.html')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (generate_password_hash(new_password), username))
        db.commit()
        session.pop('reset_user', None)
        flash("Your Password has been updated successfully!")
        return redirect(url_for('login'))
    return render_template('createpassword.html')

# Route to handle and show forget username page 
@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
    """
    Handles requests to retrieve a forgotten username.
    - On GET: Displays the forgot username form.
    - On POST: Validates email and phone number, retrieves the username if valid.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')

        if username and email and phone_number:
            # Validate user details in the database
            db = get_db()
            cursor = db.cursor()
            cursor.execute('''SELECT email,phone_number
                           FROM users WHERE email = ? AND phone_number = ?
                           ''',(email,phone_number))
            user = cursor.fetchone()
            if user:
                cursor.execute('''UPDATE users
                            SET username = ?
                            WHERE email = ? AND phone_number = ?''',
                    (username, email, phone_number))
                db.commit()
                return render_template('forgotusername.html', success_message = f"Username updated successfully! Your username is: {username}")
            return render_template('forgotusername.html',error_message='Invalid email or phone number!')
    # Display the forgot username form
    return render_template('forgotusername.html')

#------- Recommendation Using Artificial Intelligence ---------
# Function to recommend courses based on a course name
def recommend_courses(course_name, num_recommendations=3, similarity_cutoff=0.75):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        # Fetch all courses from the database
        db = get_allcourses_db()
        cursor = db.cursor()
        cursor.execute("SELECT course_name FROM allcourses")
        courses = cursor.fetchall()

        if not courses:
            raise ValueError('No courses found in the database!')

        # Extract course names
        course_names = [course[0] for course in courses]

        # Calculate the TF-IDF matrix for the course names
        tfidf = TfidfVectorizer(stop_words="english")
        tfidf_matrix = tfidf.fit_transform(course_names)

        if tfidf_matrix is None or tfidf_matrix.shape[0] == 0:
            raise ValueError('Failed to compute the TF-IDF matrix.')

        # Compute the cosine similarity between the courses
        cosine_sim = cosine_similarity(tfidf_matrix)

        if cosine_sim is None or cosine_sim.size == 0:
            raise ValueError('Failed to compute the cosine similarity matrix.')

        app.logger.info(f"Cosine similarity matrix: {cosine_sim}")

        # Find the index of the course name entered by the user (case-insensitive)
        course_name = course_name.lower()
        matched_indices = [
            i for i, name in enumerate(course_names) if course_name in name.lower()
        ]

        if not matched_indices:
            raise ValueError(f"No courses matched for '{course_name}'")

        app.logger.info(f"Matched indices for '{course_name}': {matched_indices}")

        # Collect the similarity scores for the matched course indices
        similarity_scores = [(i, cosine_sim[i].max()) for i in matched_indices]

        if not similarity_scores:
            raise ValueError('No similarity scores calculated.')

        app.logger.info(f"Similarity scores: {similarity_scores}")

        # Filter courses based on the similarity cutoff
        filtered_scores = [
            (i, score) for i, score in similarity_scores if score >= similarity_cutoff
        ]

        if not filtered_scores:
            raise ValueError(f"No courses passed the similarity cutoff of {similarity_cutoff}")

        app.logger.info(f"Filtered similarity scores: {filtered_scores}")

        # Sort the courses based on similarity score and get top recommendations
        sorted_scores = sorted(filtered_scores, key=lambda x: x[1], reverse=True)[:num_recommendations]

        if not sorted_scores:
            raise ValueError('Failed to sort and extract top recommendations.')

        app.logger.info(f"Sorted scores: {sorted_scores}")

        # Prepare the recommended courses
        recommendations = [
            {"course_name": courses[i[0]][0], "similarity_score": round(i[1], 2)}
            for i in sorted_scores
        ]

        if not recommendations:
            raise ValueError('No recommendations could be prepared.')

        app.logger.info(f"Recommendations: {recommendations}")

        return recommendations

    except Exception as e:
        app.logger.error(f"Error in recommend_courses: {e}")
        return []

# Function to fetch all courses by their names
def fetch_courses_by_names(recommended_courses):
    try:
        # Check if recommended_courses is not empty
        if not recommended_courses:
            app.logger.warning('No recommended courses provided to fetch_courses_by_names.')
            return []

        # Extract valid course names and normalize them
        course_names = [course['course_name'].strip().lower() for course in recommended_courses if 'course_name' in course and course['course_name']]
        if not course_names:
            raise ValueError('No valid course names found in recommended_courses!')

        # Prepare the SQL query with case-insensitive matching
        placeholders = ','.join(['?'] * len(course_names))
        query = f"SELECT * FROM allcourses WHERE LOWER(course_name) IN ({placeholders})"

        app.logger.info(f"Query: {query}, Parameters: {course_names}")

        # Use a local database connection instead of relying on g
        with sqlite3.connect(ALLCOURSES_DB) as db:
            db.row_factory = sqlite3.Row  # Enable dictionary-like access to rows
            cursor = db.cursor()
            cursor.execute(query, course_names)
            courses = cursor.fetchall()

        if not courses:
            app.logger.warning('No courses matched the provided names in the database.')
            return []

        # Format the result into a list of dictionaries
        formatted_courses = [
            {
                "id": course["id"],
                "course_code": course["course_code"],
                "course_name": course["course_name"],
                "seat_limit": course["seat_limit"],
                "course_unit": course["course_unit"],
            }
            for course in courses
        ]

        app.logger.info(f"Formatted courses: {formatted_courses}")
        return formatted_courses

    except sqlite3.ProgrammingError as db_error:
        app.logger.error(f"ProgrammingError in fetch_courses_by_names: {db_error}")
        return []
    except Exception as e:
        app.logger.error(f"Unexpected error in fetch_courses_by_names: {e}")
        return []

# Route for the home page
@app.route('/', methods=['GET', 'POST'])
def home():
    """ Home page with user login check and course recommendations """

    if 'user_id' not in session:
        return redirect(url_for('login'))

    username = session.get("username")

    # Fetch the user's profile picture from the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT profile_pic FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    
    sidebar_links = {
        "about": url_for("about"),
        "services": url_for("services"),
        "contact": url_for("contact")
    }

    recommended_courses = None
    allcourses = None

    if request.method == "POST":
        selected_course = request.form.get('course')
        if selected_course:
            # Fetch recommendations based on the selected course
            recommended_courses = recommend_courses(selected_course)

            if not recommended_courses:
                flash("Stay tuned! We're finding the best courses for you. Please try again shortly!", "success")
                return redirect(url_for('home'))
            else:
                allcourses = fetch_courses_by_names(recommended_courses)  # You already use this function

    response = make_response(render_template(
        "index.html",
        username=username,
        sidebar_links=sidebar_links,
        allcourses=allcourses,
        user=user
    ))

    # Prevent caching of the home page
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

#------- All route to show options of toggle button after login or at dashboard as well -------
# Individual routes for "about", "services", and "contact"
# Route for aboute us page
@app.route("/about")
def about():
    return render_template("About.html")
# Route for services page
@app.route("/services")
def services():
    return render_template("Services.html")

# Route for contact us page
@app.route("/contact",methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        return render_template('Contact.html',name=name,confirm=" thank you for reaching out to us!, we have received your message and will get back to you shortly.")
    
    return render_template("Contact.html")


#-------- Route to show all options page of profile button --------
#------- Route to show your info page ---------
@app.route("/yourInfo",methods=['GET'])
def yourInfo():
    if 'user_id' not in session:
        return "Please login to see your info!"
    
    username = session['username']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, email, phone_number,profile_pic FROM users WHERE username=?",(username,))
    details = cursor.fetchall()
    return render_template("Yourinfo.html",details=details)

#-------- Show user's reserved courses ---------
@app.route('/reservedCourses')
def reservedCourses():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_reserved_courses_db()
    cursor = db.cursor()

    # Fetch all reserved courses for the current user
    cursor.execute("SELECT * FROM reservedcourses WHERE user_id = ?", (user_id,))
    allenrolledcourses = cursor.fetchall()

    return render_template('reservedCourses.html', allenrolledcourses = allenrolledcourses)

#------- Route to show settings page --------
@app.route("/showSettings")
def settings():
    if 'user_id' not in session:
        return "You are not authorize to see this page directly, please login"
    return render_template("settings.html")

#------- To show all settings options and their route for handling all data accordingly -------
#------- Configure upload folder and their data handle to show profile pic on uploaded image -------
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

#Handle Uploaded Profile Picture And Show To the Current User
# Ensure the uploaded folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Allowed file extension check
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for Post method on uploaded image to store the image name in user database
@app.route("/update_profile_pic", methods=["POST"])
def update_profile_pic():
    if "user_id" not in session:
        flash("You must be logged in to update your profile picture.", "danger")
        return redirect(url_for("login"))

    username = session["username"]

    if "profilePic" not in request.files:
        flash("No file uploaded!")
        return redirect(url_for("settings"))

    file = request.files["profilePic"]

    if file.filename == "":
        flash("No selected file!", "warning")
        return redirect(url_for("settings"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Secure file name
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)  # Save the file to the upload folder
        
        # Store the file path in the database
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET profile_pic=? WHERE username=?", (filename, username))
        db.commit()
        flash("Profile picture updated successfully!", "success")
        return redirect(url_for("home"))

    flash("Invalid file type! Please upload a JPG, PNG, or GIF image.", "danger")
    return redirect(url_for("settings"))

#------- All route to handle edit username, password, manage notifications and save privacy --------
@app.route('/action',methods=['GET','POST'])
def show_message():
    
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    elif request.method == 'POST':
        #Checking form-type
        form_type = request.form.get('form_type')
        #Route to handle edit password options in the settings's option        
        if form_type == 'editPass-form':
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            if request.method == 'POST':
                username = session.get('username')
                currpassword = request.form['currpassword']
                newpassword = request.form['newpassword']
                confirmpassword = request.form['confirmpassword']
                if not(username or currpassword or newpassword or confirmpassword):
                    flash('Missing fields! please check.','error')
                    return redirect(url_for('settings'))
                if newpassword != confirmpassword:
                    flash('New password must be same as confirmpassword!','error')
                    return redirect(url_for('settings'))
                
                db = get_db()
                cursor = db.cursor()
                cursor.execute('''SELECT username, password
                                FROM users WHERE username = ?''',
                            (username,))
                user = cursor.fetchone()
                
                if user:
                    # Check if the old password matches and update the new password
                    if check_password_hash(user[1], currpassword):
                        hashed_password = generate_password_hash(newpassword)
                        try:
                            cursor.execute('''UPDATE users
                                            SET password = ?
                                            WHERE username = ?''',
                                        (hashed_password, user[0]))
                            db.commit()
                            flash('Password has been updated successfully!', 'success')
                            return redirect(url_for('settings'))
                        except Exception as e:
                            flash(f'An error occurred: {e}', 'error')
                        finally:
                            db.close()
                    else:
                        flash('Invalid current password!', 'error')
                        return redirect(url_for('settings'))
                else:
                    # Handle case when the user is not found
                    flash('Invalid Username!', 'error')
                    return redirect(url_for('settings'))

        elif form_type == 'notification-form':
            flash('Your preference has been saved successfully!')
            return redirect(url_for('settings'))
        
        elif form_type == 'privacy-form':
            flash('Your Privacy has been saved successfully!')
            return redirect(url_for('settings'))
        return redirect(url_for('settings'))
    return redirect(url_for('settings'))

# Route to Logout by User
@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        if request.method == 'POST':
            user_id = session.get('user_id')
            logged_in = False
            logout_time = datetime.now()                
            db = get_sessions_db() 
            cursor = db.cursor()
            if user_id:
                cursor.execute('''SELECT
                               login_time FROM sessions
                               WHERE user_id = ?
                               ''',(user_id,))
                data = cursor.fetchone()

                if data:
                    #Ensure correct format of date time
                    logout_time = datetime.strptime(str(logout_time),'%Y-%m-%d %H:%M:%S.%f')
                    login_time = datetime.strptime(str(data[0]),'%Y-%m-%d %H:%M:%S.%f')
                    active_time = str(logout_time - login_time)
                    formatted_logout_time = logout_time.strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute('''UPDATE sessions
                                SET logged_in = ?, logout_time = ?,
                                active_time = ? WHERE user_id = ?
                                ''',(logged_in, str(formatted_logout_time), active_time, user_id))
                    db.commit()
                    session.pop('user_id', None) 
                    flash("You have been logged out!", 'info')
                    return redirect(url_for('login'))
                
                session.pop('user_id', None)  
                flash("You have been logged out!", 'info')
                return redirect(url_for('login'))
            session.pop('user_id', None)  
            return redirect(url_for('login'))
        session.pop('user_id', None)  
        return redirect(url_for('login'))
    session.pop('user_id', None)  
    return None 
          
#------------------------------------------------------------------------------------

#--------All Route to manage reserve, remove course to the/from your reserved course page using courses database ---------
# Sample courses list (in a real app, these should come from a database)
# Reserve course
@app.route('/reserve_course', methods=['POST'])
def reserve_course():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        id = request.form['id']
        user_id = session['user_id']
        course_code = request.form.get('course_code')
        course_name = request.form.get('course_name')
        course_unit = request.form.get('course_unit')
        seat_limit = request.form.get('seat_limit')
        enrolled_at = datetime.now()
        
        db = get_reserved_courses_db()
        cursor = db.cursor()

        # Check if course is already reserved
        cursor.execute("SELECT * FROM reservedcourses WHERE user_id = ? AND course_name = ?", (user_id, course_name))
        existing_course = cursor.fetchone()

        if existing_course:
            flash('Course already reserved!','success')
            return redirect(url_for('home'))
        
        # Insert course into database
        cursor.execute("""
            INSERT INTO reservedcourses (id, user_id, course_code, course_name, course_unit, seat_limit, enrolled_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (id, user_id, course_code, course_name, course_unit, seat_limit, enrolled_at))
        
        #Save all changes permanently in the database
        db.commit()
        flash('Course reserved successfully!','success')
        return redirect(url_for('home'))

# Remove a reserved course by user
@app.route('/removeCourse', methods=['POST'])
def remove_course():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    id = request.form.get('id')
    course_name = request.form.get('course_name')
    user_id = session.get('user_id')

    db = get_reserved_courses_db()
    cursor = db.cursor()
    # Remove the course from the database
    cursor.execute("DELETE FROM reservedcourses WHERE id = ? AND course_name= ? AND user_id = ?", (id,course_name,user_id))
    #Save all changes permanently in the database
    db.commit()

    # Fetch the updated list of reserved courses
    cursor.execute("SELECT * FROM reservedcourses WHERE user_id=?", (user_id,))
    allenrolledcourses = cursor.fetchall()
    #Close connection from database after each deletion

    flash('Selected course removed successfully!','success')
    
    return render_template('reservedCourses.html', allenrolledcourses=allenrolledcourses)

#----------  To Run the server  -----------
if __name__ == "__main__":
    app.run(debug=False)
    