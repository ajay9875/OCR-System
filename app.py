from flask import Flask, render_template, request, session, flash, redirect, url_for, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import pandas as pd
from fuzzywuzzy import process
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from datetime import datetime
from email_validator import validate_email, EmailNotValidError

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('secret_key', '')

# Prevent denial-of-service (DoS) attacks by limiting the size of incoming requests
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

#------ All functions to create database using sqlite3 ------
USERS_DB = "users.db"
ADMIN_DB = "admins.db"

# Separate database connection functions for each database

def get_db():
    """Returns a database connection to the users database."""
    if not hasattr(g, 'users_db'):
        g.users_db = sqlite3.connect(USERS_DB)
        #db.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode
        g.users_db.row_factory = sqlite3.Row
    return g.users_db

# Database for admin details, login id, password etc.
def get_admin_db():
    """Returns a database connection to the users database."""
    if not hasattr(g, 'admin_db'):
        g.admin_db = sqlite3.connect(ADMIN_DB)
        g.admin_db.row_factory = sqlite3.Row
    return g.admin_db

# Function to define shema and create database for reserved courses 
RESERVED_COURSES_DB = "reservedcourses.db"
# Return reserved courses database
def get_reserved_courses_db():
    """Returns a database connection to the courses database."""
    if not hasattr(g, 'reservedcourses_db'):
        g.reservedcourses_db = sqlite3.connect(RESERVED_COURSES_DB)
        g.reservedcourses_db.row_factory = sqlite3.Row
    return g.reservedcourses_db

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
        
# Calling to create database for courses 
create_reserved_courses_database()

# Function to define shema and create database for admin 
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
                securityPin INTEGER NOT NULL,
                profile_pic TEXT
            )
        """)
    
        db.commit()
        
# Calling to create database for users
create_admin_database()

# Function to define shema and create database for users 
def create_users_database():
    with app.app_context():
        # Current timestamp
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                phone_number TEXT,
                created_at DATE NOT NULL,
                password TEXT NOT NULL,
                profile_pic TEXT
            )
        """)
    
        db.commit()
        
# Calling to create database for users
create_users_database()

# To return a Databse or error on call
ALLCOURSES_DB = "allcourses.db"
def get_allcourses_db():
    """Ensure database connection"""
    try:
        if not hasattr(g, 'courses_db'):
            g.courses_db = sqlite3.connect(ALLCOURSES_DB)
            g.courses_db.row_factory = sqlite3.Row
        return g.courses_db
    except Exception as e:
        app.logger.error(f"Error connecting to the database: {e}")
        return None

# Function to create allcourses database
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
        
# Calling to create database for users
create_allcourses_database()

# To create and sessions database
SESSIONS_DB = "sessions.db"
def get_sessions_db():
    """Returns a database connection to the users database."""
    if not hasattr(g, 'sessions_db'):
        g.sessions_db = sqlite3.connect(SESSIONS_DB)
        g.sessions_db.row_factory = sqlite3.Row
    return g.sessions_db

# Function to create session database
def create_sessions_database():
    with app.app_context():
        db = get_sessions_db()
        cursor = db.cursor()
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                IP_address TEXT NOT NULL,
                logged_in BOOLEAN,
                login_time DATE,
                logout_time DATE,
                active_time TEXT  
                );
        """)
    
        db.commit()
# Calling to create session database
create_sessions_database()   
        
def enable_wal_mode(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.close()

# Enable WAL for each database
enable_wal_mode('admins.db')
enable_wal_mode('users.db')
enable_wal_mode('sessions.db')
enable_wal_mode('enrollments.db')

# Close connections properly
@app.teardown_appcontext
def close_connection(exception=None):
    """Closes database connections at the end of each request."""
    for db_name in ['admins_db', 'users_db', 'allcourses_db', 'enrollments_db', 'sessions_db']:
        db = getattr(g, db_name, None)
        if db is not None:
            db.close()

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
    db.close()

    # To retrieve All courses data
    db1 = get_allcourses_db()
    cursor = db1.cursor()
    cursor.execute('SELECT * FROM allcourses')
    allcourses = cursor.fetchall()
    db.close()
   
    # To retrieve All sessions data
    db2 = get_sessions_db()
    cursor = db2.cursor()
    cursor.execute('SELECT * FROM sessions')
    allsessions = cursor.fetchall()
    db.close()
    
    # Check if any session has 'logged_in' == True
    active = 0
    for sessions in allsessions:
        if sessions['logged_in'] == 1:  # Access 'logged_in' as a key
            active = 1

    # Fetch all reserved courses for admin
    db3 = get_reserved_courses_db()
    cursor = db3.cursor()
    cursor.execute("SELECT * FROM reservedcourses")
    allenrolledcourses = cursor.fetchall()
    db.close()
    response = make_response(
        render_template(
            'adminDashboard.html',
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

# Registration page for admin
@app.route('/registerAdmin', methods=['GET', 'POST'])
def registerAdmin():
    if 'admin_id' not in session:
        flash("Admin registered successfully!")
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

        try:
            db = get_admin_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO admins (username, email, phone_number, password, securityPin) VALUES (?, ?, ?, ?, ?)",
                           (username, email, phone_number, hashed_password, securityPin))
            db.commit()
            flash("Admin registered successfully!",'success')
            return redirect(url_for("adminDashboard"))
        except sqlite3.IntegrityError:
            flash("Admin already Exist!",'error')
            return redirect(url_for("adminDashboard"))
        
# Login route for admin
@app.route('/adminLogin', methods=['GET', 'POST'])
def adminLogin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        securityPin = request.form.get('securityPin')

        db = get_admin_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cursor.fetchone()

        # Check if admin exists
        if admin:
            stored_password = admin['password']
            stored_security_pin = str(admin['securityPin'])  # Convert to string for comparison

            if check_password_hash(stored_password, password) and stored_security_pin == str(securityPin):
                session.permanent = True  # Keep session active
                session['admin_id'] = admin['id']
                session['username'] = admin['username']
                flash('Login successful!', 'success')
                return redirect(url_for('adminDashboard'))

        # Flash message and redirect on failure
        flash('Invalid Credentials!', 'error')
        return redirect(url_for("adminLogin"))

    return render_template('adminLogin.html')

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
                           SET username = ?, email = ?, phone_number = ?, password = ? WHERE id = ? ''',
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

    db = get_db()
    cursor = db.cursor()
    
    # Check if user exists before deleting
    cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
    user = cursor.fetchone()
    
    if user:
        cursor.execute('DELETE FROM users WHERE id=?', (user_id,))
        db.commit()

        # Check if table is empty and reset sequence
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]

        if count == 0:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")
            db.commit()

        flash("User deleted successfully!", "success")
    else:
        flash("User not found!", "error")
    
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
        
        cursor.execute('DELETE FROM reservedcourses WHERE id= ?',(id,))
        db.commit()
        
        flash('Selected enrolled course deleted successfully!','success')
        return redirect(url_for('adminDashboard'))
    
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
            db.close()
            session.pop('user_id', None)  # Remove username from session
            flash('User logged out successfully!','success')
            return redirect(url_for('adminDashboard'))
        flash('User id not found!','error')
        return redirect(url_for('adminDashboard'))
    return None

# Logout Route for Admin
@app.route('/adminLogout')
def adminLogout():
    if 'admin_id' not in session:
        return redirect(url_for('adminLogin'))
    session.pop('admin_id',None)
    flash("You have been logged out.")
    return redirect(url_for('adminLogin'))

#----------- Handle all login credentials or login information for Users -----------
#To register, login,logout, forgot username and password route and their handling functions at dashboard page --------
'''
@app.route('/register', methods=['POST', 'GET'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('newpassword')
        confirmpassword = request.form.get('confirmpassword')
        
        now = datetime.now()

        if not username or not email or not password:
            return render_template('signup.html', error_message="Missing fields")

        if password != confirmpassword:
            return render_template('signup.html', error_message="Passwords do not match")

        hashed_password = generate_password_hash(password)

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (username, email, phone_number, created_at, password) VALUES (?, ?, ?, ?, ?)",
                           (username, email, phone_number, now, hashed_password))
            db.commit()
            flash("Registered successfully!",'success')
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template('signup.html', error_message="Username or email already exists")
    else:
        return render_template('signup.html')
'''
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
       
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''SELECT username, password
                       FROM users WHERE username = ?''',
                       (username,)
                       )
        user = cursor.fetchone()

        if user and check_password_hash(user[1], password):
            # Capture the user's IP address
            user_ip = get_ip_address()
            
            # Store the username and IP in the session
            session['user_id'] = user[0]
            session['username'] = user[0]

            session['ip_address'] = user_ip
            
            login_time = datetime.now()
            logged_in = True
            
            db = get_sessions_db()
            cursor = db.cursor()
            user_session = cursor.execute('''SELECT user_id FROM sessions
                                          WHERE user_id = ?''',
                (username,)
            ).fetchone()  # Check if the session for the user exists

            if user_session:
                # Update the existing session
                cursor.execute(
                    "UPDATE sessions SET IP_address = ?,logged_in = ?, login_time = ? WHERE user_id = ?",
                    (user_ip, logged_in, login_time, username)
                )
            else:
                # Insert a new session if no existing session is found
                cursor.execute(
                    '''INSERT INTO sessions (IP_address, user_id, logged_in, login_time) 
                    VALUES (?, ?, ?, ?)''',
                    (user_ip, username, logged_in, login_time)
                )

            db.commit()
            flash('Logged in successfully!','success')
            return redirect(url_for('home'))
        
        # Handle invalid login
        return render_template('dashboard.html', error_message="Invalid username or password!")
    return render_template('dashboard.html')

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

# By default route for home page and after login
@app.route('/index')
def index():
    return "Please login to see this page!"

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
        db.close()

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
    db.close()
    
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
                flash('Courses not found!, please try agin.','success')
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
    elif 'user_id' not in session:
        return redirect(url_for('login'))
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
    db.close()
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
    db.close()

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
        db.close()
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
                        db.close()
                        return redirect(url_for('settings'))
                else:
                    # Handle case when the user is not found
                    flash('Invalid Username!', 'error')
                    db.close()
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
                     
                    cursor.execute('''UPDATE sessions
                                SET logged_in = ?, logout_time = ?,
                                active_time = ? WHERE user_id = ?
                                ''',(logged_in, logout_time, active_time, user_id))
                    db.commit()
                    session.pop('user_id', None)  
                    return redirect(url_for('login'))

                session.pop('user_id', None)  
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

# Remove a reserved course
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
    db.close()

    flash('Selected course removed successfully!','success')
    
    return render_template('reservedCourses.html', allenrolledcourses=allenrolledcourses)


#----------  To Run the server  -----------
if __name__ == "__main__":
    app.run(threaded=True, debug=True)
