import sqlite3
from flask import Flask, g, render_template, request, url_for, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import db # Import your db.py module

app = Flask(__name__)

# --- Flask Configuration ---
app.config['DATABASE'] = 'database.db'
# A secret key is required for session management.
# In a real application, use a strong, randomly generated key
# and store it securely (e.g., environment variable).
app.config['SECRET_KEY'] = 'a_very_secret_key_that_you_should_change'

# --- Initialize the database functions with the Flask app ---
with app.app_context():
    db.init_app(app)

# --- Before each request, check if user is logged in ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        con = db.get_db()
        user = con.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        if user is None:
            # If user_id is in session but user not found in DB, clear session
            session.clear()
            g.user = None
        else:
            g.user = user

# --- Routes for your web application ---

@app.route('/')
def index():
    """
    Renders the home page, displaying a list of topics for the logged-in user.
    If no user is logged in, it redirects to the login page.
    """
    if g.user is None:
        return redirect(url_for('login')) # Redirect to login if not logged in

    con = db.get_db()
    # Fetch topics for the logged-in user
    topics = con.execute(
        'SELECT t.id, subject, topics, time_spent, created, username'
        ' FROM topics t JOIN users u ON t.author_id = u.id'
        ' WHERE t.author_id = ?' # Filter by logged-in user's ID
        ' ORDER BY created DESC',
        (g.user['id'],)
    ).fetchall()

    print(f"DEBUG: Topics fetched for user ID {g.user['id']}: {topics}") # Debug output

    # Pass 'topics' to the template instead of 'posts'
    return render_template('index.html', topics=topics)


@app.route('/register', methods=('GET', 'POST'))
def register():
    """
    Handles user registration.
    - On GET, displays the registration form.
    - On POST, processes form data, hashes password, and inserts new user.
    """
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'] # Get password from form

        if not username or not email or not password:
            flash('Username, Email, and Password are required!')
        else:
            con = db.get_db()
            try:
                # Hash the password before storing it
                hashed_password = generate_password_hash(password)
                con.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password)
                )
                con.commit()
                flash('Registration successful! Please log in.')
                return redirect(url_for('login')) # Redirect to login after registration
            except sqlite3.IntegrityError:
                flash(f'User "{username}" already exists.')
            except Exception as e:
                flash(f'An error occurred during registration: {e}')
                print(f"Database error during registration: {e}")

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    """
    Handles user login.
    - On GET, displays the login form.
    - On POST, verifies credentials and logs in the user.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and Password are required!')
        else:
            con = db.get_db()
            user = con.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

            if user is None:
                flash('Incorrect username.')
            # Check the hashed password
            elif not check_password_hash(user['password'], password):
                flash('Incorrect password.')
            else:
                # Login successful, store user ID in session
                session.clear()
                session['user_id'] = user['id']
                flash(f'Welcome, {username}!')
                return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    """
    Logs out the current user by clearing the session.
    """
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/add_topic', methods=('GET', 'POST'))
def add_topic():
    """
    Handles adding new topics to the database.
    - On GET, displays the add topic form.
    - On POST, processes form data and inserts the new topic.
    """
    if g.user is None:
        flash('You need to be logged in to add a topic.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        subject = request.form['subject']
        topics_content = request.form['topics_content'] # Renamed from 'topics' to avoid confusion
        time_spent = request.form['time_spent']

        if not subject or not topics_content or not time_spent:
            flash('All fields (Subject, Topics Content, Time Spent) are required!')
        else:
            con = db.get_db()
            try:
                con.execute(
                    "INSERT INTO topics (author_id, subject, topics, time_spent) VALUES (?, ?, ?, ?)",
                    (g.user['id'], subject, topics_content, time_spent)
                )
                con.commit()
                flash('Topic added successfully!')
                return redirect(url_for('index'))
            except Exception as e:
                flash(f'An error occurred while adding the topic: {e}')
                print(f"Database error adding topic: {e}")

    return render_template('add_topic.html')

# --- Run the application ---
if __name__ == '__main__':
    app.run(debug=True)

