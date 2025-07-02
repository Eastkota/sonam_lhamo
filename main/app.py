import sqlite3
from flask import Flask, g, render_template, request, url_for, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import db 

app = Flask(__name__)

app.config['DATABASE'] = 'database.db'
app.config['SECRET_KEY'] = 'a_very_secret_key_that_you_should_change'

with app.app_context():
    db.init_app(app)

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        con = db.get_db()
        g.user = con.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()


@app.route('/')
def index():

    if g.user is None:
        return redirect(url_for('login'))

    con = db.get_db()
    posts = con.execute(
        'SELECT p.id, title, content, created, username'
        ' FROM posts p JOIN users u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'] 

        if not username or not email or not password:
            flash('Username, Email, and Password are required!')
        else:
            con = db.get_db()
            try:
                hashed_password = generate_password_hash(password)
                con.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password)
                )
                con.commit()
                flash('Registration successful! Please log in.')
                return redirect(url_for('login')) 
            except sqlite3.IntegrityError:
                flash(f'User "{username}" already exists.')
            except Exception as e:
                flash(f'An error occurred during registration: {e}')
                print(f"Database error during registration: {e}")

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
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
            elif not check_password_hash(user['password'], password):
                flash('Incorrect password.')
            else:
                session.clear()
                session['user_id'] = user['id']
                flash(f'Welcome, {username}!')
                return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

