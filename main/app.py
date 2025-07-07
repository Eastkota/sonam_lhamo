import sqlite3
from flask import Flask, g, render_template, request, url_for, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import db

import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
import io
import base64

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
        user = con.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        if user is None:
            session.clear()
            g.user = None
        else:
            g.user = user

def generate_topics_hours_plot(topics_data):
    subjects = [topic['topics'] for topic in topics_data]
    hours = [topic['time_spent'] for topic in topics_data]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(subjects, hours, marker='o', linestyle='-', color='#007bff')
    ax.set_xlabel('Topic Subject')
    ax.set_ylabel('Hours Spent')
    ax.set_title('Hours Spent Per Topic')
    ax.grid(True, linestyle='--', alpha=0.7)
    plt.xticks(rotation=45, ha='right') 
    plt.tight_layout() 

    # Save plot to a BytesIO object
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close(fig) 

    plot_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    return plot_base64

@app.route('/')
def index():
   
    if g.user is None:
        return redirect(url_for('login'))

    con = db.get_db()
    topics = con.execute(
        'SELECT t.id, subject, topics, time_spent, created, username'
        ' FROM topics t JOIN users u ON t.author_id = u.id'
        ' WHERE t.author_id = ?'
        ' ORDER BY created DESC',
        (g.user['id'],)
    ).fetchall()


    plot_url = None
    if topics:
        plot_url = generate_topics_hours_plot(topics)

    return render_template('index.html', topics=topics, plot_url=plot_url)


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

@app.route('/add_topic', methods=('GET', 'POST'))
def add_topic():

    if g.user is None:
        flash('You need to be logged in to add a topic.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        subject = request.form['subject']
        topics_content = request.form['topics_content']
        time_spent = request.form['time_spent']

        if not subject or not topics_content or not time_spent:
            flash('All fields (Subject, Topics Content, Time Spent) are required!')
        else:
            try:
                time_spent_int = int(time_spent)
                con = db.get_db()
                con.execute(
                    "INSERT INTO topics (author_id, subject, topics, time_spent) VALUES (?, ?, ?, ?)",
                    (g.user['id'], subject, topics_content, time_spent_int)
                )
                con.commit()
                flash('Topic added successfully!')
                return redirect(url_for('index'))
            except ValueError:
                flash('Time Spent must be a valid number (integer).')
            except Exception as e:
                flash(f'An error occurred while adding the topic: {e}')
                print(f"Database error adding topic: {e}")

    return render_template('add_topic.html')

if __name__ == '__main__':
    app.run(debug=True)

