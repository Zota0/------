from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from cryptography.fernet import Fernet
from functools import wraps
import secrets 
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_default_secret_key')
jwt_secret = os.environ.get('JWT_SECRET', 'your_jwt_secret')
encryption_key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode())
fernet = Fernet(encryption_key.encode())


users = {}


DATABASE_FILE = 'messages.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with app.app_context():
        db_cursor = conn.cursor()
        db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    conn.close()

init_db()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt_token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, jwt_secret, algorithms=['HS256'])
            current_user = data['username']
        except:
            return redirect(url_for('login'))

        if not session.get('mfa_verified'): 
            return redirect(url_for('mfa_verify')) 

        return f(current_user, *args, **kwargs)
    return decorated




@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            return render_template('index.html', form_type='register', message="Nazwa użytkownika już istnieje.", tailwind_cdn=True)

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users[username] = hashed_password
        return render_template('index.html', form_type='login', message="Rejestracja udana. Zaloguj się.", tailwind_cdn=True)

    return render_template('index.html', form_type='register', tailwind_cdn=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username not in users:
            return render_template('index.html', form_type='login', message="Nieprawidłowa nazwa użytkownika lub hasło.", tailwind_cdn=True)

        if check_password_hash(users[username], password):
            session.pop('mfa_verified', None) 
            session['username_for_mfa'] = username 
            
            mfa_code = str(secrets.randbelow(1000000)).zfill(6)
            session['mfa_code'] = mfa_code 
            return redirect(url_for('mfa_verify')) 
        else:
            return render_template('index.html', form_type='login', message="Nieprawidłowa nazwa użytkownika lub hasło.", tailwind_cdn=True)

    return render_template('index.html', form_type='login', tailwind_cdn=True)


@app.route('/mfa_verify', methods=['GET', 'POST'])
def mfa_verify():
    if request.method == 'POST':
        username = session.get('username_for_mfa') 
        submitted_mfa_code = request.form['mfa_code'] 
        stored_mfa_code = session.get('mfa_code') 

        if username and stored_mfa_code and submitted_mfa_code == stored_mfa_code:
            token = jwt.encode({
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, jwt_secret, algorithm='HS256')
            resp = redirect(url_for('protected'))
            resp.set_cookie('jwt_token', token, httponly=True, samesite='Strict')
            session['mfa_verified'] = True 
            session.pop('mfa_code', None) 
            session.pop('username_for_mfa', None) 
            return resp
        else:
            return render_template('mfa_verify.html', error="Nieprawidłowy kod MFA.", mfa_code=session.get('mfa_code')) 

    return render_template('mfa_verify.html', mfa_code=session.get('mfa_code')) 


@app.route('/protected')
@token_required
def protected(current_user):
    messages = get_messages_from_db(current_user)
    return render_template('index.html', form_type='protected', username=current_user, messages=messages, tailwind_cdn=True)


@app.route('/encrypt', methods=['POST'])
@token_required
def encrypt_data(current_user):
    data_to_encrypt = request.form['data_to_encrypt']
    encrypted_data_bytes = fernet.encrypt(data_to_encrypt.encode())
    encrypted_data = encrypted_data_bytes.decode()
    return render_template('partials/encrypted_display.html', encrypted_data=encrypted_data)


@app.route('/decrypt', methods=['POST'])
@token_required
def decrypt_data(current_user):
    encrypted_message_content = request.values.get('encrypted_data')

    if encrypted_message_content:
        try:
            decrypted_data_bytes = fernet.decrypt(encrypted_message_content.encode())
            decrypted_message_content = decrypted_data_bytes.decode()
            return render_template('partials/decrypted_message.html', decrypted_message=decrypted_message_content)
        except Exception as e:
            print(f"Błąd deszyfrowania: {e}")
            return render_template('partials/decrypted_message.html', decrypted_message="Błąd deszyfrowania.")
    else:
        return render_template('partials/decrypted_message.html', decrypted_message="Brak danych do odszyfrowania.")


@app.route('/send_message', methods=['POST'])
@token_required
def send_message(current_user):
    message_text = request.form['message_text']
    encrypted_message = fernet.encrypt(message_text.encode()).decode()

    conn = get_db_connection()
    db_cursor = conn.cursor()
    db_cursor.execute("INSERT INTO messages (username, content) VALUES (?, ?)", (current_user, encrypted_message))
    conn.commit()
    conn.close()

    messages = get_messages_from_db(current_user)
    return render_template('partials/message_list.html', messages=messages)


@app.route('/get_messages')
@token_required
def get_messages(current_user):
    messages = get_messages_from_db(current_user)
    return render_template('partials/message_list.html', messages=messages)


def get_messages_from_db(username):
    conn = get_db_connection()
    db_cursor = conn.cursor()
    db_cursor.execute("SELECT * FROM messages WHERE username = ? ORDER BY timestamp DESC", (username,))
    messages = db_cursor.fetchall()
    conn.close()
    return messages


@app.route('/logout')
def logout():
    session.pop('mfa_verified', None) 
    resp = redirect(url_for('login'))
    resp.delete_cookie('jwt_token')
    return resp


if __name__ == '__main__':
    app.run(debug=True)
