from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'database.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


def get_user(username):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def verify_password(user, password):
    return user[2] == hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', current_user=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and verify_password(user, password):
            session['username'] = username
            return redirect(url_for('index'))
        flash('Неверное имя пользователя или пароль', "failure")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Валидация
        errors = []
        if len(username) < 4:
            errors.append("Имя пользователя должно быть не менее 4 символов")
        if len(password) < 6:
            errors.append("Пароль должен быть не менее 6 символов")
        if password != confirm_password:
            errors.append("Пароли не совпадают")
        if get_user(username):
            errors.append("Пользователь с таким именем уже существует")

        if errors:
            for error in errors:
                flash(error, "failure")
            return redirect(url_for('register'))

        # Если прошли
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('''INSERT INTO users 
                        (username, password_hash)
                        VALUES (?, ?)''',
                     (username, password_hash))
            conn.commit()

            session['username'] = username
            flash("Регистрация успешна!", "success")
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash("Ошибка: Пользователь уже существует", "failure")
        except Exception as e:
            flash(f"Ошибка при регистрации: {str(e)}", "failure")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    conn.close()