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
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            middle_name TEXT,
            age INTEGER,
            university TEXT,
            year INTEGER
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

def get_user_profile(username):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''
        SELECT first_name, last_name, middle_name, age, university, year
        FROM users WHERE username = ?
    ''', (username,))
    row = c.fetchone()
    conn.close()
    return {key: row[key] for key in row.keys()} if row else None

def update_user_profile(username, data):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        UPDATE users SET
            first_name = ?, last_name = ?, middle_name = ?,
            age = ?, university = ?, year = ?
        WHERE username = ?
    ''', (
        data['first_name'], data['last_name'], data['middle_name'],
        data['age'], data['university'], data['year'],
        username
    ))
    conn.commit()
    conn.close()











# Маршруты

@app.route('/', methods=['GET', 'POST'])
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

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    username = session['username']
    profile = get_user_profile(username)

    if request.method == 'POST':
        data = {
            'first_name': request.form['first_name'].strip(),
            'last_name': request.form['last_name'].strip(),
            'middle_name': request.form['middle_name'].strip(),
            'age': request.form['age'].strip(),
            'university': request.form['university'].strip(),
            'year': request.form['year'].strip(),
        }
        update_user_profile(username, data)
        flash("Профиль обновлён", "success")
        profile = get_user_profile(username)

    return render_template('edit.html', current_user=session['username'], profile=profile)


@app.route('/update_pass', methods=['POST'])
def update_pass():
    username = session['username']
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    if len(new_password) < 6:
        flash("Пароль должен быть не менее 6 символов", "failure")
        return redirect(url_for('edit'))

    conn = sqlite3.connect(DATABASE)
    try:
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        
        if not user or user[0] != hashlib.sha256(current_password.encode()).hexdigest():
            flash("Неверный текущий пароль", "failure")
            return redirect(url_for('edit'))

        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_hash, username))
        conn.commit()
        flash("Пароль изменён", "success")
    except Exception as e:
        flash(f"Ошибка при изменении пароля: {str(e)}", "failure")
    finally:
        conn.close()

    return redirect(url_for('edit'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    username = session['username']
    
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        
        flash("Аккаунт успешно удален", "success")
        session.pop('username', None)
        return redirect(url_for('login'))
        
    except Exception as e:
        flash(f"Ошибка при удалении аккаунта: {str(e)}", "failure")
        return redirect(url_for('edit'))
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    conn.close()