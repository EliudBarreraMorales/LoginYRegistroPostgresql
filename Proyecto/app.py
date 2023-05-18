from flask import Flask, render_template, request, flash, url_for, redirect, session
import psycopg2
import psycopg2.extras
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'password'

# Base de datos
DB_HOST = "localhost"
DB_NAME = "flask"
DB_USER = "postgres"
DB_PASS = "password"
 
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

@app.route('/')
def home():
    # verificar si el usuario esta logueado
    if 'loggedin' in session:
    
        # si el usuario esta logueado mantener la sesion en el home
        return render_template('home.html', username=session['username'])
    # si el usuario no esta logueado redirijir a el login
    return redirect(url_for('login'))
 
 
# ----------------------------------------------------------------------------------------------------

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
   
    # verificar si el usuario y la contraseña tiene registrado un POST requests 
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(password)
 
        # verificar si la cuenta esta en la base de datos
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        # Obtener un registro y devolver el resultado
        account = cursor.fetchone()
 
        if account:
            password_rs = account['password']
            print(password_rs)
            # Si la cuenta existe en la tabla de usuarios en la base de datos
            if check_password_hash(password_rs, password):
                # Crear datos de sesión, podemos acceder a estos datos en otras rutas
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                # redireccionar al home
                return redirect(url_for('home'))
            else:
                # La cuenta no existe o el nombre de usuario/contraseña es incorrecto
                flash('Incorrect username/password')
        else:
            # La cuenta no existe o el nombre de usuario/contraseña es incorrecto
            flash('Incorrect username/password')
 
    return render_template('login.html')
 

 
# -----------------------------------------------------------------------------------


 
@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
 
    # Compruebe si existen solicitudes POST de "nombre de usuario", "contraseña" y "correo electrónico" (formulario enviado por el usuario)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
    
        _hashed_password = generate_password_hash(password)
 
        # verifica si la cuenta ya esta en la base de datos
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
        # si la cuenta ya existe, manda un mensaje de error
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            # si no existe una cuenta inserta los datos en la base de datos
            cursor.execute("INSERT INTO users (fullname, username, password, email) VALUES (%s,%s,%s,%s)", (fullname, username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
    elif request.method == 'POST':
        # si el formulario esta vacio
        flash('Please fill out the form!')
    return render_template('register.html')
   


# ----------------------------------------------------------------------------------------------

   
@app.route('/logout')
def logout():
    # salir de la sesion
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # redirecciona al login
   return redirect(url_for('login'))


# -----------------------------------------------------------------------------------------------


@app.route('/profile')
def profile(): 
    cursor = conn.cursor(cursor_factory = psycopg2.extras.DictCursor)
   
    # verificar si el usuario fue logueado
    if 'loggedin' in session:
        cursor.execute("SELECT * FROM users WHERE id = %s", [session['id']])
        account = cursor.fetchone()
        # muestra el perfil
        return render_template('profile.html', account=account)
    # si el usuario no es logueado lo redirije a el login
    return redirect(url_for('login'))
 
if __name__ == "__main__":
    app.run(debug=True)