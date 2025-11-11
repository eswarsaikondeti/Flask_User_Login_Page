from flask import Flask, render_template, redirect, request, url_for, session, flash
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import re
import time

app = Flask(__name__)
app.secret_key = "@1234" 
app.permanent_session_lifetime = timedelta(days=1)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_PORT'] = 5523
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345'
app.config['MYSQL_DB'] = 'users_data'

mysql = MySQL(app)

@app.route("/home_")
def home():
    return render_template("home_page.html", time=time.time())

@app.route("/create_acc")
def create_acc():
    return render_template("create_page.html", time=time.time())

@app.route("/create_new_acc", methods=["POST"])
def create_new_acc():
    new_user = request.form['user_name'].strip()
    new_email = request.form['email'].strip()
    new_password = request.form['user_pass'].strip()
    confirm_pass = request.form['con_pass'].strip()

    if new_password != confirm_pass:
        flash("❌ Passwords do not match. Please try again.", "danger")
        return redirect(url_for('create_acc'))

    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        flash("⚠️ Please enter a valid email address.", "warning")
        return redirect(url_for('create_acc'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM user_credentials WHERE email = %s", (new_email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        flash("⚠️ Account already exists. Please log in.", "warning")
        return redirect(url_for('create_acc'))

    encrypted_pass = generate_password_hash(new_password)
    cursor.execute(
        "INSERT INTO user_credentials(name, email, password) VALUES(%s, %s, %s)",
        (new_user, new_email, encrypted_pass)
    )
    mysql.connection.commit()
    cursor.close()

    flash("✅ Account created successfully! Please log in.", "success")
    return redirect(url_for('login_acc'))

@app.route("/login_acc", methods=["GET", "POST"])
def login_acc():
    if request.method == "POST":
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT name, email, password FROM user_credentials 
            WHERE name = %s OR email = %s
        """, (username, username))
        user = cursor.fetchone()
        cursor.close()

        if user:
            db_name, db_email, db_password = user
            if check_password_hash(db_password, password):
                session['username'] = db_name
                flash(f"👋 Welcome back, {db_name}!", "success")
                return redirect(url_for('logout_old_user'))
            else:
                return render_template("login_page.html",
                                       error_message="❌ Invalid password. Please try again.",
                                       username=username)
        else:
            return render_template("login_page.html",
                                   error_message="❌ Username or email not found.",
                                   username=username)

    return render_template("login_page.html")

@app.route("/logout_old_user")
def logout_old_user():
    if 'username' in session:
        user = session['username']
        return render_template("logout_user_exists.html", username=user)
    else:
        flash("⚠️ You are not logged in. Please log in first.", "warning")
        return redirect(url_for("login_acc"))

@app.route("/logout_confirm", methods=["POST"])
def logout_confirm():
    session.pop("username", None)
    flash("✅ You have been logged out successfully.", "success")
    return redirect(url_for("home"))

@app.route("/logout_newone")
def logout_newone():
    session.pop("username", None)
    flash("✅ Logged out successfully.", "info")
    return redirect(url_for("home"))

@app.route("/update_password_form")
def update_password_form():
    return render_template('forgot_password.html', time=time.time())

@app.route("/update_the_password", methods=['POST'])
def update_the_password():
    email = request.form['email'].strip()
    password = request.form['password'].strip()
    confirm_password = request.form['confirm_passw'].strip()

    if password != confirm_password:
        flash("⚠️ Passwords do not match. Please try again.", "danger")
        return redirect(url_for('update_password_form'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM user_credentials WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        flash("❌ Email not found. Please try again.", "danger")
        return redirect(url_for('update_password_form'))

    hashed_password = generate_password_hash(password)
    cursor.execute(
        "UPDATE user_credentials SET password = %s WHERE email = %s",
        (hashed_password, email)
    )
    mysql.connection.commit()
    cursor.close()

    flash("✅ Password updated successfully! Please log in with your new password.", "success")
    return redirect(url_for('login_acc'))

@app.route("/success_login")
def success_login():
    return render_template("logout_user_exists.html", time=time.time())

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

