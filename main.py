from flask import Flask, request,url_for,render_template,redirect,flash,session
from database import connect_to_database,get_database
from functools import wraps
from twilio.rest import Client
import random


app = Flask(__name__)
app.secret_key = 'your_secret_key'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'phone' not in session:
            flash('You must be logged in to access this page', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'phone' in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route('/login',methods=["POST","GET"])
def login():
    if request.method == "POST":
        phone = request.form['phone']
        password = request.form['password']

        db = get_database()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE phoneno = ? AND password = ?", (phone, password))
        user = cursor.fetchone()
        db.close()
        
        if user:
            session['phone'] = phone            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid phone number or password', 'error')
            return redirect(url_for('index'))
    if request.method == "GET":
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    db.close()

    return render_template("dashboard.html",user=user)

@app.route('/logout')
def logout():
    session.pop('phone', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

def generate_otp():
    return ''.join(random.choice('0123456789') for _ in range(6))

@app.route('/get-otp', methods=["POST","GET"])
def get_otp():
    if request.method == "POST":
        phone = request.form['phone']
        session['phone'] = phone
        otp = generate_otp()
        print(otp)
        session['otp'] = otp
        client = Client('ACb0a62a64b64ac6a9f1f926b3512dcc86', '7575763b58468f99e31c0e443f50398d')
        message = client.messages.create(
                        body='Your otp is'+otp,
                        from_='+18144580408',
                        to='+91'+phone
                     )
    return render_template("verifyOtp.html")

@app.route('/verify-otp',methods=["POST","GET"])
def verify_otp():
    if request.method == "POST":
        otp = request.form['otp']
        print('session otp '+session.get('otp'))
        if otp == session.get('otp'):
            return render_template("signup.html")
        else:
            return render_template("verifyOtp.html")
    return redirect(url_for('index'))

@app.route("/signup", methods=["POST","GET"])
def signup():
    if request.method == "POST":
        phone = session.get('phone')
        password = request.form['password']
        username = request.form['username']
        firstname = request.form['firstname'].capitalize()
        lastname = request.form['lastname'].capitalize()

        db = get_database()
        cursor = db.cursor()

        existing_user = cursor.execute("select phoneno from users where phoneno = ?",(phone,)).fetchone()
        print(existing_user)
        if existing_user:
            session.pop('phone',None)
            flash('User already exist, Login !')
            return redirect(url_for('login'))
        else:
            cursor.execute("INSERT INTO users (username,phoneno, password, firstname, lastname) VALUES (?,?,?,?,?)", (username, phone, password, firstname, lastname))
            db.commit()
            db.close()
            session.pop('phone',None)
            flash('Sign Up Successful', 'info')
            return redirect(url_for("index"))
        
    if request.method == "GET":
        return redirect(url_for("index"))
    return redirect(url_for('index'))

@app.route('/forget-password',methods=["POST","GET"])
def forget_password():
    if request.method == "POST":
        phone = request.form['phone']
        session['number'] = phone
        otp = generate_otp()
        print(otp)
        session['otp'] = otp
        client = Client('ACb0a62a64b64ac6a9f1f926b3512dcc86', '7575763b58468f99e31c0e443f50398d')
        message = client.messages.create(
                        body='Your otp is'+otp,
                        from_='+18144580408',
                        to='+91'+phone
                     )
        
        return redirect(url_for('verifyotp'))
    return render_template('forgetpassword.html')

@app.route('/verifyotp',methods=["POST","GET"])
def verifyotp():
    if request.method == "POST":
        otp = request.form['otp']
        if otp == session.get('otp'):
            
            return render_template("newpass.html")
        return redirect(url_for('verifyotp'))
    return render_template("forgetverify.html")
    
@app.route('/confirm-password',methods=["POST","GET"])
def confirm_password():
    if request.method == "POST":
        password = str(request.form['password'])
        confirm_password =  str(request.form['password1'])
        print(password,confirm_password)
        phone = session.get('number')
        if password == confirm_password:
            db = get_database()
            cursor = db.cursor()
            existing_user = cursor.execute("select phoneno from users where phoneno = ?",(phone,)).fetchone()
            if existing_user:
                cursor.execute("UPDATE users set password = ? where phoneno = ?",(password,phone))
                db.commit()
                db.close()
                
                flash('Password Reset Successful', 'info')
                return redirect(url_for("index"))
        flash('password do not match','warning')
    return render_template("newpass.html")

@app.route("/profile")
@login_required
def profile():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    db.close()
    return render_template("profile.html",user=user)

@app.route("/dare")
@login_required
def dare():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    db.close()
    return render_template("dare.html",user=user)

@app.route("/addcoin",methods=["POST","GET"])
@login_required
def addcoin():
    if request.method == "POST":
        coin = request.form['coins']
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        print(phone)
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        current_balance = user['balance']
        new_balance = current_balance + int(coin)
        cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone,))
        db.commit()
        db.close()

        flash('Balance added successfully!', 'success')
        return redirect(url_for("addcoin")) 
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        db.close()
        
        return render_template("coin.html",user=user)
    return render_template("coin.html")

@app.route("/withdraw", methods=["POST", "GET"])
@login_required
def withdraw():
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        db.close()
        return render_template("withdraw.html",user=user)
    elif request.method == "POST":
        coin = request.form['coins']
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        current_balance = cursor.fetchone()['balance']
        new_balance = current_balance - int(coin)
        cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
        db.commit()
        db.close()
        flash('Coins withdrawn successfully!', 'success')
        return redirect(url_for("withdraw"))
    return render_template('profile.html')

@app.route("/history", methods=["POST", "GET"])
@login_required
def history():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    db.close()
    return render_template("history.html",user=user)


@app.route("/leaderboard", methods=["POST", "GET"])
@login_required
def leaderboard():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    db.close()
    return render_template("leaderboard.html",user=user)


@app.route("/create-game",methods=["POST","GET"])
def create_game():
    if request.method == "POST":
        
        return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True)