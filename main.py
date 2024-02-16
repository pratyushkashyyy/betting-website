from flask import Flask, request,url_for,render_template,redirect,flash,session
from database import connect_to_database,get_database
from functools import wraps


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

@app.route('/get-otp', methods=["POST","GET"])
def get_otp():
    if request.method == "POST":
        phone = request.form['phone']
    return render_template("verifyOtp.html")

@app.route('/verify-otp',methods=["POST","GET"])
def verify_otp():
    if request.method == "POST":
        otp = request.form['otp']
        if otp == "1234":
            return render_template("signup.html")
        else:
            return render_template("verifyOtp.html")
        
    return redirect(url_for('index'))

@app.route("/signup", methods=["POST","GET"])
def signup():
    if request.method == "POST":
        phone = request.form['phone']
        password = request.form['password']

        db = get_database()
        cursor = db.cursor()

        existing_user = cursor.execute("select phoneno from users where phoneno = ?",(phone,)).fetchone()
        print(existing_user)
        if existing_user:
            flash('User already exist, Login !')
            return redirect(url_for('login'))
        else:
            cursor.execute("INSERT INTO users (username,phoneno, password) VALUES ('helloji',?, ?)", (phone, password))
            db.commit()
            db.close()
            flash('Sign Up Successful', 'info')
            return redirect(url_for("index"))
    
    if request.method == "GET":
        return redirect(url_for("index"))
    return redirect(url_for('index'))


@app.route("/profile")
@login_required
def profile():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    db.close()
    # print(user['phoneno'])
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
    # print(user['phoneno'])
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