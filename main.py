from flask import Flask, request,url_for,render_template,redirect,flash,session,send_from_directory
from database import get_database
from functools import wraps
from twilio.rest import Client
import random,os
from werkzeug.utils import secure_filename



ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        if user:
            if user['password'] == password:
                session['username'] = user['username']
                session['phone'] = phone
                session['id'] = user['id']
                db.close()
                return redirect(url_for('dashboard'))
            else:
                db.close()
                return render_template("login.html",error_message="Incorrect Login Password !")

        else:
            db.close()
            return render_template("login.html",error_message="Incorrect Login Password !")

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
    challenges = cursor.execute("SELECT * FROM challenges ORDER BY id DESC").fetchall()
    db.close()
    if 'success_message_displayed' not in session:
        session['success_message_displayed'] = True
        success_message = 'Signed in successfully'
        
    else:
        success_message = None

    return render_template("dashboard.html",user=user,challenges= challenges,success_message=success_message)


@app.route('/terms')
def term():
    return render_template('term.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

def generate_otp():
    return ''.join(random.choice('0123456789') for _ in range(6))

@app.route('/get-otp', methods=["POST","GET"])
def get_otp():
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
        phone = session.get('number')
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
        # return redirect(url_for("addcoin")) 
        return render_template("coin.html",success_message="Balance Added !",user=user)
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
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        phone = session['phone']
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        current_balance = cursor.fetchone()['balance']
        if int(coin) <= int(current_balance):
            new_balance = current_balance - int(coin)
            cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
            db.commit()
            db.close()
            flash('Coins withdrawn successfully!', 'success')
            return render_template("withdraw.html",success_message="Withdrawal Success !",user=user)
        else:
            flash('You Dont Have Balance in Your Account !','warning')
            return render_template("withdraw.html",error_message="You Dont Have Balance in Your Account !",user=user)
    return render_template('profile.html')

@app.route("/history", methods=["POST", "GET"])
@login_required
def history():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    username = session['username']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    results = cursor.execute("SELECT * FROM results WHERE user_id = ?", (username,)).fetchall()
    challenges = cursor.execute("select * from challenges where first_user = ?",(username,)).fetchall()
    db.close()
    return render_template("history.html",user=user,results=results,challenges=challenges)


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

    
@app.route('/create-challenge', methods=['GET', 'POST'])
@login_required
def create_challenge():
    if request.method == 'POST':
        game_type = request.form['game-select']
        coins_involved = request.form['coin']
        phone = session['phone']

        db = get_database()
        cursor = db.cursor()
        user = cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,)).fetchone()
        creator_id = user['username']
        session['username'] = creator_id

        current_balance = user['balance']
        if int(coins_involved) <= int(current_balance):
            new_balance = current_balance - int(coins_involved)
            cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
            flash('Coins Deducted successfully!', 'success')
            cursor.execute("INSERT INTO challenges (game_type, coins, first_user, status) VALUES (?, ?, ?, ?)",
                   (game_type, coins_involved, creator_id, 'open'))
            db.commit()
            flash('Challenge created successfully!', 'success')
            return redirect(url_for("dashboard"))
        else:
            flash('You Dont Have Enough Balance in Your Account !','warning')
            return redirect(url_for("dashboard"))


    return render_template('create_challenge.html')

@app.route('/accept_challenge/<int:challenge_id>', methods=['POST'])
@login_required
def accept_challenge(challenge_id):
    second_user = session['username']

    db = get_database()
    cursor = db.cursor()

    challenge = cursor.execute("SELECT * FROM challenges WHERE id = ? AND status = 'open'", (challenge_id,)).fetchone()

    if challenge:
        check_balance = cursor.execute("SELECT balance FROM users WHERE username = ?", (second_user,)).fetchone()
        if check_balance:
            balance = check_balance[0]
            challenge_coin = cursor.execute("select coins from challenges where id = ?",(challenge_id,)).fetchone()[0]
            if int(balance) > int(challenge_coin):
                cursor.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (challenge_coin, session['username']))
                cursor.execute("UPDATE challenges SET status = 'accepted', second_user = ? WHERE id = ?", (second_user, challenge_id))
                db.commit()
                flash('Challenge accepted!', 'success')
            else:
                flash("You dont have enough balance to accept challenge","warning")


    else:
        flash('Challenge not found or already accepted.', 'error')

    return redirect(url_for('dashboard'))


@app.route('/cancel_challenge/<int:challenge_id>', methods=['POST'])
@login_required
def cancel_challenge(challenge_id):
    try:
        db = get_database()
        cursor = db.cursor()
        challenge_coin = cursor.execute("select coins from challenges where id = ?",(challenge_id,)).fetchone()
        cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (challenge_coin[0], session['username']))

        cursor.execute("DELETE FROM challenges WHERE id = ? AND first_user = ? AND status = 'open'", (challenge_id, session['username']))

        db.commit()

        flash('Challenge canceled!', 'success')
    except Exception as e:
        flash('An error occurred while canceling the challenge.', 'error')
        print(f"Error: {e}")
    finally:
        db.close()

    return redirect(url_for('dashboard'))


@app.route('/cancel_accepted_challenge/<int:challenge_id>', methods=['POST'])
@login_required
def cancel_accepted_challenge(challenge_id):
    try:
        db = get_database()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM challenges WHERE id = ? AND status = 'accepted'", (challenge_id,))
        challenge = cursor.fetchone()

        if challenge:
            if challenge['second_user'] == session['username']:
                cursor.execute("UPDATE challenges SET status = 'open', second_user = NULL WHERE id = ?", (challenge_id,))
                challenge_coin = cursor.execute("select coins from challenges where id = ?",(challenge_id,)).fetchone()
                cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (challenge_coin[0], session['username']))

                db.commit()
                flash('Challenge canceled after acceptance.', 'success')
            else:
                flash('You are not authorized to cancel this challenge.', 'error')
        else:
            flash('Challenge not found or not accepted.', 'error')

    except Exception as e:
        flash('An error occurred while canceling the challenge.', 'error')
        print(f"Error: {e}")
    finally:
        db.close()

    return redirect(url_for('dashboard'))


@app.route('/challenge_details/<int:challenge_id>')
@login_required
def challenge_details(challenge_id):
    try:
        db = get_database()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,))
        challenge = cursor.fetchone()

        if challenge['first_user'] == session['username']:
            is_first_user = True
            is_second_user = False
        elif challenge['second_user'] == session['username']:
            is_first_user = False
            is_second_user = True
        else:
            flash('You are not authorized to view this challenge.', 'error')
            return redirect(url_for('dashboard'))

        return render_template('challenge_details.html', challenge=challenge, is_first_user=is_first_user, is_second_user=is_second_user)
    except Exception as e:
        flash('An error occurred while fetching challenge details.', 'error')
        print(f"Error: {e}")
    finally:
        db.close()


@app.route('/enter_room_code/<int:challenge_id>', methods=['GET', 'POST'])
@login_required
def enter_room_code(challenge_id):
    if request.method == 'POST':
        room_code = request.form['room_code']
        db = get_database()
        cursor = db.cursor()
        cursor.execute("UPDATE challenges SET room_code = ?, status = 'started' WHERE id = ?", (room_code, challenge_id))
        db.commit()

        flash('Room code saved successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('enter_room_code.html', challenge_id=challenge_id)

@app.route('/display_room_code/<int:challenge_id>')
@login_required
def display_room_code(challenge_id):
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT room_code FROM challenges WHERE id = ?", (challenge_id,))
    room_code = cursor.fetchone()

    if room_code:
        return render_template('display_room_code.html', room_code=room_code[0])
    else:
        flash('Room code not found.', 'error')
        return redirect(url_for('dashboard'))


@app.route('/upload/<filename>',methods=["GET"])
@login_required
def upload(filename):
    return send_from_directory('uploads',filename)


@app.route('/submit_result/<int:challenge_id>', methods=['POST','GET'])
@login_required
def submit_result(challenge_id):
    if request.method == 'POST':
        result = request.form['result']
        screenshot = request.files['screenshot']
        if screenshot and allowed_file(screenshot.filename):
            filename = secure_filename(screenshot.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            screenshot.save(file_path)
            db = get_database()
            cursor = db.cursor()
            existing_result = cursor.execute("SELECT * FROM results WHERE challenge_id = ? AND user_id = ?",
                                             (challenge_id, session['username'])).fetchone()
            if existing_result:
                flash('You have already submitted!', 'warning')
                return redirect(url_for('dashboard'))
            
            else:
                    cursor.execute("INSERT INTO results (challenge_id, user_id, screenshot_path, match_status) VALUES (?,?,?,?)",(challenge_id,session['username'],filename,result))
                    db.commit()
                    flash('Result submitted successfully!', 'success')
                    return redirect(url_for('dashboard',challenge_id=challenge_id))

                     
        else:
            flash('Invalid file format or size!', 'error')
            return redirect(url_for('submit_result',challenge_id=challenge_id))
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        user_id = session['username']
        user = cursor.execute("SELECT * FROM users WHERE username = ?",(user_id,)).fetchone()
        challenge = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()
        return render_template("result.html",user=user,challenge=challenge)


if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=80)