from flask import Flask, request,url_for,render_template,redirect,flash,session,send_from_directory,jsonify
from database import get_database
from functools import wraps

import random,os,hashlib
from werkzeug.utils import secure_filename
from datetime import datetime, timezone, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
import time,requests


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
redis_client = Redis(host='localhost', port=6379)

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1000 * 1000
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='redis://127.0.0.1:6379'
)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_indian_time():
    utc_now = datetime.utcnow()
    ist_offset = timedelta(hours=5, minutes=30)
    ist_now = utc_now + ist_offset
    return ist_now

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
@limiter.limit("5/minute")
def login():
    if request.method == "POST":
        phone = request.form['phone']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_database()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        if user:
            if user['password'] == password_hash:
                if user['is_banned'] == False:
                    session['username'] = user['username']
                    session['phone'] = phone
                    session['id'] = user['id']
                    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
                        session['admin'] = True
                        flash('Logged in successfully as admin!', 'success')
                    db.close()
                    return redirect(url_for('dashboard'))
                else:
                    db.close()
                    return render_template("login.html",error_message="User has been Banned !")

            else:
                db.close()
                return render_template("login.html",error_message="Incorrect Login Password !")
        else:
            db.close()
            return render_template("login.html",error_message="Incorrect Login Password !")

    if request.method == "GET":
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route('/sitemap', methods=["GET"])
def sitemap():
    return redirect(url_for('static',filename="sitemap.xml"))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page',1,type=int)
    per_page = 20
    offset = (page-1) * per_page
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    challenges = cursor.execute('''SELECT *
    FROM challenges
    ORDER BY id DESC, CASE
        WHEN status = 'open' THEN 1
        WHEN status = 'started' THEN 2
        WHEN status = 'accepted' THEN 3
        WHEN status = 'closed' THEN 4
        ELSE 5  -- Any other status, if applicable
    END
    LIMIT ? OFFSET ?''',(per_page, offset)).fetchall()
    settings = cursor.execute("SELECT * FROM setting").fetchone()
    message = cursor.execute("SELECT * FROM messages").fetchall()
    total_challenges = cursor.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
    total_pages = 5
    db.close()
    if 'success_message_displayed' not in session:
        session['success_message_displayed'] = True
        success_message = 'Signed in successfully'
        
    else:
        success_message = None

    return render_template("dashboard.html",user=user,message=message,challenges=challenges,success_message=success_message,settings=settings,page=page,total_pages=total_pages)

@app.route('/store_button_value', methods=['POST','GET'])
def store_button_value():
    db = get_database()
    cursor = db.cursor()
    content = request.form['button']
    challenge = request.form['challenge_id']
    id = cursor.execute("SELECT id FROM messages where challenge_id = ?",(challenge,)).fetchone()
    if id:
        cursor.execute("UPDATE messages SET sender = ? , content = ? WHERE challenge_id = ?",(session['username'],content,challenge))
        db.commit()
        flash("Message sent","success")
        return redirect(url_for('dashboard'))
    else:
        cursor.execute("INSERT INTO messages (sender, challenge_id, content) VALUES(?,?,?)",(session['username'],challenge,content))
        db.commit()
        flash("Message sent","success")
        return redirect(url_for('dashboard'))


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

@app.route('/get-otp', methods=["POST"])
@limiter.limit("30/hour")
def get_otp():
    if request.method == "POST":
        try:
            phone = request.form['phone']
            session['s_phone'] = phone
            otp = generate_otp()
            session['otp'] = otp
            requests.get(f"https://www.fast2sms.com/dev/bulkV2?authorization=SlEb0FOyQ9YJrU3Wp7d5MmqioDunAPZtCVsGT8Nwx1vX64LKfaqynbGMVHDCE4dYv7xfmhTgc26SUXwi&route=otp&variables_values={otp}&flash=0&numbers={phone}")
            flash("OTP Sent !","success")
            return redirect(url_for('verify_otp'))
        except Exception as e:
            print(e)
            flash("Enter a valid Phone Number !","warning")
            return redirect(url_for('login'))
 
@app.route('/otpverify',methods=["POST","GET"])
@limiter.limit("30/hour")
def verify_otp():
    if request.method == "POST":
        otp = request.form['otp']
        print('session otp '+session.get('otp'))
        if otp == session.get('otp'):
            flash("OTP verified !","success")
            return redirect(url_for('signup'))
        flash("wrong otp","warning")
        return redirect(url_for('verify_otp'))
    return render_template("otpverification.html")

@app.route("/signup", methods=["POST","GET"])
@limiter.limit("30/hour")
def signup():
    if request.method == "POST":
        phone = session.get('s_phone')
        password = request.form['password']
        username = request.form['username'].capitalize()
        username = username.strip()
        firstname = request.form['firstname'].capitalize()
        lastname = request.form['lastname'].capitalize()
        password_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_database()
        cursor = db.cursor()
        existing_user = cursor.execute("select phoneno from users where phoneno = ?",(phone,)).fetchone()
        existing_username = cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            session.pop('s_phone',None)
            flash('User already exist, Login !')
            return redirect(url_for('login'))
        if existing_username[0] > 0:
                flash("Username already exists. Please choose a different username.", "error")
                return redirect(url_for('signup'))
        else:
            cursor.execute("INSERT INTO users (username,phoneno, password, firstname, lastname) VALUES (?,?,?,?,?)", (username, phone, password_hash, firstname, lastname))
            db.commit()
            db.close()
            flash('Sign Up Successful', 'info')
            return redirect(url_for("index"))
    return render_template('signup.html')

@app.route('/forget-password',methods=["POST","GET"])
@limiter.limit("30 per hour")
def forget_password():
    if request.method == "POST":
        phone = request.form['phone']
        session['number'] = phone
        otp = generate_otp()
        session['otp'] = otp
        requests.get(f"https://www.fast2sms.com/dev/bulkV2?authorization=SlEb0FOyQ9YJrU3Wp7d5MmqioDunAPZtCVsGT8Nwx1vX64LKfaqynbGMVHDCE4dYv7xfmhTgc26SUXwi&route=otp&variables_values={otp}&flash=0&numbers={phone}")
        flash("OTP sent !","info")
        return redirect(url_for('verifyotp'))
    return render_template('forgetpassword.html')

@app.route('/verifyotp',methods=["POST","GET"])
@limiter.limit("30/hour")
def verifyotp():
    if request.method == "POST":
        otp = request.form['otp']
        if otp == session.get('otp'):
            flash("OTP verified !","success")
            return render_template("newpass.html")
        flash("Wrong Otp, try again !","warning")
        return redirect(url_for('verifyotp'))
    return render_template("forgetverify.html")
    
@app.route('/confirm-password',methods=["POST","GET"])
def confirm_password():
    if request.method == "POST":
        password = str(request.form['password']).strip()
        confirm_password =  str(request.form['password1']).strip()
        phone = session.get('number')
        if password == confirm_password:
            password_hash = hashlib.md5(password.encode()).hexdigest()
            db = get_database()
            cursor = db.cursor()
            existing_user = cursor.execute("select phoneno from users where phoneno = ?",(phone,)).fetchone()
            if existing_user:
                cursor.execute("UPDATE users set password = ? where phoneno = ?",(password_hash,phone))
                db.commit()
                db.close()
                
                flash('Password Reset Successful', 'success')
                return redirect(url_for("index"))
            else:
                flash("User Does not Exist !","warning")
        flash('password do not match','warning')
    return render_template("newpass.html")

@app.route("/profile", methods=["POST", "GET"])
@login_required
def profile():
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        settings = cursor.execute("SELECT * FROM setting").fetchone()
        db.close()
        return render_template("profile.html", user=user, settings=settings)
    
    if request.method == "POST":
        db = get_database()
        cursor = db.cursor()
        name = request.form['name']
        
        if name:
            name_parts = name.split()
            if len(name_parts) == 2:
                firstname, lastname = name_parts
                cursor.execute("UPDATE users SET firstname = ?, lastname = ? WHERE phoneno = ?", (firstname, lastname, session['phone']))
                db.commit()
                flash("Your Display Name Updated!", "success")
            elif len(name_parts) == 1:
                firstname = name_parts[0]
                cursor.execute("UPDATE users SET firstname = ? WHERE phoneno = ?", (firstname, session['phone']))
                db.commit()
                flash("Your Display Name Updated!", "success")
            else:
                flash("Please enter your name properly!", "warning")
        else:
            flash("Please enter your name!", "warning")
        
        db.close()
        return redirect(url_for('profile'))

    

@app.route("/dare")
@login_required
def dare():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    settings = cursor.execute("SELECT * FROM setting").fetchone()
    db.close()
    return render_template("dare.html",user=user,settings=settings)

@app.route("/approvecoin",methods=["POST","GET"])
@login_required
def approve_addcoin():
    if request.method == "POST":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        user = cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,)).fetchone()
        current_balance = user['balance']
        username = user['username']
        coin = cursor.execute("SELECT amount FROM add_coin where username = ?",(username,)).fetchone()
        new_balance = current_balance + int(coin)
        cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone,))
        db.commit()
        db.close()  
        flash('Balance added successfully!', 'success')      
        return redirect(url_for('admin'))

@app.route("/addcoin",methods=["POST","GET"])
@login_required
def addcoin():
    if request.method == "POST":
        coin = request.form['coins']
        payment_method = request.form['payment-method']
        utr = request.form['utr']
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        user = cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,)).fetchone()
        settings = cursor.execute("SELECT * FROM setting").fetchone()
        add_coin = cursor.execute("SELECT COUNT(*) FROM add_coin WHERE utr = ?", (utr,)).fetchone()
        if add_coin[0] > 0:
            flash("already submitted !","warning")
            return render_template('coin.html',success_message="Already Submitted !",user=user,settings=settings)
        else:
            transaction_date = get_indian_time().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO add_coin (username,amount,transaction_type,utr,status,transaction_date) VALUES(?,?,?,?,'pending',?)",(user['username'],coin,payment_method,utr,transaction_date))        
            db.commit()
            db.close()

            flash('Wait for Admin Approval !', 'warning')
            return render_template("coin.html",success_message="Wait for Admin Approval !",user=user,settings=settings)
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        settings = cursor.execute("SELECT * FROM setting").fetchone()
        db.close()
        
        return render_template("coin.html",user=user,settings=settings)
    return render_template("coin.html")

@app.route("/approvewithdraw", methods = ["POST","GET"])
@login_required
def approve_withdraw():
    if request.method == "POST":

        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        user = cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,)).fetchone()
        current_balance = user['balance']
        coin = cursor.execute("SELECT amount FROM withdraw_coin where username = ?",(user['username'],)).fetchone()
        if int(coin) <= int(current_balance):
            flash('Coins withdrawn successfully!', 'success')
            return render_template("withdraw.html",success_message="Withdrawal Success !",user=user)
        else:
            flash('You Dont Have Balance in Your Account !','warning')
            return render_template("withdraw.html",error_message="You Dont Have Balance in Your Account !",user=user)


@app.route("/withdraw", methods=["POST", "GET"])
@login_required
def withdraw():
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        settings = cursor.execute("SELECT * FROM setting").fetchone()
        db.close()
        return render_template("withdraw.html",user=user,settings=settings)
    if request.method == "POST":
        coin = request.form['coins']
        payment_method = request.form['payment-method']
        payment_id = request.form['upi_id']
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        user = cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,)).fetchone()
        settings = cursor.execute("SELECT * FROM setting").fetchall()
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        current_balance = cursor.fetchone()['balance']
        if int(coin) <= int(current_balance):
            transaction_date = get_indian_time().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO withdraw_coin (username, amount, transaction_type, number,status,transaction_date) VALUES (?, ?, ?, ?, 'open',?)",(user['username'],coin,payment_method,payment_id,transaction_date,))
            new_balance = current_balance - int(coin)
            cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
            db.commit()
            db.close()
            flash('Wait for Admin Approval !', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('You Dont Have Balance in Your Account !','warning')
            return render_template("withdraw.html",error_message="You Dont Have Balance in Your Account !",user=user,settings=settings)
    return render_template('profile.html')

@app.route("/history", methods=["POST", "GET"])
@login_required
def history():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    username = user['username']
    challenges = cursor.execute("SELECT * FROM challenges WHERE first_user = ? OR second_user = ? ORDER BY id DESC LIMIT 30", (username, username)).fetchall()
    recharge = cursor.execute("SELECT * FROM add_coin WHERE username = ? ORDER BY id DESC LIMIT 30",(username,)).fetchall()
    withdraw = cursor.execute("SELECT * FROM withdraw_coin WHERE username = ? ORDER BY id DESC LIMIT 30",(username,)).fetchall()
    settings = cursor.execute("SELECT * FROM setting").fetchone()

    db.close()
    return render_template("history.html", user=user, challenges=challenges, settings=settings,recharge=recharge,withdraw=withdraw)


@app.route("/leaderboard", methods=["POST", "GET"])
@login_required
def leaderboard():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    settings = cursor.execute("SELECT * FROM setting").fetchone()
    challenges = cursor.execute("SELECT * FROM users ORDER BY wins DESC LIMIT 10").fetchall()
    
    db.close()
    return render_template("leaderboard.html",user=user,settings=settings,challenges=challenges)



@app.route('/create-challenge', methods=['GET', 'POST'])
@login_required
def create_challenge():
    timestamp = datetime.now()
    timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
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
        try:
            if user['active_challenge'] == 1:
                flash('You already have an active challenge.', 'error')
                return redirect(url_for('dashboard'))
            elif int(coins_involved) <= int(current_balance):
                new_balance = current_balance - int(coins_involved)
                cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
                cursor.execute("UPDATE users SET active_challenge = '1' where username = ?",(session['username'],))
                flash('Coins Deducted successfully!', 'success')
                cursor.execute("INSERT INTO challenges (game_type, coins, first_user, status,timestamp) VALUES (?, ?, ?, ?, ?)",
                    (game_type, coins_involved, creator_id, 'open', timestamp))
                db.commit()
                flash('Challenge created successfully!', 'success')
                return redirect(url_for("dashboard"))
        except Exception as e:
            print(e)
            flash("Please Enter Coin !","warning")
            return redirect(url_for('dashboard'))
        else:
            flash('You Dont Have Enough Balance in Your Account !','warning')
            return redirect(url_for("dashboard"))
@app.route('/accept_challenge/<int:challenge_id>', methods=['POST'])
@login_required
def accept_challenge(challenge_id):
    second_user = session['username']
    db = get_database()
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (second_user,)).fetchone()
    challenge = cursor.execute("SELECT * FROM challenges WHERE id = ? AND status = 'open'", (challenge_id,)).fetchone()
    if user['active_challenge'] == 1:
            flash('You already have an active challenge.', 'error')
            return redirect(url_for('dashboard'))
    if challenge:
        check_balance = cursor.execute("SELECT balance FROM users WHERE username = ?", (second_user,)).fetchone()
        if check_balance:
            balance = check_balance[0]
            challenge_coin = cursor.execute("select coins from challenges where id = ?",(challenge_id,)).fetchone()[0]
            if int(balance) >= int(challenge_coin):
                cursor.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (challenge_coin, session['username']))
                cursor.execute("UPDATE challenges SET status = 'accepted', second_user = ? WHERE id = ?", (second_user, challenge_id))
                cursor.execute("UPDATE users SET active_challenge = 1 where username = ?",(session['username'],))
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
        cursor.execute("UPDATE users SET balance = balance + ? , active_challenge = 0 WHERE username = ?", (challenge_coin[0], session['username']))
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
                cursor.execute("UPDATE users SET balance = balance + ? , active_challenge = 0 WHERE username = ?", (challenge_coin[0], session['username']))
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
        challenge = cursor.execute("SELECT second_user, status FROM challenges WHERE id = ?",(challenge_id,)).fetchone()
        if not challenge:
            flash("Challenge Doesn't Exist !","warning")
            return redirect(url_for('dashboard'))
        second_user, status = challenge
        if second_user is None or status == 'open':
            flash("Other User Has Cancelled the Match !","warning")
            return redirect(url_for('dashboard'))
        cursor.execute("UPDATE challenges SET room_code = ?, status = 'started' WHERE id = ?", (room_code, challenge_id))
        db.commit()

        flash('Room code saved successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('enter_room_code.html', challenge_id=challenge_id)

@app.route('/enter_room_code1/<int:challenge_id>', methods=['GET', 'POST'])
@login_required
def enter_room_code1(challenge_id):
    if request.method == 'POST':
        room_code = request.form['room_code']
        password = request.form['password']
        db = get_database()
        cursor = db.cursor()
        cursor.execute("UPDATE challenges SET room_code = ?, password = ?, status = 'started' WHERE id = ?", (room_code, password, challenge_id))
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
        result = request.form.get('result')
        screenshot = request.files.get('screenshot')
        db = get_database()
        cursor = db.cursor()
        existing_submission = cursor.execute("SELECT * FROM results where challenge_id = ? AND (first_user = ? or second_user = ?)",(challenge_id,session['username'],session['username'])).fetchone()
        if existing_submission:
                flash('You have already submitted a result for this challenge','warning')
                db.close()
                return redirect(url_for('dashboard'))
        if screenshot and allowed_file(screenshot.filename):
            timestamp = int(time.time())
            filename = secure_filename(screenshot.filename)
            _, ext = os.path.splitext(filename)
            filename = f"screenshot_{generate_otp()}_{timestamp}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            screenshot.save(file_path)
            cursor.execute("BEGIN TRANSACTION")
            existing_result = cursor.execute("SELECT * FROM results WHERE challenge_id = ?", (challenge_id,)).fetchone()
            
            if not existing_result:
                cursor.execute("INSERT INTO results (challenge_id,status) VALUES(?,?)",(challenge_id,'undecided',))
                db.commit()

            first_user = cursor.execute("SELECT first_user FROM challenges where id = ?",(challenge_id,)).fetchone()[0]
            second_user = cursor.execute("SELECT second_user FROM challenges where id = ?",(challenge_id,)).fetchone()[0]

            if first_user == session['username']:

                cursor.execute("UPDATE results SET first_user = ?, screenshot1 = ?, match_status = ? WHERE challenge_id = ?",
                                   (session['username'], filename, result, challenge_id))
                db.commit()
                flash("Result Submitted Successfully !","success")
                user1 = cursor.execute("SELECT first_user FROM results where challenge_id = ?",(challenge_id,)).fetchone()[0]
                user2 = cursor.execute("SELECT second_user FROM results where challenge_id = ?",(challenge_id,)).fetchone()[0]
                if user1 and user2:
                    winner = auto_win(challenge_id,cursor)
                    db.commit()
                    if winner:
                        flash(f"{winner} wins the challenge !","success")
                return redirect(url_for('dashboard'))
            
            if second_user == session['username']:
                cursor.execute("UPDATE results SET second_user = ?, screenshot2 = ?, match_status2 = ? WHERE challenge_id = ?",
                                   (session['username'], filename, result, challenge_id))
                db.commit()
                flash("Result Submitted Successfully !","success")
                user1 = cursor.execute("SELECT first_user FROM results where challenge_id = ?",(challenge_id,)).fetchone()[0]
                user2 = cursor.execute("SELECT second_user FROM results where challenge_id = ?",(challenge_id,)).fetchone()[0]
                if user1 and user2:
                    winner = auto_win(challenge_id,cursor)
                    db.commit()
                    if winner:
                        flash(f"{winner} wins the challenge !","success")
                return redirect(url_for('dashboard'))
            

            else:
                flash("Error submitted Result , Contact Admin !","warning")
                return redirect(url_for('dashboard'))

        else:
            flash('Please Attach any Screenshot !','info')
            return redirect(url_for('submit_result',challenge_id=challenge_id))
        
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        user_id = session['username']
        user = cursor.execute("SELECT * FROM users WHERE username = ?",(user_id,)).fetchone()
        challenge = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()
        return render_template("result.html",user=user,challenge=challenge)
    
def auto_win(challenge_id,cursor):
    challenge = cursor.execute("SELECT * FROM challenges WHERE id = ?",(challenge_id,)).fetchone()
    result1_row = cursor.execute("SELECT match_status FROM results WHERE challenge_id = ?",(challenge_id,)).fetchone()
    result2_row = cursor.execute("SELECT match_status2 FROM results WHERE challenge_id = ?", (challenge_id,)).fetchone()
    try:
        if result1_row and result2_row:
            result1 = result1_row[0]
            result2 = result2_row[0]
            if result1 == "win" and result2 == "loss":
                cursor.execute("UPDATE challenges SET winner = ? WHERE id = ?",(challenge['first_user'],challenge_id,))
                cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("closed",challenge_id,))
                cursor.execute("UPDATE results SET status = ? WHERE challenge_id = ?",("decided",challenge_id,))
                cursor.execute("UPDATE results SET winner = ? WHERE challenge_id = ?",(challenge['first_user'],challenge_id,))
                bet_amount = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()['coins']
                winning_amount = bet_amount + int(bet_amount-bet_amount*0.06)
                cursor.execute("UPDATE challenges SET winnning_amount = ? where id = ?",(winning_amount,challenge_id))
                cursor.execute("UPDATE users SET balance = balance + ? , active_challenge = 0 where username = ?",(winning_amount,challenge['first_user'],))
                cursor.execute("UPDATE users SET wins = wins + ? where username = ?",(1,challenge['first_user'],))
                cursor.execute("UPDATE users SET active_challenge = 0 where username = ?",(challenge['second_user'],))
                return challenge['first_user']
            elif result1 == "loss" and result2 == "win":
                cursor.execute("UPDATE challenges SET winner = ? WHERE id = ?",(challenge['second_user'],challenge_id,))
                cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("closed",challenge_id,))
                cursor.execute("UPDATE results SET status = ? WHERE challenge_id = ?",("decided",challenge_id,))
                cursor.execute("UPDATE results SET winner = ? WHERE challenge_id = ?",(challenge['second_user'],challenge_id,))
                bet_amount = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()['coins']
                winning_amount = bet_amount + int(bet_amount-bet_amount*0.06)
                cursor.execute("UPDATE challenges SET winnning_amount = ? where id = ?",(winning_amount,challenge_id))
                cursor.execute("UPDATE users SET balance = balance + ? , active_challenge = 0 where username = ?",(winning_amount,challenge['second_user'],))
                cursor.execute("UPDATE users SET wins = wins + ? where username = ?",(1,challenge['second_user'],))
                cursor.execute("UPDATE users SET active_challenge = 0 where username = ?",(challenge['first_user'],))
                return challenge['second_user']
            elif result1 == "cancel" and result2 == "cancel":
                cursor.execute("UPDATE challenges SET winner = ? WHERE id = ?",("cancelled",challenge_id,))
                cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("cancelled",challenge_id,))
                cursor.execute("UPDATE results SET status = ? WHERE challenge_id = ?",("decided",challenge_id,))
                cursor.execute("UPDATE results SET winner = ? WHERE challenge_id = ?",("cancelled",challenge_id,))
                challenge_coin = cursor.execute("select coins from challenges where id = ?",(challenge_id,)).fetchone()
                cursor.execute("UPDATE users SET balance = balance + ?, active_challenge = 0 WHERE username = ?", (challenge_coin[0], challenge['first_user'],))
                cursor.execute("UPDATE users SET balance = balance + ?, active_challenge = 0 WHERE username = ?", (challenge_coin[0], challenge['second_user'],))
                cursor.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
                flash("Challenge cancelled !","success")
            
            elif result1 == 'win' and result1 == 'win':
                cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("pending",challenge_id,))
                flash("Result Pending","warning")
                
            elif result1 == 'loss' and result1 == 'loss':
                cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("pending",challenge_id,))
                flash("Result Pending","warning")
                
            
    except Exception as e:
        print("Error Happened!!!")
        print(e)

@app.route('/admin')
@login_required
def admin():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        db = get_database()
        cursor = db.cursor()
        add = cursor.execute("SELECT status FROM add_coin").fetchall()
        add_status = any(status[0] == 'pending' for status in add)
        result = cursor.execute("SELECT status FROM results").fetchall()
        result_status = any(status[0] == 'undecided' for status in result)
        withdraw = cursor.execute("SELECT status FROM withdraw_coin").fetchall()
        withdraw_status = any(status[0] == 'open' for status in withdraw)
        db.close()
        return render_template('admin.html',add_status=add_status,result_status=result_status,withdraw_status=withdraw_status)
    else:
        return render_template("404.html")
    
@app.route('/admin/all_user', methods=["POST","GET"])
@login_required
def admin_alluser():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            page = request.args.get('page',1,type=int)
            per_page = 10
            offset = (page-1) * per_page
            db = get_database()
            cursor = db.cursor()
            users = cursor.execute("SELECT * FROM users ORDER BY id DESC LIMIT ? OFFSET ?",(per_page,offset)).fetchall()
            total_users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_pages = (total_users + per_page - 1) // per_page
            db.close()
            return render_template('all_user.html',users=users,page=page,total_pages=total_pages,total_users=total_users)
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            username = request.form['username']
            try:
                cursor.execute("DELETE from users where username = ?",(username,))
                users = cursor.execute("SELECT * FROM users").fetchall()
                db.commit()
                flash("User Deleted !","success")
            except Exception as e:
                db.rollback()
                flash(f"An Error happened: {str(e)}","error")
            finally:
                db.close()
            return redirect(url_for('admin_alluser'))
    else:
        return render_template("404.html")
    
@app.route('/admin/search/alluser', methods=['POST', 'GET'])
@login_required
def admin_alluser_search():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            search_query = request.form['search']
            search = cursor.execute("SELECT * FROM users WHERE username LIKE ? OR phoneno = ?", (search_query, search_query)).fetchall()
            db.close()
            if search:
                return render_template("alluser_search.html", search=search)
            else:
                flash('No User records found for the provided username.', 'warning')
                return redirect(url_for('admin_alluser'))
        else:
            return render_template("alluser_search.html")
    else:
        return render_template("404.html")

@app.route('/admin/balance', methods=['POST'])
@login_required
def update_balance():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == 'POST':
            try:
                db = get_database()
                cursor = db.cursor()
                username = request.form['username']
                new_balance = request.form['balance']
                new_balance = int(new_balance)
                cursor.execute("UPDATE users SET balance = ? WHERE username =?",(new_balance,username))
                db.commit()
                flash("User Balance Updated !","success")
                return redirect(url_for('admin_alluser'))
            except Exception as e:
                print(e)
                flash("Please Enter Valid Amount !","warning")
                return redirect(url_for('admin_alluser'))

    
@app.route('/admin/challenge_id',methods=["POST","GET"])
@login_required
def admin_challengeid():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            page = request.args.get('page',1,type=int)
            per_page = 10
            offset = (page-1) * per_page
            challenges = cursor.execute("SELECT * FROM challenges order by id desc LIMIT ? OFFSET ?",(per_page,offset)).fetchall()
            total_challenges = cursor.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
            total_pages = (total_challenges + per_page - 1) // per_page
            db.close()
            return render_template('challenge_id.html',challenges=challenges,page=page,total_pages=total_pages)
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            id = request.form['challenge_id']
            challenge = cursor.execute("SELECT * FROM challenges WHERE id = ?", (id,)).fetchone()
            
            if challenge['winner']:
                flash("Winner already decided !","warning")
                return redirect(url_for('admin_challengeid'))
            else:
                cursor.execute("UPDATE users SET balance = balance + ? WHERE username IN (?, ?)", (challenge['coins'],challenge['first_user'], challenge['second_user']))
                cursor.execute("UPDATE users SET active_challenge = 0 WHERE username IN (?, ?)", (challenge['first_user'], challenge['second_user']))
                cursor.execute("DELETE FROM challenges WHERE id = ?",(id,))
                flash(f"Challenge no. {id} Deleted !","info")   
                db.commit()
            return redirect(url_for('admin_challengeid'))

    else:
        return render_template("404.html")
    
@app.route('/admin/search/challenge', methods=['POST', 'GET'])
@login_required
def admin_challenge_search():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            search_query = request.form['search']
            capitalize = search_query.capitalize()
            
            search = cursor.execute("SELECT * FROM challenges WHERE first_user in (?, ?) OR second_user in (?,?) OR id = ? ORDER BY id DESC", (search_query, capitalize,search_query,capitalize,search_query,)).fetchall()
            db.close()
            if search:
                return render_template("challenge_search.html", search=search)
            else:
                flash('No Challenge records found for the provided username.', 'warning')
                return redirect(url_for('admin_challengeid'))
        else:
            return render_template("challenge_search.html")
    else:
        return render_template("404.html")
    
@app.route('/admin/admin_result')
@login_required
def admin_result():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        db = get_database()
        cursor = db.cursor()
        page = request.args.get('page',1,type=int)
        per_page = 10
        offset = (page-1) * per_page
        results = cursor.execute("SELECT * FROM results JOIN challenges ON results.challenge_id = challenges.id ORDER BY CASE WHEN results.status = 'undecided' THEN 1 ELSE 2 END, id DESC LIMIT ? OFFSET ?", (per_page, offset)).fetchall()
        total_results = cursor.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        total_pages = (total_results + per_page - 1) // per_page
        return render_template('admin_result.html',results=results,page=page,total_pages=total_pages)
    else:
        return render_template("404.html")
    
@app.route('/admin/search/result', methods=['POST', 'GET'])
@login_required
def admin_result_search():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            search_query = request.form['search']
            capitalize = search_query.capitalize()
            search = cursor.execute("SELECT * FROM results WHERE first_user in (?, ?) OR second_user in (?,?) OR id = ? ORDER BY id DESC", (search_query, capitalize,search_query,capitalize,search_query,)).fetchall()
            db.close()
            if search:
                return render_template("result_search.html", search=search)
            else:
                flash('No Results records found for the provided username.', 'warning')
                return redirect(url_for('admin_result'))
        else:
            return render_template("result_search.html")
    else:
        return render_template("404.html")
    
@app.route('/admin/decide_winner',methods=["POST"])
@login_required
def admin_decide_winner():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        challenge_id = request.form['challenge_id']
        winner = request.form['user']
        db = get_database()
        cursor = db.cursor()
        cursor.execute("UPDATE challenges SET winner = ? WHERE id = ?",(winner,challenge_id,))
        cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("closed",challenge_id,))
        cursor.execute("UPDATE results SET status = ? WHERE challenge_id = ?",("decided",challenge_id,))
        cursor.execute("UPDATE results SET winner = ? WHERE challenge_id = ?",(winner,challenge_id,))
        bet_amount = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()['coins']
        users = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()
        if users['first_user'] == winner:
            loser = users['second_user']
        elif users['second_user'] == winner:
            loser = users['first_user']
        else:
            return "an error happend"
        winning_amount = bet_amount + int(bet_amount-bet_amount*0.06)
        cursor.execute("UPDATE challenges SET winnning_amount = ? where id = ?",(winning_amount,challenge_id))
        cursor.execute("UPDATE users SET balance = balance + ? , active_challenge = 0 where username = ?",(winning_amount,winner))
        cursor.execute("UPDATE users SET wins = wins + ? where username = ?",(1,winner))
        cursor.execute("UPDATE users SET active_challenge = 0 where username = ?",(loser,))
        db.commit()
        db.close()
        flash("winner selected","success")
        return redirect(url_for('admin_result'))
    else:
        return render_template("404.html")

@app.route('/admin/cancel_match', methods=['POST'])
@login_required
def admin_cancel_match():
        if session['phone'] in ['8406909448', '7019222294', '7411123457']:
            try:
                challenge_id = request.form['challenge_id']
                db = get_database()
                cursor = db.cursor()
                challenge = cursor.execute("SELECT * FROM challenges WHERE id = ?",(challenge_id,)).fetchone()
                cursor.execute("UPDATE challenges SET winner = ? WHERE id = ?",("cancelled",challenge_id,))
                cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("cancelled",challenge_id,))
                cursor.execute("UPDATE results SET status = ? WHERE challenge_id = ?",("decided",challenge_id,))
                cursor.execute("UPDATE results SET winner = ? WHERE challenge_id = ?",("cancelled",challenge_id,))
                challenge_coin = cursor.execute("select coins from challenges where id = ?",(challenge_id,)).fetchone()
                print(challenge_coin[0])
                print(challenge['first_user'],challenge['second_user'])
                cursor.execute("UPDATE users SET balance = balance + ?, active_challenge = 0 WHERE username = ?", (challenge_coin[0], challenge['first_user'],))
                cursor.execute("UPDATE users SET balance = balance + ?, active_challenge = 0 WHERE username = ?", (challenge_coin[0], challenge['second_user'],))
                cursor.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
                flash("Challenge cancelled !","success")
                db.commit()
                return redirect(url_for('admin_result'))
            except Exception as e:
                db.rollback()
                flash(f"error happened {e}","warning")
                return redirect(url_for('admin_result'))
            finally:
                db.close()
        
        else:
                return render_template("404.html")
            



@app.route('/admin/add_coin',methods=["POST","GET"])
@login_required
def admin_addcoin():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            page = request.args.get('page',1,type=int)
            per_page = 10
            offset = (page-1) * per_page
            payments = cursor.execute("SELECT * FROM add_coin ORDER BY CASE WHEN status = 'pending' THEN 1 ELSE 2 END, id DESC LIMIT ? OFFSET ?",(per_page,offset)).fetchall()
            total_add_coin = cursor.execute("SELECT COUNT(*) FROM add_coin").fetchone()[0]
            total_pages = (total_add_coin + per_page - 1) // per_page
            return render_template('add_coin.html',payments=payments,page=page,total_pages=total_pages)
        
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            amount = request.form['amount']
            username = request.form['username']
            id = request.form['id']
            button = request.form['button']
            if button == "approved":
                cursor.execute("UPDATE users set balance = balance + ? WHERE username = ?",(amount,username))
                cursor.execute("UPDATE add_coin set status = ? WHERE id = ?",(button,id))
                flash(f"Balance Update for user {username}","info")
                db.commit()
            else:
                cursor.execute("UPDATE add_coin set status = ? WHERE id = ?",(button,id))
                db.commit()
                flash(f"Duplicated or Rejected for user {username}","info")
            return redirect(url_for('admin_addcoin'))
    else:
        return render_template("404.html")
    
@app.route('/admin/search/addcoin',methods=['POST','GET'])
@login_required
def admin_addcoin_search():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            search_query = request.form['search']
            capitlize = search_query.capitalize()
            search = cursor.execute("SELECT * FROM add_coin WHERE username in (?,?) ORDER BY id DESC",(search_query,capitlize)).fetchall()
            db.close()
            if search:
                return render_template("addcoin_search.html",search=search)
            else:
                flash('No add Coin records found for the provided username.', 'warning')
                return redirect(url_for('admin_addcoin'))
        else:
            return render_template('add_coin.html')
    else:
        return render_template("404.html")
    
@app.route('/admin/withdraw_coin', methods=["POST","GET"])
@login_required
def admin_withdrawcoin():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            page = request.args.get('page',1,type=int)
            per_page = 10
            offset = (page-1) * per_page
            withdraws = cursor.execute('''
SELECT w.*, u.balance
FROM withdraw_coin w
JOIN users u ON w.username = u.username
ORDER BY CASE WHEN w.status = 'open' THEN 1 ELSE 2 END, w.id DESC
LIMIT ? OFFSET ?;
''',(per_page,offset)).fetchall()
            total_withdrawals = cursor.execute("SELECT COUNT(*) FROM withdraw_coin").fetchone()[0]
            total_pages = (total_withdrawals + per_page - 1) // per_page
            db.close()
            return render_template('withdraw_coin.html',withdraws = withdraws,page=page,total_pages=total_pages)
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            id = request.form['id']
            button = request.form['button']
            if button == "approved":
                cursor.execute("UPDATE withdraw_coin SET status = ? WHERE id = ?",(button,id,))
                db.commit()
                db.close()
                flash(f"Withdrawal Approved !","success")
            elif button == "denied":
                amount = request.form['amount']
                username = request.form['username']
                current_balance = cursor.execute("SELECT balance FROM users WHERE username = ?",(username,)).fetchone()[0]
                cursor.execute("UPDATE users SET balance = ? + ? WHERE username = ?",(current_balance,amount,username)) 
                cursor.execute("UPDATE withdraw_coin SET status = ? WHERE id = ?",(button,id))
                db.commit()
                db.close()
                flash("Withdrawal rejected !","success")
            return redirect(url_for('admin_withdrawcoin'))
    else:
        return render_template("404.html")
    
    
@app.route('/admin/search/withdraw', methods=['POST', 'GET'])
@login_required
def admin_withdraw_search():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            search_query = request.form['search']
            capitalize = search_query.capitalize()
            search = cursor.execute("SELECT * FROM withdraw_coin WHERE username in (?, ?) ORDER BY id DESC", (search_query, capitalize,)).fetchall()
            db.close()
            if search:
                return render_template("withdraw_search.html", search=search)
            else:
                flash('No withdrawal records found for the provided username.', 'warning')
                return redirect(url_for('admin_withdrawcoin'))
        else:

            return render_template("withdraw_search.html")
    else:
        return render_template("404.html")


@app.route('/admin/setting',methods=["POST","GET"])
@login_required
def setting():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            settings = cursor.execute("SELECT * FROM setting").fetchone()

            return render_template('setting.html',settings=settings)
        if request.method == "POST":
            db =get_database()
            cursor = db.cursor()
            new_upi = request.form['upi_id']
            cursor.execute("UPDATE setting set upi_id = ?",(new_upi,))
            db.commit()
            db.close()
            flash("Upi Id updated","success")
            return redirect(url_for('setting'))
    else:
        return render_template("404.html")

@app.route('/admin/setting/telegram_id',methods=["POST","GET"])
@login_required
def setting_telegram():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            settings = cursor.execute("SELECT * FROM setting").fetchone()
            return render_template('setting.html',settings=settings)

        if request.method == "POST":
            db =get_database()
            cursor = db.cursor()
            telegram = request.form['telegram_id']
            tel = telegram.split(":")
            social = tel[0].strip()
            new_telegram = tel[1].strip()
            cursor.execute("UPDATE setting set telegram_id = ?",(new_telegram,))
            cursor.execute("UPDATE setting set social = ?",(social,))
            db.commit()
            db.close()
            flash("Telegram Id updated","success")
            return redirect(url_for('setting'))
    else:
        return render_template("404.html")


@app.route('/admin/setting/qr',methods=["POST","GET"])
@login_required
def setting_qr():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            settings = cursor.execute("SELECT * FROM setting").fetchone()

            return render_template('setting.html',settings=settings)
        if request.method == "POST":
            db =get_database()
            cursor = db.cursor()
            qr_code = request.files['qrcode']
            if qr_code and allowed_file(qr_code.filename):
                filename = secure_filename(qr_code.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                qr_code.save(file_path)
            cursor.execute("UPDATE setting set qr_code = ?",(filename,))
            db.commit()
            flash("QR Code Updated !","success")
            db.close()
            return redirect(url_for('setting'))

    else:
        return render_template("404.html")
    
@app.route('/admin/setting/button', methods=['POST','GET'])
@login_required
def chat_button():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            settings = cursor.execute("SELECT * FROM setting")
            return render_template('/admin',settings=settings)
        if request.method == "POST":
            button1 = request.form['button1']
            button2 = request.form['button2']
            button3 = request.form['button3']
            db = get_database()
            cursor = db.cursor()
            cursor.execute("UPDATE setting SET button1 = ? , button2 = ? , button3 = ?",(button1,button2,button3))
            db.commit()
            db.close()
            return redirect(url_for('setting'))
    else:
        return render_template("404.html")
    
@app.route('/admin/setting/header',methods=['GET','POST'])
@login_required
def header_scroll():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            settings = cursor.execute("SELECT * FROM setting").fetchone()
            db.close()
            return render_template('setting.html',settings=settings)
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            header = request.form['header']
            cursor.execute("UPDATE setting SET header = ?",(header,))
            db.commit()
            db.close()
            return redirect(url_for('setting'))
    else:
        return render_template("404.html")

# jbjhkfhjfjhkvhj

@app.route('/admin/setting/change_background',methods=['GET','POST'])
@login_required
def change_background():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            settings = cursor.execute("SELECT * FROM setting").fetchone()
            db.close()
            return render_template('setting.html',settings=settings)
        if request.method == "POST":
            try:
                db = get_database()
                cursor = db.cursor()
                bg_image = request.files['bg_image']
                if bg_image and allowed_file(bg_image.filename):
                    filename = "bg.jpg"
                    file_path = os.path.join('static', filename)
                    os.makedirs(os.path.dirname(file_path),exist_ok=True)
                    bg_image.save(file_path)

                db.commit()
            except Exception as e:
                db.rollback()
                flash(f"Some error happened ! ,{e}")
            finally:
                db.close()

            return redirect(url_for('setting'))
    else:
        return render_template("404.html")


@app.route('/delete_old_challenges', methods=['POST'])
def delete_old_challenge():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:
        try:
            db = get_database()
            cursor = db.cursor()
            days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
            old_results = cursor.execute("SELECT id, screenshot1, screenshot2 FROM results WHERE challenge_id IN (SELECT id FROM challenges WHERE timestamp < ?)", (days_ago,)).fetchall()

            for result in old_results:
                screenshot1_path = result[1]
                screenshot2_path = result[2]
                if screenshot1_path:
                    file_path1 = os.path.join(app.config['UPLOAD_FOLDER'], screenshot1_path)
                    if os.path.exists(file_path1):
                        os.remove(file_path1)
                if screenshot2_path:
                    file_path2 = os.path.join(app.config['UPLOAD_FOLDER'], screenshot2_path)
                    if os.path.exists(file_path2):
                        os.remove(file_path2)

            cursor.execute("DELETE FROM results WHERE challenge_id IN (SELECT id FROM challenges WHERE timestamp < ?)", (days_ago,))
            db.commit()

            cursor.execute("DELETE FROM challenges WHERE timestamp < ?",(days_ago,))
            db.commit()
            
            flash("Old challenges and associated results deleted successfully !","success")
            return redirect(url_for('setting'))
        except Exception as e:
            flash(f"Error deleting old challenges and results: {str(e)}", "error")
            return redirect(url_for('setting'))
        finally:
            db.close()
    else:
        return render_template("404.html")

@app.route('/admin/ban_user/', methods=['POST'])
def admin_ban_user():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:    
        db = get_database()
        cursor = db.cursor()
        try:
            user_id = request.form['user_id']
            cursor.execute("UPDATE users SET is_banned = ? WHERE id = ?",(True,user_id))
            db.commit()
        except Exception as e:
            flash(f"Error Happened ! {e}","warning")
            return redirect(url_for('admin_alluser'))
            db.rollback()
        finally:
            db.close()
        flash("User has been banned !","success")
        return redirect(url_for("admin_alluser"))
    else:
        return render_template("404.html")

@app.route('/admin/unban_user/', methods=['POST'])
def admin_unban_user():
    if session['phone'] in ['8406909448', '7019222294', '7411123457']:    
        db = get_database()
        cursor = db.cursor()
        try:
            user_id = request.form['user_id']
            cursor.execute("UPDATE users SET is_banned = ? WHERE id = ?",(False,user_id))
            db.commit()
        except Exception as e:
            flash(f"Error Happened ! {e}","warning")
            return redirect(url_for('admin_alluser'))
            db.rollback()
        finally:
            db.close()
        flash("User has been Unbanned !","success")
        return redirect(url_for("admin_alluser"))
    else:
        return render_template("404.html")


    
@app.errorhandler(404)
def error(e):
    return render_template('404_1.html'), 404


if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=8000)
