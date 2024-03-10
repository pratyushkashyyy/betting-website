from flask import Flask, request,url_for,render_template,redirect,flash,session,send_from_directory,jsonify
from database import get_database
from functools import wraps
from twilio.rest import Client
import random,os,hashlib
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

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
        password_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_database()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        if user:
            if user['password'] == password_hash:
                session['username'] = user['username']
                session['phone'] = phone
                session['id'] = user['id']
                if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
                    session['admin'] = True
                    flash('Logged in successfully as admin!', 'success')
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
    page = request.args.get('page',1,type=int)
    per_page = 8
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
    total_pages = (total_challenges + per_page - 1) // per_page
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
def get_otp():
    if request.method == "POST":
        phone = request.form['phone']
        session['phone'] = phone
        otp = generate_otp()
        print(otp)
        session['otp'] = otp
        client = Client('ACb0a62a64b64ac6a9f1f926b3512dcc86', '236ada804a2c1cfe6548633288e58fa0')
        message = client.messages.create(
                        body='Your otp for GameMates is '+otp,
                        from_='+18144580408',
                        to='+91'+phone
                     )
        flash("OTP Sent !","success")
        return redirect(url_for('verify_otp'))
 
@app.route('/otpverify',methods=["POST","GET"])
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
def signup():
    if request.method == "POST":
        phone = session.get('phone')
        password = request.form['password']
        username = request.form['username']
        firstname = request.form['firstname'].capitalize()
        lastname = request.form['lastname'].capitalize()
        password_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_database()
        cursor = db.cursor()
        existing_user = cursor.execute("select phoneno from users where phoneno = ?",(phone,)).fetchone()
        existing_username = cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            session.pop('phone',None)
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
def forget_password():
    if request.method == "POST":
        phone = request.form['phone']
        session['number'] = phone
        otp = generate_otp()
        print(otp)
        session['otp'] = otp
        client = Client('ACb0a62a64b64ac6a9f1f926b3512dcc86', '236ada804a2c1cfe6548633288e58fa0')
        message = client.messages.create(
                        body='Your otp is'+otp,
                        from_='+18144580408',
                        to='+91'+phone
                     )
        flash("OTP sent !","info")
        return redirect(url_for('verifyotp'))
    return render_template('forgetpassword.html')

@app.route('/verifyotp',methods=["POST","GET"])
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

@app.route("/profile")
@login_required
def profile():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    settings = cursor.execute("SELECT * FROM setting").fetchone()
    db.close()
    return render_template("profile.html",user=user,settings=settings)

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
            cursor.execute("INSERT INTO add_coin (username,amount,transaction_type,utr,status) VALUES(?,?,?,?,'pending')",(user['username'],coin,payment_method,utr))        
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
            cursor.execute("INSERT INTO withdraw_coin (username, amount, transaction_type, number,status) VALUES (?, ?, ?, ?, 'open')",(user['username'],coin,payment_method,payment_id,))
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
    username = session['username']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    challenges = cursor.execute("SELECT * FROM challenges WHERE first_user = ? OR second_user = ?", (username, username)).fetchall()
    settings = cursor.execute("SELECT * FROM setting").fetchone()

    db.close()
    return render_template("history.html",user=user,challenges=challenges,settings=settings)


@app.route("/leaderboard", methods=["POST", "GET"])
@login_required
def leaderboard():
    db = get_database()
    cursor = db.cursor()
    phone = session['phone']
    cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
    user = cursor.fetchone()
    settings = cursor.execute("SELECT * FROM setting").fetchone()
    challenges = cursor.execute("SELECT * FROM users").fetchall()
    
    db.close()
    return render_template("leaderboard.html",user=user,settings=settings,challenges=challenges)



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
        if user['active_challenge'] == 1:
            flash('You already have an active challenge.', 'error')
            return redirect(url_for('dashboard'))
        elif int(coins_involved) <= int(current_balance):
            new_balance = current_balance - int(coins_involved)
            cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
            cursor.execute("UPDATE users SET active_challenge = '1' where username = ?",(session['username'],))
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
        result = request.form['result']
        screenshot = request.files['screenshot']
        if screenshot and allowed_file(screenshot.filename):
            filename = secure_filename(screenshot.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            screenshot.save(file_path)
            db = get_database()
            cursor = db.cursor()
            existing_result = cursor.execute("SELECT * FROM results WHERE challenge_id = ?", (challenge_id,)).fetchone()
            if not existing_result:
                cursor.execute("INSERT INTO results (challenge_id,status) VALUES(?,?)",(challenge_id,'undecided',))
                db.commit()
            existing_submission = cursor.execute("SELECT * FROM results where challenge_id = ? AND (first_user = ? or second_user = ?)",(challenge_id,session['username'],session['username'])).fetchone()
            if existing_submission:
                flash('You have already submitted a result for this challenge','warning')
                return redirect(url_for('dashboard'))

            first_user = cursor.execute("SELECT first_user FROM results where challenge_id = ?",(challenge_id,)).fetchone()[0]
            second_user = cursor.execute("SELECT second_user FROM results where challenge_id = ?",(challenge_id,)).fetchone()[0]
            
            if second_user:
                    cursor.execute("UPDATE results SET first_user = ?, screenshot1 = ?, match_status = ? WHERE challenge_id = ?",
                                   (session['username'], filename, result, challenge_id))
                    flash('Result submitted successfully!', 'success')
                    winner = auto_win(challenge_id, cursor)
                    if winner:
                        flash(f"{winner} wins the challenge !","success")
                    db.commit()
                    return redirect(url_for('dashboard',challenge_id=challenge_id))

            elif first_user:
                    cursor.execute("UPDATE results SET second_user = ?, screenshot2 = ?, match_status2 = ? WHERE challenge_id = ?",
                                   (session['username'], filename, result, challenge_id))
                    flash('Result submitted successfully!', 'success')
                    winner = auto_win(challenge_id, cursor)
                    if winner:
                        flash(f"{winner} wins the challenge !","success")
                    db.commit()
                    return redirect(url_for('dashboard',challenge_id=challenge_id))

            else:
                cursor.execute("UPDATE results SET first_user = ?, screenshot1 = ?, match_status = ? WHERE challenge_id = ?",(session['username'], filename, result, challenge_id))
                flash('Result submitted successfully!', 'success')
                db.commit()                    
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
def auto_win(challenge_id,cursor):
    challenge = cursor.execute("SELECT * FROM challenges WHERE id = ?",(challenge_id,)).fetchone()
    result1_row = cursor.execute("SELECT match_status FROM results WHERE challenge_id = ? AND first_user = ?",(challenge_id,challenge['first_user'])).fetchone()
    result2_row = cursor.execute("SELECT match_status2 FROM results WHERE challenge_id = ? AND second_user = ?", (challenge_id, challenge['second_user'])).fetchone()

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
    else:
        return 'Error Happened, Please Contact Admin'

@app.route('/admin')
@login_required
def admin():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
        return render_template('admin.html')
    else:
        return render_template("404.html")
    
@app.route('/admin/all_user', methods=["POST","GET"])
@login_required
def admin_alluser():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
        if request.method == "GET":
            page = request.args.get('page',1,type=int)
            per_page = 10
            offset = (page-1) * per_page
            db = get_database()
            cursor = db.cursor()
            users = cursor.execute("SELECT * FROM users LIMIT ? OFFSET ?",(per_page,offset)).fetchall()
            total_users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_pages = (total_users + per_page - 1) // per_page
            db.close()
            return render_template('all_user.html',users=users,page=page,total_pages=total_pages)
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
            return render_template('all_user.html',users=users)    
    else:
        return render_template("404.html")
    
@app.route('/admin/balance', methods=['POST'])
@login_required
def update_balance():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
        if request.method == 'POST':
            db = get_database()
            cursor = db.cursor()
            username = request.form['username']
            new_balance = request.form['balance']
            cursor.execute("UPDATE users SET balance = ? WHERE username =?",(new_balance,username))
            db.commit()
            flash("User Balance Updated !","success")
            return redirect(url_for('admin_alluser'))

    
@app.route('/admin/challenge_id',methods=["POST","GET"])
@login_required
def admin_challengeid():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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
    
@app.route('/admin/admin_result')
@login_required
def admin_result():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
        db = get_database()
        cursor = db.cursor()
        page = request.args.get('page',1,type=int)
        per_page = 10
        offset = (page-1) * per_page
        results = cursor.execute("SELECT * FROM results ORDER BY CASE WHEN status = 'undecided' THEN 1 ELSE 2 END, id DESC LIMIT ? OFFSET ?", (per_page, offset)).fetchall()
        total_results = cursor.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        total_pages = (total_results + per_page - 1) // per_page
        return render_template('admin_result.html',results=results,page=page,total_pages=total_pages)
    else:
        return render_template("404.html")
    
@app.route('/admin/decide_winner',methods=["POST"])
@login_required
def admin_decide_winner():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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


@app.route('/admin/add_coin',methods=["POST","GET"])
@login_required
def admin_addcoin():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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
    
@app.route('/admin/withdraw_coin', methods=["POST","GET"])
@login_required
def admin_withdrawcoin():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            page = request.args.get('page',1,type=int)
            per_page = 10
            offset = (page-1) * per_page
            withdraws = cursor.execute("SELECT * FROM withdraw_coin ORDER BY CASE WHEN status = 'open' THEN 1 ELSE 2 END, id DESC LIMIT ? OFFSET ?",(per_page,offset)).fetchall()
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
                cursor.execute("UPDATE withdraw_coin SET status = ? WHERE id = ?",(button,id))
                db.commit()
                db.close()
                flash("Withdrawal rejected !","success")
            return redirect(url_for('admin_withdrawcoin'))
    else:
        return render_template("404.html")

@app.route('/admin/message')
@login_required
def admin_message():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
        return render_template('message.html')
    else:
        return render_template("404.html")

@app.route('/admin/setting',methods=["POST","GET"])
@login_required
def setting():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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
@app.route('/admin/setting/qr',methods=["POST","GET"])
@login_required
def setting_qr():
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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
    if session['phone'] == '8406909448' or session['phone'] == '7019222294' or session['phone'] == '7411123457':
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


if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=80)