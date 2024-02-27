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
                if session['phone'] == '8406909448':
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
        cursor.execute("INSERT INTO add_coin (username,amount,transaction_type,utr,status) VALUES(?,?,?,?,'pending')",(user['username'],coin,payment_method,utr))        
        db.commit()
        db.close()

        flash('Wait for Admin Approval !', 'warning')
        return render_template("coin.html",success_message="Wait for Admin Approval !",user=user)
    if request.method == "GET":
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,))
        user = cursor.fetchone()
        db.close()
        
        return render_template("coin.html",user=user)
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
        db.close()
        return render_template("withdraw.html",user=user)
    elif request.method == "POST":
        coin = request.form['coins']
        payment_method = request.form['payment-method']
        payment_id = request.form['payment-number']
        db = get_database()
        cursor = db.cursor()
        phone = session['phone']
        user = cursor.execute("SELECT * FROM users WHERE phoneno = ?", (phone,)).fetchone()
        cursor.execute("SELECT balance FROM users WHERE phoneno = ?", (phone,))
        current_balance = cursor.fetchone()['balance']
        if int(coin) <= int(current_balance):
            cursor.execute("INSERT INTO withdraw_coin (username, amount, transaction_type, number,status) VALUES (?, ?, ?, ?, 'open')",(user['username'],coin,payment_method,payment_id,))
            new_balance = current_balance - int(coin)
            cursor.execute("UPDATE users SET balance = ? WHERE phoneno = ?", (new_balance, phone))
            db.commit()
            db.close()
            flash('Wait for Admin Approval !', 'success')
            return render_template("withdraw.html",success_message="Wait for Admin Approval !",user=user)
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
    challenges = cursor.execute("select * from challenges where first_user = ?",(username,)).fetchall()
    db.close()
    return render_template("history.html",user=user,challenges=challenges)


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
                    db.commit()
                    return redirect(url_for('dashboard',challenge_id=challenge_id))

            elif first_user:
                    cursor.execute("UPDATE results SET second_user = ?, screenshot2 = ?, match_status2 = ? WHERE challenge_id = ?",
                                   (session['username'], filename, result, challenge_id))
                    flash('Result submitted successfully!', 'success')
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

@app.route('/admin')
@login_required
def admin():
    if session['phone'] == '8406909448':
        return render_template('admin.html')
    else:
        return render_template("404.html")
    
@app.route('/admin/all_user')
@login_required
def admin_alluser():
    if session['phone'] == '8406909448':
        db = get_database()
        cursor = db.cursor()
        users = cursor.execute("SELECT * FROM users").fetchall()
        return render_template('all_user.html',users=users)
    else:
        return render_template("404.html")
    
@app.route('/admin/challenge_id',methods=["POST","GET"])
@login_required
def admin_challengeid():
    if session['phone'] == '8406909448':
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            challenges = cursor.execute("SELECT * FROM challenges").fetchall()
            db.close()
            return render_template('challenge_id.html',challenges=challenges)
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            id = request.form['challenge_id']
            cursor.execute("DELETE FROM challenges WHERE id = ?",(id,))
            db.commit()
            return redirect(url_for('admin_challengeid'))

    else:
        return render_template("404.html")
    
@app.route('/admin/admin_result')
@login_required
def admin_result():
    if session['phone'] == '8406909448':
        db = get_database()
        cursor = db.cursor()
        results = cursor.execute("SELECT * FROM results")     
        return render_template('admin_result.html',results=results)
    else:
        return render_template("404.html")
    
@app.route('/admin/decide_winner',methods=["POST"])
@login_required
def admin_decide_winner():
    if session['phone'] == '8406909448':
        challenge_id = request.form['challenge_id']
        winner = request.form['user']
        db = get_database()
        cursor = db.cursor()
        cursor.execute("UPDATE challenges SET winner = ? WHERE id = ?",(winner,challenge_id,))
        cursor.execute("UPDATE challenges SET status = ? WHERE id = ?",("closed",challenge_id,))
        cursor.execute("UPDATE results SET status = ? WHERE challenge_id = ?",("decided",challenge_id,))
        bet_amount = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()['coins']
        users = cursor.execute("SELECT * FROM challenges where id = ?",(challenge_id,)).fetchone()
        if users['first_user'] == winner:
            loser = users['second_user']
        elif users['second_user'] == winner:
            loser = users['first_user']
        else:
            return "an error happend"
        winning_amount = bet_amount + int(bet_amount-bet_amount*0.06)
        cursor.execute("UPDATE users SET balance = balance + ? where username = ?",(winning_amount,winner))
        cursor.execute("UPDATE users SET wins = wins + ? where username = ?",(1,winner))
        cursor.execute("UPDATE users SET balance = balance - ? where username = ?",(bet_amount,loser))
        db.commit()
        db.close()
        flash("winner selected","success")
        return redirect(url_for('admin_result'))
    else:
        return render_template("404.html")


@app.route('/admin/add_coin',methods=["POST","GET"])
@login_required
def admin_addcoin():
    if session['phone'] == '8406909448':
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            payments = cursor.execute("SELECT * FROM add_coin").fetchall()
            db.close()
            return render_template('add_coin.html',payments=payments)
        
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            amount = request.form['amount']
            username = request.form['username']
            id = request.form['id']
            button = request.form['button']
            cursor.execute("UPDATE users set balance = balance + ? WHERE username = ?",(amount,username))
            cursor.execute("UPDATE add_coin set status = ? WHERE id = ?",(button,id))
            db.commit()
            return redirect(url_for('admin_addcoin'))
    else:
        return render_template("404.html")
    
@app.route('/admin/withdraw_coin', methods=["POST","GET"])
@login_required
def admin_withdrawcoin():
    if session['phone'] == '8406909448':
        if request.method == "GET":
            db = get_database()
            cursor = db.cursor()
            withdraws = cursor.execute("SELECT * FROM withdraw_coin").fetchall()
            db.close()
            return render_template('withdraw_coin.html',withdraws = withdraws)
        if request.method == "POST":
            db = get_database()
            cursor = db.cursor()
            id = request.form['id']
            button = request.form['button']
            cursor.execute("UPDATE withdraw_coin SET status = ? WHERE id = ?",(button,id,))
            db.commit()
            return redirect(url_for('admin_withdrawcoin'))
    else:
        return render_template("404.html")

@app.route('/admin/message')
@login_required
def admin_message():
    if session['phone'] == '8406909448':
        return render_template('message.html')
    else:
        return render_template("404.html")

@app.route('/admin/setting')
@login_required
def setting():
    if session['phone'] == '8406909448':
        return render_template('setting.html')
    else:
        return render_template("404.html")




if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=80)