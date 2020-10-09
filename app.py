import datetime
import re
import smtplib

from flask import Flask, redirect, render_template, request, flash, url_for, escape
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, or_, and_, exists as exist
from flask import session as login_session
import string, random
from hashlib import sha256

from flask_socketio import SocketIO, emit
from flask_wtf import CSRFProtect
#from flask_csp.csp import csp_header

from database_setup import Base, Users, Chat, Messages, Reset

app = Flask(__name__)
app.secret_key = "qyAxbizRZdk_q2mEIrTtGx87"
WTF_CSRF_SECRET_KEY = "sd54asfdSA5DA5SF8WEFS3F5Aiopjj98h5"
csrf = CSRFProtect(app)
socketio = SocketIO(app)

app.config.update(
#SESSION_COOKIE_SECURE=True,
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SAMESITE='Lax',
)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy']='default-src \'self\''
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

engine = create_engine('mysql+mysqldb://akm:password@localhost/msgs')
Base.metadata.bind = engine
#Base.metadata.drop_all()
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
session = DBSession()



@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if request.form['user_name']:
            if check_user(escape(request.form["user_name"])):
                user_name = request.form["user_name"]
        if request.form['pass']:
            password = sha256(str(request.form['pass']).encode('utf-8')).hexdigest()
            print(password)
        try:
            user_data = session.query(Users.username, Users.password, Users.email, Users.active).filter_by(username=user_name,
                                                                                              password=password).one()
            # print(user_check)
        except Exception as e:
            print(e)
            print('No Data')
            flash('Incorrect Credentials')
            return redirect('/login')
        if user_data.username and (user_data.active == 'Y'):
            login_session['username'] = user_name
            login_session['email'] = user_data.email
            return redirect('/home')
        if user_data.username and (user_data.active == 'N'):
            flash("Please activate your account via the link sent to your mail")
            print('Inactive account!')
            return redirect('/login')
        else:
            print('Incorrect Credentials!')
            return redirect('/login')

    if request.method == 'GET':
        if 'username' in login_session:
            return redirect(url_for('home'))
        #state = ''.join(
            #random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(32))
        #login_session['state'] = state
        return render_template('login.html', login_session=login_session)


@app.route('/')
@app.route('/home', methods=['POST', 'GET'])
def home():
    if request.method == 'GET':
        if 'username' not in login_session:
            return redirect('/login')
        else:
            print("Login user name: " + str(login_session['username']))
            logged_user = session.query(Users).filter_by(username=login_session['username']).one()
            print(logged_user.id)
            # chats = session.query(Chat).filter_by(from_id=logged_user['id'])
            # print(chats)
            # messages = session.query(Messages).filter_by(chat_id=chats['id']).all()
            # print(messages)
            return render_template('home.html', login_session=login_session)

    if request.method == 'POST':
        return render_template('home.html', login_session=login_session)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if request.form['user'] and request.form['email']:
            print("username before check: "+ request.form['user'])
            if check_user(escape(request.form["user"])):
                user_name = request.form["user"]
            print("username after check: " + user_name)

            user_email = escape(request.form['email'])
            mail_exist = session.query(Users.email).filter_by(email=user_email).scalar() is not None
            print('Email: '+ user_email)
        if request.form['password1'] == request.form['password2']:

            if check_pass(request.form['password1']):
                password = sha256(str(request.form['password1']).encode('utf-8')).hexdigest()
                print(password)
                try:
                    if mail_exist:
                        print('mail alraedy exist, try to login')
                        return redirect(url_for('login'))
                    else:
                        new_user = Users(username=user_name, email=user_email, password=password, fname=request.form['fname'], lname=request.form['lname'])
                        session.add(new_user)
                        session.commit()
                        print('user added!!!!!!')

                        user_link = session.query(Users).filter_by(email=user_email).one()
                        print(user_link.email)
                    try:
                        sendmail(user_link.email,user_link.act_link, purpose='activate')
                    except:
                        print('failed to send mail!!!')
                    return redirect(url_for('login'))
                except:
                    flash('Check all required fields')
                    return redirect(url_for('register'))
            else:
                flash('Password not complex')
                return redirect(url_for('register'))
        else:
            flash('Passwords didn\'t match!!')
            return redirect(url_for('register'))



    return render_template('register.html')

@app.route('/checkpoint/<string:id>')
def checkpoint(id):
    user = session.query(Users).filter_by(act_link=str(id)).one()
    print(user.act_link)
    if user.act_link == id:
        session.query(Users).filter_by(act_link=id).update({'active': 'Y', 'act_link': ''})
        session.commit()
        print('Account activated')
        return redirect(url_for('login'))
    else:
        flash("Inavlid activation Link!")
        return redirect(url_for('login'))

@app.route('/change_password', methods=['POST', 'GET'])
def chgpass():
    if login_session['username']:
        if request.method == 'POST':
            if request.form['oldpass']:
                if (request.form['pass1'] == request.form['pass2']):
                    if check_pass(request.form['pass1']):
                        user = session.query(Users).filter_by(username=login_session['username']).one()
                        if sha256(str(request.form['oldpass']).encode('utf-8')).hexdigest() == user.password:
                            session.query(Users).filter_by(username=login_session['username']).update({'password': sha256(str(request.form['pass1']).encode('utf-8')).hexdigest()})
                            session.commit()
                            flash('Password Changed Successfully')
                            print('Password Changed Successfully')
                            return redirect(url_for('chgpass'))
                        else:
                            flash('Current password is not correct')
                            return redirect(url_for('chgpass'))
                    else:
                        flash('Please use secure complex password')
                        return redirect(url_for('chgpass'))
                else:
                    flash('unmatched new password, please retype it correctly')
                    return redirect(url_for('chgpass'))
            else:
                flash('you must enter current password')
                return redirect(url_for('chgpass'))

        if request.method == 'GET':
            return render_template('change_pass.html')



@app.route('/send', methods=['POST', 'GET'])
def send():
    if request.method == 'POST':

        if 'username' not in login_session:
            return redirect('/login')
        if request.form['receiver']:
            receiver_name = escape(request.form['receiver'])
        else:
            return render_template('send.html')
        if request.form['msg']:
            msg = escape(request.form['msg'])
        else:
            return render_template('send.html')
        from_user = session.query(Users).filter_by(username=login_session['username']).one()
        print(from_user.id)
        try:
            to_user = session.query(Users).filter_by(username=receiver_name).one()
            print(to_user.id)
        except Exception as e:
            print(e)
            return render_template('send.html')
        try:
            exist1 = session.query(Chat.from_id, Chat.to_id).filter_by(from_id=from_user.id,
                                                                       to_id=to_user.id).scalar() is not None
            exist2 = session.query(Chat.from_id, Chat.to_id).filter_by(from_id=to_user.id,
                                                                       to_id=from_user.id).scalar() is not None

            print(exist1, exist2)
            if (exist1 == False) and (exist2 == False):
                new_chat = Chat(from_id=from_user.id, to_id=to_user.id)
                session.add(new_chat)
                session.commit()
                print("New chat created.")


        except Exception as e:
            print('Error here!!')
            return print(e)
            # redirect('/send')
        print('before new msg')
        chat_info = session.query(Chat).filter(or_(Chat.from_id == from_user.id, Chat.to_id == from_user.id)).one()
        # chat_info = session.query(Chat.id).filter_by(from_id=from_user.id, to_id=to_user.id).one()
        new_msg = Messages(chat_id=chat_info.id, sender_id=from_user.id, msg_body=msg)
        session.add(new_msg)
        session.commit()
        print('New messages added!')
        return redirect(url_for('chat_user', id=chat_info.id))

    if request.method == 'GET':
        if 'username' not in login_session:
            return redirect('/login')
        return render_template('send.html')
    return render_template('send.html')


@app.route('/read', methods=['POST', 'GET'])
def read():
    if request.method == "GET":
        if login_session['username']:
            user_id = session.query(Users.id).filter_by(username=login_session['username']).one()

            exist = session.query(Chat).filter(or_(Chat.from_id == user_id, Chat.to_id == user_id)).scalar() is not None

            if exist == False:
                print("You don't have chats yet")
                return redirect('/home')
            chats = session.query(Chat).filter(or_(Chat.from_id == user_id, Chat.to_id == user_id)).all()

            results = [r.__dict__ for r in chats]
            print(len(results))
            my_chats = {}
            for x in range(0, len(results)):
                print('CHAT_ID: ' + str(results[x]['id']) + '\n')
                my_chats_id = results[x]['id']
                if results[x]['from_id'] == user_id.id:
                    chat_user = session.query(Users.username).filter_by(id=results[x]['to_id']).one()
                    my_chats[my_chats_id] = chat_user.username
                elif results[x]['to_id'] == user_id.id:
                    chat_user = session.query(Users.username).filter_by(id=results[x]['from_id']).one()
                    my_chats[my_chats_id] = chat_user.username
                #print(chat_user)
                print(my_chats)




            return render_template('msgs.html', login_session=login_session, chats=my_chats)
    return "Returned!!"

@app.route('/read/<int:id>', methods=['GET', 'POST'])
def chat_user(id):
    if login_session['username']:
        if request.method == 'POST':
            if request.form['msg']:
                msg = escape(request.form['msg'])
                sender = session.query(Users.id).filter_by(username=login_session['username']).one()
                sender_id = sender.id
                new_msg = Messages(chat_id=id, sender_id=sender_id, msg_body=msg)
                session.add(new_msg)
                session.commit()
        chat_msgs = session.query(Messages).filter_by(chat_id=id).order_by(Messages.create_time).all()
        results = [r.__dict__ for r in chat_msgs]
        msgs = []
        for x in range(0, len(results)):
            sender_id = results[x]['sender_id']
            print(sender_id)
            sender = session.query(Users.username).filter_by(id=sender_id).one()
            msgs.append([sender.username, results[x]['msg_body']])
        #print(msgs[0][0])
        return render_template('msgs.html', login_session=login_session, msgs=msgs, chat_id=id)





@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if login_session['username']:

        #del login_session['email']
        del login_session['username']
        del login_session['email']
        login_session.clear()
        return redirect('home')
    else:
        print('can not del session data')
        return redirect('home')


@app.route('/forget', methods=['GET', 'POST'])
def forget():
    if request.method == 'GET':
        return render_template('forget.html')
    if request.method == 'POST':
        if request.form['mail']:
            email = request.form['mail']
            mail_exist = session.query(Users.email).filter_by(email=email).scalar() is not None
            if mail_exist:
                user_id = session.query(Users.id).filter_by(email=email).one()
                reset_random = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(64))

                old_reset = session.query(Reset).filter_by(user_id=user_id).scalar() is not None
                if old_reset:
                    session.query(Reset).filter_by(user_id=user_id).update({'hash_link': reset_random})
                    session.commit()
                else:
                    reset_row = Reset(user_id=user_id, hash_link=reset_random)
                    session.add(reset_row)
                    session.commit()
                sendmail(email,reset_random, purpose='reset')
                return render_template('forget.html', sent=True)
            else:
                return render_template('forget.html', sent=False)
                print('Sorry, This mail not registered yet!')



        #return render_template('forget.html', sent=True)

@app.route('/reset/<string:id>', methods=['GET', 'POST'])
def reset(id):

    link_exist = session.query(Reset).filter_by(hash_link=id).scalar() is not None
    if link_exist:
        reset_data = session.query(Reset).filter_by(hash_link=id).one()
        print(reset_data.link_time)
        print(datetime.datetime.now())
        print(datetime.timedelta(minutes=30))
        if reset_data.link_time > datetime.datetime.now() - datetime.timedelta(minutes=30):
            if request.method == 'GET':
                return render_template('reset.html')
            if request.method == 'POST':
                if request.form['password1'] == request.form['password2']:
                    if check_pass(request.form['password1']):
                        session.query(Users).filter_by(id=reset_data.user_id).update({'password': sha256(request.form['password1'])})
                        session.commit()
                        return redirect(url_for('login'))
                    else:
                        print('Weak Password')
                        return redirect(url_for('reset', id=id))
        else:
            return render_template('forget.html', expired=True)
    else:
        return render_template('forget.html', exist=False)


        


@app.route('/dbdump')
def dump():
    filename = "db_" + str(datetime.datetime)
    print(filename)
    import csv
    outfile = open(filename+'.csv', 'wb')
    outcsv = csv.writer(outfile)
    records = session.query(session).all()
    [outcsv.writerow([getattr(curr, column.name) for column in session.__mapper__.columns]) for curr in records]
    #outcsv.writerows(records)
    # or maybe use outcsv.writerows(records)

    outfile.close()
    return outfile

def check_pass(password):
    strength = 0
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if len(password) >= 8:

        print(password)
        if any(char.islower() for char in password):
            strength +=1
            print(strength)
        if any(char.isupper() for char in password):
            strength +=1
            print(strength)
        if any(char.isdigit() for char in password):
            strength +=1
            print(strength)
        if regex.search(password):
            strength += 1
            print(strength)
    print(strength)
    if strength >= 3 :
        return True
    else:
        return False

def check_user(user):
    if re.match("^[A-Za-z]+.*", user) and (len(user) >= 4):
        regex = re.compile('[@!#$%^&*()<>?/\|}{~:]')
        if (regex.search(user) == None):
            return True
        else:
            flash('username can not contain special characters !')
            return False
    else:
        flash("Username have certain characters that is not allowed !")
        return False

def sendmail(name, hash, purpose):

    gmail_user = 'akm.smart.power@gmail.com'
    gmail_password = 'FAKMis@sky01'

    sent_from = gmail_user
    #to = name
    to = 'akm.01@hotmail.com'

    if purpose == 'reset':
        subject = 'SecureChat Password Reset Instructions'
        body = 'Hello,\nTo reset your SecureChat account password use the following link:\n\n' \
               'http://localhost:5000/reset/'+hash+'\n\n' \
                'If you did not request a reset, kindly ignore that mail.\n' \
                'Notice: The link is only valid for 30 minute.\nThanks'

    if purpose == 'activate':
        subject = 'SecureChat Activation Instructions'
        body = 'Hello,\nTo activate your SecureChat account please use the following link:\n\n' \
               'http://localhost:5000/checkpoint/' + hash + '\n\n' \
                                                       '\nThanks'

    email_text =  'Subject: {}\n\n{}'.format(subject, body)

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_password)
        server.sendmail(sent_from, to, email_text)
        server.close()

        print('Email sent!')
    except:
        print('Something went wrong...')
    #return "test mail"

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
