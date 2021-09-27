# # Route for handling the login page logic
from logging import error
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask.json import load
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm, MFAForm, RegistrationForm, RequestResetForm, PasswordChangeForm
from utils import decode_token, generate_token,  hash_password, validate_password, send_email, verify_otp
from werkzeug.utils import escape
from dbconn import change_password, insertUser, fetchsecret, user_exist, email_exist, User, get_mfa, get_username, toggle_mfa, get_email
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from config import app
from datetime import timedelta
  

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'
login_manager.login_message_category = "error"
login_manager.needs_refresh_message = ("Session timeout, please re-login")
login_manager.needs_refresh_message_category = "info"


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True


@login_manager.user_loader
def load_user(username):
    return User(username=username)

@app.route('/login_mfa', methods=["GET", "POST"])
def login_mfa():
    token = request.args.get("token")
    decodedToken = decode_token(token)
    username = decodedToken['username']
    email = decodedToken['email']

    form = MFAForm(request.form)    
    if request.method == "POST":
        if form.validate_on_submit():
            otp = form.otp.data
            result = verify_otp(otp, username, email)
            if result:
                user = User(username)
                login_user(user)
                return redirect(url_for('home'),code=307)

    return render_template('mfa.html', form=form)


@app.route('/', methods=["GET", "POST"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm(request.form)
    if request.method == "POST":
        if form.validate_on_submit():
            fetched_pass  = fetchsecret(form.username.data)
            if fetched_pass:
                validation = validate_password(fetched_pass, form.password.data)
                if validation:
                    mfa_status = get_mfa(form.username.data)
                    if mfa_status == "Enabled":
                        email = get_email(form.username.data)
                        sent = send_email(form.username.data, email, 'otp')
                        if sent:
                            flash("An OTP message has been sent to your email account.")
                            token = generate_token(form.username.data, email)
                            
                        return redirect(url_for('login_mfa', token=token))
                    else:
                        user = User(form.username.data)
                        login_user(user, remember=form.remember_me.data)
                        return redirect(url_for('home'),code=307)
                # else:
            flash("Invalid Credentials", "error")

    return render_template('index.html', form=form)

@app.route('/register', methods=["GET","POST"])
def register():
    form = RegistrationForm(request.form)
    if request.method == "POST":
        if form.validate_on_submit():
            username = form.username.data
            
            if email_exist(form.email.data):
                flash("Email address already in use.", "error")

            elif user_exist(form.username.data):
                flash("Username has been taken.", "error")

            elif form.password.data == form.confirm_password.data:
                hashed_pass = hash_password(form.password.data)

                result = insertUser(escape(username), hashed_pass, form.email.data)
                if result:
                    flash("Thank you for registering")
                else:
                    flash("Encounter error with registration.\nPlease contact Administrator.", "error")


    return render_template('registration.html',form=form)


@app.route('/home', methods=["GET","POST"])
@login_required
def home():
    mfa_status = get_mfa(current_user)
    if mfa_status == "Enabled":
        mfa_button = "Disable MFA"
    else:
        mfa_button = "Enable MFA"

    return render_template('home.html', mfa_status=mfa_status, mfa_button=mfa_button)

@app.route('/change_mfa', methods=["POST"])
@login_required
def change_mfa():
    username = current_user
    toggle_mfa(username)
    return redirect(url_for('home'))


@app.route('/logout', methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    flash("Successfully logged out")
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=["GET","POST"])
def forgot_password():
    form = RequestResetForm(request.form)
    if form.validate_on_submit():

        email = form.email.data
        username = get_username(email)
        if username is not None:
            sent = send_email(username, email, 'reset')
            if sent:
                flash("A password reset message has been sent to your email account")
                token = generate_token(username, email)
                return redirect(url_for('reset_password', token=token))
        else:
            flash("We couldn't find an account associated with "+email,"error")
    
    return render_template('forgot_password.html',form=form)

@app.route('/reset_password', methods=["GET","POST"])
def reset_password():
    token =  request.args.get("token")
    decodedToken = decode_token(token)
    username = decodedToken['username']
    email = decodedToken['email']

    form = PasswordChangeForm()
    if request.method == "POST":
        if form.validate_on_submit():
            otp = form.otp.data
            result = verify_otp(otp, username, email)

            if result:
                print("Verified")
                if form.password.data == form.confirm_password.data:
                    hashed_pass = hash_password(form.password.data)
                    result = change_password(email, username, hashed_pass)
                    if result:
                        flash("Password has successfully been changed.")
                    else:
                        flash("Error performing password change.\nPlease contact administrator.","error")
                return redirect(url_for('index'))
            else:
                print("Failed")
                flash("Invalid OTP","error")
        
    return render_template('reset_password.html',form=form)

@app.route('/resend_otp', methods=["POST"])
def resend_otp():
    referrer_param = request.referrer.split("?",1)[0]
    token_param = request.referrer.split("?",1)[1]
    token = token_param.split("=",1)[1]
    decodedToken = decode_token(token)
    username = decodedToken['username']
    email = decodedToken['email']
    
    if "login_mfa" in referrer_param:
        sent = send_email(username, email, 'otp')
    else:    
        sent = send_email(username, email, 'reset')
    
    if sent:
        return "True"
    else:
        return "False"
    
if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=True, ssl_context=("certificates\server.crt","certificates\server.key"))

