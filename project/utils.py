from flask_bcrypt import Bcrypt
from itsdangerous.serializer import Serializer
import pyotp 
from flask import Flask
from pyotp import totp
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
from config import app
import base64 
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

bcrypt = Bcrypt()

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def validate_password(hash, password):
    return bcrypt.check_password_hash(hash, password)

def send_email(username, email, type):
    otp = generate_otp(username, email)
    if type=="reset":
        subjmessage = "Walnut Co. - Password Recovery"
        messagetype= "<br>We have received request to reset your account password."
    
    elif type=="otp":
        subjmessage="Walnut Co. - Verify Login"
        messagetype="<br>Below is your OTP:"

    message = Mail(
    from_email=(os.environ.get('dummy_mail')),
        to_emails=email,
        subject=subjmessage,
        html_content=("Hi <strong>"+username+"</strong>."
        +messagetype+
        "<br><strong>"+otp+"</strong><br>"
        "Enter code to complete action."))

    sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
    response = sg.send(message)
    return True

def encodeSecret(username, email):
    return base64.b32encode(bytearray(username+app.config["SECRET_KEY"]+email, 'ascii')).decode('utf-8')

def generate_otp(username,email):
    encodedSecret = encodeSecret(username,email)
    totp = pyotp.TOTP(encodedSecret, interval=180)
    return totp.now()

def generate_token(username, email):
    s = Serializer(app.config["SECRET_KEY"], expires_in=900)
    token = s.dumps({'username':username, 'email':email})
    return token

def verify_otp(otp, username, email):
    encodedSecret = encodeSecret(username,email)
    totp = pyotp.TOTP(encodedSecret, interval=180)
    return totp.verify(otp)


def decode_token(token):
    s = Serializer(app.config["SECRET_KEY"])
    decodedToken = s.loads(token)
    return decodedToken

