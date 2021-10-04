from flask import Flask
from flask_wtf import recaptcha
from flask_wtf.csrf import CSRFProtect
from flask_wtf.recaptcha.validators import Recaptcha
import os 

app = Flask(__name__)
app.config["SECRET_KEY"] = "$2a$10$H2xkzFT8kZVSjjFJsl0uJOef.cKc7y0.WdLe0uo/wIenxkl0u28Fm"
csrf = CSRFProtect(app)
app.config['RECAPTCHA_USE_SSL'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('recaptcha_pub_key')
app.config['RECAPTCHA_PRIVATE_KEY']= os.environ.get('recaptcha_priv_key')
app.config['RECAPTCHA_OPTIONS'] = {'theme':'black'}
app.config['SESSION_COOKIE_SECURE'] = True #Prevent sending cookie over an unencrypted channel
# app.config['SESSION_COOKIE_HTTPONLY'] = True  //HTTPONLY is set to True by default
recaptcha = Recaptcha(app)