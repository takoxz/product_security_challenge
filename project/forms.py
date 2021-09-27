from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.recaptcha import validators
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import EqualTo, InputRequired, Regexp, Length, ValidationError
from wtforms.fields.html5 import EmailField
import re 

def password_complexity_check(form, field):
    password = field.data
    pattern = "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})"
    pass_check = re.findall(pattern, password)
    if not pass_check:
        raise ValidationError("Password must contain at least 1 uppercase letter, at least 1 lowercase letter, at least 1 digit, and at least 1 special character. With a minimum of 8 characters.")   
    
def username_check(form, field):
    username = field.data
    pattern = "[a-zA-Z0-9_]{6,}"
    username_check = re.match(pattern, username)
    if not username_check:
        raise ValidationError("Username can only contain letters, numbers and underscore. With a minimum of 6 characters.") 

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired()], render_kw={"placeholder": "Password"})
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    email = EmailField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), username_check], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), password_complexity_check], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo('password', message="Password must match.")], render_kw={"placeholder": "Confirm Password"})
    recaptcha = RecaptchaField()
    submit = SubmitField('Sign Up')

class RequestResetForm(FlaskForm):
    email = EmailField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
    # username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    submit = SubmitField('Reset Password')

class PasswordChangeForm(FlaskForm):
    otp = StringField(validators=[InputRequired()], render_kw={"placeholder": "OTP"})
    password = PasswordField(validators=[InputRequired(), password_complexity_check], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo('password', message="Password must match.")], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Confirm')

class MFAForm(FlaskForm):
    otp = StringField(validators=[InputRequired()], render_kw={"placeholder": "OTP"})
    submit = SubmitField('Submit')
