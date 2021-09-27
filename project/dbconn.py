from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from config import app

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///mydb.db'
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True, nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.LargeBinary(256), nullable=False)
    mfa_enable = db.Column(db.Integer, nullable=False, server_default="0" )

    def __init__(self,username):
        self.username = username

    def get_id(self):
        return self.username

    def __repr__(self):
        return "%s" % (self.username)

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect('mydb.db')

    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()    

def insertUser(username, hashed_pass, email):
    conn = get_db()
    c = conn.cursor()
    r = c.execute("INSERT INTO USER(username,password,email) VALUES(?,?,?)",[username, hashed_pass, email])
    if r:
        conn.commit()
        return True
    else:
        return False

def fetchsecret(username):
    #DB Connection
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT password FROM User where username = (?)",[username])
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        return None

def user_exist(username):
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT username FROM User where username = (?)",[username])
    result = cursor.fetchone()
    if result:
        return True
    else:
        return False

def email_check(email, username):
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT username FROM User where email = (?)",[email])
    result = cursor.fetchone()
    if result and (result[0] == username):
        return True  
    else:
        return False

def get_username(email):
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT username FROM User where email = (?)",[email])
    result = cursor.fetchone()
    if result:
        return result[0]
        # return True  
    else:
        return None

def get_email(username):
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT email FROM User where username = (?)",[username])
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        return None

def email_exist(email):
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT email FROM User where email = (?)",[email])
    result = cursor.fetchone()
    if result:
        return True
    else:
        return False

def change_password(email,username,hashed_pass):
    conn = get_db()
    c = conn.cursor()
    result = c.execute("UPDATE USER SET password=? WHERE username=? AND email=?",[hashed_pass, username, email])
    # result = conn.commit()
    if result:
        conn.commit()
        return True
    else:
        return False

def get_mfa(username):
    conn = get_db()
    c = conn.cursor()
    cursor = c.execute("SELECT mfa_enable FROM User where username = (?)",[str(username)])
    result = cursor.fetchone()
    if result[0] == 1:
        return "Enabled"
    else:
        return "Disabled"

def toggle_mfa(username):
    mfa_status = get_mfa(username)
    if mfa_status == "Enabled":
        mfa_change = 0
    else:
        mfa_change = 1

    conn = get_db()
    c = conn.cursor()
    result = c.execute("UPDATE USER SET mfa_enable=? WHERE username=?",[mfa_change,str(username)])
    if result:
        conn.commit()
        return True
    else:
        return False
        