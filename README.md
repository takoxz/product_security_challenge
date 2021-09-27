# The Zendesk Product Security Challenge

## Getting Started
### Windows
#### Running project as executable 
1. Open up command prompt and navigate to the executable location
```
cd project\dist\app
```
2. Execute app.exe
```
app.exe
```
#### Running project as source code (optional)
1. Clone this repository. <br>
```
git clone --bare https://github.com/takoxz/product_security_challenge
```

2. Initialize python virtual environment.<br>

```
python -m venv app
app\Scripts\activate.bat
pip install -r project\requirements.txt
```

3. Run Flask Server in HTTPS mode
```
cd project
python -m flask run --cert=certificates\server.crt --key=certificates\server.key
```
4. Server will be started on https:/127.0.0.1:5000
 
## Features Implemented 
1. Account Registration
2. Account Login\Logout 
    - Allow user to enable MFA for login 
4. Self-service Password Reset 
    - OTP sent via email for password reset 

## Mechanisms Implemented
- Server-side Validation
  - Fields Validation (WTForms)
  - Username allow only alphanumeric and underscores (Regex)
  - Password Complexity Check (Regex)
    - minimum of 8 characters
    - at least 1 uppercase letter
    - at least 1 lowercase letter
    - at least 1 digit
    - at least 1 special character   
- Session Management
  - Flask-Login Library 
- MultiFactor-Authentication
  - OTP Generation (PyOTP Library)
  - URL Signing/Expiration (ItsDangerous)
- Password Hash 
  - Flask-Bcrypt  
- TLS/SSL Connection
  - Self-signed certificate
```  
  openssl genrsa -aes256 -out server.key 1024  
  openssl req -new -key server.key -out server.csr
  openssl x509 -req -days 365 -in server.csr -signkey server.key -pit server.crt
```
- CSRF Protection
  - CSRFProtect module from Flask-WTF
- reCAPTCHA in Registration Form 
  - Google reCAPTCHA  & Flask-WTF
- Parameterised SQL queries


## Possible Improvements
- Known Password Check/Prevent use of weak password 
  - Advice users on getting strong password to guard against Bruteforce attack
- <s>Account Lockout</s>
  - <s>Guard against Bruteforce attack</s>
- Logging/Login audit log
  -  Check for unauthorised access or suspicious login attempts



