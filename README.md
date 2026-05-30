 TOTP Authentication System
SEC3104 Advanced Cryptography — Team 19
A two-factor authentication system using Time-Based One-Time Passwords (TOTP). 
Employees log in with a password and a 6-digit code that changes every 30 seconds.

Requirements
Python 3.10 or higher
Install dependencies:
pip install -r requirements.txt

How to Run
Web application: 
python app.py
Then open your browser at: http://127.0.0.1:5000
Attack simulation:
python attack_simulation.py
    Note: main.py is a Windows-only CLI simulator and requires the msvcrt module.


Project Files
app.py                Flask web application
auth.py               Registration, login, and re-enrollment logic
totp_utils.py         OTP generation and verification (RFC 6238)
security.py           Password hashing (PBKDF2) and secret encryption (AES-256)
users.py              In-memory user store
attack_simulation.py  Automated attack scenarios
main.py               Windows CLI simulator


Features
6-digit OTP that changes every 30 seconds
Unique encrypted secret per user
Server verifies codes without storing them
Replay attack prevention
Account lockout after 3 failed attempts
Re-enrollment when a device is lost

