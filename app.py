from flask import Flask, render_template, request, redirect, url_for, session

from auth import (
    register_user,
    verify_password,
    login,
    re_enroll_user
)

from users import users_db
from security import load_secret


app = Flask(__name__)
app.secret_key = "totp-demo-secret-key"


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/register-page", methods=["GET"])
def register_page():
    return render_template("register.html")


# Registration phase
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    # Register the user and generate a unique shared secret
    success, result = register_user(username, password)

    if success:
        return render_template(
            "register.html",
            success="Account created successfully."
        )

    return render_template(
        "register.html",
        error=result
    )


# Login phase - first factor: password
@app.route("/login", methods=["POST"])
def login_password():
    username = request.form.get("username")
    password = request.form.get("password")

    if username not in users_db:
        return render_template(
            "index.html",
            error="Invalid username or password"
        )

    # Check the password before requesting OTP
    if not verify_password(username, password):
        # Use login() so wrong password attempts are counted for lockout
        success, message = login(username, password, "")

        return render_template(
            "index.html",
            error=message
        )

    # Store login data temporarily until OTP verification is completed
    session["username"] = username
    session["password"] = password

    return redirect(url_for("otp_verify_page"))


# OTP verification page
@app.route("/otp-verify", methods=["GET"])
def otp_verify_page():
    username = session.get("username")
    password = session.get("password")

    # Prevent direct access to OTP verification without password validation
    if not username or username not in users_db or not password:
        return redirect(url_for("index"))

    return render_template(
        "otp_verify.html",
        username=username
    )


# Login phase - second factor: OTP
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    username = session.get("username")
    password = session.get("password")
    otp = request.form.get("otp")

    # Reject OTP verification if no login session exists
    if not username or username not in users_db or not password:
        return redirect(url_for("index"))

    # Enforce 6-digit OTP on the server side
    if not otp or not otp.isdigit() or len(otp) != 6:
        success, message = login(username, password, otp or "")

        return render_template(
            "otp_verify.html",
            username=username,
            success=success,
            message=message
        )

    # Server side verifies password and OTP using the same auth logic
    success, message = login(username, password, otp)

    if success:
        # Mark the user as fully authenticated after OTP verification
        session.pop("password", None)
        session["logged_in"] = username

        return redirect(url_for("dashboard"))

    return render_template(
        "otp_verify.html",
        username=username,
        success=success,
        message=message
    )


# Simulated client-side authenticator for generating TOTP codes
@app.route("/authenticator/<username>", methods=["GET"])
def authenticator_page(username):
    session_username = session.get("username")
    password = session.get("password")

    # Protect the authenticator page from direct URL access
    if (
        not session_username
        or session_username != username
        or username not in users_db
        or not password
    ):
        return redirect(url_for("index"))

    # Decrypt the shared secret only for the simulated authenticator page
    secret = load_secret(users_db[username]["shared_secret"])

    return render_template(
        "authenticator.html",
        username=username,
        secret=secret
    )


@app.route("/dashboard", methods=["GET"])
def dashboard():
    username = session.get("logged_in")

    # Protect the dashboard from users who have not completed OTP verification
    if not username or username not in users_db:
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        username=username
    )


# Re-enrollment phase
@app.route("/re-enroll", methods=["GET", "POST"])
def re_enroll():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username not in users_db:
            return render_template(
                "re_enroll.html",
                error="Invalid username or password"
            )

        # Verify user identity before replacing the shared secret
        if not verify_password(username, password):
            return render_template(
                "re_enroll.html",
                error="Invalid username or password"
            )

        # Generate a new shared secret and replace the old one
        success, result = re_enroll_user(username, password)

        if success:
            return render_template(
                "re_enroll.html",
                success="Re-enrollment completed successfully.",
                username=username,
                new_secret=result
            )

        return render_template(
            "re_enroll.html",
            error=result
        )

    return render_template("re_enroll.html")


@app.route("/logout")
def logout():
    # Clear all session values during logout
    session.clear()

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
