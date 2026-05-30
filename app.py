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


@app.route("/register", methods=["POST"]) 
def register():
    username = request.form.get("username")
    password = request.form.get("password")

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


@app.route("/login", methods=["POST"])
def login_password():
    username = request.form.get("username")
    password = request.form.get("password")

    if username not in users_db:
        return render_template(
            "index.html",
            error="Invalid username or password"
        )

    if not verify_password(username, password):
        return render_template(
            "index.html",
            error="Invalid username or password"
        )

    # Store login data temporarily until OTP verification is completed
    session["username"] = username
    session["password"] = password

    return redirect(url_for("otp_verify_page"))


@app.route("/otp-verify", methods=["GET"])
def otp_verify_page():
    username = session.get("username")

    # Prevent direct access to OTP verification without password validation
    if not username or username not in users_db:
        return redirect(url_for("index"))

    return render_template(
        "otp_verify.html",
        username=username
    )


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    username = session.get("username")
    password = session.get("password")
    otp = request.form.get("otp")

    # Reject OTP verification if no login session exists
    if not username or username not in users_db:
        return redirect(url_for("index"))

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

# Simulated authenticator page for generating TOTP codes
@app.route("/authenticator/<username>", methods=["GET"])
def authenticator_page(username):
    if username not in users_db:
        return redirect(url_for("index"))

     
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

# Verify user identity before generating a new shared secret
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

        if not verify_password(username, password):
            return render_template(
                "re_enroll.html",
                error="Invalid username or password"
            )

        # Generate a new shared secret after confirming the user's password
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