import time
import sys
import msvcrt

# sys and msvcrt are used only to make the command-line OTP timer interactive on Windows.
# They are not part of the cryptographic protocol.

# Import server-side logic and utilities
from auth import register_user, login, re_enroll_user, verify_password
from totp_utils import generate_totp
from users import users_db


# Calculate remaining seconds before the current OTP expires
def get_remaining_seconds():
    return 30 - (int(time.time()) % 30)


# ----------------------------
# Client-Side Simulation
# ----------------------------

# Simulate client-side OTP generation with live countdown and user input
def read_otp_with_live_timer(secret):
    entered_otp = ""

    while True:
        # Generate the current OTP using the shared secret and current time
        current_otp = generate_totp(secret)
        remaining = get_remaining_seconds()

        # Display OTP, countdown, and user input in the same line
        sys.stdout.write(
            f"\rCurrent OTP: {current_otp} | Expires in: {remaining:02d} seconds | Enter OTP: {entered_otp}      "
        )
        sys.stdout.flush()

        # Read keyboard input without stopping the countdown
        if msvcrt.kbhit():
            char = msvcrt.getwch()

            # Enter key ends the OTP input
            if char == "\r":
                print()
                return entered_otp

            # Backspace removes the last entered digit
            elif char == "\b":
                entered_otp = entered_otp[:-1]

            # Accept only digits and limit the OTP length to 6
            elif char.isdigit() and len(entered_otp) < 6:
                entered_otp += char

        # Small delay to keep the display smooth
        time.sleep(0.2)


# ----------------------------
# Server-Side Simulation
# ----------------------------

# Registration phase
def register_flow():
    print("\n--- Registration ---")

    username = input("Enter new username: ")
    password = input("Enter new password: ")

    # Register the user and generate a shared secret
    success, result = register_user(username, password)

    if success:
        print("\nRegistration successful.")
        print(f"Shared secret generated for {username}: {result}")
        print("In a real system, this would be provisioned through a QR code.")
    else:
        print(f"\nRegistration failed: {result}")


# Login phase
def login_flow():
    print("\n--- Login ---")

    username = input("Enter username: ")
    password = input("Enter password: ")

    user = users_db.get(username)

    if not user:
        print("\nUser not found. Please register first.")
        return

    # First factor: verify password before requesting OTP
    if not verify_password(username, password):
        success, message = login(username, password, "")
        print(f"\n{message}")
        print("Access denied.")
        return

    print("\nPassword verified successfully.")
    print("Server is now requesting OTP.")

    while True:
        user = users_db.get(username)

        # Stop if the account is temporarily locked
        if user["lock_until"] and time.time() < user["lock_until"]:
            print("\nAccount temporarily locked. Try again later.")
            return

        print("\n--- Client Side ---")
        print("Type the current OTP while the timer is running.")
        print("Press Enter when finished.\n")

        # decrypt the secret before passing to OTP generator
        from security import load_secret
        raw_secret = load_secret(user["shared_secret"])

        # Client side generates and displays the OTP
        entered_otp = read_otp_with_live_timer(raw_secret)

        print("\n--- Server Side ---")

        # Server side verifies the submitted OTP
        success, message = login(username, password, entered_otp)

        print(message)

        if success:
            print("Access granted. Session started.")
            return

        print("Access denied.")

        # Stop if repeated failures triggered temporary lock
        if user["lock_until"] and time.time() < user["lock_until"]:
            print("Account temporarily locked. Try again later.")
            return

        print("Try again using the current OTP.")


# Re-enrollment phase
def re_enrollment_flow():
    print("\n--- Re-enrollment ---")

    username = input("Enter username: ")
    password = input("Enter password: ")

    if username not in users_db:
        print("\nUser not found. Please register first.")
        return

    # Verify user identity before replacing the shared secret
    if not verify_password(username, password):
        print("\nIncorrect password.")
        print("Re-enrollment denied.")
        return

    # Generate a new shared secret and replace the old one
    success, result = re_enroll_user(username, password)  # password required

    if success:
        print("\nRe-enrollment successful.")
        print(f"New shared secret: {result}")
        print("Old shared secret has been replaced.")
    else:
        print(f"\nRe-enrollment failed: {result}")


# Display stored users during runtime for simulation/testing only
def show_runtime_users():
    print("\n--- Runtime User Store ---")
    print(users_db)


# Main simulation menu
def main():
    print("=== TOTP Client-Server Simulation ===")

    while True:
        print("\nChoose an option:")
        print("1. Register user")
        print("2. Login")
        print("3. Re-enroll user")
        print("4. Show stored users during runtime")
        print("5. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            register_flow()
        elif choice == "2":
            login_flow()
        elif choice == "3":
            re_enrollment_flow()
        elif choice == "4":
            show_runtime_users()
        elif choice == "5":
            print("Simulation ended.")
            break
        else:
            print("Invalid choice. Please try again.")


main()
