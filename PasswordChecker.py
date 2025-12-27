# Ryomen Kingsfall

import re
# Password strength criteria
MIN_LENGTH = 12

BAD_PASSWORDS = {
    "password", "123456", "123456789", "12345",
    "password1", "qwerty", "abc123", "letmein",
    "welcome", "admin", "login", "iloveyou",
    "trustno1", "dragon", "sunshine", "master", "hello",
    "freedom", "whatever", "qazwsx", "123123", "654321",
    "superman", "1q2w3e4r", "batman", "football", "monkey",
    "shadow", "baseball", "starwars", "1234", "passw0rd"
    
}

SPECIAL_CHARS = r'[!@#$%^&*(),.?":{}|<>]'

# Functions to check password strength
def password_issues(password: str) -> list[str]:
    """Return a list of issues found with the password."""
    issues = []

    if len(password) < MIN_LENGTH:
        issues.append("Password is too short.")
    if password.lower() in BAD_PASSWORDS:
        issues.append("Password is too common.")
    if not re.search(r'[A-Z]', password):
        issues.append("Missing an uppercase letter.")
    if not re.search(r'[a-z]', password):
        issues.append("Missing a lowercase letter.")
    if not re.search(r'\d', password):
        issues.append("Missing a digit.")
    if not re.search(SPECIAL_CHARS, password):
        issues.append("Missing a special character.")

    return issues

# Main functions
def is_strong_password(password: str) -> bool:
    return len(password_issues(password)) == 0

# Provide feedback on password strength
def password_feedback(password: str) -> str:
    issues = password_issues(password)
    if not issues:
        return "This password is strong."
    return issues[0]
# Example usage / calling the functions
if __name__ == "__main__":
    pw = input("Enter a password: ")
    print(password_feedback(pw))
    print("Strong?" , is_strong_password(pw))
    

