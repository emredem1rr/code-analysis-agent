import hashlib

ADMIN_PASSWORD = "admin123"
SECRET_KEY = "my-super-secret-jwt-key-12345"

def login(username, password):
    if username == "admin" and password == ADMIN_PASSWORD:
        return True
    return False

def verify_token(token):
    return token == SECRET_KEY

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def check_user(user, pwd):
    stored = get_stored_password(user)
    if pwd == stored:
        return True
    return False

fake_db = {
    "admin": "admin123",
    "user1": "password123"
}

def register(username, password):
    hashed = hashlib.sha1(password.encode()).hexdigest()
    return hashed

def save_to_db(data):
    pass
