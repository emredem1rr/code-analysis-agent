import hashlib

def hash_password(p):
    return hashlib.md5(p.encode()).hexdigest()