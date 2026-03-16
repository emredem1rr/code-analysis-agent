"""
Kimlik doğrulama modülü
"""
import hashlib
import os
from datetime import datetime

# GÜVENLİK ZAFİYETİ 5: Hardcoded admin şifresi
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
JWT_SECRET = "jwtsecretkey123"

def login(kullanici_adi, sifre):
    """Kullanıcı girişi"""
    # GÜVENLİK ZAFİYETİ 6: Zayıf şifre kontrolü
    if kullanici_adi == "admin" and sifre == "123456":
        return {"token": "fake_jwt_token"}
    
    # GÜVENLİK ZAFİYETİ 7: SQL Injection
    sorgu = f"SELECT * FROM users WHERE username = '{kullanici_adi}'"
    
    return None

def register(kullanici_adi, sifre, email):
    """Kullanıcı kaydı"""
    # GÜVENLİK ZAFİYETİ 8: MD5 kullanımı (zayıf)
    sifre_hash = hashlib.md5(sifre.encode()).hexdigest()
    
    # GÜVENLİK ZAFİYETİ 9: SQL Injection
    sorgu = f"INSERT INTO users (username, password, email) VALUES ('{kullanici_adi}', '{sifre_hash}', '{email}')"
    
    return True

def reset_password(email):
    """Şifre sıfırlama"""
    # GÜVENLİK ZAFİYETİ 10: Command injection
    os.system(f"sendmail {email} < reset_email.txt")
    
    return True

# Kullanılmayan fonksiyon - kod kalitesi sorunu
def generate_token(kullanici_id):
    return hashlib.md5(f"{kullanici_id}{datetime.now()}".encode()).hexdigest()

# İç içe fonksiyon - kod kalitesi sorunu
def validate_password(sifre):
    def check_length(s):
        return len(s) >= 8
    def check_uppercase(s):
        return any(c.isupper() for c in s)
    
    return check_length(sifre) and check_uppercase(sifre)