"""
Yapılandırma dosyası
"""

# GÜVENLİK ZAFİYETLERİ 15-20: Hardcoded secret'lar
DB_USERNAME = "root"
DB_PASSWORD = "123456"
API_SECRET = "sk_test_abcdefghijklmnopqrs"
JWT_SECRET = "jwtsecretkey123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GÜVENLİK ZAFİYETİ 21: Production'da DEBUG açık!
DEBUG = True

# Kullanılmayan ayarlar - kod kalitesi sorunu
EXTRA_SETTINGS = {
    "setting1": "value1",
    "setting2": "value2",
    "setting3": "value3"
}