"""
Ana uygulama dosyası
"""
import os
import json
import pickle
import hashlib
from database import baglan, sorgu_calistir
from helpers import log_yaz, dosya_oku

# GÜVENLİK ZAFİYETİ 1: Hardcoded API key
API_KEY = "sk_live_1234567890abcdef"
SECRET_KEY = "supersecretkey123"
DEBUG = True

def kullanici_girisi(kullanici_adi, sifre):
    """Kullanıcı girişi yapar"""
    # GÜVENLİK ZAFİYETİ 2: SQL Injection
    sorgu = f"SELECT * FROM kullanicilar WHERE kullanici_adi = '{kullanici_adi}' AND sifre = '{sifre}'"
    sonuc = sorgu_calistir(sorgu)
    return sonuc

def veri_yukle(dosya_adi):
    """Dosyadan veri yükler"""
    # GÜVENLİK ZAFİYETİ 3: Pickle RCE
    with open(dosya_adi, 'rb') as f:
        return pickle.load(f)

def hesapla(sayi):
    """Çok uzun fonksiyon - kod kalitesi sorunu"""
    sonuc = 0
    for i in range(100):
        for j in range(100):
            for k in range(100):
                sonuc += (i * j * k) / (i + j + k + 1)
                sonuc -= (i - j) * (k + 1)
                if sonuc > 1000:
                    sonuc = 1000
                elif sonuc < -1000:
                    sonuc = -1000
    return sonuc

def calistir():
    """Ana çalıştırma fonksiyonu"""
    # GÜVENLİK ZAFİYETİ 4: eval() kullanımı
    komut = input("Komut girin: ")
    eval(komut)

# Kullanılmayan değişkenler - kod kalitesi sorunu
x = 42
y = 100
z = x + y

if __name__ == "__main__":
    print("Uygulama başlatıldı")
    calistir()