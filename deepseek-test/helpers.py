"""
Yardımcı fonksiyonlar
"""
import os
from datetime import datetime

# GÜVENLİK ZAFİYETİ 14: Hardcoded admin password
ADMIN_PASSWORD = "admin123"

def log_yaz(mesaj):
    """Log yaz - KAYNAK SIZINTISI!"""
    # HATA: Dosya kapatılmamış!
    f = open("uygulama.log", "a")
    f.write(f"[{datetime.now()}] {mesaj}\n")
    # f.close() unutulmuş!
    return True

def dosya_oku(dosya_adi):
    """Dosya oku - HATA YÖNETİMİ YOK!"""
    # HATA: Try-except yok!
    with open(dosya_adi, 'r') as f:
        icerik = f.read()
    return icerik

def dosya_sil(dosya_adi):
    """Dosya sil - HATA YÖNETİMİ YOK!"""
    os.remove(dosya_adi)
    print("Dosya silindi")  # Bu satıra hiç ulaşılamaz (dead code)
    return True

def ayarlari_yukle():
    """Ayarları yükle - İÇ İÇE FONKSİYONLAR"""
    def parse_json(veri):
        def temizle(metin):
            return metin.strip()
        return temizle(veri)
    return parse_json('{"test": "deger"}')

# ÇOK FAZLA PARAMETRE - kod kalitesi sorunu
def hesapla(a, b, c, d, e, f, g):
    """7 parametre alan fonksiyon"""
    return a + b + c + d + e + f + g

# Gereksiz import'lar - kod kalitesi sorunu
import sys
import json
import math
import random
import csv