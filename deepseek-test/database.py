"""
Veritabanı modülü
"""
import os
import sqlite3

# GÜVENLİK ZAFİYETİ 11: Hardcoded database path
DB_PATH = "C:\\Users\\test\\veritabani.db"
DB_USER = "root"
DB_PASS = "123456"

# Global değişken - kod kalitesi sorunu
baglanti = None

def baglan():
    """Veritabanına bağlan"""
    global baglanti
    # GÜVENLİK ZAFİYETİ 12: Hardcoded credentials
    baglanti = sqlite3.connect(DB_PATH)
    return baglanti

def sorgu_calistir(sorgu):
    """SQL sorgusu çalıştır"""
    # HATA YÖNETİMİ YOK - kod kalitesi sorunu
    cursor = baglanti.cursor()
    cursor.execute(sorgu)
    return cursor.fetchall()

def kullanici_ekle(ad, email):
    """Kullanıcı ekle"""
    # GÜVENLİK ZAFİYETİ 13: SQL Injection
    sorgu = "INSERT INTO kullanicilar (ad, email) VALUES ('%s', '%s')" % (ad, email)
    cursor = baglanti.cursor()
    cursor.execute(sorgu)
    baglanti.commit()

def tablo_olustur():
    """Tablo oluştur - KULLANILMAYAN FONKSİYON"""
    cursor = baglanti.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS kullanicilar (id INTEGER PRIMARY KEY, ad TEXT, email TEXT)")
    baglanti.commit()

# Gereksiz import'lar - kod kalitesi sorunu
import sys
import json
import math
import random