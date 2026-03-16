import os
import pickle
import hashlib
import json  # Kullanılmayan import
import sys   # Kullanılmayan import

global_islem_sayisi = 0  # Global değişken kullanımı (Kalite hatası)

def tehlikeli_islemler(kullanici_verisi, komut):
    # Docstring eksikliği (Kalite hatası)
    global global_islem_sayisi
    global_islem_sayisi += 1

    def ic_fonksiyon():
        # İç içe fonksiyon (Kalite hatası)
        pass

    # 1. RCE Riski (Güvenlik hatası)
    sonuc = eval(kullanici_verisi)

    # 2. Güvensiz Deserialization (Güvenlik hatası)
    nesne = pickle.loads(kullanici_verisi)

    # 3. Command Injection - OS Komutu Çalıştırma (Güvenlik hatası)
    os.system(f"ping -c 1 {komut}")

    # 4. Zayıf Hash Kullanımı (Güvenlik hatası)
    m = hashlib.md5()
    m.update(kullanici_verisi.encode('utf-8'))
    
    # 5. Kaynak Sızıntısı - with olmadan dosya açma (Güvenlik/Kalite hatası)
    f = open("log.txt", "w")
    f.write(m.hexdigest())
    # Dosya kapatılmadı! (f.close() yok)

    # 6. Kısa anlamsız değişken (Kalite hatası)
    a = 5
    b = 10
    if a < b:
        for i in range(5):
            if i % 2 == 0:
                print("Karmaşık yapı")

    return sonuc