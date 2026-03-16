import sqlite3

def veritabanina_baglan(kullanici_adi):
    """Veritabanına bağlanıp kullanıcıyı getirir."""
    baglanti = sqlite3.connect('test.db')
    cursor = baglanti.cursor()
    
    # Gelişmiş SQL Injection Hazırlığı ve Çalıştırılması
    sorgu = f"SELECT * FROM users WHERE username = '{kullanici_adi}'"
    print("Çalıştırılan sorgu:", sorgu)
    
    cursor.execute(sorgu)
    veriler = cursor.fetchall()
    
    return veriler