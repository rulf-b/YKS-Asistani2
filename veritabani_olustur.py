from app import app, db

# Bu script, veritabanı tablolarını oluşturmak için kullanılır.
print("Veritabanı tabloları oluşturuluyor...")

# app_context olmadan veritabanı işlemi yapılamaz.
with app.app_context():
    db.create_all()

print("Tablolar başarıyla oluşturuldu! 'veritabani.db' dosyası oluşmuş olmalı.")