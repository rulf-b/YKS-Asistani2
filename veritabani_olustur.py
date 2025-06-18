from flask import Flask
from models import db
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# Bu script, veritabanı tablolarını oluşturmak için kullanılır.
print("Veritabanı tabloları oluşturuluyor...")

# app_context olmadan veritabanı işlemi yapılamaz.
with app.app_context():
    db.create_all()

print("Tablolar başarıyla oluşturuldu! 'veritabani.db' dosyası oluşmuş olmalı.")