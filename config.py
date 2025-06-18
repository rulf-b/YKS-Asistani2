# config.py (güncellenmiş kısım)
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'change-me'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'yks.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AWS S3 (Mevcut)
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_S3_BUCKET = os.environ.get('AWS_S3_BUCKET_NAME')

    # Upload limits (Mevcut)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx'}

    # YENİ EKLENECEK: E-posta Ayarları (Flask-Mail için)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') # Örn: 'smtp.googlemail.com' (Gmail için)
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587')) # Örn: 587 (TLS için), 465 (SSL için)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true' # True/False
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true' # True/False (ya TLS ya SSL)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') # E-posta adresiniz (örn: your-email@gmail.com)
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') # E-posta şifreniz veya uygulama şifreniz
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME) # Varsayılan gönderici