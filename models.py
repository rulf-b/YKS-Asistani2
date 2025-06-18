from datetime import datetime, timedelta
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
import os

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    ders_tercihi = db.Column(db.String(50), nullable=True)
    bos_zamanlar_json = db.Column(db.Text, nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    reset_token_used = db.Column(db.Boolean, default=False)

    # İlişkiler
    tekrar_konulari = db.relationship('TekrarKonu', backref='user', lazy=True, cascade="all, delete-orphan")
    soru_analizleri = db.relationship('SoruAnaliz', backref='author', lazy=True)
    denemeleri = db.relationship('DenemeSinavi', backref='author', lazy=True)
    hedef = db.relationship('Hedef', backref='user', uselist=False, cascade="all, delete-orphan")
    calisma_oturumlari = db.relationship('CalismaOturumu', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=600):
        self.reset_token_used = False
        secret = os.getenv('SECRET_KEY')
        if not secret:
            raise RuntimeError('SECRET_KEY ortam değişkeni tanımsız.')
        s = URLSafeTimedSerializer(secret)
        return s.dumps({'user_id': self.id}, salt='reset-password')

    @staticmethod
    def verify_reset_token(token):
        secret = os.getenv('SECRET_KEY')
        if not secret:
            raise RuntimeError('SECRET_KEY ortam değişkeni tanımsız.')
        s = URLSafeTimedSerializer(secret)
        try:
            user_id = s.loads(token, salt='reset-password', max_age=600)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Hedef(db.Model):
    __tablename__ = "hedef"
    id = db.Column(db.Integer, primary_key=True)
    universite = db.Column(db.String(100), nullable=False)
    bolum = db.Column(db.String(100), nullable=False)
    hedef_siralama = db.Column(db.Integer, nullable=True)
    hedef_tyt_net = db.Column(db.Float, nullable=True)
    hedef_ayt_net = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

class TekrarKonu(db.Model):
    __tablename__ = "tekrar_konu"
    id = db.Column(db.Integer, primary_key=True)
    konu_adi = db.Column(db.String(250), nullable=False)
    son_tekrar = db.Column(db.DateTime, nullable=True)
    tekrar_sayisi = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SoruAnaliz(db.Model):
    __tablename__ = "soru_analiz"
    id = db.Column(db.Integer, primary_key=True)
    soru_metni = db.Column(db.Text, nullable=False)
    cevap_metni = db.Column(db.Text, nullable=True)
    analiz_sonucu = db.Column(db.Text, nullable=False)
    tarih = db.Column(db.DateTime, default=datetime.utcnow)
    konu = db.Column(db.String(250), nullable=True)
    zorluk_derecesi = db.Column(db.String(50), nullable=True)
    hata_turu = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class DenemeSinavi(db.Model):
    __tablename__ = "deneme_sinavi"
    id = db.Column(db.Integer, primary_key=True)
    kaynak = db.Column(db.String(100), nullable=False)
    tarih = db.Column(db.DateTime, default=datetime.utcnow)
    tyt_turkce_d = db.Column(db.Integer, default=0)
    tyt_turkce_y = db.Column(db.Integer, default=0)
    tyt_sosyal_d = db.Column(db.Integer, default=0)
    tyt_sosyal_y = db.Column(db.Integer, default=0)
    tyt_mat_d = db.Column(db.Integer, default=0)
    tyt_mat_y = db.Column(db.Integer, default=0)
    tyt_fen_d = db.Column(db.Integer, default=0)
    tyt_fen_y = db.Column(db.Integer, default=0)
    ayt_mat_d = db.Column(db.Integer, default=0)
    ayt_mat_y = db.Column(db.Integer, default=0)
    ayt_fiz_d = db.Column(db.Integer, default=0)
    ayt_fiz_y = db.Column(db.Integer, default=0)
    ayt_kim_d = db.Column(db.Integer, default=0)
    ayt_kim_y = db.Column(db.Integer, default=0)
    ayt_biy_d = db.Column(db.Integer, default=0)
    ayt_biy_y = db.Column(db.Integer, default=0)
    ayt_edebiyat_d = db.Column(db.Integer, default=0)
    ayt_edebiyat_y = db.Column(db.Integer, default=0)
    ayt_tarih1_d = db.Column(db.Integer, default=0)
    ayt_tarih1_y = db.Column(db.Integer, default=0)
    ayt_cografya1_d = db.Column(db.Integer, default=0)
    ayt_cografya1_y = db.Column(db.Integer, default=0)
    ayt_tarih2_d = db.Column(db.Integer, default=0)
    ayt_tarih2_y = db.Column(db.Integer, default=0)
    ayt_cografya2_d = db.Column(db.Integer, default=0)
    ayt_cografya2_y = db.Column(db.Integer, default=0)
    ayt_felsefe_d = db.Column(db.Integer, default=0)
    ayt_felsefe_y = db.Column(db.Integer, default=0)
    ayt_din_d = db.Column(db.Integer, default=0)
    ayt_din_y = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class CalismaOturumu(db.Model):
    __tablename__ = "calisma_oturumu"
    id = db.Column(db.Integer, primary_key=True)
    tarih = db.Column(db.DateTime, default=datetime.utcnow)
    calisma_suresi_dakika = db.Column(db.Integer, nullable=False)
    konu_adi = db.Column(db.String(250), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='calisma_oturumlari', lazy=True)

class QuizSonucu(db.Model):
    __tablename__ = "quiz_sonucu"
    id = db.Column(db.Integer, primary_key=True)
    dogru_sayisi = db.Column(db.Integer, nullable=False)
    yanlis_sayisi = db.Column(db.Integer, nullable=False)
    bos_sayisi = db.Column(db.Integer, nullable=False)
    konu = db.Column(db.String(250), nullable=False)
    tarih = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class HaftalikPlan(db.Model):
    __tablename__ = "haftalik_plan"
    id = db.Column(db.Integer, primary_key=True)
    gun = db.Column(db.String(50), nullable=False)
    konu = db.Column(db.String(250), nullable=False)
    sure = db.Column(db.Integer, nullable=False)
    notlar = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_token"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(256), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

    def is_expired(self, expire_minutes=10):
        return datetime.utcnow() > self.created_at + timedelta(minutes=expire_minutes)