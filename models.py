from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timedelta
from passlib.context import CryptContext
import os
from itsdangerous import URLSafeTimedSerializer

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(30), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=True)
    password_hash = Column(String(60), nullable=False)
    is_admin = Column(Boolean, nullable=False, default=False)
    ders_tercihi = Column(String(50), nullable=True)
    bos_zamanlar_json = Column(Text, nullable=True)
    email_confirmed = Column(Boolean, default=False)
    reset_token_used = Column(Boolean, default=False)

    def set_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def get_reset_token(self, expires_sec=600):
        self.reset_token_used = False
        s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'varsayilan-gizli-anahtar'))
        return s.dumps({'user_id': self.id}, salt='reset-password')

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'varsayilan-gizli-anahtar'))
        try:
            user_id = s.loads(token, salt='reset-password', max_age=600)['user_id']
        except Exception:
            return None
        return user_id

class Hedef(Base):
    __tablename__ = "hedef"
    id = Column(Integer, primary_key=True, index=True)
    universite = Column(String(100), nullable=False)
    bolum = Column(String(100), nullable=False)
    hedef_siralama = Column(Integer, nullable=True)
    hedef_tyt_net = Column(Float, nullable=True)
    hedef_ayt_net = Column(Float, nullable=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False, unique=True)

class SoruAnaliz(Base):
    __tablename__ = "soru_analiz"
    id = Column(Integer, primary_key=True, index=True)
    soru_metni = Column(Text, nullable=False)
    cevap_metni = Column(Text, nullable=True)
    analiz_sonucu = Column(Text, nullable=False)
    tarih = Column(DateTime, default=datetime.utcnow)
    konu = Column(String(250), nullable=True)
    zorluk_derecesi = Column(String(50), nullable=True)
    hata_turu = Column(String(100), nullable=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

class DenemeSinavi(Base):
    __tablename__ = "deneme_sinavi"
    id = Column(Integer, primary_key=True, index=True)
    kaynak = Column(String(100), nullable=False)
    tarih = Column(DateTime, default=datetime.utcnow)
    tyt_turkce_d = Column(Integer, default=0)
    tyt_turkce_y = Column(Integer, default=0)
    tyt_sosyal_d = Column(Integer, default=0)
    tyt_sosyal_y = Column(Integer, default=0)
    tyt_mat_d = Column(Integer, default=0)
    tyt_mat_y = Column(Integer, default=0)
    tyt_fen_d = Column(Integer, default=0)
    tyt_fen_y = Column(Integer, default=0)
    ayt_mat_d = Column(Integer, default=0)
    ayt_mat_y = Column(Integer, default=0)
    ayt_fiz_d = Column(Integer, default=0)
    ayt_fiz_y = Column(Integer, default=0)
    ayt_kim_d = Column(Integer, default=0)
    ayt_kim_y = Column(Integer, default=0)
    ayt_biy_d = Column(Integer, default=0)
    ayt_biy_y = Column(Integer, default=0)
    ayt_edebiyat_d = Column(Integer, default=0)
    ayt_edebiyat_y = Column(Integer, default=0)
    ayt_tarih1_d = Column(Integer, default=0)
    ayt_tarih1_y = Column(Integer, default=0)
    ayt_cografya1_d = Column(Integer, default=0)
    ayt_cografya1_y = Column(Integer, default=0)
    ayt_tarih2_d = Column(Integer, default=0)
    ayt_tarih2_y = Column(Integer, default=0)
    ayt_cografya2_d = Column(Integer, default=0)
    ayt_cografya2_y = Column(Integer, default=0)
    ayt_felsefe_d = Column(Integer, default=0)
    ayt_felsefe_y = Column(Integer, default=0)
    ayt_din_d = Column(Integer, default=0)
    ayt_din_y = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

class CalismaOturumu(Base):
    __tablename__ = "calisma_oturumu"
    id = Column(Integer, primary_key=True, index=True)
    tarih = Column(DateTime, default=datetime.utcnow)
    calisma_suresi_dakika = Column(Integer, nullable=False)
    konu_adi = Column(String(250), nullable=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

class QuizSonucu(Base):
    __tablename__ = "quiz_sonucu"
    id = Column(Integer, primary_key=True, index=True)
    dogru_sayisi = Column(Integer, nullable=False)
    yanlis_sayisi = Column(Integer, nullable=False)
    bos_sayisi = Column(Integer, nullable=False)
    konu = Column(String(250), nullable=False)
    tarih = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

class HaftalikPlan(Base):
    __tablename__ = "haftalik_plan"
    id = Column(Integer, primary_key=True, index=True)
    gun = Column(String(50), nullable=False)
    konu = Column(String(250), nullable=False)
    sure = Column(Integer, nullable=False)
    notlar = Column(Text, nullable=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_token"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    token = Column(String(256), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    used = Column(Boolean, default=False)

    def is_expired(self, expire_minutes=10):
        return datetime.utcnow() > self.created_at + timedelta(minutes=expire_minutes)