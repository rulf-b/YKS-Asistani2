# --- KÜTÜPHANELER ---
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from config import Config
import logging
from logging.handlers import RotatingFileHandler
import os

# --- UYGULAMA KURULUMU ---
app = Flask(__name__)
app.config.from_object(Config)

# --- GÜVENLİK BAŞLIKLARI ---
@app.after_request
def add_security_headers(response):
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# --- RATE LIMITING ---
limiter = Limiter(
    storage_uri="memory://",
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# --- CSRF KORUMASI ---
csrf = CSRFProtect(app)

# --- LOGLAMA KURULUMU ---
def setup_logging():
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    # Güvenlik log dosyası
    security_handler = RotatingFileHandler(
        'logs/security.log', 
        maxBytes=10240, 
        backupCount=10
    )
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    security_handler.setLevel(logging.INFO)
    app.logger.addHandler(security_handler)
    
    # Genel log dosyası
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10240,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('YKS Asistanı başlatılıyor')

setup_logging()

# --- VERİTABANI KURULUMU ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Bu sayfaya erişmek için lütfen giriş yapın.'
login_manager.login_message_category = 'info'

# --- E-POSTA KURULUMU ---
mail = Mail(app)

# --- API GÜVENLİĞİ ---
def mask_api_key(api_key):
    if not api_key:
        return None
    return f"{api_key[:4]}...{api_key[-4:]}"

# API anahtarı kontrolü ve maskeleme
api_key = os.getenv('GOOGLE_API_KEY')
if api_key:
    app.logger.info(f"API Key loaded: {mask_api_key(api_key)}")
else:
    app.logger.warning("API Key not found!")

# --- DOSYA DOĞRULAMA ---
def validate_file_content(file_stream):
    magic_numbers = {
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'%PDF': 'application/pdf',
        b'PK\x03\x04': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }
    header = file_stream.read(8)
    file_stream.seek(0)
    
    for magic, mime in magic_numbers.items():
        if header.startswith(magic):
            return True, mime
    return False, None

# --- ŞİFRE GÜVENLİĞİ ---
def validate_password(password):
    if len(password) < 12:
        return False, "Şifre en az 12 karakter uzunluğunda olmalıdır."
    if not any(c.isupper() for c in password):
        return False, "Şifre en az bir büyük harf içermelidir."
    if not any(c.islower() for c in password):
        return False, "Şifre en az bir küçük harf içermelidir."
    if not any(c.isdigit() for c in password):
        return False, "Şifre en az bir rakam içermelidir."
    if not any(c in "!@#$%^&*" for c in password):
        return False, "Şifre en az bir özel karakter (!@#$%^&*) içermelidir."
    return True, "Şifre gereksinimleri karşılanıyor."

# Diğer importları buraya taşıyoruz
from flask import render_template, url_for, flash, redirect, request, jsonify, send_file, abort
from flask_login import UserMixin, login_user, current_user, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer as Serializer
from datetime import datetime, timedelta
import json
import os
import signal
import google.generativeai as genai
import PIL.Image
from markdown import markdown
import bleach
from dotenv import load_dotenv
from functools import wraps
from forms import (
    RegistrationForm,
    LoginForm,
    FileUploadForm,
    RequestResetForm,
    ResetPasswordForm,
    HedefForm,
)

# Load environment variables
load_dotenv()

# --- GOOGLE AI KURULUMU ---
api_key = os.getenv('GOOGLE_API_KEY')
if not api_key:
    print("UYARI: GOOGLE_API_KEY bulunamadı! Lütfen .env dosyanızı kontrol edin.")
else:
    try:
        genai.configure(api_key=api_key)
        # Test amaçlı bir model oluşturmayı dene
        model = genai.GenerativeModel('gemini-pro')
        print("Google AI API başarıyla yapılandırıldı ve test edildi.")
    except Exception as e:
        print(f"Google AI API yapılandırma hatası: {str(e)}")

def get_gemini_response(prompt, model_name='gemini-pro'):
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini API Hatası: {str(e)}")
        return f"Üzgünüm, bir hata oluştu: {str(e)}"

def get_gemini_analysis(soru_metni=None, soru_resmi=None, ogrenci_cevabi=""):
    try:
        if not os.getenv('GOOGLE_API_KEY'):
            return "Gemini API anahtarı ayarlanmadığı için analiz yapılamıyor.", None, None, None
        
        model = genai.GenerativeModel('gemini-pro')
        
        # Prompt'u hazırla
        prompt = YKS_ANALIZ_PROMPT.format(ogrenci_cevabi=ogrenci_cevabi)
        
        content_parts = [prompt]
        if soru_resmi:
            content_parts.insert(0, soru_resmi)
        elif soru_metni:
            content_parts.insert(0, f"Lütfen aşağıdaki metin sorusunu analiz et: {soru_metni}")
        
        response = model.generate_content(content_parts)
        full_text = response.text
        
        # Markdown formatını temizle
        full_text = full_text.strip()
        if full_text.startswith('```markdown') and full_text.endswith('```'):
            full_text = full_text[len('```markdown'):-len('```')].strip()
        elif full_text.startswith('```') and full_text.endswith('```'):
            full_text = full_text[len('```'):-len('```')].strip()
            
        # Bölümleri ayır
        parts = full_text.split('---')
        if len(parts) >= 2:
            bolum1 = parts[0].strip()
            bolum2 = parts[1].strip()
            
            # Konu ve zorluk derecesini çıkar
            konu = None
            zorluk = None
            hata_turu = None
            
            for line in bolum2.split('\n'):
                if line.startswith('Konu:'):
                    konu = line.replace('Konu:', '').strip()
                elif line.startswith('Zorluk:'):
                    zorluk = line.replace('Zorluk:', '').strip()
                elif line.startswith('Hata Türü:'):
                    hata_turu = line.replace('Hata Türü:', '').strip()
            
            return bolum1, konu, zorluk, hata_turu
        
        return full_text, None, None, None
        
    except Exception as e:
        print(f"Gemini API Hatası: {str(e)}")
        return "Analiz sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.", None, None, None

# --- KULLANICI YÜKLEYİCİ FONKSİYON ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- VERİTABANI MODELLERİ ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    ders_tercihi = db.Column(db.String(50), nullable=True)
    bos_zamanlar_json = db.Column(db.Text, nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    
    soru_analizleri = db.relationship('SoruAnaliz', backref='author', lazy=True)
    denemeleri = db.relationship('DenemeSinavi', backref='author', lazy=True)
    hedef = db.relationship('Hedef', backref='user', uselist=False, cascade="all, delete-orphan")
    tekrar_konulari = db.relationship('TekrarKonu', backref='user', lazy=True, cascade="all, delete-orphan")
    calisma_oturumlari = db.relationship('CalismaOturumu', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Hedef(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    universite = db.Column(db.String(100), nullable=False)
    bolum = db.Column(db.String(100), nullable=False)
    hedef_siralama = db.Column(db.Integer, nullable=True)
    hedef_tyt_net = db.Column(db.Float, nullable=True)
    hedef_ayt_net = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

class TekrarKonu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    konu_adi = db.Column(db.String(250), nullable=False)
    son_tekrar = db.Column(db.DateTime, nullable=True)
    tekrar_sayisi = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SoruAnaliz(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    tarih = db.Column(db.DateTime, default=datetime.utcnow)
    calisma_suresi_dakika = db.Column(db.Integer, nullable=False)
    konu_adi = db.Column(db.String(250), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- ADMİN KORUMA DECORATOR'I ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Bu sayfaya erişim yetkiniz yok.", "danger")
            return redirect(url_for('anasayfa'))
        return f(*args, **kwargs)
    return decorated_function

# --- API FONKSİYONLARI ---
# api_key globalde bir kez ayarlanır ve fonksiyonlar içinde os.getenv ile alınır.
# Bu kısım, API anahtarının uygulamanın başında doğru yüklenip yüklenmediğini kontrol eder.
api_key_global = os.getenv("GOOGLE_API_KEY") # Globalde tanımladık
# GEÇİCİ KOD: API anahtarının yüklenip yüklenmediğini kontrol edelim
print(f"API Anahtarı Yüklendi mi?: {bool(api_key_global)}")
print(f"API Anahtarının İlk 5 Karakteri: {api_key_global[:5] if api_key_global else 'Yok'}") # İlk 5 karakteri göster, tamamını değil güvenlik için
if api_key_global:
    genai.configure(api_key=api_key_global)
else:
    print("UYARI: Gemini API anahtarı .env dosyasında bulunamadı. Lütfen .env dosyanızı kontrol edin.")

# --- SAYFA ROUTE'LARI ---

@app.route("/ai-geri-bildirim", methods=['GET'])
@login_required
def ai_feedback():
    feedback_report = "Yapay zeka geri bildirim raporu oluşturulamadı."

    # Kullanıcının sağladığı limitlere göre verileri çekelim
    denemeler = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.desc()).limit(3).all()
    analizler = SoruAnaliz.query.filter_by(author=current_user).order_by(SoruAnaliz.tarih.desc()).limit(5).all()
    calismalar = CalismaOturumu.query.filter_by(user=current_user).order_by(CalismaOturumu.tarih.desc()).limit(5).all()

    # Yeterli veri yoksa, kullanıcıyı yönlendirici bir mesajla ana sayfaya geri gönder
    if not denemeler and not analizler and not calismalar:
        flash(f"""### ❗ Yeterli Veri Bulunamadı

Kişiselleştirilmiş bir geri bildirim raporu oluşturabilmem için daha fazla veriye ihtiyacım var. Lütfen şunları eklediğinizden emin olun:

* **Hedef Bilgileri:** <a href="{url_for('hedef_belirle')}" class="text-primary fw-bold text-decoration-none">Hedef Belirle</a> sayfasından üniversite, bölüm, sıralama, net bilgileri, alan tercihi ve boş zaman dilimlerinizi girin.
* **En Az 2 Deneme Sonucu:** <a href="{url_for('deneme_takibi')}" class="text-primary fw-bold text-decoration-none">Deneme Takibi</a> sayfasından en az 2 deneme sonucu girin.
* **En Az 3 Soru Analizi:** <a href="{url_for('soru_analizi')}" class="text-primary fw-bold text-decoration-none">Soru Analizi</a> sayfasından en az 3 soru analizi yapın (özellikle "Bilgi Eksikliği" hatası içerenler faydalı olacaktır).
* **En Az 3 Çalışma Oturumu:** <a href="{url_for('calisma_takibi')}" class="text-primary fw-bold text-decoration-none">Çalışma Takibi</a> sayfasından en az 3 çalışma oturumu kaydedin.

Bu verileri tamamladığınızda, sana özel ve çok daha detaylı bir performans raporu sunabilirim!""", "warning")
        return redirect(url_for('anasayfa'))

    # Kullanıcıdan gelen bilgilerle bir özet hazırla (Tüm bilgileri dahil ediyoruz)
    veri_ozeti = f"Kullanıcı: {current_user.username}\n"

    hedef = current_user.hedef
    if hedef:
        veri_ozeti += f"Hedef Üniversite: {hedef.universite}, Hedef Bölüm: {hedef.bolum}\n"
        veri_ozeti += f"Hedef Sıralama: {hedef.hedef_siralama}\n"
        veri_ozeti += f"Hedef TYT Net: {hedef.hedef_tyt_net}, Hedef AYT Net: {hedef.hedef_ayt_net}\n"

    if current_user.ders_tercihi:
        veri_ozeti += f"Ders Tercihi: {current_user.ders_tercihi}\n"
    if current_user.bos_zamanlar_json:
        veri_ozeti += f"Boş Zaman Dilimleri: {current_user.bos_zamanlar_json}\n"

    if denemeler:
        veri_ozeti += "\n--- Son Denemeler ---\n"
        for d in denemeler:
            tyt_net = (d.tyt_turkce_d - d.tyt_turkce_y / 4) + (d.tyt_sosyal_d - d.tyt_sosyal_y / 4) + \
                        (d.tyt_mat_d - d.tyt_mat_y / 4) + (d.tyt_fen_d - d.tyt_fen_y / 4)
            veri_ozeti += f"Tarih: {d.tarih.strftime('%d-%m-%Y')}, Kaynak: {d.kaynak}, TYT Net: {tyt_net:.2f}\n"

    if analizler:
        veri_ozeti += "\n--- Soru Analizleri (Eksik Konular ve Hata Türleri) ---\n"
        for a in analizler:
            veri_ozeti += f"- Konu: {a.konu}, Hata Türü: {a.hata_turu}, Zorluk: {a.zorluk_derecesi}\n"

    if calismalar:
        veri_ozeti += "\n--- Çalışma Alışkanlıkları ---\n"
        for c in calismalar:
            veri_ozeti += f"- {c.tarih.strftime('%d-%m-%Y %H:%M')}: {c.calisma_suresi_dakika} dk, Konu: {c.konu_adi or 'Belirtilmedi'}\n"

    # Prompt oluştur (sizin prompt yapınızı kullanarak, ancak veri_ozeti'ni daha zengin hale getirdik)
    prompt = AI_FEEDBACK_PROMPT.format(veri_ozeti=veri_ozeti)

    # Gemini çağrısı
    try:
        api_key = os.getenv("GOOGLE_API_KEY") # Fonksiyon içinde tekrar kontrol
        if not api_key:
            feedback_report = "API anahtarı ayarlanmadığı için rapor oluşturulamadı."
        else:
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            yanit = model.generate_content(prompt)
            feedback_report = yanit.text.strip()

            # Gerekirse yapay zeka çıktısını temizle
            if feedback_report.startswith('```markdown') and feedback_report.endswith('```'):
                feedback_report = feedback_report[len('```markdown'):-len('```')].strip()
            elif feedback_report.startswith('```') and feedback_report.endswith('```'):
                feedback_report = feedback_report[len('```'):-len('```')].strip()

            # Yapay zeka hala boş veya genel "belirsiz" yanıtlar döndürdüğünde uyarı (olmamalı ama önlem)
            if not feedback_report or "Belirsiz" in feedback_report or "Bir soru bulunmadığı için" in feedback_report or "Soru Yok" in feedback_report:
                feedback_report = """### ❗ Rapor Oluşturulamadı

Yapay zekâdan kişiselleştirilmiş bir rapor alınamadı. Lütfen daha fazla veri eklediğinizden emin olun veya daha sonra tekrar deneyin."""


    except Exception as e:
        import traceback 
        print(f"------------ YAPAY ZEKA HATA DETAYI BAŞLANGIÇ ------------")
        print(f"Yapay zekâya bağlanırken bir sorun oluştu: {e}")
        traceback.print_exc() 
        print(f"------------ YAPAY ZEKA HATA DETAYI BİTİŞ ------------")
        feedback_report = f"""### ❌ Rapor Oluşturulurken Hata Oluştu

Yapay zekâdan rapor alınırken beklenmedik bir sorun oluştu:
`{e}`

Lütfen internet bağlantınızın aktif olduğundan ve <a href="https://aistudio.google.com/app/apikey" target="_blank" class="text-primary fw-bold text-decoration-none">Google API Anahtarınızın</a> (`.env` dosyasındaki `GOOGLE_API_KEY`) doğru ve geçerli olduğundan emin olun. Daha sonra tekrar denemeyi deneyebilirsiniz. Teknik destek için bu hatayı paylaşabilirsiniz.
"""

        safe_feedback_report = bleach.clean(
        markdown(feedback_report),
        tags=bleach.sanitizer.ALLOWED_TAGS + ['p', 'br'],
        strip=True
    )
    return render_template('ai_feedback.html', title='Yapay Zeka Geri Bildirimi', safe_feedback_report=safe_feedback_report)

@app.route("/")
@app.route("/anasayfa")
@login_required
def anasayfa():
    # Mevcut veriler
    tekrar_konu_sayisi = TekrarKonu.query.filter_by(user_id=current_user.id).count()
    analizler = SoruAnaliz.query.filter_by(author=current_user).order_by(SoruAnaliz.tarih.desc()).limit(3).all()
    denemeler = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.desc()).limit(3).all()
    calisma_oturumleri = CalismaOturumu.query.filter_by(user=current_user).order_by(CalismaOturumu.tarih.desc()).limit(3).all()

    # YENİ EKLENEN HESAPLAMALAR
    toplam_calisma_suresi_dakika = db.session.query(db.func.sum(CalismaOturumu.calisma_suresi_dakika)).filter_by(user_id=current_user.id).scalar() or 0
    toplam_calisma_suresi_saat = toplam_calisma_suresi_dakika / 60

    toplam_analiz_edilen_soru = SoruAnaliz.query.filter_by(user_id=current_user.id).count()

    # İlerleme çubukları için netler
    current_user_tyt_net = 0
    current_user_ayt_net = 0
    tyt_ilerleme_yuzde = 0
    ayt_ilerleme_yuzde = 0

    son_deneme = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.desc()).first()
    if current_user.hedef and son_deneme:
        current_user_tyt_net = (son_deneme.tyt_turkce_d - son_deneme.tyt_turkce_y / 4) + \
                               (son_deneme.tyt_sosyal_d - son_deneme.tyt_sosyal_y / 4) + \
                               (son_deneme.tyt_mat_d - son_deneme.tyt_mat_y / 4) + \
                               (son_deneme.tyt_fen_d - son_deneme.tyt_fen_y / 4)
        
        # Kullanıcının ders tercihine göre AYT netini hesaplamak daha doğru olurdu,
        # şimdilik tüm AYT derslerini toplayan bir tahmin yapalım.
        # Daha doğru bir hesaplama için `hedef_analizi` rotasında kullandığınız AYT net hesaplama mantığını buraya taşıyabilirsiniz.
        current_user_ayt_net = (son_deneme.ayt_mat_d - son_deneme.ayt_mat_y / 4) + \
                               (son_deneme.ayt_fiz_d - son_deneme.ayt_fiz_y / 4) + \
                               (son_deneme.ayt_kim_d - son_deneme.ayt_kim_y / 4) + \
                               (son_deneme.ayt_biy_d - son_deneme.ayt_biy_y / 4) + \
                               (son_deneme.ayt_edebiyat_d - son_deneme.ayt_edebiyat_y / 4) + \
                               (son_deneme.ayt_tarih1_d - son_deneme.ayt_tarih1_y / 4) + \
                               (son_deneme.ayt_cografya1_d - son_deneme.ayt_cografya1_y / 4) + \
                               (son_deneme.ayt_tarih2_d - son_deneme.ayt_tarih2_y / 4) + \
                               (son_deneme.ayt_cografya2_d - son_deneme.ayt_cografya2_y / 4) + \
                               (son_deneme.ayt_felsefe_d - son_deneme.ayt_felsefe_y / 4) + \
                               (son_deneme.ayt_din_d - son_deneme.ayt_din_y / 4)


        if current_user.hedef.hedef_tyt_net > 0:
            tyt_ilerleme_yuzde = (current_user_tyt_net / current_user.hedef.hedef_tyt_net) * 100
            if tyt_ilerleme_yuzde > 100: tyt_ilerleme_yuzde = 100 # %100'ü geçmesin
        if current_user.hedef.hedef_ayt_net > 0:
            ayt_ilerleme_yuzde = (current_user_ayt_net / current_user.hedef.hedef_ayt_net) * 100
            if ayt_ilerleme_yuzde > 100: ayt_ilerleme_yuzde = 100 # %100'ü geçmesin
            
    return render_template('anasayfa.html', 
                           title='Ana Sayfa', 
                           tekrar_konu_sayisi=tekrar_konu_sayisi, 
                           analizler=analizler, 
                           denemeler=denemeler, 
                           calisma_oturumleri=calisma_oturumleri,
                           toplam_calisma_suresi_dakika=toplam_calisma_suresi_dakika,
                           toplam_calisma_suresi_saat=toplam_calisma_suresi_saat,
                           toplam_analiz_edilen_soru=toplam_analiz_edilen_soru,
                           current_user_tyt_net=current_user_tyt_net,
                           current_user_ayt_net=current_user_ayt_net,
                           tyt_ilerleme_yuzde=tyt_ilerleme_yuzde,
                           ayt_ilerleme_yuzde=ayt_ilerleme_yuzde
                           )

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('anasayfa'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password,
                email_confirmed=False
            )
            db.session.add(user)
            db.session.commit()
            # E-posta doğrulama linki gönder
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('confirm_email', token=token, _external=True)
            send_email(user.email, 'YKS Asistanı: E-posta Doğrulama', 'confirm_email', 
                       user=user, confirm_url=confirm_url, expires_min=60) # 60 dakika geçerlilik
            flash('Kayıt başarılı! Hesabınızı etkinleştirmek için e-postanıza gönderilen linke tıklayın.', 'info')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('register'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'danger')
    return render_template('register.html', title='Kayıt Ol', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('anasayfa'))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                if not user.email_confirmed:
                    flash('Lütfen hesabınızı etkinleştirmek için e-postanızı doğrulayın.', 'warning')
                    return redirect(url_for('login'))
                login_user(user, remember=form.remember_me.data)
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('anasayfa'))
            else:
                flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
        except Exception as e:
            flash(f'Giriş sırasında bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('login'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'danger')
    return render_template('login.html', title='Giriş Yap', form=form)

@app.route("/logout")
@login_required
def logout():
    if current_user.is_authenticated:
        username = current_user.username
        logout_user()
        app.logger.info(f"Kullanıcı çıkışı: {username}")
        flash('Başarıyla çıkış yapıldı.', 'info')
    return redirect(url_for('login'))

@app.route("/soru-analizi", methods=['GET', 'POST'])
@login_required
def soru_analizi():
    benzer_sorular = None
    if request.method == 'POST':
        soru_metni_form = request.form.get('soru', '')
        cevap_metni = request.form.get('cevap', '')
        resim_dosyasi = request.files.get('soru_resmi')
        islem_yapildi = False
        
        # get_gemini_analysis fonksiyonunun artık 4 değer döndürdüğünü unutmayın
        analiz_sonucu, konu, zorluk_derecesi, hata_turu = (None, None, None, None) 

        if resim_dosyasi and resim_dosyasi.filename != '':
            img = PIL.Image.open(resim_dosyasi.stream)
            analiz_sonucu, konu, zorluk_derecesi, hata_turu = get_gemini_analysis(soru_resmi=img, ogrenci_cevabi=cevap_metni)
            soru_metni_kayit_icin = f"Yüklenen resim ({resim_dosyasi.filename})"
            islem_yapildi = True
        elif soru_metni_form:
            analiz_sonucu, konu, zorluk_derecesi, hata_turu = get_gemini_analysis(soru_metni=soru_metni_form, ogrenci_cevabi=cevap_metni)
            soru_metni_kayit_icin = soru_metni_form
            islem_yapildi = True

        if islem_yapildi and analiz_sonucu:
            # Hata türü "Bilgi Eksikliği" içeriyorsa tekrar konusuna ekle
            if konu and hata_turu and "Bilgi Eksikliği" in hata_turu:
                # Alt konuyu da içerecek şekilde TekrarKonu'ya ekle
                yeni_tekrar = TekrarKonu(konu_adi=konu, user=current_user)
                db.session.add(yeni_tekrar)
                flash(f'"{konu}" konusu tekrar listene eklendi!', 'info')
            
            # SoruAnaliz modeline zorluk derecesi ve hata türünü de kaydet
            yeni_analiz = SoruAnaliz(
                soru_metni=soru_metni_kayit_icin, 
                cevap_metni=cevap_metni, 
                analiz_sonucu=analiz_sonucu, 
                konu=konu, 
                zorluk_derecesi=zorluk_derecesi, # Yeni
                hata_turu=hata_turu,             # Yeni
                author=current_user
            )
            db.session.add(yeni_analiz)
            db.session.commit()
            flash('Sorunuz başarıyla analiz edildi!', 'success')

            # Benzer soruları bulurken artık alt konuyu daha iyi kullanabiliriz
            if konu:
                # Konunun sadece ana kısmını alıp benzerlik arayabiliriz veya tam eşleşme
                # Şimdilik tam eşleşme ile bırakıyorum, ileride esneklik eklenebilir
                benzer_sorular = SoruAnaliz.query.filter(
                    SoruAnaliz.konu == konu, 
                    SoruAnaliz.id != yeni_analiz.id,
                    SoruAnaliz.user_id == current_user.id # Sadece kendi soruları arasından benzer bul
                ).order_by(db.func.random()).limit(3).all()
    
    gecmis_analizler = SoruAnaliz.query.filter_by(author=current_user).order_by(SoruAnaliz.tarih.desc()).all()
    return render_template('soru_analizi.html', title='Soru Analizi', gecmis_analizler=gecmis_analizler, benzer_sorular=benzer_sorular)

@app.route('/calisma-takibi', methods=['GET', 'POST'])
@login_required
def calisma_takibi():
    if request.method == 'POST':
        try:
            calisma_suresi = int(request.form.get('calisma_suresi'))
            konu_adi = request.form.get('konu_adi')

            if calisma_suresi < 1:
                flash("Çalışma süresi 1 dakikadan az olamaz.", "danger")
                return redirect(url_for('calisma_takibi'))

            yeni_oturum = CalismaOturumu(
                calisma_suresi_dakika=calisma_suresi,
                konu_adi=konu_adi,
                user=current_user
            )
            db.session.add(yeni_oturum)
            db.session.commit()
            flash("Çalışma oturumu başarıyla kaydedildi!", "success")
            return redirect(url_for('calisma_takibi'))

        except (ValueError, TypeError):
            flash("Lütfen geçerli bir sayı girin.", "danger")
            return redirect(url_for('calisma_takibi'))

    # GET isteği için: geçmiş oturumları getir
    gecmis_oturumlar = CalismaOturumu.query.filter_by(user=current_user).order_by(CalismaOturumu.tarih.desc()).all()
    return render_template("calisma_takibi.html", title="Çalışma Takibi", gecmis_oturumlar=gecmis_oturumlar)


@app.route("/deneme-takibi", methods=['GET', 'POST'])
@login_required
def deneme_takibi():
    if request.method == 'POST':
        yeni_deneme = DenemeSinavi(
            kaynak=request.form.get('kaynak','Bilinmeyen'),
            tyt_turkce_d=int(request.form.get('tyt_turkce_d',0)), tyt_turkce_y=int(request.form.get('tyt_turkce_y',0)),
            tyt_sosyal_d=int(request.form.get('tyt_sosyal_d',0)), tyt_sosyal_y=int(request.form.get('tyt_sosyal_y',0)),
            tyt_mat_d=int(request.form.get('tyt_mat_d',0)), tyt_mat_y=int(request.form.get('tyt_mat_y',0)),
            tyt_fen_d=int(request.form.get('tyt_fen_d',0)), tyt_fen_y=int(request.form.get('tyt_fen_y',0)),
            ayt_mat_d=int(request.form.get('ayt_mat_d',0)), ayt_mat_y=int(request.form.get('ayt_mat_y',0)),
            ayt_fiz_d=int(request.form.get('ayt_fiz_d',0)), ayt_fiz_y=int(request.form.get('ayt_fiz_y',0)),
            ayt_kim_d=int(request.form.get('ayt_kim_d',0)), ayt_kim_y=int(request.form.get('ayt_kim_y',0)),
            ayt_biy_d=int(request.form.get('ayt_biy_d',0)), ayt_biy_y=int(request.form.get('ayt_biy_y',0)),
            ayt_edebiyat_d=int(request.form.get('ayt_edebiyat_d',0)), ayt_edebiyat_y=int(request.form.get('ayt_edebiyat_y',0)),
            ayt_tarih1_d=int(request.form.get('ayt_tarih1_d',0)), ayt_tarih1_y=int(request.form.get('ayt_tarih1_y',0)),
            ayt_cografya1_d=int(request.form.get('ayt_cografya1_d',0)), ayt_cografya1_y=int(request.form.get('ayt_cografya1_y',0)),
            ayt_tarih2_d=int(request.form.get('ayt_tarih2_d',0)), ayt_tarih2_y=int(request.form.get('ayt_tarih2_y',0)),
            ayt_cografya2_d=int(request.form.get('ayt_cografya2_d',0)), ayt_cografya2_y=int(request.form.get('ayt_cografya2_y',0)),
            ayt_felsefe_d=int(request.form.get('ayt_felsefe_d',0)), ayt_felsefe_y=int(request.form.get('ayt_felsefe_y',0)),
            ayt_din_d=int(request.form.get('ayt_din_d',0)), ayt_din_y=int(request.form.get('ayt_din_y',0)),
            author=current_user
        )
        db.session.add(yeni_deneme)
        db.session.commit()
        flash('Deneme sonucunuz başarıyla kaydedildi!', 'success')
        return redirect(url_for('deneme_takibi'))
    
    denemeler_tablo_icin = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.desc()).all()
    denemeler_grafik_icin = list(reversed(denemeler_tablo_icin))
    grafik_etiketler = [f"{d.kaynak} ({d.tarih.strftime('%d-%m')})" for d in denemeler_grafik_icin]
    grafik_veriler = [(d.tyt_turkce_d-d.tyt_turkce_y/4)+(d.tyt_sosyal_d-d.tyt_sosyal_y/4)+(d.tyt_mat_d-d.tyt_mat_y/4)+(d.tyt_fen_d-d.tyt_fen_y/4) for d in denemeler_grafik_icin]
    
    # 'denemeler_grafik_icin' değişkenini de şablona gönderiyoruz.
    return render_template('deneme_takibi.html', title='Deneme Takibi', denemeler=denemeler_tablo_icin, grafik_etiketler=json.dumps(grafik_etiketler), grafik_veriler=json.dumps(grafik_veriler), denemeler_grafik_icin=denemeler_grafik_icin)

@app.route("/performans-yorumu")
@login_required
def performans_yorumu():
    denemeler = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.asc()).all()
    if len(denemeler) < 2:
        flash('Yorum için en az 2 deneme sonucu girmelisiniz.', 'info')
        return redirect(url_for('deneme_takibi'))
    performans_ozeti = ""
    for deneme in denemeler:
        toplam_net = (deneme.tyt_turkce_d-deneme.tyt_turkce_y/4)+(deneme.tyt_sosyal_d-deneme.tyt_sosyal_y/4)+(deneme.tyt_mat_d-deneme.tyt_mat_y/4)+(deneme.tyt_fen_d-deneme.tyt_fen_y/4)
        performans_ozeti += f"- {deneme.tarih.strftime('%d-%m-%Y')}, {deneme.kaynak}: Toplam TYT Net: {toplam_net:.2f}\n"
    prompt = PERFORMANS_YORUM_PROMPT.format(performans_ozeti=performans_ozeti)
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    try:
        response = model.generate_content(prompt)
        flash(response.text, 'success')
    except Exception as e:
        flash(f"Yapay zekâdan yorum alınırken bir hata oluştu: {e}", 'danger')
    return redirect(url_for('deneme_takibi'))

@app.route('/hedef-belirle', methods=['GET', 'POST'])
@login_required
def hedef_belirle():
    form = HedefForm()
    mevcut_hedef = current_user.hedef
    
    if form.validate_on_submit():
        try:
            if mevcut_hedef:
                mevcut_hedef.universite = form.universite.data
                mevcut_hedef.bolum = form.bolum.data
                mevcut_hedef.hedef_siralama = form.hedef_siralama.data
                mevcut_hedef.hedef_tyt_net = form.hedef_tyt_net.data
                mevcut_hedef.hedef_ayt_net = form.hedef_ayt_net.data
                current_user.ders_tercihi = form.ders_tercihi.data
                flash('Hedefin güncellendi!', 'success')
            else:
                yeni_hedef = Hedef(
                    universite=form.universite.data,
                    bolum=form.bolum.data,
                    hedef_siralama=form.hedef_siralama.data,
                    hedef_tyt_net=form.hedef_tyt_net.data,
                    hedef_ayt_net=form.hedef_ayt_net.data,
                    user=current_user
                )
                current_user.ders_tercihi = form.ders_tercihi.data
                db.session.add(yeni_hedef)
                flash('Hedefin kaydedildi!', 'success')
            
            db.session.commit()
            return redirect(url_for('hedef_belirle'))
        except Exception as e:
            db.session.rollback()
            flash(f'Bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('hedef_belirle'))
    
    # Form verilerini doldur
    if mevcut_hedef:
        form.universite.data = mevcut_hedef.universite
        form.bolum.data = mevcut_hedef.bolum
        form.hedef_siralama.data = mevcut_hedef.hedef_siralama
        form.hedef_tyt_net.data = mevcut_hedef.hedef_tyt_net
        form.hedef_ayt_net.data = mevcut_hedef.hedef_ayt_net
        form.ders_tercihi.data = current_user.ders_tercihi
    
    return render_template('hedef_belirle.html', title='Hedef Belirle', form=form)

@app.route('/hedef-analizi')
@login_required
def hedef_analizi():
    hedef = current_user.hedef
    son_deneme = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.desc()).first()
    
    if not hedef:
        flash('Hedef analizi için önce bir hedef belirlemelisiniz.', 'warning')
        return redirect(url_for('hedef_belirle'))
    if not son_deneme:
        flash('Hedef analizi için en az bir deneme sonucu girmelisiniz.', 'warning')
        return redirect(url_for('deneme_takibi'))

    mevcut_tyt_net = (son_deneme.tyt_turkce_d-son_deneme.tyt_turkce_y/4)+(son_deneme.tyt_sosyal_d-son_deneme.tyt_sosyal_y/4)+(son_deneme.tyt_mat_d-son_deneme.tyt_mat_y/4)+(son_deneme.tyt_fen_d-son_deneme.tyt_fen_y/4)
    # AYT net hesaplamasında Sayısal varsayılmıştır, öğrencinin ders tercihine göre özelleştirilebilir.
    # Şimdilik AYT netini genel alıyoruz, ileride ders tercihine göre daha spesifik hale getirilebilir.
    mevcut_ayt_net = (son_deneme.ayt_mat_d-son_deneme.ayt_mat_y/4)+(son_deneme.ayt_fiz_d-son_deneme.ayt_fiz_y/4)+(son_deneme.ayt_kim_d-son_deneme.ayt_kim_y/4)+(son_deneme.ayt_biy_d-son_deneme.ayt_biy_y/4)

    # Prompt'a ders tercihi ve boş zaman dilimlerini de ekleyelim
    user_data_for_ai = f"Kullanıcı Adı: {current_user.username}\n"
    user_data_for_ai += f"Hedef: {hedef.universite} - {hedef.bolum}\n"
    user_data_for_ai += f"Hedef Sıralama: {hedef.hedef_siralama}\n"
    user_data_for_ai += f"Hedef İçin Tahmini Netler: TYT ~{hedef.hedef_tyt_net} net, AYT ~{hedef.hedef_ayt_net} net.\n"
    user_data_for_ai += f"Son Deneme Adı: {son_deneme.kaynak}\n"
    user_data_for_ai += f"Mevcut TYT Net: {mevcut_tyt_net:.2f}\n"
    user_data_for_ai += f"Mevcut AYT Net: {mevcut_ayt_net:.2f}\n"
    if current_user.ders_tercihi:
        user_data_for_ai += f"Ders Tercihi: {current_user.ders_tercihi}\n"
    if current_user.bos_zamanlar_json:
        user_data_for_ai += f"Kullanıcının Belirttiği Boş Zaman Dilimleri: {current_user.bos_zamanlar_json}\n"


    prompt = HEDEF_ANALIZI_PROMPT.format(
        hedef_tyt_net=hedef.hedef_tyt_net,
        mevcut_tyt_net=mevcut_tyt_net,
        tyt_fark=hedef.hedef_tyt_net - mevcut_tyt_net,
        hedef_ayt_net=hedef.hedef_ayt_net,
        mevcut_ayt_net=mevcut_ayt_net,
        ayt_fark=hedef.hedef_ayt_net - mevcut_ayt_net,
        hedef_siralama=hedef.hedef_siralama,
        user_data_for_ai=user_data_for_ai
    )
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    try:
        response = model.generate_content(prompt)
        analiz_sonucu = response.text.strip() # Düzgün boşluklar için strip kullanmaya devam

        # Gerekirse yapay zeka çıktısını temizle (kod blokları vs. için)
        if analiz_sonucu.startswith('```markdown') and analiz_sonucu.endswith('```'):
            analiz_sonucu = analiz_sonucu[len('```markdown'):-len('```')].strip()
        elif analiz_sonucu.startswith('```') and analiz_sonucu.endswith('```'):
            analiz_sonucu = analiz_sonucu[len('```'):-len('```')].strip()

    except Exception as e:
        import traceback 
        print(f"------------ HEDEF ANALİZİ HATA DETAYI BAŞLANGIÇ ------------")
        print(f"Yapay zekâdan hedef analizi alınırken bir sorun oluştu: {e}")
        traceback.print_exc() 
        print(f"------------ HEDEF ANALİZİ HATA DETAYI BİTİŞ ------------")
        analiz_sonucu = f"""### ❌ Analiz Oluşturulurken Hata Oluştu

Yapay zekâdan hedef analizi alınırken beklenmedik bir sorun oluştu:
`{e}`

Lütfen internet bağlantınızın aktif olduğundan ve <a href="https://aistudio.google.com/app/apikey" target="_blank" class="text-primary fw-bold text-decoration-none">Google API Anahtarınızın</a> (`.env` dosyasındaki `GOOGLE_API_KEY`) doğru ve geçerli olduğundan emin olun. Daha sonra tekrar denemeyi deneyebilirsiniz. Teknik destek için bu hatayı paylaşabilirsiniz.
"""
    return render_template('hedef_analizi.html', title='Hedef Analizi', analiz=analiz_sonucu)

@app.route('/mini-quiz')
@login_required
def mini_quiz():
    quiz_analizi = None
    safe_quiz_icerigi = None
    secilen_sorular_objeleri = []
    konu_havuzu = ["Türkçe", "Matematik", "Fizik", "Kimya", "Biyoloji", "Tarih", "Coğrafya", "Felsefe"]

    if request.method == 'POST':
        # POST işlemleri burada devam eder...
        pass

    # GET isteği veya POST sonrası quiz_icerigi/quiz_analizi None ise quiz oluşturma formunu göster
    return render_template(
        'mini_quiz.html',
        title='Mini Quiz',
        konular=konu_havuzu,
        tum_konular=[],
        safe_quiz_icerigi=safe_quiz_icerigi,
        secilen_sorular=secilen_sorular_objeleri,
        quiz_analizi=quiz_analizi,
    )
@app.route('/haftalik-plan', methods=['GET', 'POST'])
@login_required
def haftalik_plan():
    plan = None
    if request.method == 'POST':
        son_denemeler = DenemeSinavi.query.filter_by(author=current_user).order_by(DenemeSinavi.tarih.desc()).limit(2).all()
        # Sadece "Bilgi Eksikliği" içeren son 10 soru analizini al
        son_analizler_icin_plan = SoruAnaliz.query.filter(
            SoruAnaliz.user_id == current_user.id,
            SoruAnaliz.hata_turu.like('%Bilgi Eksikliği%') # "Bilgi Eksikliği" içerenleri al
        ).order_by(SoruAnaliz.tarih.desc()).limit(10).all()
        
        hedef = current_user.hedef
        veri_ozeti = f"Kullanıcı: {current_user.username}\n"
        if hedef:
            veri_ozeti += f"Hedefi: {hedef.universite} {hedef.bolum}\n"
        
        if son_denemeler:
            veri_ozeti += "Son deneme netleri:\n"
            for deneme in son_denemeler:
                 toplam_tyt = (deneme.tyt_turkce_d-deneme.tyt_turkce_y/4)+(deneme.tyt_sosyal_d-deneme.tyt_sosyal_y/4)+(deneme.tyt_mat_d-deneme.tyt_mat_y/4)+(deneme.tyt_fen_d-deneme.tyt_fen_y/4)
                 veri_ozeti += f"- {deneme.kaynak} ({deneme.tarih.strftime('%d-%m-%Y')}): TYT Net: {toplam_tyt:.2f}\n"
        
        # En çok hata yapılan konuları ve hata türlerini plana ekle
        if son_analizler_icin_plan:
            veri_ozeti += "\nSon Belirlenen Eksik Konular ve Hata Türleri:\n"
            for analiz in son_analizler_icin_plan:
                veri_ozeti += f"- Konu: {analiz.konu}, Hata Türü: {analiz.hata_turu}, Zorluk: {analiz.zorluk_derecesi}\n"

        prompt = f"""
        Sen uzman bir YKS öğrenci koçusun. Aşağıdaki verileri ve öğrencinin performansını kullanarak, bu öğrenci için **oldukça kişiselleştirilmiş, motive edici ve gerçekçi bir 7 günlük çalışma planı** oluştur.
        Planı, her gün için **3-4 somut görev** içerecek şekilde Markdown formatında hazırla.
        Planda deneme çözümü, **özel olarak belirtilen eksik konuların tekrarı (hata türüne ve zorluğuna göre öncelik vererek)** ve soru çözümünü dengeli bir şekilde dağıt.
        Öğrencinin geçmiş hatalarından ders çıkarmasına ve hedef netlerine ulaşmasına yardımcı olacak stratejiler ekle.

        Öğrenci Verileri:
        {veri_ozeti}

        Plan Örneği (format ve içerik için rehber):
        ### Gün 1: [Günün Teması/Odak Noktası]
        * **Konu Tekrarı:** [Ders > Konu > Alt Konu] - [Hata Türü] - [Zorluk]. Bu konuyu [Önerilen Kaynak Türü: ders notu/video/kitap] üzerinden [Süre] çalış.
        * **Soru Çözümü:** Bu konuyla ilgili [Soru Sayısı] adet [Kolay/Orta/Zor] soru çöz.
        * **Ek Görev:** [Motivasyon/Dikkatinin dağılmaması için öneri/kısa bir dinlenme önerisi]

        ### Gün 2: [Günün Teması/Odak Noktası]
        * **Deneme Sınavı:** [TYT/AYT/Genel] deneme çözümü (Süre).
        * **Deneme Analizi:** Yanlış ve boş bıraktığın soruların konularını ve hata türlerini belirle.
        * **Takip Çalışması:** Belirlediğin 1-2 eksik konunun özetini çıkar.

        ... (7 güne kadar devam et)

        ### Ek Notlar:
        * Bu plan sana özel hazırlandı, ancak esnek olmaktan çekinme.
        * Her 45-50 dakikalık çalışma sonrası 10 dakika mola vermeyi unutma.
        * Düzenli uyku ve sağlıklı beslenme, başarının anahtarıdır!
        """
        try:
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            response = model.generate_content(prompt)
            plan = response.text.strip() # Düzgün boşluklar için strip kullanmaya devam
        except Exception as e:
            flash(f"Plan oluşturulurken bir hata oluştu: {e}", "danger")
            plan = "Yapay zekâdan plan alınamadı. Lütfen daha sonra tekrar deneyin veya API anahtarınızı kontrol edin."
    return render_template('haftalik_plan.html', title='Haftalık Planın', plan=plan)
    
# --- ADMİN PANELİ ROUTE'LARI ---
@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    soru_count = SoruAnaliz.query.count()
    deneme_count = DenemeSinavi.query.count()
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/dashboard.html', title='Admin Paneli', user_count=user_count, soru_count=soru_count, deneme_count=deneme_count, users=users)

@app.route('/admin/user/<int:user_id>')
@admin_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin/user_detail.html', title=f"{user.username} Detayları", user=user)

# YENİ: E-posta doğrulama token'ı için Serializer objesi oluşturma (uygulama bağlamında çalışmalı)
def generate_confirmation_token(email):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps(email, salt='email-confirm').decode('utf-8')

# YENİ: E-posta doğrulama token'ını doğrulama
def confirm_token(token, expiration=3600): # 1 saat (3600 saniye) geçerli
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

# YENİ: E-posta gönderme yardımcı fonksiyonu
def send_email(to, subject, template_name, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.html = render_template(f'email/{template_name}.html', **kwargs)
    mail.send(msg)

# YENİ: E-posta Doğrulama Rotası
@app.route('/confirm/<token>')
def confirm_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('anasayfa'))
    
    email = confirm_token(token)
    if not email:
        flash('Doğrulama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('register')) # Tekrar kayıt veya giriş sayfasına yönlendir

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        flash('E-posta adresiniz zaten doğrulanmış.', 'success')
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('E-posta adresiniz başarıyla doğrulandı!', 'success')
    
    return redirect(url_for('login'))

# YENİ: Şifre Sıfırlama İstek Rotası
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('anasayfa'))
    
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for('reset_token', token=token, _external=True)
            send_email(user.email, 'YKS Asistanı: Şifre Sıfırlama İsteği', 'reset_password', 
                       user=user, reset_url=reset_url, expires_min=30)
            flash('Şifre sıfırlama talimatları e-posta adresinize gönderildi. Lütfen e-postanızı kontrol edin.', 'info')
            return redirect(url_for('login'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'danger')
            
    return render_template('reset_request.html', title='Şifre Sıfırla', form=form)

# YENİ: Şifre Sıfırlama Token Doğrulama ve Yeni Şifre Belirleme Rotası
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('anasayfa'))
    
    user = User.verify_reset_token(token)
    if not user:
        flash('Şifre sıfırlama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('reset_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password_hash = hashed_password
        db.session.commit()
        flash('Şifreniz başarıyla güncellendi! Artık yeni şifrenizle giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'danger')
    
    return render_template('reset_token.html', title='Şifre Sıfırla', form=form)


# --- UYGULAMAYI ÇALIŞTIR ---
def signal_handler(sig, frame):
    print('Uygulama kapatılıyor...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False)