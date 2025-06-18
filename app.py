# --- KÜTÜPHANELER ---
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from markdown import markdown
from datetime import datetime
import os
import random
import re
import json
from dotenv import load_dotenv
import google.generativeai as genai
from werkzeug.utils import secure_filename
from functools import wraps
import PIL.Image
from flask_mail import Mail, Message
from itsdangerous import TimedSerializer as Serializer, URLSafeTimedSerializer # URLSafeTimedSerializer eklendi
from flask import current_app # current_app import edildi

# --- UYGULAMA KURULUMU ---
app = Flask(__name__)
app.jinja_env.filters['markdown'] = markdown 
load_dotenv() # .env dosyasını yükle
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'varsayilan-gizli-anahtar')

# Veritabanı bağlantısı: PostgreSQL için veya yerel SQLite için
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url if database_url else 'sqlite:///veritabani.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail yapılandırması
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Bu sayfayı görüntülemek için lütfen giriş yapın."
login_manager.login_message_category = "info"
mail = Mail(app) # Mail objesini initialize et

# --- KULLANICI YÜKLEYİCİ FONKSİYON ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- VERİTABANI MODELLERİ ---
# app.models'dan çekildiği varsayılıyor, bu dosya içinde yeniden tanımlanmayacak.
# Ancak, user tarafından yüklenen 'app.py' dosyası tüm modelleri içerdiği için,
# burada da modelleri tekrar tanımlıyorum. Modüler bir yapıda bu modeller
# models.py'den import edilmelidir.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    ders_tercihi = db.Column(db.String(50), nullable=True) # Sayısal, Sözel, Eşit Ağırlık
    bos_zamanlar_json = db.Column(db.Text, nullable=True) # JSON olarak boş zaman dilimleri
    email_confirmed = db.Column(db.Boolean, default=False) # E-posta doğrulandı mı?
    
    soru_analizleri = db.relationship('SoruAnaliz', backref='author', lazy=True)
    denemeleri = db.relationship('DenemeSinavi', backref='author', lazy=True)
    hedef = db.relationship('Hedef', backref='user', uselist=False, cascade="all, delete-orphan")
    tekrar_konulari = db.relationship('TekrarKonu', backref='user', lazy=True, cascade="all, delete-orphan")
    # Quiz ile ilgili modeller dahil edilmediği için bu kısım burada eksik kalacak.

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800): # 30 dakika geçerli
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


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
    konu_adi = db.Column(db.String(200), nullable=False)
    eklenme_tarihi = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SoruAnaliz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    soru_metni = db.Column(db.Text, nullable=False)
    cevap_metni = db.Column(db.Text, nullable=True)
    analiz_sonucu = db.Column(db.Text, nullable=False)
    tarih = db.Column(db.DateTime, default=datetime.utcnow)
    konu = db.Column(db.String(250), nullable=True) # Ders > Konu > Alt Konu formatında saklayabiliriz
    zorluk_derecesi = db.Column(db.String(50), nullable=True) # Kolay/Orta/Zor
    hata_turu = db.Column(db.String(100), nullable=True) # Bilgi Eksikliği, İşlem Hatası vb.
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
    calisma_suresi_dakika = db.Column(db.Integer, nullable=False) # Dakika cinsinden
    konu_adi = db.Column(db.String(250), nullable=True) # Çalışılan konu
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='calisma_oturumleri', lazy=True) # User modeline geri bağlantı


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

def get_gemini_analysis(soru_metni=None, soru_resmi=None, ogrenci_cevabi=""):
    # API anahtarını fonksiyon içinde tekrar kontrol ediyoruz
    if not api_key_global: # Globaldeki api_key_global değişkenini kullan
        return "Gemini API anahtarı ayarlanmadığı için analiz yapılamıyor.", None, None, None
    
    model = genai.GenerativeModel('gemini-1.5-pro-latest')
    
    # Prompt'u daha net hale getirelim ve istemediğimiz çıktıları belirtelim
    # BÖLÜM 1 ve BÖLÜM 2 ayrımını ve '---' işaretini koruyarak sadece istenen Markdown'ı almasını isteyelim
    prompt = f"""
    Sen bir YKS yapay zekâ koçusun. Analizini iki bölüm halinde yapacaksın.
    BÖLÜM 1: VERİ BLOKU (Kullanıcıya gösterilmeyecek - Makine tarafından okunacak)
    [KONU]: [Sorunun ait olduğu ders, konu ve **alt başlığı** "Ders > Konu > Alt Başlık" formatında belirt. Örn: "Matematik > Fonksiyonlar > Bileşke Fonksiyon"]
    [ZORLUK_DERECESI]: [Sorunun zorluğunu tahmin et: Kolay/Orta/Zor]
    [HATA_TURU]: [Öğrencinin düşünce zincirindeki hatayı tespit et. Hatayı **daha spesifik** bir şekilde belirt (örn: "Bilgi Eksikliği - Türev Kuralları", "İşlem Hatası - Negatif Sayı İşlemi", "Dikkat Dağınağıklığı - Soru Kökünü Yanlış Okuma", "Yanlış Anlama - Kavramsal Hata").]
    ---
    BÖLÜM 2: KULLANICIYA GÖSTERİLECEK ANALİZ (Sadece ve sadece Markdown formatında metin olarak, HTML etiketleri veya kod blokları içermesin)
    ### 📚 Konu ve Zorluk Analizi
    * **Ders ve Konu:** [Tespit ettiğin konuyu "Ders > Konu > Alt Başlık" formatında buraya tekrar yaz]
    * **Zorluk Derecesi:** [Kolay/Orta/Zor]
    ### 🤔 Hata Analizi
    * **Hata Türü:** [Tespit ettiğin spesifik hata türünü buraya tekrar yaz]
    * **Açıklama:** Hatayı kısaca açıkla ve bu hatanın genellikle neden yapıldığını belirt.
    ### 💡 Çözüm Yolu ve Geri Bildirim
    * **Doğru Çözüm:** Sorunun doğru çözümünü adım adım göster. Her adımı net bir şekilde açıkla.
    * **Kişisel Tavsiye:** Öğrenciye hatasını gidermesi için **hata türüne özel** ve motive edici bir tavsiye yaz. (Örn: "Bilgi Eksikliği" ise "Bu konunun temelini sağlamlaştırmak için X kaynağını tekrar gözden geçir.", "İşlem Hatası" ise "Daha dikkatli olmak için bol bol pratik yapmalısın." gibi.)
    ### 🎬 Tavsiye Edilen Kaynaklar
    * **Önemli:** Doğrudan video linki VERME. Bunun yerine, öğrencinin YouTube'da aratabileceği 2-3 adet spesifik **arama sorgusu** öner. (Örn: "Parçalı fonksiyonlar konu anlatımı YKS", "Türev kuralları örnek çözümleri")
    ---
    Öğrencinin Cevabı ve Düşüncesi:**
{ogrenci_cevabi}
---
"""
    
    content_parts = [prompt]
    if soru_resmi:
        content_parts.insert(0, soru_resmi)
    elif soru_metni:
        content_parts.insert(0, f"Lütfen aşağıdaki metin sorusunu analiz et: {soru_metni}")
    
    try:
        response = model.generate_content(content_parts)
        full_text = response.text
        
        # Fazla boşlukları ve potansiyel kod bloğu işaretlerini temizleyelim
        full_text = full_text.strip()
        if full_text.startswith('```markdown') and full_text.endswith('```'):
            full_text = full_text[len('```markdown'):-len('```')].strip()
        elif full_text.startswith('```') and full_text.endswith('```'):
            full_text = full_text[len('```'):-len('```')].strip()

        # Bölüm 1 ve Bölüm 2'yi ayır
        parts = full_text.split('---', 1)
        
        # Eğer parçalara ayrılamıyorsa (yani '---' yoksa veya format bozuksa)
        if len(parts) < 2:
            # Bu durumda tüm metni analiz olarak alıp varsayılanları ayarlayalım
            user_analysis = parts[0].strip() if parts else "Analiz formatı hatalı."
            konu = None
            zorluk_derecesi = None
            hata_turu = None
        else:
            data_block = parts[0]
            user_analysis = parts[1].strip()

            # Regex ile bilgileri çıkar
            konu_match = re.search(r"\[KONU\]:\s*(.*)", data_block)
            zorluk_derecesi_match = re.search(r"\[ZORLUK_DERECESI\]:\s*(.*)", data_block)
            hata_turu_match = re.search(r"\[HATA_TURU\]:\s*(.*)", data_block)

            konu = konu_match.group(1).strip() if konu_match else None
            zorluk_derecesi = zorluk_derecesi_match.group(1).strip() if zorluk_derecesi_match else None
            hata_turu = hata_turu_match.group(1).strip() if hata_turu_match else None

        # Yapay zeka boş veya genel "belirsiz" yanıtlar döndürdüğünde özel bir mesaj göster
        # HTML etiketlerini veya "BÖLÜM 2:" gibi başlıkları temizleyelim.
        if "Belirsiz" in user_analysis or "Bir soru bulunmadığı için" in user_analysis or "Soru Yok" in user_analysis or "<p>BÖLÜM 2:" in user_analysis:
            user_analysis = """### 📚 Konu ve Zorluk Analizi
* **Ders ve Konu:** Henüz bir soru analiz edilmedi.
* **Zorluk Derecesi:** Belirlenemedi.
### 🤔 Hata Analizi
* **Hata Türü:** Belirlenemedi.
* **Açıklama:** Analiz yapabilmem için lütfen bir soru ve dilerseniz kendi çözümünüzü veya düşüncelerinizi paylaşın.
### 💡 Çözüm Yolu ve Geri Bildirim
* **Doğru Çözüm:** Bir soru analiz edildiğinde burada doğru çözüm yolunu göreceksiniz.
* **Kişisel Tavsiye:** Analiz için ilk sorunuzu girerek YKS hedeflerinize bir adım daha yaklaşın!
### 🎬 Tavsiye Edilen Kaynaklar
* **Önemli:** Konuya özel kaynak önerileri için lütfen bir soru analizi yapın.
"""
            konu = None
            zorluk_derecesi = None
            hata_turu = None

        return user_analysis, konu, zorluk_derecesi, hata_turu
    except Exception as e:
        import traceback 
        print(f"------------ YAPAY ZEKA HATA DETAYI BAŞLANGIÇ ------------")
        print(f"Yapay zekâya bağlanırken bir sorun oluştu: {e}")
        traceback.print_exc() 
        print(f"------------ YAPAY ZEKA HATA DETAYI BİTİŞ ------------")
        return f"Yapay zekâya bağlanırken bir sorun oluştu: {e}\n\nLütfen API anahtarınızın doğru olduğundan ve internet bağlantınızın bulunduğundan emin olun.", None, None, None

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
    prompt = f"""
Sen bir YKS koçusun. Aşağıdaki öğrenci verilerine göre, kişiye özel bir geri bildirim raporu hazırla.
* Motivasyon verici ama dürüst bir dil kullan.
* 3 ana bölüm oluştur: 
1. Genel Durum Değerlendirmesi,
2. Gelişim Alanları ve Öneriler,
3. Kapanış Notu.
Rapor sadece Markdown formatında olsun, başka hiçbir metin veya HTML etiketi ekleme.

Veriler:
{veri_ozeti}
"""

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

    return render_template('ai_feedback.html', title='Yapay Zeka Geri Bildirimi', feedback_report=feedback_report)

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
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
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
    return render_template('register.html', title='Kayıt Ol', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin: 
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('anasayfa'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.email_confirmed: 
                flash('Lütfen hesabınızı etkinleştirmek için e-postanızı doğrulayın.', 'warning')
                return redirect(url_for('login'))
            login_user(user, remember=True)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('anasayfa'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
    
    # GET isteği için formu oluştur
    form = {
        'username': request.form.get('username', ''),
        'password': request.form.get('password', '')
    }
    
    return render_template('login.html', title='Giriş Yap', form=form)

@app.route("/logout")
def logout():
    logout_user()
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
    prompt = f"Bir YKS öğrencisinin deneme performansı: {performans_ozeti}. Bu performansı bir koç gibi yorumla."
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
    mevcut_hedef = current_user.hedef
    if request.method == 'POST':
        universite = request.form.get('universite')
        bolum = request.form.get('bolum')
        hedef_siralama = request.form.get('hedef_siralama')
        hedef_tyt_net = request.form.get('hedef_tyt_net')
        hedef_ayt_net = request.form.get('hedef_ayt_net')
        ders_tercihi = request.form.get('ders_tercihi')
        
        # Boş zaman dilimlerini formdan alıyoruz (JavaScript tarafından gönderilecek)
        bos_zamanlar_data = {}
        for day in ["Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma", "Cumartesi", "Pazar"]:
            bos_zamanlar_data[day] = request.form.getlist(f'bos_zaman_{day}[]') # Liste olarak al

        bos_zamanlar_json = json.dumps(bos_zamanlar_data)


        if not all([universite, bolum, hedef_siralama, hedef_tyt_net, hedef_ayt_net, ders_tercihi]):
            flash('Lütfen tüm zorunlu alanları doldurun.', 'danger')
            return redirect(url_for('hedef_belirle'))
        
        if mevcut_hedef:
            mevcut_hedef.universite = universite
            mevcut_hedef.bolum = bolum
            mevcut_hedef.hedef_siralama = int(hedef_siralama)
            mevcut_hedef.hedef_tyt_net = float(hedef_tyt_net)
            mevcut_hedef.hedef_ayt_net = float(hedef_ayt_net)
            flash('Hedefin güncellendi!', 'success')
        else:
            yeni_hedef = Hedef(
                universite=universite, 
                bolum=bolum, 
                hedef_siralama=int(hedef_siralama), 
                hedef_tyt_net=float(hedef_tyt_net), 
                hedef_ayt_net=float(hedef_ayt_net), 
                user=current_user
            )
            db.session.add(yeni_hedef)
            flash('Hedefin kaydedildi!', 'success')
        
        # Kullanıcının ders tercihi ve boş zaman bilgilerini User modeline kaydet
        current_user.ders_tercihi = ders_tercihi
        current_user.bos_zamanlar_json = bos_zamanlar_json
        
        db.session.commit()
        return redirect(url_for('anasayfa'))
    
    # Mevcut boş zamanları çekip HTML'e göndermek için
    mevcut_bos_zamanlar = {}
    if current_user.bos_zamanlar_json:
        mevcut_bos_zamanlar = json.loads(current_user.bos_zamanlar_json)

    return render_template(
        'hedef_belirle.html', 
        title='Hedefini Belirle', 
        hedef=mevcut_hedef,
        mevcut_bos_zamanlar=mevcut_bos_zamanlar
    )

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


    prompt = f"""
    Sen uzman bir YKS rehber öğretmenisin. Bir öğrencinin hedefini, son deneme sonucunu ve genel profilini kullanarak, **hedefe ulaşma yolundaki ilerlemesini, mevcut güçlü ve zayıf yönlerini, hedefine olan net ve sıralama farklarını detaylı bir şekilde analiz et.**

    Analizini aşağıdaki Markdown formatında, motive edici ama gerçekçi bir dille hazırlamanı istiyorum. Rapor sadece belirtilen başlıkları ve içeriği içermeli, başka hiçbir metin veya kod bloğu içermemeli.

    ### 🎯 Genel Durum ve Hedefe Yakınlık
    * [Burada genel durumu, hedefe ne kadar yakın olduğunu, sıralama hedefine göre mevcut durumunu değerlendir.]
    * **Net Farkları:**
        * TYT Hedef: {hedef.hedef_tyt_net} net, Mevcut: {mevcut_tyt_net:.2f} net (Fark: {hedef.hedef_tyt_net - mevcut_tyt_net:.2f})
        * AYT Hedef: {hedef.hedef_ayt_net} net, Mevcut: {mevcut_ayt_net:.2f} net (Fark: {hedef.hedef_ayt_net - mevcut_ayt_net:.2f})
    * **Sıralama Hedefi:** Yaklaşık {hedef.hedef_siralama}. sıraya girmeyi hedefliyorsun.

    ### 🚀 İlerleme ve Geliştirilmesi Gereken Alanlar
    * [Mevcut netlerin ve ders tercihin ışığında hangi derslere/konulara daha çok ağırlık vermen gerektiğini, hangi alanlarda (örn: TYT mi AYT mi) daha çok çalışman gerektiğini belirt.]
    * [Varsa, son deneme analizlerinden elde edilen verilere dayanarak (Örn: "Matematik'te fonksiyonlar konusunda işlem hataları yaşıyorsun.") spesifik öneriler sun.]

    ### 💡 Stratejik Tavsiyeler ve Yol Haritası
    * [Net farklarını kapatmak için somut, haftalık/günlük çalışma stratejileri öner. (Örn: "Her gün X kadar paragraf, Y kadar problem çöz.") ]
    * [Ders tercihini (Sayısal/Sözel/EA) ve belirlediğin boş zaman dilimlerini dikkate alarak ders dağılımı konusunda tavsiyelerde bulun.]
    * [Motivasyonunu yüksek tutmak için pratik öneriler (mola, uyku vb.) ekle.]

    ### ⚠️ Unutma!
    [Buraya YKS sıralamalarının her yıl değişebileceğini, OBP etkisini ve istikrarlı çalışmanın önemini belirten kısa, motive edici bir not ekle.]

    Öğrenci Verileri:
    {user_data_for_ai}
    """
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
    tekrar_konulari = TekrarKonu.query.filter_by(user=current_user).all()
    #tum_konular_listesi = Konu.query.all() # Konu modeli atlandığı için bu satırı yorum satırı yaptık

    # Konu havuzunu sadece tekrar edilmesi gereken alt konuları içerecek şekilde oluştur
    konu_havuzu = list(set([k.konu_adi for k in tekrar_konulari]))
    
    quiz_icerigi = None
    quiz_analizi = None
    secilen_sorular_objeleri = [] # Şablona gönderilecek soru objeleri

    # QUIZ OLUŞTURMA FORM GÖNDERİMİ (POST)
    if request.method == 'POST' and 'create_quiz' in request.form:
        secilen_konular_formdan = request.form.getlist('quiz_konulari')
        quiz_zorluk = request.form.get('quiz_zorluk')

        if not secilen_konular_formdan and not konu_havuzu:
            flash('Quiz oluşturmak için en az bir konu seçmeli veya tekrar listenizde konu olmalı.', 'warning')
            return redirect(url_for('mini_quiz'))

        konular_for_ai = secilen_konular_formdan if secilen_konular_formdan else konu_havuzu[:3] # Eğer formdan gelmezse tekrar listesinden 3 tane al
        konular_for_ai_str = ", ".join(konular_for_ai)

        prompt = f"""
        Sen bir YKS soru hazırlama uzmanısın. Aşağıdaki konulardan, her birinden en az bir tane olacak şekilde, toplam 5 adet çoktan seçmeli (A, B, C, D, E) test sorusu hazırla.
        Soruların formatı şu şekilde olmalı:
        **Soru [Soru Numarası]:** [Sorunun Metni]
        A) [Şık A]
        B) [Şık B]
        C) [Şık C]
        D) [Şık D]
        E) [Şık E]

        Soruların zorluk seviyesi genel olarak "{quiz_zorluk}" olsun.
        Cevap anahtarını en sonda, `### CEVAP ANAHTARI ###` başlığı altında şu formatta ver:
        [Soru Numarası]. [Doğru Şık]
        Örnek:
        1. A
        2. B
        ...

        Her sorunun ait olduğu konuyu (Ders > Konu > Alt Konu formatında) ve zorluk derecesini ayrıca her sorunun hemen üstüne şu formatta belirt:
        [KONU: Matematik > Türev > Limit, ZORLUK: Orta]

        Quiz Konuları:
        - {konular_for_ai_str}
        """
        
        try:
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            response = model.generate_content(prompt)
            quiz_icerigi_raw = response.text

            # Quiz içeriğini ve cevap anahtarını ayrıştır
            quiz_parts = quiz_icerigi_raw.split("### CEVAP ANAHTARI ###")
            if len(quiz_parts) < 2:
                raise ValueError("Quiz içeriği veya cevap anahtarı bulunamadı.")
            
            quiz_sorular_text = quiz_parts[0].strip()
            cevap_anahtari_text = quiz_parts[1].strip()

            # Soruları parse et ve geçici Question objelerine dönüştür
            questions_data = []
            current_question = {}
            for line in quiz_sorular_text.split('\n'):
                line = line.strip()
                if line.startswith('**Soru'):
                    if current_question:
                        questions_data.append(current_question)
                    current_question = {'text': line, 'options': {}, 'topic': '', 'difficulty': ''}
                elif line.startswith('[KONU:'):
                    topic_match = re.search(r'KONU: (.*?), ZORLUK: (.*?)\]', line)
                    if topic_match:
                        current_question['topic'] = topic_match.group(1).strip()
                        current_question['difficulty'] = topic_match.group(2).strip()
                elif re.match(r'^[A-E]\)', line):
                    option_key = line[0]
                    current_question['options'][option_key] = line[2:].strip()
                elif current_question:
                    # Eğer bu bir şık değilse, sorunun devamı olabilir
                    if 'text' in current_question:
                        current_question['text'] += '\n' + line

            if current_question: # Son soruyu da ekle
                questions_data.append(current_question)

            # Cevap anahtarını parse et
            cevap_anahtari_map = {}
            for line in cevap_anahtari_text.split('\n'):
                line = line.strip()
                if re.match(r'^\d+\.', line):
                    parts = line.split('.', 1)
                    q_num = parts[0].strip()
                    ans = parts[1].strip()
                    cevap_anahtari_map[int(q_num)] = ans

            # Soruları şablona göndermek için Question objelerine dönüştür
            secilen_sorular_objeleri = []
            for i, q_data in enumerate(questions_data):
                q_text = q_data['text'].replace(f'**Soru {i+1}:**', '').strip()
                correct_ans = cevap_anahtari_map.get(i+1, 'X') # Güvenlik için
                # Burada gerçek Question objeleri yaratıp ID ataması yapıyoruz,
                # ancak bunlar henüz DB'ye kaydedilmediği için sadece front-end'de kullanılacak.
                # Gerçek senaryoda bu sorular DB'ye kaydedilmeli ve gerçek ID'leri alınmalı.
                temp_question = Question(
                    text=q_text,
                    options_json=json.dumps(q_data['options']),
                    correct_answer=correct_ans,
                    topic=q_data['topic'],
                    difficulty=q_data['difficulty']
                )
                # Geçici bir ID atayalım, veya daha iyisi, her soruyu DB'ye kaydedip gerçek ID'sini kullanalım.
                # Quiz'i submit ederken bu geçici ID'ler sorun yaratacaktır.
                # Bu yüzden, bu adımı atladığımız için, mini-quizde soru kayıt kısmı şimdilik pasif kalacak.
                temp_question.id = i + 1 # Geçici bir ID ataması
                secilen_sorular_objeleri.append(temp_question)
            
            flash('Quiz başarıyla oluşturuldu!', 'success')

        except Exception as e:
            print(f"Quiz oluşturma hatası: {e}")
            flash(f"Quiz oluşturulurken bir hata oluştu: {e}. Lütfen daha sonra tekrar deneyin.", "danger")
            quiz_icerigi = None # Hata durumunda quiz_icerigi'ni None yapalım.


    # QUIZ SONUÇLARINI GÖNDERME (POST)
    elif request.method == 'POST' and 'submit_quiz' in request.form:
        # Bu kısım, AI Geliştirmeleri adımı atlandığı için çalışmayacak.
        # Çünkü quiz soruları DB'ye kaydedilmediği ve gerçek ID'leri olmadığı için
        # Formdan gelen soru ID'leri ile eşleşme sağlanamaz.
        flash('Quiz sonuç analizi yapılamıyor: Soru verileri bulunamadı.', 'danger')
        quiz_analizi = "Quiz analiz raporu oluşturulamadı çünkü sorular veritabanına kaydedilemedi."
        
        # Aşağıdaki kod aslında quiz geliştirme adımına aittir, bu adım atlandığı için burayı çalıştırmayacağız.
        """
        kullanici_cevaplari = {}
        dogru_cevap_sayisi = 0
        yanlis_cevap_sayisi = 0
        bos_cevap_sayisi = 0
        cevaplanan_sorular_listesi = []

        for key, value in request.form.items():
            if key.startswith('soru_'):
                question_id = int(key.replace('soru_', ''))
                kullanici_cevaplari[question_id] = value

        for q_id, u_answer in kullanici_cevaplari.items():
            question = Question.query.get(q_id)
            if question:
                is_correct = (u_answer == question.correct_answer)
                user_quiz_answer = UserQuizAnswer(
                    user_id=current_user.id,
                    question_id=question.id,
                    user_answer=u_answer,
                    is_correct=is_correct
                )
                db.session.add(user_quiz_answer)

                if is_correct:
                    dogru_cevap_sayisi += 1
                else:
                    yanlis_cevap_sayisi += 1
                    cevaplanan_sorular_listesi.append({
                        'soru_metni': question.text,
                        'kullanici_cevabi': u_answer,
                        'dogru_cevap': question.correct_answer,
                        'konu': question.topic,
                        'zorluk': question.difficulty
                    })

        db.session.commit()

        ai_analiz_prompt = f\"\"\"
        Sen bir YKS quiz değerlendirme uzmanısın. Bir öğrencinin mini quiz sonuçlarını ve yanlış cevapladığı soruların detaylarını vereceğim.
        Aşağıdaki formata göre detaylı bir geri bildirim ve analiz yapmanı istiyorum:
        ### 📊 Quiz Sonuç Özeti
        * Toplam Soru Sayısı: {len(kullanici_cevaplari)}
        * Doğru Cevap Sayısı: {dogru_cevap_sayisi}
        * Yanlış Cevap Sayısı: {yanlis_cevap_sayisi}
        * Boş Bırakılan Soru Sayısı: {bos_cevap_sayisi}
        ### 🤔 Hata Analizi ve Gelişim Alanları
        Yanlış cevaplanan soruların detayları:
        {json.dumps(cevaplanan_sorular_listesi, ensure_ascii=False, indent=2)}
        (...)
        \"\"\"
        try:
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            response = model.generate_content(ai_analiz_prompt)
            quiz_analizi = response.text.strip()
            flash('Quiz sonuçlarınız başarıyla analiz edildi!', 'success')
        except Exception as e:
            flash(f"Quiz sonuç analizi yapılırken bir hata oluştu: {e}.", "danger")
            quiz_analizi = "Quiz analiz raporu oluşturulamadı."
        quiz_icerigi = None
        secilen_sorular_objeleri = []
        """


    # GET isteği veya POST sonrası quiz_icerigi/quiz_analizi None ise quiz oluşturma formunu göster
    # Tum_konular, Konu modeli atlandığı için burada None olarak gönderilecek veya boş liste.
    return render_template('mini_quiz.html', 
                           title='Mini Quiz', 
                           konular=konu_havuzu, # Tekrar konuları
                           tum_konular=[], # Konu modeli atlandığı için boş liste
                           quiz_icerigi=quiz_icerigi, # AI'dan gelen ham quiz içeriği (eğer quiz oluşturulmuşsa)
                           secilen_sorular=secilen_sorular_objeleri, # Şablona gönderilen parse edilmiş soru objeleri
                           quiz_analizi=quiz_analizi) # AI'dan gelen quiz analiz raporu

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
    
    # Form'dan gelen kod
    # from app.forms import RequestResetForm # Buradan import edilmesi gerekiyor
    # form = RequestResetForm() 
    
    # Geçici olarak forms.py'deki formları içermediğimiz için manuel form kontrolü
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for('reset_token', token=token, _external=True)
            send_email(user.email, 'YKS Asistanı: Şifre Sıfırlama İsteği', 'reset_password', 
                       user=user, reset_url=reset_url, expires_min=30) # 30 dakika geçerlilik
            flash('Şifre sıfırlama talimatları e-posta adresinize gönderildi. Lütfen e-postanızı kontrol edin.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Bu e-posta adresine sahip bir kullanıcı bulunamadı.', 'danger')
            # Güvenlik için, e-posta bulunmasa bile "gönderildi" mesajı vermek daha iyi olabilir
            # flash('Şifre sıfırlama talimatları e-posta adresinize gönderildi (eğer kayıtlıysa).', 'info')
            
    return render_template('reset_request.html', title='Şifre Sıfırla') # form=form çıkarıldı

# YENİ: Şifre Sıfırlama Token Doğrulama ve Yeni Şifre Belirleme Rotası
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('anasayfa'))
    
    user = User.verify_reset_token(token)
    if not user:
        flash('Şifre sıfırlama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('reset_request'))
    
    # Form'dan gelen kod
    # from app.forms import ResetPasswordForm # Buradan import edilmesi gerekiyor
    # form = ResetPasswordForm() 
    
    # Geçici olarak forms.py'deki formları içermediğimiz için manuel form kontrolü
    if request.method == 'POST':
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if password != password2:
            flash('Şifreler eşleşmiyor.', 'danger')
            return redirect(url_for('reset_token', token=token))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password_hash = hashed_password
        db.session.commit()
        flash('Şifreniz başarıyla güncellendi! Artık yeni şifrenizle giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_token.html', title='Şifre Sıfırla') # form=form çıkarıldı


# --- UYGULAMAYI ÇALIŞTIR ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)