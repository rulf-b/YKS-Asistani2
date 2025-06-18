# --- KÜTÜPHANELER ---
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, DateTime, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime
import os
from dotenv import load_dotenv
import google.generativeai as genai
from markdown import markdown
import json
from typing import Optional
from starlette.middleware.sessions import SessionMiddleware
import bcrypt
from itsdangerous import URLSafeTimedSerializer
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from models import Base, User, Hedef, SoruAnaliz, DenemeSinavi, CalismaOturumu, QuizSonucu, HaftalikPlan, PasswordResetToken

# --- UYGULAMA KURULUMU ---
load_dotenv()

# Mail ayarları (Gmail için örnek - kendi bilgilerinizle değiştirin)
MAIL_CONFIG = {
    'MAIL_USERNAME': os.getenv('MAIL_USERNAME', 'test@example.com'),
    'MAIL_PASSWORD': os.getenv('MAIL_PASSWORD', 'test-password'),
    'MAIL_FROM': os.getenv('MAIL_FROM', 'test@example.com'),
    'MAIL_PORT': int(os.getenv('MAIL_PORT', '587')),
    'MAIL_SERVER': os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    'MAIL_TLS': os.getenv('MAIL_TLS', 'True').lower() == 'true',
    'MAIL_SSL': os.getenv('MAIL_SSL', 'False').lower() == 'true'
}

app = FastAPI(title="YKS Asistanı", version="1.0.0")

# Session middleware ekle
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY', 'varsayilan-gizli-anahtar'))

# Jinja2 templates kurulumu
templates = Jinja2Templates(directory="templates")
templates.env.filters['markdown'] = markdown

# Veritabanı kurulumu
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
else:
    database_url = 'sqlite:///veritabani.db'

engine = create_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Şifreleme
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Gemini API kurulumu
api_key_global = os.getenv("GOOGLE_API_KEY")
if api_key_global:
    genai.configure(api_key=api_key_global)
    print(f"API Anahtarı Yüklendi mi?: {bool(api_key_global)}")
else:
    print("UYARI: Gemini API anahtarı .env dosyasında bulunamadı.")

# --- VERİTABANI MODELLERİ ---
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
    reset_token_used = Column(Boolean, default=False)  # Token kullanıldı mı?

    def set_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def get_reset_token(self, expires_sec=600):  # 10 dakika geçerli
        # Önceki token'ı sıfırla
        self.reset_token_used = False
        s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'varsayilan-gizli-anahtar'))
        return s.dumps({'user_id': self.id}, salt='reset-password')
    
    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'varsayilan-gizli-anahtar'))
        try:
            user_id = s.loads(token, salt='reset-password', max_age=600)['user_id']  # 10 dakika
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

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

# --- DEPENDENCY FUNCTIONS ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    user = db.query(User).filter(User.id == user_id).first()
    return user

def login_required(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return None
    return user

def admin_required(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None or not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bu sayfaya erişim yetkiniz yok")
    return user

# --- ROUTES ---
@app.get("/", response_class=HTMLResponse)
async def anasayfa(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    # Kullanıcının verilerini veritabanından çek
    denemeler = db.query(DenemeSinavi).filter(DenemeSinavi.user_id == user.id).order_by(DenemeSinavi.tarih.desc()).limit(3).all()
    analizler = db.query(SoruAnaliz).filter(SoruAnaliz.user_id == user.id).order_by(SoruAnaliz.tarih.desc()).limit(5).all()
    calismalar = db.query(CalismaOturumu).filter(CalismaOturumu.user_id == user.id).order_by(CalismaOturumu.tarih.desc()).limit(5).all()
    
    # İstatistikler
    toplam_calisma_suresi_dakika = db.query(CalismaOturumu.calisma_suresi_dakika).filter(CalismaOturumu.user_id == user.id).all()
    toplam_calisma_suresi_dakika = sum([c.calisma_suresi_dakika for c in toplam_calisma_suresi_dakika]) if toplam_calisma_suresi_dakika else 0
    toplam_calisma_suresi_saat = toplam_calisma_suresi_dakika / 60
    
    toplam_analiz_edilen_soru = db.query(SoruAnaliz).filter(SoruAnaliz.user_id == user.id).count()
    
    # Net hesaplamaları
    current_user_tyt_net = 0
    current_user_ayt_net = 0
    tyt_ilerleme_yuzde = 0
    ayt_ilerleme_yuzde = 0
    
    son_deneme = db.query(DenemeSinavi).filter(DenemeSinavi.user_id == user.id).order_by(DenemeSinavi.tarih.desc()).first()
    hedef = db.query(Hedef).filter(Hedef.user_id == user.id).first()
    
    if son_deneme:
        current_user_tyt_net = (son_deneme.tyt_turkce_d - son_deneme.tyt_turkce_y / 4) + \
                              (son_deneme.tyt_sosyal_d - son_deneme.tyt_sosyal_y / 4) + \
                              (son_deneme.tyt_mat_d - son_deneme.tyt_mat_y / 4) + \
                              (son_deneme.tyt_fen_d - son_deneme.tyt_fen_y / 4)
        
        current_user_ayt_net = (son_deneme.ayt_mat_d - son_deneme.ayt_mat_y / 4) + \
                              (son_deneme.ayt_fiz_d - son_deneme.ayt_fiz_y / 4) + \
                              (son_deneme.ayt_kim_d - son_deneme.ayt_kim_y / 4) + \
                              (son_deneme.ayt_biy_d - son_deneme.ayt_biy_y / 4)
    
    if hedef:
        if hedef.hedef_tyt_net and hedef.hedef_tyt_net > 0:
            tyt_ilerleme_yuzde = (current_user_tyt_net / hedef.hedef_tyt_net) * 100
        if hedef.hedef_ayt_net and hedef.hedef_ayt_net > 0:
            ayt_ilerleme_yuzde = (current_user_ayt_net / hedef.hedef_ayt_net) * 100
    
    return templates.TemplateResponse("anasayfa.html", {
        "request": request,
        "user": user,
        "denemeler": denemeler,
        "analizler": analizler,
        "calisma_oturumları": calismalar,
        "toplam_calisma_suresi_dakika": toplam_calisma_suresi_dakika,
        "toplam_calisma_suresi_saat": toplam_calisma_suresi_saat,
        "toplam_analiz_edilen_soru": toplam_analiz_edilen_soru,
        "tekrar_konu_sayisi": 0,  # Basitleştirilmiş
        "tyt_ilerleme_yuzde": tyt_ilerleme_yuzde,
        "ayt_ilerleme_yuzde": ayt_ilerleme_yuzde,
        "current_user_tyt_net": current_user_tyt_net,
        "current_user_ayt_net": current_user_ayt_net,
        "hedef": hedef
    })

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    registered = request.query_params.get("registered")
    success = None
    if registered:
        success = "Kayıt başarılı! Lütfen giriş yapın."
    return templates.TemplateResponse("login.html", {"request": request, "user": None, "success": success})

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    db: Session = Depends(get_db)
):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    error = None
    if not username or not password:
        error = "Kullanıcı adı ve şifre zorunludur."
        return templates.TemplateResponse("login.html", {"request": request, "error": error, "user": None})
    user = db.query(User).filter(User.username == username).first()
    if user and user.check_password(password):
        request.session["user_id"] = user.id
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    else:
        error = "Kullanıcı adı veya şifre hatalı."
        return templates.TemplateResponse("login.html", {"request": request, "error": error, "user": None})

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "user": None})

@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    db: Session = Depends(get_db)
):
    form = await request.form()
    username = form.get("username")
    email = form.get("email")
    password = form.get("password")
    password2 = form.get("password2")
    error = None
    if not username or not email or not password or not password2:
        error = "Tüm alanlar zorunludur."
        return templates.TemplateResponse("register.html", {"request": request, "error": error, "user": None})
    if password != password2:
        error = "Şifreler eşleşmiyor."
        return templates.TemplateResponse("register.html", {"request": request, "error": error, "user": None})
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        error = "Bu kullanıcı adı zaten kullanılıyor."
        return templates.TemplateResponse("register.html", {"request": request, "error": error, "user": None})
    # Yeni kullanıcı oluştur
    user = User(username=username, email=email)
    user.set_password(password)
    db.add(user)
    db.commit()
    # Kayıt başarılı, ana sayfaya yönlendir
    request.session['user_id'] = user.id
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return response

# --- GEMINI API FONKSİYONU ---
def get_gemini_analysis(soru_metni=None, soru_resmi=None, ogrenci_cevabi=""):
    if not api_key_global:
        return "Gemini API anahtarı ayarlanmadığı için analiz yapılamıyor. Lütfen .env dosyanızda GOOGLE_API_KEY tanımlı mı kontrol edin.", None, None, None
    model = genai.GenerativeModel('gemini-1.5-pro-latest')
    prompt = f"""
    Sen bir YKS (Yükseköğretim Kurumları Sınavı) soru analiz uzmanısın. 
    Öğrencinin verdiği cevabı analiz et ve aşağıdaki formatta yanıt ver:

    ## BÖLÜM 1: SORU ANALİZİ
    - **Konu:** [Soru hangi konudan?]
    - **Zorluk Seviyesi:** [Kolay/Orta/Zor]
    - **Çözüm Yöntemi:** [Nasıl çözülür?]

    ## BÖLÜM 2: ÖĞRENCİ CEVABI DEĞERLENDİRMESİ
    - **Doğruluk:** [Doğru/Yanlış/Kısmen Doğru]
    - **Hata Türü:** [Bilgi Eksikliği/İşlem Hatası/Kavram Yanılgısı/Dikkat Hatası]
    - **Öneriler:** [Öğrenciye özel tavsiyeler]

    ---

    **SORU:** {soru_metni}
    **ÖĞRENCİ CEVABI:** {ogrenci_cevabi}
    """
    try:
        response = model.generate_content(prompt)
        return response.text, None, None, None
    except Exception as e:
        import traceback
        print("------------ GEMINI API HATA DETAYI BAŞLANGIÇ ------------")
        print(f"Yapay zekâya bağlanırken bir sorun oluştu: {e}")
        traceback.print_exc()
        print("------------ GEMINI API HATA DETAYI BİTİŞ ------------")
        return f"Yapay zekâya bağlanırken bir hata oluştu: {e}\nLütfen API anahtarınızı ve internet bağlantınızı kontrol edin.", None, None, None

@app.get("/soru-analizi", response_class=HTMLResponse)
async def soru_analizi_page(request: Request, current_user: User = Depends(login_required)):
    return templates.TemplateResponse("soru_analizi.html", {
        "request": request,
        "user": current_user,
        "benzer_sorular": [],
        "gecmis_analizler": []
    })

@app.post("/soru-analizi")
async def soru_analizi(
    request: Request,
    soru_metni: str = Form(...),
    ogrenci_cevabi: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    analiz_sonucu, konu, zorluk, hata_turu = get_gemini_analysis(soru_metni, None, ogrenci_cevabi)
    
    # Veritabanına kaydet
    soru_analiz = SoruAnaliz(
        soru_metni=soru_metni,
        cevap_metni=ogrenci_cevabi,
        analiz_sonucu=analiz_sonucu,
        konu=konu,
        zorluk_derecesi=zorluk,
        hata_turu=hata_turu,
        user_id=current_user.id
    )
    db.add(soru_analiz)
    db.commit()
    
    return templates.TemplateResponse("soru_analizi.html", {
        "request": request,
        "user": current_user,
        "analiz_sonucu": analiz_sonucu
    })

@app.get("/deneme_takibi", response_class=HTMLResponse)
async def deneme_takibi_page(request: Request, current_user: User = Depends(login_required), db: Session = Depends(get_db)):
    # Kullanıcının denemelerini veritabanından çek
    denemeler = db.query(DenemeSinavi).filter(DenemeSinavi.user_id == current_user.id).order_by(DenemeSinavi.tarih.desc()).all()
    
    # Grafik için verileri hazırla
    denemeler_grafik_icin = list(reversed(denemeler))
    grafik_etiketler = [f"{d.kaynak} ({d.tarih.strftime('%d-%m')})" for d in denemeler_grafik_icin]
    grafik_veriler = [(d.tyt_turkce_d-d.tyt_turkce_y/4)+(d.tyt_sosyal_d-d.tyt_sosyal_y/4)+(d.tyt_mat_d-d.tyt_mat_y/4)+(d.tyt_fen_d-d.tyt_fen_y/4) for d in denemeler_grafik_icin]
    
    return templates.TemplateResponse("deneme_takibi.html", {
        "request": request,
        "user": current_user,
        "denemeler": denemeler,
        "grafik_etiketler": json.dumps(grafik_etiketler),
        "grafik_veriler": json.dumps(grafik_veriler),
        "denemeler_grafik_icin": denemeler_grafik_icin
    })

@app.get("/hedef_belirle", response_class=HTMLResponse)
async def hedef_belirle_page(request: Request, current_user: User = Depends(login_required), db: Session = Depends(get_db)):
    # Kullanıcının mevcut hedefini veritabanından çek
    hedef = db.query(Hedef).filter(Hedef.user_id == current_user.id).first()
    
    # Mevcut boş zamanları çek
    mevcut_bos_zamanlar = {}
    if current_user.bos_zamanlar_json:
        try:
            mevcut_bos_zamanlar = json.loads(current_user.bos_zamanlar_json)
        except:
            mevcut_bos_zamanlar = {}
    
    return templates.TemplateResponse("hedef_belirle.html", {
        "request": request,
        "user": current_user,
        "hedef": hedef,
        "mevcut_bos_zamanlar": mevcut_bos_zamanlar
    })

@app.get("/mini_quiz", response_class=HTMLResponse)
async def mini_quiz_page(
    request: Request, 
    success: Optional[str] = None,
    current_user: User = Depends(login_required),
    db: Session = Depends(get_db)
):
    # Quiz konuları (gerçek uygulamada veritabanından çekilecek)
    konular = ["Matematik", "Fizik", "Kimya", "Biyoloji", "Türkçe", "Tarih", "Coğrafya"]
    
    # Kullanıcının quiz sonuçlarını getir
    quiz_sonuclari = db.query(QuizSonucu).filter(QuizSonucu.user_id == current_user.id).order_by(QuizSonucu.tarih.desc()).all()
    
    # Basit quiz içeriği oluştur
    quiz_icerigi = """
# Mini Quiz: Matematik

## Soru 1
**Soru:** 2x + 5 = 13 denkleminin çözümü nedir?

A) x = 4  
B) x = 3  
C) x = 5  
D) x = 6

**Cevap:** A) x = 4

---

## Soru 2
**Soru:** Bir üçgenin iç açıları toplamı kaç derecedir?

A) 90°  
B) 180°  
C) 270°  
D) 360°

**Cevap:** B) 180°

---

## Soru 3
**Soru:** 3² × 2³ işleminin sonucu nedir?

A) 24  
B) 48  
C) 72  
D) 96

**Cevap:** C) 72

---

## Soru 4
**Soru:** Bir sayının %20'si 40 ise, bu sayı kaçtır?

A) 100  
B) 150  
C) 200  
D) 250

**Cevap:** C) 200

---

## Soru 5
**Soru:** 0.25 kesri yüzde olarak nasıl yazılır?

A) %25  
B) %2.5  
C) %0.25  
D) %250

**Cevap:** A) %25
"""
    
    success_message = None
    if success == "1":
        success_message = "Quiz sonucu başarıyla kaydedildi!"
    
    return templates.TemplateResponse("mini_quiz.html", {
        "request": request,
        "user": current_user,
        "quiz_sonuclari": quiz_sonuclari,
        "konular": konular,
        "quiz_icerigi": quiz_icerigi,
        "success_message": success_message
    })

@app.post("/mini_quiz")
async def mini_quiz_post(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        # Form verilerini manuel olarak al
        form = await request.form()
        
        # Quiz sonuçlarını al
        dogru_sayisi = int(form.get('dogru_sayisi', 0))
        yanlis_sayisi = int(form.get('yanlis_sayisi', 0))
        bos_sayisi = int(form.get('bos_sayisi', 0))
        konu = form.get('konu', 'Genel')
        
        # Yeni quiz sonucu oluştur
        yeni_quiz = QuizSonucu(
            dogru_sayisi=dogru_sayisi,
            yanlis_sayisi=yanlis_sayisi,
            bos_sayisi=bos_sayisi,
            konu=konu,
            user_id=current_user.id
        )
        db.add(yeni_quiz)
        db.commit()
        
        return RedirectResponse(url="/mini_quiz?success=1", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        return templates.TemplateResponse("mini_quiz.html", {
            "request": request,
            "user": current_user,
            "quiz_sonuclari": [],
            "konular": ["Matematik", "Fizik", "Kimya", "Biyoloji", "Türkçe", "Tarih", "Coğrafya"],
            "quiz_icerigi": "",
            "error": f"Kayıt sırasında hata oluştu: {str(e)}"
        })

@app.get("/haftalik_plan", response_class=HTMLResponse)
async def haftalik_plan_page(request: Request, current_user: User = Depends(login_required)):
    return templates.TemplateResponse("haftalik_plan.html", {
        "request": request,
        "user": current_user,
        "planlar": []
    })

@app.get("/calisma_takibi")
async def calisma_takibi(
    request: Request,
    success: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    gecmis_oturumlar = db.query(CalismaOturumu).filter(CalismaOturumu.user_id == current_user.id).order_by(CalismaOturumu.tarih.desc()).all()
    
    success_message = None
    if success == "1":
        success_message = "Çalışma oturumu başarıyla kaydedildi!"
    
    return templates.TemplateResponse("calisma_takibi.html", {
        "request": request,
        "user": current_user,
        "gecmis_oturumlar": gecmis_oturumlar,
        "success_message": success_message
    })

@app.get("/ai-geri-bildirim", response_class=HTMLResponse)
async def ai_feedback_page(request: Request, current_user: User = Depends(login_required)):
    return templates.TemplateResponse("ai_feedback.html", {
        "request": request,
        "user": current_user,
        "feedback_report": ""
    })

@app.post("/calisma_takibi")
async def calisma_takibi_post(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        # Form verilerini manuel olarak al
        form = await request.form()
        calisma_suresi_str = form.get("calisma_suresi", "")
        konu_adi = form.get("konu_adi", "")
        
        # Çalışma süresini sayıya çevir
        try:
            calisma_suresi = int(calisma_suresi_str) if calisma_suresi_str else None
        except ValueError:
            calisma_suresi = None
        
        # Form validasyonu
        if not calisma_suresi or calisma_suresi < 1:
            gecmis_oturumlar = db.query(CalismaOturumu).filter(CalismaOturumu.user_id == current_user.id).order_by(CalismaOturumu.tarih.desc()).all()
            return templates.TemplateResponse("calisma_takibi.html", {
                "request": request,
                "user": current_user,
                "gecmis_oturumlar": gecmis_oturumlar,
                "error": "Çalışma süresi 1 dakikadan az olamaz."
            })
        
        # Yeni oturum oluştur
        yeni_oturum = CalismaOturumu(
            calisma_suresi_dakika=calisma_suresi,
            konu_adi=konu_adi,
            user_id=current_user.id
        )
        db.add(yeni_oturum)
        db.commit()
        
        # Başarı mesajı ile yönlendir
        response = RedirectResponse(url="/calisma_takibi?success=1", status_code=status.HTTP_302_FOUND)
        return response
        
    except Exception as e:
        gecmis_oturumlar = db.query(CalismaOturumu).filter(CalismaOturumu.user_id == current_user.id).order_by(CalismaOturumu.tarih.desc()).all()
        return templates.TemplateResponse("calisma_takibi.html", {
            "request": request,
            "user": current_user,
            "gecmis_oturumlar": gecmis_oturumlar,
            "error": f"Kayıt sırasında hata oluştu: {str(e)}"
        })

@app.post("/deneme_takibi")
async def deneme_takibi_post(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        # Form verilerini manuel olarak al
        form = await request.form()
        
        # Tüm form alanlarını güvenli şekilde al
        kaynak = form.get('kaynak', 'Bilinmeyen')
        tyt_turkce_d = int(form.get('tyt_turkce_d', 0))
        tyt_turkce_y = int(form.get('tyt_turkce_y', 0))
        tyt_sosyal_d = int(form.get('tyt_sosyal_d', 0))
        tyt_sosyal_y = int(form.get('tyt_sosyal_y', 0))
        tyt_mat_d = int(form.get('tyt_mat_d', 0))
        tyt_mat_y = int(form.get('tyt_mat_y', 0))
        tyt_fen_d = int(form.get('tyt_fen_d', 0))
        tyt_fen_y = int(form.get('tyt_fen_y', 0))
        ayt_mat_d = int(form.get('ayt_mat_d', 0))
        ayt_mat_y = int(form.get('ayt_mat_y', 0))
        ayt_fiz_d = int(form.get('ayt_fiz_d', 0))
        ayt_fiz_y = int(form.get('ayt_fiz_y', 0))
        ayt_kim_d = int(form.get('ayt_kim_d', 0))
        ayt_kim_y = int(form.get('ayt_kim_y', 0))
        ayt_biy_d = int(form.get('ayt_biy_d', 0))
        ayt_biy_y = int(form.get('ayt_biy_y', 0))
        ayt_edebiyat_d = int(form.get('ayt_edebiyat_d', 0))
        ayt_edebiyat_y = int(form.get('ayt_edebiyat_y', 0))
        ayt_tarih1_d = int(form.get('ayt_tarih1_d', 0))
        ayt_tarih1_y = int(form.get('ayt_tarih1_y', 0))
        ayt_cografya1_d = int(form.get('ayt_cografya1_d', 0))
        ayt_cografya1_y = int(form.get('ayt_cografya1_y', 0))
        ayt_tarih2_d = int(form.get('ayt_tarih2_d', 0))
        ayt_tarih2_y = int(form.get('ayt_tarih2_y', 0))
        ayt_cografya2_d = int(form.get('ayt_cografya2_d', 0))
        ayt_cografya2_y = int(form.get('ayt_cografya2_y', 0))
        ayt_felsefe_d = int(form.get('ayt_felsefe_d', 0))
        ayt_felsefe_y = int(form.get('ayt_felsefe_y', 0))
        ayt_din_d = int(form.get('ayt_din_d', 0))
        ayt_din_y = int(form.get('ayt_din_y', 0))
        
        yeni_deneme = DenemeSinavi(
            kaynak=kaynak,
            tyt_turkce_d=tyt_turkce_d,
            tyt_turkce_y=tyt_turkce_y,
            tyt_sosyal_d=tyt_sosyal_d,
            tyt_sosyal_y=tyt_sosyal_y,
            tyt_mat_d=tyt_mat_d,
            tyt_mat_y=tyt_mat_y,
            tyt_fen_d=tyt_fen_d,
            tyt_fen_y=tyt_fen_y,
            ayt_mat_d=ayt_mat_d,
            ayt_mat_y=ayt_mat_y,
            ayt_fiz_d=ayt_fiz_d,
            ayt_fiz_y=ayt_fiz_y,
            ayt_kim_d=ayt_kim_d,
            ayt_kim_y=ayt_kim_y,
            ayt_biy_d=ayt_biy_d,
            ayt_biy_y=ayt_biy_y,
            ayt_edebiyat_d=ayt_edebiyat_d,
            ayt_edebiyat_y=ayt_edebiyat_y,
            ayt_tarih1_d=ayt_tarih1_d,
            ayt_tarih1_y=ayt_tarih1_y,
            ayt_cografya1_d=ayt_cografya1_d,
            ayt_cografya1_y=ayt_cografya1_y,
            ayt_tarih2_d=ayt_tarih2_d,
            ayt_tarih2_y=ayt_tarih2_y,
            ayt_cografya2_d=ayt_cografya2_d,
            ayt_cografya2_y=ayt_cografya2_y,
            ayt_felsefe_d=ayt_felsefe_d,
            ayt_felsefe_y=ayt_felsefe_y,
            ayt_din_d=ayt_din_d,
            ayt_din_y=ayt_din_y,
            user_id=current_user.id
        )
        db.add(yeni_deneme)
        db.commit()
        
        return RedirectResponse(url="/deneme_takibi?success=1", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        return templates.TemplateResponse("deneme_takibi.html", {
            "request": request,
            "user": current_user,
            "denemeler": [],
            "grafik_etiketler": [],
            "grafik_veriler": [],
            "denemeler_grafik_icin": [],
            "error": f"Kayıt sırasında hata oluştu: {str(e)}"
        })

@app.post("/hedef_belirle")
async def hedef_belirle_post(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        # Form verilerini manuel olarak al
        form = await request.form()
        
        # Hedef bilgilerini al
        hedef_tyt = int(form.get('hedef_tyt', 0))
        hedef_ayt = int(form.get('hedef_ayt', 0))
        hedef_ydt = int(form.get('hedef_ydt', 0))
        hedef_okul = form.get('hedef_okul', '')
        hedef_bolum = form.get('hedef_bolum', '')
        hedef_tarih = form.get('hedef_tarih', '')
        
        # Mevcut hedefi kontrol et
        mevcut_hedef = db.query(Hedef).filter(Hedef.user_id == current_user.id).first()
        
        if mevcut_hedef:
            # Mevcut hedefi güncelle
            mevcut_hedef.hedef_tyt = hedef_tyt
            mevcut_hedef.hedef_ayt = hedef_ayt
            mevcut_hedef.hedef_ydt = hedef_ydt
            mevcut_hedef.hedef_okul = hedef_okul
            mevcut_hedef.hedef_bolum = hedef_bolum
            mevcut_hedef.hedef_tarih = hedef_tarih
        else:
            # Yeni hedef oluştur
            yeni_hedef = Hedef(
                hedef_tyt=hedef_tyt,
                hedef_ayt=hedef_ayt,
                hedef_ydt=hedef_ydt,
                hedef_okul=hedef_okul,
                hedef_bolum=hedef_bolum,
                hedef_tarih=hedef_tarih,
                user_id=current_user.id
            )
            db.add(yeni_hedef)
        
        db.commit()
        return RedirectResponse(url="/hedef_belirle?success=1", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        return templates.TemplateResponse("hedef_belirle.html", {
            "request": request,
            "user": current_user,
            "hedef": None,
            "error": f"Kayıt sırasında hata oluştu: {str(e)}"
        })

@app.post("/haftalik_plan")
async def haftalik_plan_post(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        # Form verilerini manuel olarak al
        form = await request.form()
        
        # Plan bilgilerini al
        gun = form.get('gun', '')
        konu = form.get('konu', '')
        sure = int(form.get('sure', 0))
        notlar = form.get('notlar', '')
        
        # Yeni plan oluştur
        yeni_plan = HaftalikPlan(
            gun=gun,
            konu=konu,
            sure=sure,
            notlar=notlar,
            user_id=current_user.id
        )
        db.add(yeni_plan)
        db.commit()
        
        return RedirectResponse(url="/haftalik_plan?success=1", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        return templates.TemplateResponse("haftalik_plan.html", {
            "request": request,
            "user": current_user,
            "planlar": [],
            "error": f"Kayıt sırasında hata oluştu: {str(e)}"
        })

@app.get("/performans_yorumu")
async def performans_yorumu(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    # Basit performans yorumu
    return RedirectResponse(url="/deneme_takibi", status_code=status.HTTP_302_FOUND)

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    # Tüm kullanıcıları getir
    users = db.query(User).all()
    
    # İstatistikler
    total_users = len(users)
    total_denemeler = db.query(DenemeSinavi).count()
    total_calisma_oturumlari = db.query(CalismaOturumu).count()
    total_quiz_sonuclari = db.query(QuizSonucu).count()
    total_soru_analizleri = db.query(SoruAnaliz).count()
    
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "user": current_user,
        "users": users,
        "total_users": total_users,
        "total_denemeler": total_denemeler,
        "total_calisma_oturumlari": total_calisma_oturumlari,
        "total_quiz_sonuclari": total_quiz_sonuclari,
        "total_soru_analizleri": total_soru_analizleri
    })

@app.get("/admin/user/{user_id}", response_class=HTMLResponse)
async def admin_user_detail(
    request: Request,
    user_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    # Kullanıcıyı getir
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    
    # Kullanıcının verilerini getir
    denemeler = db.query(DenemeSinavi).filter(DenemeSinavi.user_id == user_id).order_by(DenemeSinavi.tarih.desc()).all()
    calisma_oturumlari = db.query(CalismaOturumu).filter(CalismaOturumu.user_id == user_id).order_by(CalismaOturumu.tarih.desc()).all()
    quiz_sonuclari = db.query(QuizSonucu).filter(QuizSonucu.user_id == user_id).order_by(QuizSonucu.tarih.desc()).all()
    soru_analizleri = db.query(SoruAnaliz).filter(SoruAnaliz.user_id == user_id).order_by(SoruAnaliz.tarih.desc()).all()
    hedef = db.query(Hedef).filter(Hedef.user_id == user_id).first()
    haftalik_planlar = db.query(HaftalikPlan).filter(HaftalikPlan.user_id == user_id).order_by(HaftalikPlan.id.desc()).all()
    
    return templates.TemplateResponse("admin/user_detail.html", {
        "request": request,
        "user": current_user,
        "target_user": user,
        "denemeler": denemeler,
        "calisma_oturumlari": calisma_oturumlari,
        "quiz_sonuclari": quiz_sonuclari,
        "soru_analizleri": soru_analizleri,
        "hedef": hedef,
        "haftalik_planlar": haftalik_planlar
    })

@app.post("/admin/user/{user_id}/delete")
async def admin_delete_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    # Kendini silmeye çalışıyorsa engelle
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Kendinizi silemezsiniz")
    
    # Kullanıcıyı getir
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    
    # Kullanıcının tüm verilerini sil
    db.query(DenemeSinavi).filter(DenemeSinavi.user_id == user_id).delete()
    db.query(CalismaOturumu).filter(CalismaOturumu.user_id == user_id).delete()
    db.query(QuizSonucu).filter(QuizSonucu.user_id == user_id).delete()
    db.query(SoruAnaliz).filter(SoruAnaliz.user_id == user_id).delete()
    db.query(Hedef).filter(Hedef.user_id == user_id).delete()
    db.query(HaftalikPlan).filter(HaftalikPlan.user_id == user_id).delete()
    
    # Kullanıcıyı sil
    db.delete(user)
    db.commit()
    
    return RedirectResponse(url="/admin?success=1", status_code=status.HTTP_302_FOUND)

@app.get("/reset_password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    return templates.TemplateResponse("reset_request.html", {"request": request, "user": None})

@app.post("/reset_password", response_class=HTMLResponse)
async def reset_password_post(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    form = await request.form()
    email = form.get("email")
    error = None
    success = None
    user = db.query(User).filter(User.email == email).first()
    if not user:
        error = "Bu e-posta adresine sahip bir kullanıcı bulunamadı."
        return templates.TemplateResponse("reset_request.html", {"request": request, "error": error, "user": None})
    # Token oluştur ve kaydet
    token = user.get_reset_token()
    reset_token_entry = PasswordResetToken(user_id=user.id, token=token)
    db.add(reset_token_entry)
    db.commit()
    reset_url = f"http://localhost:8000/reset_password/{token}"
    # E-posta gönderimi
    try:
        # Mail ayarlarını kontrol et
        if MAIL_CONFIG['MAIL_USERNAME'] == 'test@example.com' or MAIL_CONFIG['MAIL_PASSWORD'] == 'test-password':
            raise Exception("Mail ayarları yapılandırılmamış. Lütfen .env dosyasında mail ayarlarını tanımlayın.")
        
        conf = ConnectionConfig(
            MAIL_USERNAME = MAIL_CONFIG['MAIL_USERNAME'],
            MAIL_PASSWORD = MAIL_CONFIG['MAIL_PASSWORD'],
            MAIL_FROM = MAIL_CONFIG['MAIL_FROM'],
            MAIL_PORT = MAIL_CONFIG['MAIL_PORT'],
            MAIL_SERVER = MAIL_CONFIG['MAIL_SERVER'],
            MAIL_STARTTLS = True,
            MAIL_SSL_TLS = False,
            USE_CREDENTIALS = True
        )
        message = MessageSchema(
            subject="YKS Asistanı Şifre Sıfırlama",
            recipients=[user.email],
            body=f"Şifrenizi sıfırlamak için tıklayın: <a href='{reset_url}'>Şifre Sıfırla</a>",
            subtype="html"
        )
        fm = FastMail(conf)
        background_tasks.add_task(fm.send_message, message)
        success = "Şifre sıfırlama talimatları e-posta adresinize gönderildi. Lütfen e-postanızı kontrol edin."
    except Exception as e:
        # E-posta gönderimi başarısız olursa linki direkt göster
        error_msg = str(e)
        if "Mail ayarları yapılandırılmamış" in error_msg:
            success = f"Mail ayarları yapılandırılmamış. Şifre sıfırlama linki: {reset_url}"
        else:
            success = f"E-posta gönderimi başarısız oldu ({error_msg}). Şifre sıfırlama linki: {reset_url}"
    
    return templates.TemplateResponse("reset_request.html", {"request": request, "success": success, "user": None})

@app.get("/reset_password/{token}", response_class=HTMLResponse)
async def reset_token_page(request: Request, token: str, db: Session = Depends(get_db)):
    reset_token_entry = db.query(PasswordResetToken).filter_by(token=token).first()
    if not reset_token_entry or reset_token_entry.used or reset_token_entry.is_expired():
        error = "Bu şifre sıfırlama linki geçersiz, süresi dolmuş veya daha önce kullanılmış. Yeni bir link talep edin."
        return templates.TemplateResponse("reset_request.html", {"request": request, "error": error, "user": None})
    user = db.query(User).filter(User.id == reset_token_entry.user_id).first()
    if not user:
        error = "Kullanıcı bulunamadı."
        return templates.TemplateResponse("reset_request.html", {"request": request, "error": error, "user": None})
    return templates.TemplateResponse("reset_token.html", {"request": request, "token": token, "user": None})

@app.post("/reset_password/{token}", response_class=HTMLResponse)
async def reset_token_post(request: Request, token: str, db: Session = Depends(get_db)):
    form = await request.form()
    password = form.get("password")
    password2 = form.get("password2")
    reset_token_entry = db.query(PasswordResetToken).filter_by(token=token).first()
    if not reset_token_entry or reset_token_entry.used or reset_token_entry.is_expired():
        error = "Bu şifre sıfırlama linki geçersiz, süresi dolmuş veya daha önce kullanılmış. Yeni bir link talep edin."
        return templates.TemplateResponse("reset_request.html", {"request": request, "error": error, "user": None})
    user = db.query(User).filter(User.id == reset_token_entry.user_id).first()
    if not user:
        error = "Kullanıcı bulunamadı."
        return templates.TemplateResponse("reset_request.html", {"request": request, "error": error, "user": None})
    if not password or not password2 or password != password2:
        error = "Şifreler boş olamaz ve aynı olmalı."
        return templates.TemplateResponse("reset_token.html", {"request": request, "token": token, "error": error, "user": None})
    if user.check_password(password):
        error = "Yeni şifreniz mevcut şifrenizle aynı olamaz."
        return templates.TemplateResponse("reset_token.html", {"request": request, "token": token, "error": error, "user": None})
    user.set_password(password)
    reset_token_entry.used = True
    db.commit()
    success = "Şifreniz başarıyla güncellendi! Artık yeni şifrenizle giriş yapabilirsiniz."
    return templates.TemplateResponse("login.html", {"request": request, "success": success, "user": None})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 