from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
try:
    from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey
    from sqlalchemy.orm import sessionmaker, Session, relationship
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.sql import func
except ImportError as e:
    raise SystemExit(
        "Gerekli kütüphaneler yüklü değil. 'pip install -r requirements.txt' komutunu çalıştırın." 
    ) from e
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
import jwt
import os
import json
import google.generativeai as genai
from dotenv import load_dotenv
import uvicorn
from pydantic import BaseModel, EmailStr
from pathlib import Path

# --- Ortam Değişkenleri ve Temel Kurulum ---
load_dotenv()

Base = declarative_base()

# --- VERİTABANI MODELLERİ ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    ders_tercihi = Column(String, nullable=True)
    bos_zamanlar_json = Column(Text, nullable=True)
    email_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    hedef = relationship("Hedef", back_populates="user", uselist=False, cascade="all, delete-orphan")
    soru_analizleri = relationship("SoruAnaliz", back_populates="user", cascade="all, delete-orphan")
    denemeleri = relationship("DenemeSinavi", back_populates="user", cascade="all, delete-orphan")
    tekrar_konulari = relationship("TekrarKonu", back_populates="user", cascade="all, delete-orphan")
    calisma_oturumlari = relationship("CalismaOturumu", back_populates="user", cascade="all, delete-orphan")

class Hedef(Base):
    __tablename__ = "hedefler"
    id = Column(Integer, primary_key=True, index=True)
    universite = Column(String)
    bolum = Column(String)
    hedef_siralama = Column(Integer)
    hedef_tyt_net = Column(Float)
    hedef_ayt_net = Column(Float)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    user = relationship("User", back_populates="hedef")

class SoruAnaliz(Base):
    __tablename__ = "soru_analizleri"
    id = Column(Integer, primary_key=True, index=True)
    soru_metni = Column(Text)
    cevap_metni = Column(Text)
    analiz_sonucu = Column(Text)
    konu = Column(String)
    zorluk_derecesi = Column(String)
    hata_turu = Column(String)
    tarih = Column(DateTime, default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="soru_analizleri")

class DenemeSinavi(Base):
    __tablename__ = "deneme_sinavlari"
    id = Column(Integer, primary_key=True, index=True)
    kaynak = Column(String)
    tarih = Column(DateTime, default=func.now())
    # ... (tüm net alanları)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="denemeleri")

class TekrarKonu(Base):
    __tablename__ = "tekrar_konulari"
    id = Column(Integer, primary_key=True, index=True)
    konu_adi = Column(String)
    son_tekrar = Column(DateTime, nullable=True)
    tekrar_sayisi = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="tekrar_konulari")

class CalismaOturumu(Base):
    __tablename__ = "calisma_oturumlari"
    id = Column(Integer, primary_key=True, index=True)
    tarih = Column(DateTime, default=func.now())
    calisma_suresi_dakika = Column(Integer)
    konu_adi = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="calisma_oturumlari")

# --- Veritabanı Bağlantısı ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./yks_asistani.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# --- FastAPI Uygulaması ---
app = FastAPI(title="YKS Asistanı v2.0", version="2.0.0")

# --- Middleware ---
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
        return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yks.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- Pydantic Modelleri ---
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- Güvenlik ve Yardımcı Fonksiyonlar ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# .env dosyasında güçlü bir SECRET_KEY tanımlanmalıdır
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY ortam değişkeni tanımsız.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 hafta

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(HTTPBearer()), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

# --- GOOGLE AI ---
api_key_global = os.getenv("GOOGLE_API_KEY")
if api_key_global:
    genai.configure(api_key=api_key_global)

# --- FRONTEND RENDERER ---
templates = Jinja2Templates(directory="templates")
TEMPLATE_FILES = [f for f in os.listdir('templates') if f.endswith('.html')]

def render(request: Request, template_name: str, context: dict = None):
    title = template_name.split(".")[0].replace("_", " ").title()
    base_context = {
        "request": request, "user": None, "title": title, "errors": [], "success": "",
        "hedef": None, "denemeler": [], "analizler": [], "calisma_oturumleri": [],
        "toplam_calisma_suresi_saat": 0, "toplam_calisma_suresi_dakika": 0,
        "toplam_analiz_edilen_soru": 0, "tekrar_konu_sayisi": 0,
        "tyt_ilerleme_yuzde": 0, "ayt_ilerleme_yuzde": 0,
        "current_user_tyt_net": 0, "current_user_ayt_net": 0,
        "haftalik_calisma": [0, 0, 0, 0, 0, 0, 0]
    }
    if context: base_context.update(context)
    return templates.TemplateResponse(template_name, base_context)

# --- API ROTALARI ---
@app.post("/api/register", response_model=Token, tags=["API"])
async def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user_in.email).first()
    if db_user: raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user_in.password)
    new_user = User(username=user_in.username, email=user_in.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/login", response_model=Token, tags=["API"])
async def login_for_access_token(form_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- FRONTEND ROTALARI ---
@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def route_root(request: Request):
    return render(request, "anasayfa.html")

# Diğer tüm HTML sayfaları için otomatik rotalar
for template_file in TEMPLATE_FILES:
    route_path = f"/{template_file.split('.')[0]}"
    if route_path == "/anasayfa": continue # Kök rota zaten var

    def create_route_func(template_name):
        async def route_func(request: Request):
            return render(request, template_name)
        return route_func

    app.get(route_path, response_class=HTMLResponse, tags=["Frontend"])(create_route_func(template_file))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)