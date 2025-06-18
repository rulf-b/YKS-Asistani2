#!/usr/bin/env python3
"""
Admin hesabı oluşturma scripti
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main_fastapi import User, Base
from werkzeug.security import generate_password_hash, check_password_hash

# Veritabanı bağlantısı
DATABASE_URL = "sqlite:///./veritabani.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

def create_admin_user():
    """Admin kullanıcısı oluşturur"""
    db = SessionLocal()
    
    try:
        print("=== YKS Asistanı Admin Hesabı Oluşturma ===\n")
        
        # Kullanıcı adı al
        username = input("Admin kullanıcı adını girin: ").strip()
        if not username:
            print("❌ Kullanıcı adı boş olamaz!")
            return
        
        # Şifre al
        password = input("Admin şifresini girin: ").strip()
        if not password:
            print("❌ Şifre boş olamaz!")
            return
        
        # Kullanıcı adı kontrolü
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"⚠️  '{username}' kullanıcı adı zaten mevcut!")
            choice = input("Bu kullanıcıyı admin yapmak ister misiniz? (e/h): ").strip().lower()
            if choice in ['e', 'evet', 'y', 'yes']:
                existing_user.is_admin = True
                db.commit()
                print(f"✅ '{username}' kullanıcısı admin yapıldı!")
            else:
                print("❌ İşlem iptal edildi.")
            return
        
        # Yeni admin kullanıcısı oluştur
        admin_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            is_admin=True,
            email_confirmed=True
        )
        
        db.add(admin_user)
        db.commit()
        
        print(f"✅ Admin hesabı başarıyla oluşturuldu!")
        print(f"👤 Kullanıcı Adı: {username}")
        print(f"🔑 Şifre: {password}")
        print(f"🔐 Admin Yetkisi: Evet")
        print("\n🚀 Artık bu hesapla giriş yapıp admin paneline erişebilirsiniz!")
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        db.rollback()
    finally:
        db.close()

def list_users():
    """Mevcut kullanıcıları listeler"""
    db = SessionLocal()
    
    try:
        users = db.query(User).all()
        print("\n=== Mevcut Kullanıcılar ===")
        if not users:
            print("Henüz kullanıcı yok.")
            return
        
        print(f"{'ID':<5} {'Kullanıcı Adı':<20} {'Admin':<10} {'Email Onaylı':<15}")
        print("-" * 50)
        for user in users:
            admin_status = "✅ Evet" if user.is_admin else "❌ Hayır"
            email_status = "✅ Evet" if user.email_confirmed else "❌ Hayır"
            print(f"{user.id:<5} {user.username:<20} {admin_status:<10} {email_status:<15}")
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
    finally:
        db.close()

def make_user_admin():
    """Mevcut kullanıcıyı admin yapar"""
    db = SessionLocal()
    
    try:
        print("\n=== Kullanıcıyı Admin Yapma ===")
        
        # Kullanıcıları listele
        users = db.query(User).all()
        if not users:
            print("Henüz kullanıcı yok.")
            return
        
        print("Mevcut kullanıcılar:")
        print(f"{'ID':<5} {'Kullanıcı Adı':<20} {'Admin':<10}")
        print("-" * 35)
        for user in users:
            admin_status = "✅ Evet" if user.is_admin else "❌ Hayır"
            print(f"{user.id:<5} {user.username:<20} {admin_status:<10}")
        
        # Kullanıcı seç
        try:
            user_id = int(input("\nAdmin yapmak istediğiniz kullanıcının ID'sini girin: "))
        except ValueError:
            print("❌ Geçersiz ID!")
            return
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print("❌ Kullanıcı bulunamadı!")
            return
        
        if user.is_admin:
            print(f"⚠️  '{user.username}' zaten admin!")
            return
        
        # Admin yap
        user.is_admin = True
        db.commit()
        print(f"✅ '{user.username}' kullanıcısı admin yapıldı!")
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        db.rollback()
    finally:
        db.close()

def remove_admin():
    """Kullanıcının admin yetkisini kaldırır"""
    db = SessionLocal()
    
    try:
        print("\n=== Admin Yetkisini Kaldırma ===")
        
        # Admin kullanıcıları listele
        admin_users = db.query(User).filter(User.is_admin == True).all()
        if not admin_users:
            print("Admin kullanıcı bulunamadı.")
            return
        
        print("Admin kullanıcılar:")
        print(f"{'ID':<5} {'Kullanıcı Adı':<20}")
        print("-" * 25)
        for user in admin_users:
            print(f"{user.id:<5} {user.username:<20}")
        
        # Kullanıcı seç
        try:
            user_id = int(input("\nAdmin yetkisini kaldırmak istediğiniz kullanıcının ID'sini girin: "))
        except ValueError:
            print("❌ Geçersiz ID!")
            return
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print("❌ Kullanıcı bulunamadı!")
            return
        
        if not user.is_admin:
            print(f"⚠️  '{user.username}' zaten admin değil!")
            return
        
        # Admin yetkisini kaldır
        user.is_admin = False
        db.commit()
        print(f"✅ '{user.username}' kullanıcısının admin yetkisi kaldırıldı!")
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        db.rollback()
    finally:
        db.close()

def change_password():
    """Kullanıcı şifresini değiştirir"""
    db = SessionLocal()
    
    try:
        print("\n=== Kullanıcı Şifresi Değiştirme ===")
        
        # Kullanıcıları listele
        users = db.query(User).all()
        if not users:
            print("Henüz kullanıcı yok.")
            return
        
        print("Mevcut kullanıcılar:")
        print(f"{'ID':<5} {'Kullanıcı Adı':<20}")
        print("-" * 25)
        for user in users:
            print(f"{user.id:<5} {user.username:<20}")
        
        # Kullanıcı seç
        try:
            user_id = int(input("\nŞifresini değiştirmek istediğiniz kullanıcının ID'sini girin: "))
        except ValueError:
            print("❌ Geçersiz ID!")
            return
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print("❌ Kullanıcı bulunamadı!")
            return
        
        # Yeni şifre al
        new_password = input(f"'{user.username}' için yeni şifreyi girin: ").strip()
        if not new_password:
            print("❌ Şifre boş olamaz!")
            return
        
        # Şifreyi değiştir
        user.password_hash = generate_password_hash(new_password)
        db.commit()
        print(f"✅ '{user.username}' kullanıcısının şifresi değiştirildi!")
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        db.rollback()
    finally:
        db.close()

def delete_user():
    """Kullanıcıyı siler"""
    db = SessionLocal()
    try:
        print("\n=== Kullanıcı Silme ===")
        users = db.query(User).all()
        if not users:
            print("Henüz kullanıcı yok.")
            return
        print("Mevcut kullanıcılar:")
        print(f"{'ID':<5} {'Kullanıcı Adı':<20}")
        print("-" * 25)
        for user in users:
            print(f"{user.id:<5} {user.username:<20}")
        try:
            user_id = int(input("\nSilmek istediğiniz kullanıcının ID'sini girin: "))
        except ValueError:
            print("❌ Geçersiz ID!")
            return
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print("❌ Kullanıcı bulunamadı!")
            return
        confirm = input(f"'{user.username}' kullanıcısını silmek istediğinize emin misiniz? (e/h): ").strip().lower()
        if confirm not in ['e', 'evet', 'y', 'yes']:
            print("❌ İşlem iptal edildi.")
            return
        db.delete(user)
        db.commit()
        print(f"✅ '{user.username}' kullanıcısı silindi!")
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        db.rollback()
    finally:
        db.close()

def main():
    """Ana menü"""
    while True:
        print("\n" + "="*50)
        print("🔧 YKS Asistanı Admin Yönetimi")
        print("="*50)
        print("1. Yeni admin hesabı oluştur")
        print("2. Mevcut kullanıcıları listele")
        print("3. Kullanıcıyı admin yap")
        print("4. Admin yetkisini kaldır")
        print("5. Kullanıcı şifresini değiştir")
        print("6. Kullanıcı sil")
        print("7. Çıkış")
        print("="*50)
        choice = input("Seçiminizi yapın (1-7): ").strip()
        if choice == "1":
            create_admin_user()
        elif choice == "2":
            list_users()
        elif choice == "3":
            make_user_admin()
        elif choice == "4":
            remove_admin()
        elif choice == "5":
            change_password()
        elif choice == "6":
            delete_user()
        elif choice == "7":
            print("👋 Görüşürüz!")
            break
        else:
            print("❌ Geçersiz seçim!")

if __name__ == "__main__":
    main()