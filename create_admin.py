from app import app, db, User, bcrypt

def main():
    with app.app_context():
        print("--- İlk Admin Kullanıcısını Oluşturma ---")
        username = input("Admin için bir kullanıcı adı girin: ")
        password = input("Admin için bir şifre girin: ")

        # Kullanıcı adının daha önce alınıp alınmadığını kontrol et
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"'{username}' adlı kullanıcı zaten mevcut. Lütfen farklı bir ad seçin.")
            return

        # Şifreyi hash'le ve yeni admin kullanıcısını oluştur
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        admin_user = User(username=username, password_hash=hashed_password, is_admin=True)
        
        db.session.add(admin_user)
        db.session.commit()
        print(f"'{username}' adlı admin kullanıcısı başarıyla oluşturuldu!")

if __name__ == '__main__':
    main()