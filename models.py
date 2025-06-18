from app import db, login_manager # app'den db ve login_manager import edildi
from flask_login import UserMixin
from itsdangerous import TimedSerializer as Serializer, URLSafeTimedSerializer # URLSafeTimedSerializer eklendi
from flask import current_app # current_app import edildi (uygulama bağlamına erişim için)
import json # JSON işlemleri için
from datetime import datetime # datetime eklendi

# Mevcut User modeli
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) # E-posta doğrulama için gerekli, eğer yoksa ekleyin
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmed = db.Column(db.Boolean, default=False) # YENİ: E-posta doğrulandı mı?
    
    ders_tercihi = db.Column(db.String(50), nullable=True)
    bos_zamanlar_json = db.Column(db.Text, nullable=True)
    soru_analizleri = db.relationship('SoruAnaliz', backref='author', lazy=True)
    denemeleri = db.relationship('DenemeSinavi', backref='author', lazy=True)
    hedef = db.relationship('Hedef', backref='user', uselist=False, cascade="all, delete-orphan")
    tekrar_konulari = db.relationship('TekrarKonu', backref='user', lazy=True, cascade="all, delete-orphan")
    # Quiz modelleri atlandığı için UserQuizAnswer ilişkisi kaldırıldı.

    def set_password(self, password):
        from app import bcrypt # bcrypt'i burada import et
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        from app import bcrypt # bcrypt'i burada import et
        return bcrypt.check_password_hash(self.password_hash, password)

    # Şifre sıfırlama token'ı oluşturma metodu
    def get_reset_token(self, expires_sec=1800): # 30 dakika geçerli
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    # Şifre sıfırlama token'ını doğrulama metodu
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Konu modeli atlandığı için bu kısım kaldırıldı.
# class Konu(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     adi = db.Column(db.String(100), unique=True, nullable=False)
#     ust_konu_id = db.Column(db.Integer, db.ForeignKey('konu.id'), nullable=True)
#     alt_konular = db.relationship('Konu', backref=db.backref('ust_konu', remote_side=[id]), lazy=True)
#     seviye = db.Column(db.Integer, nullable=False, default=1)

#     def __repr__(self):
#         return f'<Konu {self.adi}>'

# Question modeli quiz geliştirmeleri atlandığı için eski haline döndürüldü.
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    topic = db.Column(db.String(64), nullable=False)
    # isterseniz seçenekleri JSON olarak tutabilirsiniz

# UserQuizAnswer modeli quiz geliştirmeleri atlandığı için kaldırıldı.
# class UserQuizAnswer(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
#     user_answer = db.Column(db.String(10), nullable=False)
#     is_correct = db.Column(db.Boolean, nullable=False)
#     quiz_date = db.Column(db.DateTime, default=datetime.utcnow)
    
#     question = db.relationship('Question', backref='user_answers', lazy=True)

#     def __repr__(self):
#         return f'<UserQuizAnswer User:{self.user_id} Question:{self.question_id} Answer:{self.user_answer} Correct:{self.is_correct}>'


# Mevcut diğer modelleriniz (Hedef, TekrarKonu, SoruAnaliz, DenemeSinavi, CalismaOturumu)
# Yukarıda tekrar tanımlandıkları için burada tekrar yazılmalarına gerek yok.
# Ancak models.py sadece model tanımlamalarını içermeli, app.py içinde bu modellerin tekrar tanımlanması ideal değildir.