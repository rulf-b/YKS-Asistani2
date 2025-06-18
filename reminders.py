# reminders.py (güncellenmiş kısımlar)

from flask import Blueprint
# from flask_mail import Message # Bu satır app.py'de import edildiğinden burada tekrar etmesine gerek kalmaz
# from . import mail, db # app'den mail ve db import etmeniz gerekecek
# from .models import User, Performance # models.py'den User ve ihtiyacınız olan diğer modelleri import edin

# app'den mail ve db objelerini ve User modelini import etmeniz gerekecek.
# Eğer bu dosya bir blueprint ise, app objesi Flask'ta farklı şekilde erişilir.
# Basitlik adına, app.py'ye benzer importları burada da tutalım.
from app import mail, db, app # app objesini de import ettik
from models import User, TekrarKonu # Performance yerine TekrarKonu kullanacağız

# app objesi Flask-Mail ile initialize edildiği için app context'i gerekli
with app.app_context():
    from flask_mail import Message


reminders_bp = Blueprint('reminders', __name__)

@reminders_bp.route('/send_reminders')
def send_weekly_reminders():
    users = User.query.all()
    for u in users:
        # Tekrar konularını al
        weak_topics = [t.konu_adi for t in TekrarKonu.query.filter_by(user_id=u.id).order_by(TekrarKonu.eklenme_tarihi.desc()).limit(5).all()]
        
        if not weak_topics:
            print(f"Kullanıcı {u.username} için tekrar konusu bulunamadı.")
            continue

        # E-posta içeriği
        email_body = f"Merhaba {u.username},\n\nBu hafta tekrar etmeniz gereken önemli konular:\n\n"
        for topic in weak_topics:
            email_body += f"- {topic}\n"
        email_body += "\nBu konuları tekrar ederek YKS yolculuğunda daha da güçlenebilirsin!\n\n"
        email_body += "Başarılar dileriz,\nYKS Asistanı Ekibi"

        # Mesajı oluştur ve gönder
        msg = Message('YKS Asistanı: Haftalık Tekrar Hatırlatma',
                      sender=app.config['MAIL_DEFAULT_SENDER'], # app.config'ten gönderici
                      recipients=[u.email])
        msg.body = email_body
        
        try:
            mail.send(msg)
            print(f"Kullanıcı {u.username} ({u.email}) için hatırlatma e-postası başarıyla gönderildi.")
        except Exception as e:
            print(f"Kullanıcı {u.username} ({u.email}) için e-posta gönderme hatası: {e}")

    return 'Hatırlatmalar gönderildi', 200

# schedule.every().monday.at('08:00').do(send_weekly_reminders) # Zamanlayıcı aktifse kalsın