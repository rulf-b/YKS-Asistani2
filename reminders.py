from flask_mail import Message
from . import mail, db
from .models import User, Performance
import schedule

reminders_bp = Blueprint('reminders', __name__)

@reminders_bp.route('/send_reminders')
def send_weekly_reminders():
    users = User.query.all()
    for u in users:
        weak_topics = [p.topic for p in Performance.query.filter_by(user_id=u.id).order_by(Performance.score).limit(3)]
        msg = Message('Tekrar Hatırlatma', recipients=[u.email])
        msg.body = f"En zayıf konularınız: {', '.join(weak_topics)}"
        mail.send(msg)
    return 'Hatırlatmalar gönderildi', 200

# schedule.every().monday.at('08:00').do(send_weekly_reminders)