from flask import Blueprint, jsonify, render_template, current_app
from flask_login import login_required, current_user
from app import mail, db
from flask_mail import Message
import random

enhancements_bp = Blueprint('enhancements', __name__)

def get_user_weak_topics(user):
    # İdealde DB’den çekersiniz; örnek sabit liste:
    return ['Matematik', 'Fizik']

@enhancements_bp.route('/send_reminders')
def send_reminders():
    users = db.session.query(db.Model).filter_by().all()  # User.query.all() olarak düzenleyin
    for user in users:
        topics = get_user_weak_topics(user)
        msg = Message(
            subject='YKS Tekrar Hatırlatması',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email],
            body=f"Merhaba {user.username},\nBu hafta tekrar etmeniz gereken konular: {', '.join(topics)}."
        )
        mail.send(msg)
    return 'Reminders sent'

@enhancements_bp.route('/api/dashboard-data')
@login_required
def dashboard_data():
    # Chart.js’e JSON veri
    data = {
        'labels': ['Deneme 1', 'Deneme 2', 'Deneme 3'],
        'scores': [75, 82, 90]
    }
    return jsonify(data)

def load_questions():
    from models import Question
    return Question.query.all()

@enhancements_bp.route('/quiz')
@login_required
def quiz():
    questions = load_questions()
    weak_topics = get_user_weak_topics(current_user)
    weighted = []
    for q in questions:
        weight = 2 if q.topic in weak_topics else 1
        weighted.extend([q] * weight)
    selected = random.sample(weighted, min(5, len(weighted)))
    return render_template('quiz.html', questions=selected)
