import random
from flask import Blueprint, render_template
from .models import Question, Performance

quiz_bp = Blueprint('quiz', __name__)

@quiz_bp.route('/quiz')
def quiz():
    questions = Question.query.all()
    weights = [1/(q.difficulty or 1) for q in questions]
    selected = random.choices(questions, weights, k=5)
    return render_template('quiz.html', questions=selected)