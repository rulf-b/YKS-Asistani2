from flask import Blueprint, jsonify
from .models import Performance

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/api/stats')
def stats():
    data = Performance.query.all()
    return jsonify([{'date': p.date.isoformat(), 'score': p.score} for p in data])