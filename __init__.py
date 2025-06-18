# Bu dosya sadece Python paketi olduğunu belirtmek için var
# Tüm uygulama mantığı app.py'de

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_caching import Cache

from config import Config

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
mail = Mail()
cache = Cache(config={'CACHE_TYPE': 'simple'})

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    cache.init_app(app)

    # Register blueprints
    from app.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.uploads import uploads_bp
    app.register_blueprint(uploads_bp, url_prefix='/uploads')

    from app.main import main_bp
    app.register_blueprint(main_bp)

    from app.enhancements import enhancements_bp
    app.register_blueprint(enhancements_bp)

    return app
