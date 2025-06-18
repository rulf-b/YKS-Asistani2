# auth.py (güncellenmiş kısımlar)

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from app import db, bcrypt, mail, limiter, validate_password
from models import User # User modelini import et
from forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm # Formları import et
from itsdangerous import URLSafeTimedSerializer as Serializer # YENİ: URLSafeTimedSerializer import edildi
import logging

auth_bp = Blueprint('auth', __name__)

# YENİ: E-posta doğrulama token'ı için Serializer objesi oluşturma (uygulama bağlamında çalışmalı)
def generate_confirmation_token(email):
    s = Serializer(current_app.config['SECRET_KEY'])
    return s.dumps(email, salt='email-confirm').encode().decode('utf-8')

# YENİ: E-posta doğrulama token'ını doğrulama
def confirm_token(token, expiration=3600): # 1 saat (3600 saniye) geçerli
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
    except:
        current_app.logger.warning(f"Geçersiz veya süresi dolmuş token: {token[:10]}...")
        return False
    return email

# YENİ: E-posta gönderme yardımcı fonksiyonu
def send_email(to, subject, template_name, **kwargs):
    try:
        msg = Message(subject, recipients=[to])
        msg.html = render_template(f'email/{template_name}.html', **kwargs)
        mail.send(msg)
        current_app.logger.info(f"E-posta gönderildi: {to}")
    except Exception as e:
        current_app.logger.error(f"E-posta gönderme hatası: {str(e)}")
        raise

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Şifre güvenlik kontrolü
        is_valid, message = validate_password(form.password.data)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html', form=form)

        try:
            user = User(
                username=form.username.data,
                email=form.email.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()

            # E-posta doğrulama
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('auth.confirm_email', token=token, _external=True)
            send_email(user.email, 'YKS Asistanı: E-posta Doğrulama', 'confirm_email', 
                      user=user, confirm_url=confirm_url, expires_min=60)

            current_app.logger.info(f"Yeni kullanıcı kaydı: {user.username}")
            flash('Kayıt başarılı! Hesabınızı etkinleştirmek için e-postanıza gönderilen linke tıklayın.', 'info')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Kayıt hatası: {str(e)}")
            flash('Kayıt sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'danger')
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)

# YENİ: E-posta Doğrulama Rotası
@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    email = confirm_token(token)
    if not email:
        flash('Doğrulama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('auth.register'))

    try:
        user = User.query.filter_by(email=email).first_or_404()
        if user.email_confirmed:
            flash('E-posta adresiniz zaten doğrulanmış.', 'success')
        else:
            user.email_confirmed = True
            db.session.commit()
            current_app.logger.info(f"E-posta doğrulandı: {email}")
            flash('E-posta adresiniz başarıyla doğrulandı!', 'success')
    except Exception as e:
        current_app.logger.error(f"E-posta doğrulama hatası: {str(e)}")
        flash('Doğrulama sırasında bir hata oluştu.', 'danger')
    
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('anasayfa'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                if not user.email_confirmed:
                    flash('Lütfen hesabınızı etkinleştirmek için e-postanızı doğrulayın.', 'warning')
                    return redirect(url_for('auth.login'))

                login_user(user, remember=form.remember_me.data)
                current_app.logger.info(f"Kullanıcı girişi: {user.username}")
                
                next_page = request.args.get('next')
                if next_page and not next_page.startswith('/'):
                    return redirect(url_for('anasayfa'))
                return redirect(next_page or url_for('anasayfa'))
            else:
                current_app.logger.warning(f"Başarısız giriş denemesi: {form.username.data}")
                flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
        except Exception as e:
            current_app.logger.error(f"Giriş hatası: {str(e)}")
            flash('Giriş sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'danger')
    
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        username = current_user.username
        logout_user()
        current_app.logger.info(f"Kullanıcı çıkışı: {username}")
        flash('Başarıyla çıkış yapıldı.', 'info')
    return redirect(url_for('auth.login'))

# YENİ: Şifre Sıfırlama İstek Rotası
@auth_bp.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    form = RequestResetForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                token = generate_confirmation_token(user.email)
                reset_url = url_for('auth.reset_token', token=token, _external=True)
                send_email(user.email, 'YKS Asistanı: Şifre Sıfırlama İsteği', 'reset_password', 
                          user=user, reset_url=reset_url, expires_min=30)
                current_app.logger.info(f"Şifre sıfırlama isteği: {user.email}")
                flash('Şifre sıfırlama talimatları e-posta adresinize gönderildi.', 'info')
                return redirect(url_for('auth.login'))
        except Exception as e:
            current_app.logger.error(f"Şifre sıfırlama hatası: {str(e)}")
            flash('Şifre sıfırlama sırasında bir hata oluştu.', 'danger')
    
    return render_template('reset_request.html', title='Şifre Sıfırla', form=form)

# YENİ: Şifre Sıfırlama Token Doğrulama ve Yeni Şifre Belirleme Rotası
@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    email = confirm_token(token)
    if not email:
        flash('Şifre sıfırlama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('auth.reset_request'))
    
    try:
        user = User.query.filter_by(email=email).first_or_404()
        form = ResetPasswordForm()
        
        if form.validate_on_submit():
            # Şifre güvenlik kontrolü
            is_valid, message = validate_password(form.password.data)
            if not is_valid:
                flash(message, 'danger')
                return render_template('reset_token.html', title='Şifre Sıfırla', form=form)

            user.set_password(form.password.data)
            db.session.commit()
            current_app.logger.info(f"Şifre sıfırlama başarılı: {user.email}")
            flash('Şifreniz başarıyla güncellendi!', 'success')
            return redirect(url_for('auth.login'))
            
    except Exception as e:
        current_app.logger.error(f"Şifre sıfırlama hatası: {str(e)}")
        flash('Şifre sıfırlama sırasında bir hata oluştu.', 'danger')
    
    return render_template('reset_token.html', title='Şifre Sıfırla', form=form)