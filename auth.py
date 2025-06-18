# auth.py (güncellenmiş kısımlar)

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db, bcrypt, mail # YENİ: mail objesini import et
from app.models import User # User modelini import et
from app.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm # Formları import et
from flask_mail import Message # YENİ: Message import edildi
from itsdangerous import URLSafeTimedSerializer as Serializer # YENİ: URLSafeTimedSerializer import edildi
from flask import current_app # YENİ: current_app import edildi

auth_bp = Blueprint('auth', __name__)

# YENİ: E-posta doğrulama token'ı için Serializer objesi oluşturma (uygulama bağlamında çalışmalı)
def generate_confirmation_token(email):
    s = Serializer(current_app.config['SECRET_KEY'])
    return s.dumps(email, salt='email-confirm').decode('utf-8')

# YENİ: E-posta doğrulama token'ını doğrulama
def confirm_token(token, expiration=3600): # 1 saat (3600 saniye) geçerli
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

# YENİ: E-posta gönderme yardımcı fonksiyonu
def send_email(to, subject, template_name, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.html = render_template(f'email/{template_name}.html', **kwargs)
    mail.send(msg)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data) # Email alanını buradan alır
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        # YENİ: E-posta doğrulama linki gönder
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        send_email(user.email, 'YKS Asistanı: E-posta Doğrulama', 'confirm_email', 
                   user=user, confirm_url=confirm_url, expires_min=60) # 60 dakika geçerlilik

        flash('Kayıt başarılı! Hesabınızı etkinleştirmek için e-postanıza gönderilen linke tıklayın.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)

# YENİ: E-posta Doğrulama Rotası
@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    email = confirm_token(token)
    if not email:
        flash('Doğrulama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('auth.register')) # Tekrar kayıt veya giriş sayfasına yönlendir

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        flash('E-posta adresiniz zaten doğrulanmış.', 'success')
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('E-posta adresiniz başarıyla doğrulandı!', 'success')
    
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('anasayfa'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed: # YENİ: E-posta doğrulaması kontrolü
                flash('Lütfen hesabınızı etkinleştirmek için e-postanızı doğrulayın.', 'warning')
                return redirect(url_for('auth.login'))

            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('anasayfa'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'danger')
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yapıldı.', 'info')
    return redirect(url_for('auth.login'))

# YENİ: Şifre Sıfırlama İstek Rotası
@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    form = RequestResetForm() # YENİ FORM: forms.py'ye eklenecek
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for('auth.reset_token', token=token, _external=True)
            send_email(user.email, 'YKS Asistanı: Şifre Sıfırlama İsteği', 'reset_password', 
                       user=user, reset_url=reset_url, expires_min=30) # 30 dakika geçerlilik
            flash('Şifre sıfırlama talimatları e-posta adresinize gönderildi. Lütfen e-postanızı kontrol edin.', 'info')
            return redirect(url_for('auth.login'))
        else:
            flash('Bu e-posta adresine sahip bir kullanıcı bulunamadı.', 'danger')
    return render_template('reset_request.html', title='Şifre Sıfırla', form=form) # YENİ ŞABLON: reset_request.html

# YENİ: Şifre Sıfırlama Token Doğrulama ve Yeni Şifre Belirleme Rotası
@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.anasayfa'))
    
    user = User.verify_reset_token(token)
    if not user:
        flash('Şifre sıfırlama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('auth.reset_request'))
    
    form = ResetPasswordForm() # YENİ FORM: forms.py'ye eklenecek
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password_hash = hashed_password
        db.session.commit()
        flash('Şifreniz başarıyla güncellendi! Artık yeni şifrenizle giriş yapabilirsiniz.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_token.html', title='Şifre Sıfırla', form=form) # YENİ ŞABLON: reset_token.html