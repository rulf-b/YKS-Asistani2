# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from models import User
import re

def validate_password_strength(form, field):
    password = field.data
    if len(password) < 12:
        raise ValidationError('Şifre en az 12 karakter uzunluğunda olmalıdır.')
    if not any(c.isupper() for c in password):
        raise ValidationError('Şifre en az bir büyük harf içermelidir.')
    if not any(c.islower() for c in password):
        raise ValidationError('Şifre en az bir küçük harf içermelidir.')
    if not any(c.isdigit() for c in password):
        raise ValidationError('Şifre en az bir rakam içermelidir.')
    if not any(c in "!@#$%^&*" for c in password):
        raise ValidationError('Şifre en az bir özel karakter (!@#$%^&*) içermelidir.')

def validate_username(form, field):
    # Kullanıcı adı güvenlik kontrolü
    if not re.match("^[a-zA-Z0-9_-]{3,20}$", field.data):
        raise ValidationError('Kullanıcı adı sadece harf, rakam, alt çizgi ve tire içerebilir (3-20 karakter).')
    
    # Kullanıcı adı benzersizlik kontrolü
    user = User.query.filter_by(username=field.data).first()
    if user:
        raise ValidationError('Bu kullanıcı adı zaten kullanılıyor.')

def validate_email(form, field):
    # E-posta benzersizlik kontrolü
    user = User.query.filter_by(email=field.data).first()
    if user:
        raise ValidationError('Bu e-posta adresi zaten kullanılıyor.')

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı',
        validators=[
            DataRequired(message='Kullanıcı adı gereklidir.'),
            Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter arasında olmalıdır.'),
            validate_username
        ])
    email = StringField('E-posta',
        validators=[
            DataRequired(message='E-posta adresi gereklidir.'),
            Email(message='Geçerli bir e-posta adresi giriniz.'),
            validate_email
        ])
    password = PasswordField('Şifre',
        validators=[
            DataRequired(message='Şifre gereklidir.'),
            validate_password_strength
        ])
    confirm_password = PasswordField('Şifreyi Onayla',
        validators=[
            DataRequired(message='Şifre onayı gereklidir.'),
            EqualTo('password', message='Şifreler eşleşmiyor.')
        ])
    submit = SubmitField('Kayıt Ol')

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı',
        validators=[
            DataRequired(message='Kullanıcı adı gereklidir.'),
            Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter arasında olmalıdır.')
        ])
    password = PasswordField('Şifre',
        validators=[
            DataRequired(message='Şifre gereklidir.')
        ])
    remember_me = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class RequestResetForm(FlaskForm):
    email = StringField('E-posta',
        validators=[
            DataRequired(message='E-posta adresi gereklidir.'),
            Email(message='Geçerli bir e-posta adresi giriniz.')
        ])
    submit = SubmitField('Şifre Sıfırlama İste')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Bu e-posta adresine sahip bir hesap bulunamadı.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Yeni Şifre',
        validators=[
            DataRequired(message='Yeni şifre gereklidir.'),
            validate_password_strength
        ])
    confirm_password = PasswordField('Şifreyi Onayla',
        validators=[
            DataRequired(message='Şifre onayı gereklidir.'),
            EqualTo('password', message='Şifreler eşleşmiyor.')
        ])
    submit = SubmitField('Şifreyi Sıfırla')

class FileUploadForm(FlaskForm):
    file = FileField('Dosya Seç',
        validators=[
            DataRequired(message='Lütfen bir dosya seçin.')
        ])
    submit = SubmitField('Yükle')

class HedefForm(FlaskForm):
    universite = StringField('Üniversite',
        validators=[
            DataRequired(message='Üniversite adı gereklidir.'),
            Length(min=2, max=100, message='Üniversite adı 2-100 karakter arasında olmalıdır.')
        ])
    bolum = StringField('Bölüm',
        validators=[
            DataRequired(message='Bölüm adı gereklidir.'),
            Length(min=2, max=100, message='Bölüm adı 2-100 karakter arasında olmalıdır.')
        ])
    hedef_siralama = IntegerField('Hedef Sıralama',
        validators=[
            DataRequired(message='Hedef sıralama gereklidir.'),
            NumberRange(min=1, message='Geçerli bir sıralama giriniz.')
        ])
    hedef_tyt_net = IntegerField('Hedef TYT Net',
        validators=[
            DataRequired(message='Hedef TYT net gereklidir.'),
            NumberRange(min=0, max=120, message='TYT net 0-120 arasında olmalıdır.')
        ])
    hedef_ayt_net = IntegerField('Hedef AYT Net',
        validators=[
            DataRequired(message='Hedef AYT net gereklidir.'),
            NumberRange(min=0, max=160, message='AYT net 0-160 arasında olmalıdır.')
        ])
    submit = SubmitField('Hedef Belirle')