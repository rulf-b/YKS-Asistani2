# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, SelectField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), Length(min=3, max=64, message='Kullanıcı adı 3-64 karakter arasında olmalıdır.')])
    email = StringField('E-posta', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), Email(message='Geçerli bir e-posta adresi giriniz.'), Length(max=120, message='E-posta adresi çok uzun.')])
    password = PasswordField('Şifre', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), Length(min=6, message='Şifre en az 6 karakter olmalıdır.')])
    password2 = PasswordField('Şifre Tekrar', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), EqualTo('password', message='Şifreler eşleşmiyor.')])
    submit = SubmitField('Kayıt Ol')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Bu kullanıcı adı zaten alınmış. Lütfen farklı bir tane seçin.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Bu e-posta adresi zaten kayıtlı. Lütfen farklı bir tane kullanın.')

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(message='Bu alan boş bırakılamaz.')])
    password = PasswordField('Şifre', validators=[DataRequired(message='Bu alan boş bırakılamaz.')])
    remember_me = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class FileUploadForm(FlaskForm):
    file = FileField('Dosya Seç', validators=[DataRequired(message='Lütfen bir dosya seçin.')])
    submit = SubmitField('Yükle')

class RequestResetForm(FlaskForm):
    email = StringField('E-posta', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), Email(message='Geçerli bir e-posta adresi giriniz.'), Length(max=120, message='E-posta adresi çok uzun.')])
    submit = SubmitField('Şifremi Sıfırlama İsteği Gönder')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Bu e-posta adresine sahip bir kullanıcı bulunamadı.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Yeni Şifre', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), Length(min=6, message='Şifre en az 6 karakter olmalıdır.')])
    password2 = PasswordField('Yeni Şifre Tekrar', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), EqualTo('password', message='Şifreler eşleşmiyor.')])
    submit = SubmitField('Şifreyi Sıfırla')

class HedefForm(FlaskForm):
    universite = StringField('Hedef Üniversite', validators=[DataRequired(message='Bu alan boş bırakılamaz.')])
    bolum = StringField('Hedef Bölüm', validators=[DataRequired(message='Bu alan boş bırakılamaz.')])
    hedef_siralama = IntegerField('Hedef Sıralama', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), NumberRange(min=1, message='Sıralama 1\'den büyük olmalıdır.')])
    hedef_tyt_net = FloatField('Tahmini TYT Neti', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), NumberRange(min=0, max=120, message='TYT neti 0-120 arasında olmalıdır.')])
    hedef_ayt_net = FloatField('Tahmini AYT Neti', validators=[DataRequired(message='Bu alan boş bırakılamaz.'), NumberRange(min=0, max=160, message='AYT neti 0-160 arasında olmalıdır.')])
    ders_tercihi = SelectField('Alan Tercihi', choices=[('', 'Seçiniz...'), ('Sayısal', 'Sayısal'), ('Sözel', 'Sözel'), ('Eşit Ağırlık', 'Eşit Ağırlık')], validators=[DataRequired(message='Lütfen alan tercihinizi seçin.')])
    submit = SubmitField('Hedefimi ve Bilgilerimi Kaydet')