# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('E-posta', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Şifre', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Şifre Tekrar', validators=[DataRequired(), EqualTo('password')])
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
    username = StringField('Kullanıcı Adı', validators=[DataRequired()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    remember_me = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class FileUploadForm(FlaskForm):
    file = FileField('Dosya Seç', validators=[DataRequired()])
    submit = SubmitField('Yükle')

class RequestResetForm(FlaskForm):
    email = StringField('E-posta', validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField('Şifremi Sıfırlama İsteği Gönder')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Bu e-posta adresine sahip bir kullanıcı bulunamadı.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Yeni Şifre', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Yeni Şifre Tekrar', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Şifreyi Sıfırla')