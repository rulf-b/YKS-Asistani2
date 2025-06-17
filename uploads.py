from flask import Blueprint, request, redirect, url_for, flash, current_app, render_template
import boto3
from werkzeug.utils import secure_filename
from app.forms import FileUploadForm

uploads_bp = Blueprint('uploads', __name__)

def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in current_app.config['ALLOWED_EXTENSIONS']

@uploads_bp.route('/', methods=['GET', 'POST'])
def upload_file():
    form = FileUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            flash('Bu dosya türüne izin verilmiyor.', 'danger')
            return redirect(request.url)
        if file.content_length > current_app.config['MAX_CONTENT_LENGTH']:
            flash('Dosya boyutu çok büyük.', 'danger')
            return redirect(request.url)
        # AWS S3’e yükle
        s3 = boto3.client(
            's3',
            aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY']
        )
        bucket = current_app.config['AWS_S3_BUCKET']
        s3.upload_fileobj(file, bucket, filename)
        flash('Dosya başarıyla yüklendi.', 'success')
        return redirect(url_for('uploads.upload_file'))
    return render_template('upload.html', form=form)
