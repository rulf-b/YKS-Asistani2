import os
import magic
import hashlib
import time
from flask import current_app, Blueprint, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
from flask_login import login_required, current_user
from forms import FileUploadForm

uploads_bp = Blueprint('uploads', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx'}
ALLOWED_MIME_TYPES = {
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'application/pdf': '.pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx'
}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_type(file_stream):
    # Dosya içeriğini kontrol et
    mime = magic.from_buffer(file_stream.read(2048), mime=True)
    file_stream.seek(0)
    return mime in ALLOWED_MIME_TYPES

def validate_file_size(file_stream):
    # Dosya boyutunu kontrol et
    file_stream.seek(0, os.SEEK_END)
    size = file_stream.tell()
    file_stream.seek(0)
    return size <= MAX_FILE_SIZE

def generate_safe_filename(filename):
    # Güvenli dosya adı oluştur
    name = secure_filename(filename)
    # Dosya adına benzersiz hash ekle
    timestamp = str(int(time.time()))
    name_hash = hashlib.sha256(f"{name}{timestamp}".encode()).hexdigest()[:8]
    ext = os.path.splitext(name)[1]
    return f"{name_hash}_{name}"

def save_file(file_stream, filename):
    try:
        if not allowed_file(filename):
            current_app.logger.warning(f"İzin verilmeyen dosya uzantısı: {filename}")
            return None, "İzin verilmeyen dosya uzantısı."

        if not validate_file_size(file_stream):
            current_app.logger.warning(f"Dosya boyutu çok büyük: {filename}")
            return None, "Dosya boyutu 16MB'dan büyük olamaz."

        if not validate_file_type(file_stream):
            current_app.logger.warning(f"Geçersiz dosya türü: {filename}")
            return None, "Geçersiz dosya türü."

        safe_filename = generate_safe_filename(filename)
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)
        
        # Dosya içeriğinin hash'ini hesapla
        file_stream.seek(0)
        file_hash = hashlib.sha256(file_stream.read()).hexdigest()
        file_stream.seek(0)
        
        # Dosyayı kaydet
        file_stream.save(upload_path)
        
        current_app.logger.info(f"Dosya başarıyla yüklendi: {safe_filename} (Hash: {file_hash[:8]})")
        return safe_filename, None

    except Exception as e:
        current_app.logger.error(f"Dosya yükleme hatası: {str(e)}")
        return None, "Dosya yükleme sırasında bir hata oluştu."

def delete_file(filename):
    try:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            current_app.logger.info(f"Dosya silindi: {filename}")
            return True
        return False
    except Exception as e:
        current_app.logger.error(f"Dosya silme hatası: {str(e)}")
        return False

@uploads_bp.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Dosya seçilmedi.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Dosya seçilmedi.', 'danger')
            return redirect(request.url)

        if file:
            filename, error = save_file(file, file.filename)
            if error:
                flash(error, 'danger')
                return redirect(request.url)

            try:
                # AWS S3'e yükle
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
                    aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY']
                )
                
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                s3.upload_file(
                    file_path,
                    current_app.config['AWS_S3_BUCKET'],
                    f"uploads/{current_user.id}/{filename}"
                )
                
                # Yerel dosyayı sil
                os.remove(file_path)
                
                flash('Dosya başarıyla yüklendi!', 'success')
                return redirect(url_for('uploads.upload_file'))
                
            except ClientError as e:
                current_app.logger.error(f"AWS S3 yükleme hatası: {str(e)}")
                flash('Dosya yüklenirken bir hata oluştu.', 'danger')
                return redirect(request.url)
                
    return render_template('upload.html')
