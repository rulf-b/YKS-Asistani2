# YKS Asistanı

Bu proje hem FastAPI hem de Flask kullanılarak geliştirilmiş bir YKS asistanıdır.

## Kurulum

1. Proje dizininde aşağıdaki komut ile tüm bağımlılıkları yükleyin:

```bash
pip install -r requirements.txt
```

2. `.env` dosyanızı oluşturarak gerekli anahtar ve ayarları girin.

3. Veritabanı şemasının güncel olduğundan emin olmak için aşağıdaki komutu çalıştırın:

```bash
python update_db.py
```

4. Uygulamayı çalıştırmak için FastAPI sürümü:

```bash
python main_fastapi.py
```

veya Flask sürümü:

```bash
python app.py
```

## Hata Çözümü

Eğer "Internal Server Error" hatası alırsanız çoğunlukla eksik bağımlılıklardan kaynaklanır. Yukarıdaki kurulum adımlarını uyguladığınızdan emin olun.
