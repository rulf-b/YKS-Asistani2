# Gerekli kütüphaneleri programımıza dahil ediyoruz.
import google.generativeai as genai
import os  # İşletim sistemiyle ilgili işlemler için (yeni eklendi)
from dotenv import load_dotenv  # .env dosyasını okumak için (yeni eklendi)

# -----------------------------------------------------------------------------
# ----- .env DOSYASINDAN API ANAHTARINI YÜKLEME ----- (Burası değişti)
# -----------------------------------------------------------------------------
load_dotenv()  # .env dosyasını bul ve içindeki değişkenleri yükle

# os.getenv() ile yüklenen değişkenler arasından 'GOOGLE_API_KEY' olanı al
api_key = os.getenv("GOOGLE_API_KEY")

# Eğer API anahtarı bulunamazsa programı hata mesajıyla durdur.
if not api_key:
    raise ValueError("GOOGLE_API_KEY bulunamadı. Lütfen .env dosyanızı kontrol edin.")

# API anahtarını kullanarak genai kütüphanesini yapılandır.
genai.configure(api_key=api_key)
# -----------------------------------------------------------------------------


print("--- YKS Yapay Zekâ Koçu'na Hoş Geldiniz ---")
print("Lütfen analiz etmek istediğiniz soruyu ve cevabınızı girin.")
print("-" * 20)

# 1. ADIM: KULLANICIDAN VERİYİ ALMA
soru = input("Lütfen soruyu metin olarak girin (şıklar dahil): \n> ")
ogrenci_cevabi = input("\nBu soru hakkındaki kendi cevabınızı veya düşüncelerinizi girin: \n> ")

print("\nHarika! Bilgiler alındı. Yapay zekâdan analiz isteniyor...")
print("-" * 20)

# 2. ADIM: YAPAY ZEKÂ İÇİN PROMPT (KOMUT) OLUŞTURMA
prompt = f"""
Sen YKS hazırlık sürecindeki lise öğrencilerine yardım eden bir yapay zekâ koçusun.
Sana bir soru ve öğrencinin cevabını vereceğim. Aşağıdaki formata göre analiz yapmanı istiyorum:

1.  **Ders/Konu/Alt Başlık:** Sorunun ait olduğu ders, konu ve alt başlığı belirt. (Örnek: Matematik > Fonksiyonlar > Bileşke Fonksiyon)
2.  **Zorluk Derecesi:** Sorunun zorluğunu tahmin et (Kolay/Orta/Zor).
3.  **Hata Analizi:** Öğrencinin düşünce zincirindeki hatayı tespit et. Hata türünü belirt (Bilgi eksikliği, işlem hatası, dikkat dağınıklığı, yanlış anlama).
4.  **Kişisel Geri Bildirim:** Öğrenciye hatasını anlatan ve doğrusunu adım adım gösteren, pozitif ve motive edici bir açıklama yaz.

---
**Soru:**
{soru}

**Öğrencinin Cevabı ve Düşüncesi:**
{ogrenci_cevabi}
---
"""

# 3. ADIM: YAPAY ZEKÂ İLE İLETİŞİME GEÇME
model = genai.GenerativeModel('gemini-1.5-flash-latest')
response = model.generate_content(prompt)

# 4. ADIM: SONUCU EKRANA YAZDIRMA
print("\n--- YAPAY ZEKA ANALİZİ ---")
print(response.text)