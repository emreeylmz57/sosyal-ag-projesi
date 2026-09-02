# Flask Sosyal Ağ ve Gelişmiş Rol Tabanlı Yönetim Sistemi

Bu proje, Python ve Flask çatıları kullanılarak geliştirilmiş; gelişmiş bir Rol Tabanlı Erişim Kontrolü (RBAC), hiyerarşik yetki delegasyonu, sosyal akış, birebir mesajlaşma ve kapsamlı moderasyon paneli içeren web tabanlı bir sosyal ağ ve yönetim uygulamasıdır.

## 🚀 Başlıca Özellikler

* **🔐 Güvenli Kimlik Doğrulama & Oturum Yönetimi:** Flask-Login ve Werkzeug şifreleme (hashing) altyapısı. Oturum açan kullanıcıların anlık ban kontrolü (`@app.before_request`).
* **👥 Gelişmiş Rol Tabanlı Erişim Kontrolü (RBAC) & Delegasyon:** 
  * Öncelik dereceli (`priority`) dinamik roller[cite: 1, 11, 19].
  * SortableJS ile sürükle-bırak rol sıralaması[cite: 19].
  * Yöneticilerin temel yetkileri (silme, puan verme, rol atama, banlama) başkalarına devredebilmesi (*delegation*)[cite: 1, 11, 12].
* **📌 Sosyal Akış ve Medya Paylaşımı:** 
  * Herkese açık (`public`) veya arkadaşlara özel (`friends`) gizlilik filtreli gönderiler[cite: 1, 14].
  * Güvenli dosya/resim yükleme (`secure_filename`)[cite: 1].
  * Beğeni, yorum, içerik düzenleme ve repost (yeniden paylaşım) özellikleri[cite: 1, 14, 20, 21].
* **💬 Gerçek Zamanlı Mesajlaşma & Sosyal Ağ:** 
  * Birebir sohbet modülü ve okunmamış mesaj sayaçları[cite: 1, 17].
  * Kullanıcı engelleme (`block_user`) ve şikayet mekanizmaları[cite: 1].
  * Veritabanı tabanlı anlık bildirim sistemi (`Notification`)[cite: 1, 14].
* **🛡️ Kapsamlı Moderasyon & Çöp Kutusu (Arşiv):** 
  * Şikayet edilen kullanıcı ve gönderilerin denetim paneli[cite: 1, 5, 14].
  * Silinen gönderiler (`DeletedPost`) ve hesaplar (`DeletedUser`) için çöp kutusu ve tek tuşla geri yükleme (`restore`) desteği[cite: 1, 4, 6, 9, 21].
* **📊 Sistem Logları (AuditLog) & İstatistikler:** 
  * Kritik işlemlerin kayıt altına alınması ve Chart.js ile admin panelinde görselleştirilmesi[cite: 1, 6, 16].

## 🛠️ Kullanılan Teknolojiler

| Kategori | Teknolojiler & Araçlar |
| :--- | :--- |
| **Backend** | Python, Flask, Flask-SQLAlchemy, Flask-Login, Werkzeug[cite: 1] |
| **Veritabanı** | Microsoft SQL Server (LocalDB) / pyodbc (`ClientCharset=UTF8` Türkçe karakter desteğiyle)[cite: 1] |
| **Frontend & UI** | HTML5, Tailwind CSS, JavaScript (Fetch API), Chart.js, SortableJS[cite: 1, 6, 11, 19] |

## ⚙️ Kurulum ve Çalıştırma

1. Projeyi klonlayın veya indirin:
   ```bash
   git clone [https://github.com/kullaniciadi/proje-adi.git](https://github.com/kullaniciadi/proje-adi.git)
   cd proje-adi
2. Sanal ortamı oluşturup aktif hale getirin:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows için: venv\Scripts\activate
3. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install flask flask-sqlalchemy flask-login pyodbc werkzeug
4. SQL Server LocalDB bağlantı ayarlarınızı app.py içerisindeki bağlantı dizesinden (params) kendi veritabanı adınıza göre güncelleyin[cite: 1].
5. Uygulamayı çalıştırın:
   ```bash
   python app2.py
6.  Tarayıcınızda http://127.0.0.1:5000 adresine giderek sistemi kullanmaya başlayın.
