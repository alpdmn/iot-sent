# 🛰️ IoT Sent — IP Kamera & IoT Cihaz Keşif Aracı  

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![Contributions welcome](https://img.shields.io/badge/Contributions-Welcome-orange.svg)

---

### 🔍 Nedir?
**IoT Sent**, yerel ağdaki IP kameralar ve IoT cihazlarını tespit etmek, yaygın portları taramak ve temel güvenlik açıklarını test etmek için geliştirilmiş açık kaynaklı bir siber güvenlik aracıdır.  
Tamamen **Python** ile yazılmıştır ve hem **aktif** hem de **pasif ağ izleme** modlarını destekler.

---
Versiyon: 1.0.0

Yazar: Alp Eren Duman
## 🚀 Özellikler

| Özellik | Açıklama |
|----------|-----------|
| 🔬 **Aktif Tarama** | ARP üzerinden cihaz keşfi yapar, MAC adresi ve üretici bilgilerini toplar. |
| 🌐 **Port Tarama** | 100 thread ile paralel olarak yaygın portları tarar (21,22,23,80,443,554,8080...). |
| 🧠 **Risk Analizi** | Açık port ve servis sonuçlarına göre otomatik risk skoru hesaplar. |
| 🔑 **Zafiyet Testleri** | FTP anonim giriş, HTTP varsayılan şifre, RTSP, Telnet testleri. |
| 🕵️ **Pasif Dinleme** | ARP, DHCP, mDNS, SSDP trafiğini izleyerek yeni cihazları tespit eder. |
| 📊 **Raporlama** | Sonuçları JSON veya HTML formatında kaydeder. |

---

## 📦 Kurulum

> **Gereksinimler:**  
> Python 3.10 veya üzeri, `pip` kurulu olmalı.

```bash
# Depoyu klonla
git clone https://github.com/alpdmn/iot-sent.git
cd iot-sent


# Bağımlılıkları yükle
pip install -r requirements.txt
```
💡 Not: Aktif ağ taraması yapmak için yönetici (root/sudo) yetkisi gerekir.

🧰 Kullanım

🎯 Aktif Tarama
Belirli bir IP aralığında cihazları bulur:
sudo python3 iot_sent.py -t 192.168.1.0/24

🧪 JSON Formatında Sonuç
sudo python3 iot_sent.py -t 192.168.1.0/24 --json

🕵️ Pasif Dinleme
Ağ arayüzünü dinler, yeni cihazları yakalar:
sudo python3 iot_sent.py -P -i wlan0 -s 60

💾 HTML Raporu Kaydet
sudo python3 iot_sent.py -t 192.168.1.0/24 --save-html rapor.html


🧮 Risk Skoru Sistemi
| Durum                 | Puan |
| --------------------- | ---- |
| Açık port             | +1   |
| FTP anonim erişim     | +5   |
| HTTP varsayılan şifre | +5   |
| Telnet oturum ekranı  | +5   |
| RTSP aktif            | +3   |
| Toplam Skor | Seviye         |
| ----------- | -------------- |
| 0–2         | ✅ Düşük Risk   |
| 3–7         | ⚠️ Orta Risk   |
| 8+          | 🔥 Yüksek Risk |

⚙️ Parametreler
| Parametre           | Açıklama                                   |
| ------------------- | ------------------------------------------ |
| `-t`, `--target`    | Taranacak IP aralığı (örn: 192.168.1.0/24) |
| `-p`, `--ports`     | Özel port listesi (örn: 21,80,443)         |
| `-P`, `--pasif`     | Pasif izleme modunu aktif eder             |
| `-i`, `--interface` | Pasif dinleme arayüzü (varsayılan: eth0)   |
| `--save-json`       | Sonuçları JSON dosyasına kaydeder          |
| `--save-html`       | HTML rapor dosyası üretir                  |
| `-q`, `--quiet`     | Sessiz mod, minimum çıktı                  |
| `-v`, `--version`   | Sürüm bilgisini gösterir                   |

Geliştirici Notu

Bu proje öğrenme ve araştırma amaçlı geliştirilmiştir.
Gerçek ağlarda izinsiz tarama yapmak yasal değildir.
Lütfen yalnızca izinli ve kendi ağınızda kullanınız.

📜 Lisans

Bu proje MIT Lisansı
 altında lisanslanmıştır.
Kullanım ve dağıtım serbesttir, kaynak belirtilmesi yeterlidir.
