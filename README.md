# iot-sent
IP Kamera &amp; IoT cihaz keşfi, port tarama ve basit zafiyet testleri.
# 🛰️ IoT Sent — IP Kamera & IoT Cihaz Keşif Aracı

Yerel ağdaki IoT cihazlarını tespit eden, portları paralel tarayan ve basit zafiyet kontrolleri yapan araç.

## Kurulum
Bilgisayarında:
pip install -r requirements.txt

> Aktif taramalar için `sudo` gerekebilir.

## Kullanım
python3 iot_sent.py -h
sudo python3 iot_sent.py -t 192.168.1.0/24
sudo python3 iot_sent.py -P -i wlan0 -s 60
sudo python3 iot_sent.py -t 192.168.1.0/24 --save-html rapor.html


## Uyarı
Bu araç eğitim/araştırma amaçlıdır. Yalnızca **izinli** ağlarda kullanınız.
