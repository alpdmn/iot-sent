
"""
iot_sent.py

IoT cihaz tarayıcı ve basit zaafiyet test aracı.
"""

import scapy.all as scapy
from scapy.layers.l2 import Ether
import requests
import argparse
import socket
import sys
import json
from pyfiglet import Figlet
import concurrent.futures
import ftplib
from requests.auth import HTTPBasicAuth

YAYGIN_PORTLAR = [21, 22, 23, 80, 443, 554, 8000, 8080, 25, 53, 110, 115, 443, 3306]
BULUNAN_CIHAZLAR = {}

def yazdir_afis():
    afis = Figlet(font='slant')
    print(afis.renderText('IoT Sent'))
    print("IP Kamera & IoT Cihaz Keşif Aracı\n")

def mac_ureticisini_bul(mac_adresi):
    try:
        url = f"https://api.macvendors.com/{mac_adresi}"
        cevap = requests.get(url, timeout=3)
        if cevap.status_code == 200:
            return cevap.text
        else:
            return "Bilinmiyor"
    except:
        return "Bilinmiyor"

def agdaki_cihazlari_bul(ip_araligi):
    if not ip_araligi:
        print("[-] IP aralığı belirtilmedi.")
        sys.exit(1)
    print(f"[+] {ip_araligi} IP aralığı taranıyor...\n")
    try:
        arp_istek = scapy.ARP(pdst=ip_araligi)
        yayin = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        paket = yayin / arp_istek
        cevaplar = scapy.srp(paket, timeout=2, verbose=False)[0]

        cihazlar = []
        for cevap in cevaplar:
            ip = cevap[1].psrc
            mac = cevap[1].hwsrc
            uretici = mac_ureticisini_bul(mac)
            cihazlar.append({
                "ip": ip,
                "mac": mac,
                "uretici": uretici
            })
        return cihazlar
    except PermissionError:
        print("[-] Yönetici (root) yetkisi gerekiyor! Programı sudo ile çalıştırın.")
        sys.exit(1)
    except Exception as hata:
        print(f"[-] Hata: {hata}")
        sys.exit(1)

def port_tara_single(ip, port, zaman_asimi=1):
    soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soket.settimeout(zaman_asimi)
    try:
        sonuc = soket.connect_ex((ip, port))
        if sonuc == 0:
            return port
    except socket.error:
        return None
    finally:
        soket.close()
    return None

def portlari_tara(ip, portlar=YAYGIN_PORTLAR, zaman_asimi=1, sessiz=False):
    if not sessiz:
        print(f"\n[+] {ip} için paralel port taraması başlatılıyor...")

    acik_portlar = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        gelecekteki_sonuc = {executor.submit(port_tara_single, ip, port, zaman_asimi): port for port in portlar}

        for future in concurrent.futures.as_completed(gelecekteki_sonuc):
            port = gelecekteki_sonuc[future]
            try:
                sonuc = future.result()
                if sonuc is not None:
                    acik_portlar.append(sonuc)
                    if not sessiz:
                        print(f"    [AÇIK] Port {port}")
                else:
                    if not sessiz:
                        print(f"    [KAPALI] Port {port}")
            except Exception as e:
                if not sessiz:
                    print(f"    [-] Hata: Port {port} - {e}")

    return sorted(acik_portlar)

def banner_al(ip, port, timeout=2):
    try:
        soket = socket.socket()
        soket.settimeout(timeout)
        soket.connect((ip, port))
        soket.sendall(b"\r\n")
        banner = soket.recv(1024).decode(errors='ignore').strip()
        soket.close()
        return banner if banner else "Banner alınamadı"
    except Exception:
        return "Banner alınamadı"

def ftp_anon_giris_test(ip, timeout=3):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=timeout)
        ftp.login()
        ftp.quit()
        return True
    except:
        return False

def http_varsayilan_sifre_test(ip, port, timeout=5):
    """
    Basit HTTP Basic Auth varsayılan kullanıcı/sifre testi
    """
    url = f"http://{ip}:{port}/"
    denenen_kullanicilar = [("admin", "admin"), ("admin", "12345"), ("root", "root"), ("admin", "password")]
    for kullanici, sifre in denenen_kullanicilar:
        try:
            cevap = requests.get(url, auth=HTTPBasicAuth(kullanici, sifre), timeout=timeout)
            if cevap.status_code == 200:
                return f"Varsayılan kullanıcı/sifre bulundu: {kullanici}:{sifre}"
        except:
            continue
    return None

def rtsp_zafiyet_test(ip, port, timeout=5):
    """
    Basit RTSP DESCRIBE isteği gönderir, cevap varsa servis aktif ve test başarılı demektir.
    """
    try:
        soket = socket.socket()
        soket.settimeout(timeout)
        soket.connect((ip, port))
        istekgonder = b"DESCRIBE rtsp://%s/ RTSP/1.0\r\nCSeq: 2\r\n\r\n" % ip.encode()
        soket.sendall(istekgonder)
        cevap = soket.recv(4096).decode(errors='ignore')
        soket.close()
        if "RTSP" in cevap:
            return True
        else:
            return False
    except:
        return False
def telnet_varsayilan_sifre_test(ip, timeout=3):
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(timeout)
        soket.connect((ip, 23))
        veri = soket.recv(1024).decode(errors='ignore')
        soket.close()
        if "login" in veri.lower() or "user" in veri.lower():
            return "Telnet oturum ekranı görüldü, giriş denemesi yapılabilir"
        else:
            return "Telnet açık ama oturum ekranı yok"
    except Exception as e:
        return None


def sonucu_yazdir(cihazlar):
    if not cihazlar:
        print("[-] Hiç cihaz bulunamadı.")
        return

    print(f"\n{'IP Adresi':<18} {'MAC Adresi':<20} {'Üretici (Vendor)'}")
    print("-" * 60)
    for cihaz in cihazlar:
        print(f"{cihaz['ip']:<18} {cihaz['mac']:<20} {cihaz['uretici']}  -->  {cihaz.get('risk_seviyesi', '')}")


     
        if "telnet_varsayilan_sifre" in cihaz:
            sonuc = cihaz["telnet_varsayilan_sifre"]
            if sonuc:
                print(f"    [!] Telnet Zaafiyeti: {sonuc}")


def pasif_paket_yakala(paket):
    if scapy.ARP in paket and paket[scapy.ARP].op == 2:
        ip = paket[scapy.ARP].psrc
        mac = paket[scapy.ARP].hwsrc
        if ip not in BULUNAN_CIHAZLAR:
            BULUNAN_CIHAZLAR[ip] = mac
            print(f"[Yeni Cihaz - ARP] IP: {ip} MAC: {mac}")

    elif scapy.DHCP in paket:
        try:
            dhcp_options = paket[scapy.DHCP].options
            mesaj_tipi = None
            yiaddr = None
            for opt in dhcp_options:
                if isinstance(opt, tuple):
                    if opt[0] == 'message-type':
                        mesaj_tipi = opt[1]
                    elif opt[0] == 'yiaddr':
                        yiaddr = opt[1]
            if mesaj_tipi in [2, 5]:
                mac = paket[Ether].src
                ip = yiaddr
                if ip and ip not in BULUNAN_CIHAZLAR:
                    BULUNAN_CIHAZLAR[ip] = mac
                    print(f"[Yeni Cihaz - DHCP] IP: {ip} MAC: {mac}")
        except Exception:
            pass

    elif scapy.UDP in paket and (paket[scapy.UDP].sport == 5353 or paket[scapy.UDP].dport == 5353):
        if scapy.DNS in paket and scapy.DNSQR in paket:
            ip = paket[scapy.IP].src
            mac = paket[Ether].src
            if ip not in BULUNAN_CIHAZLAR:
                BULUNAN_CIHAZLAR[ip] = mac
                print(f"[Yeni Cihaz - mDNS] IP: {ip} MAC: {mac}")

    elif scapy.UDP in paket and (paket[scapy.UDP].sport == 1900 or paket[scapy.UDP].dport == 1900):
        ip = paket[scapy.IP].src
        mac = paket[Ether].src
        if ip not in BULUNAN_CIHAZLAR:
            BULUNAN_CIHAZLAR[ip] = mac
            print(f"[Yeni Cihaz - SSDP] IP: {ip} MAC: {mac}")

def pasif_dinleme(arayuz, sure, sessiz):
    if not sessiz:
        print(f"[+] {sure} saniye boyunca {arayuz} arayüzünde pasif dinleme yapılıyor...")
    scapy.sniff(iface=arayuz, prn=pasif_paket_yakala, timeout=sure)
    if not sessiz:
        print("\n[+] Dinleme tamamlandı.")
        print("Bulunan cihazlar:")
        for ip, mac in BULUNAN_CIHAZLAR.items():
            print(f"IP: {ip}, MAC: {mac}")
def json_kaydet(dosya_adi, veri):
    try:
        with open(dosya_adi, "w", encoding="utf-8") as dosya:
            json.dump(veri, dosya, indent=4, ensure_ascii=False)
        print(f"[✓] JSON raporu kaydedildi: {dosya_adi}")
    except Exception as e:
        print(f"[!] JSON kaydedilemedi: {e}")
from jinja2 import Environment, FileSystemLoader
import os

def html_kaydet(dosya_adi, cihazlar):
    try:
        klasor = os.path.dirname(os.path.abspath(__file__))
        env = Environment(loader=FileSystemLoader(os.path.join(klasor, "templates")))
        sablon = env.get_template("rapor.html")

        html_icerik = sablon.render(cihazlar=cihazlar)
        with open(dosya_adi, "w", encoding="utf-8") as dosya:
            dosya.write(html_icerik)
        print(f"[✓] HTML raporu kaydedildi: {dosya_adi}")
    except Exception as e:
        print(f"[!] HTML kaydedilemedi: {e}")
def risk_skoru_hesapla(cihaz):
    skor = 0

   
    skor += len(cihaz.get("acik_portlar", []))

   
    if cihaz.get("ftp_anon_giris"):
        skor += 5

    
    if cihaz.get("telnet_varsayilan_sifre"):
        skor += 5

    
    if cihaz.get("http_varsayilan_sifre"):
        skor += 5

    
    if cihaz.get("rtsp_aktif"):
        skor += 3

    
    if skor <= 2:
        seviye = "✅ Düşük Risk"
    elif skor <= 7:
        seviye = "⚠️ Orta Risk"
    else:
        seviye = "🔥 Yüksek Risk"

    cihaz["risk_skoru"] = skor
    cihaz["risk_seviyesi"] = seviye

def main():
    yazdir_afis()

    yardim_metni = """
IoT Sent - IP Kamera & IoT Cihaz Keşif Aracı
(Parametre açıklamaları burada yer alıyor...)
"""

    parser = argparse.ArgumentParser(
        description="IoT Sent - IP Kamera & IoT Cihaz Keşif Aracı",
        epilog=yardim_metni,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-t", "--target", required=False, help="Taranacak IP aralığı (örnek: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", type=str, help="Taranacak portlar (virgülle ayrılmış, örn: 22,80,443)")
    parser.add_argument("-o", "--timeout", type=float, default=1, help="Port tarama zaman aşımı (saniye), varsayılan=1")
    parser.add_argument("-j", "--json", action="store_true", help="Sonuçları JSON formatında göster")
    parser.add_argument("-q", "--quiet", action="store_true", help="Sessiz mod (minimum çıktı)")
    parser.add_argument("-P", "--pasif", action="store_true", help="Pasif izleme modunu aktif eder (aktif tarama yapmaz)")
    parser.add_argument("-i", "--interface", default="eth0", help="Pasif mod için ağ arayüzü (varsayılan eth0)")
    parser.add_argument("-s", "--sure", type=int, default=30, help="Pasif mod dinleme süresi saniye cinsinden (varsayılan 30)")
    parser.add_argument("-v", "--version", action="version", version="IoT Sent 1.5")
    parser.add_argument("--save-json", help="Sonuçları JSON dosyası olarak kaydeder (örn: scan.json)")
    parser.add_argument("--save-html", help="Sonuçları HTML raporu olarak kaydeder (örn: rapor.html)")

    args = parser.parse_args()

    
    if args.pasif:
        pasif_dinleme(args.interface, args.sure, args.quiet)
        return

    
    if not args.target:
        print("[-] Aktif tarama için hedef IP aralığı belirtmelisiniz. -t parametresi gerekli.")
        parser.print_help()
        sys.exit(1)

   
    if args.ports:
        try:
            portlar = [int(p.strip()) for p in args.ports.split(",")]
        except:
            print("[-] Port listesi hatalı. Virgülle ayrılmış sayılar olmalı. Örnek: 21,80,443")
            sys.exit(1)
    else:
        portlar = YAYGIN_PORTLAR

    
    cihazlar = agdaki_cihazlari_bul(args.target)
    
    if args.json:
        print(json.dumps(cihazlar, indent=4, ensure_ascii=False))

    if args.save_json:
        json_kaydet(args.save_json, cihazlar)

    if args.save_html:
        html_kaydet(args.save_html, cihazlar)

    
    for cihaz in cihazlar:
        ip = cihaz["ip"]
        acik_portlar = portlari_tara(ip, portlar, args.timeout, args.quiet)
        cihaz["acik_portlar"] = acik_portlar

        
        risk_skoru_hesapla(cihaz)

       
        if 21 in acik_portlar:
            cihaz["ftp_anon_giris"] = ftp_anon_giris_test(ip)

        if 80 in acik_portlar or 443 in acik_portlar:
            cihaz["http_varsayilan_sifre"] = None
            for port in [80, 443]:
                if port in acik_portlar:
                    sonuc = http_varsayilan_sifre_test(ip, port)
                    if sonuc:
                        cihaz["http_varsayilan_sifre"] = sonuc
                        break

        if 554 in acik_portlar:
            cihaz["rtsp_aktif"] = rtsp_zafiyet_test(ip, 554)

        if 23 in acik_portlar:
            cihaz["telnet_varsayilan_sifre"] = telnet_varsayilan_sifre_test(ip)

    
    if args.save_json:
        json_kaydet(args.save_json, cihazlar)

    if args.save_html:
        html_kaydet(args.save_html, cihazlar)


    if args.json:
        print(json.dumps(cihazlar, indent=4, ensure_ascii=False))
    else:
        sonucu_yazdir(cihazlar)



if __name__ == "__main__":
    main()
