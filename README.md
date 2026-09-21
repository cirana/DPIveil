# DPIveil

DPIveil is a lightweight Windows command-line network traffic tool written in Python.

The project is currently in its initial development stage. The first milestone is a stable CLI core with administrator checks, profile loading, logging, graceful shutdown, and WinDivert/PyDivert integration.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Press `Ctrl+C` to stop DPIveil cleanly.

## HTTPS stratejisi ve test

Varsayılan profil giden TLS ClientHello paketini **SNI alan adının içinde** iki TCP parçasına ayırır; ikinci parçanın sıra numarası ilk parçanın uzunluğu kadar ilerletilir. SNI okunamazsa `first_chunk_size` (32 bayt) kullanılır. Önceki yöntemle karşılaştırmak için `profiles/default.json` içindeki `split_mode` değerini `fixed` yapabilirsiniz. Günlükte `TLS split`, parça boyutları, gelen TCP sıfırlamaları ve gönderim hataları gösterilir.

Windows DNS sorgusunu DPIveil TLS paketini görmeden önce yapar. Yanlış adrese yönlendirilmiş bir DNS sonucunu paket parçalama düzeltemez. Sadece curl denemesinde şifreli DNS kullanmak için DPIveil kapalıyken ve yönetici olarak açıkken aşağıdaki **aynı** komutu çalıştırın:

```powershell
curl.exe -4 --http1.1 --doh-url https://cloudflare-dns.com/dns-query --resolve cloudflare-dns.com:443:1.1.1.1 --connect-timeout 10 --max-time 20 -I -v https://discord.com/
```

Uygulamaların tamamı için Windows 11'de etkin ağ bağdaştırıcısında şifreli DNS ayarlayın: Ayarlar > Ağ ve internet > Ethernet/Wi-Fi bağlantısı > DNS sunucusu ataması > Düzenle. IPv4 için `1.1.1.1` ve `1.0.0.1`, IPv6 için `2606:4700:4700::1111` ve `2606:4700:4700::1001` girin; Windows sunuyorsa **yalnızca şifreli DNS** seçeneğini kullanın. Önceki DNS ayarlarını kaydedin; gerekirse geri alabilirsiniz. Bağlantı yenilemesi ve `ipconfig /flushdns` gerekebilir. Tek başına düz DNS sunucusunu değiştirmek ağdaki müdahaleyi önlemeyebilir. [Cloudflare'ın Windows yönergesi](https://developers.cloudflare.com/1.1.1.1/setup/windows/).

Normal IPv4 HTTPS bağlantısını da `curl.exe -4 -I -v https://www.cloudflare.com/` ile kontrol edin. `TLS split` satırı paket gönderiminin denendiğini gösterir; sunucunun paketleri aldığı veya erişim engelinin aşıldığı anlamına gelmez. `Inbound TCP RST` gelen bir sıfırlamayı gösterir ama kimin gönderdiğini kanıtlamaz. Sertifika denetimini kapatıp yönlendirme sayfasını başarı saymayın.
