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

Varsayılan test profili yalnızca `discord.com` ve alt alan adlarının giden TLS ClientHello paketini **SNI alan adının içinde** iki TCP parçasına ayırır; ikinci parçanın sıra numarası ilk parçanın uzunluğu kadar ilerletilir. Ters sıra denemesi başarısız olduğu için `reverse_order` varsayılan olarak `false` değerindedir. SNI okunamazsa `first_chunk_size` (32 bayt) kullanılır. Önceki yöntemle karşılaştırmak için `profiles/default.json` içindeki `split_mode` değerini `fixed` yapabilirsiniz. `target_domains` listesini düzenleyerek farklı alan adlarını seçebilirsiniz. Günlükte `TLS split`, parça boyutları, gelen TCP SYN-ACK/RST paketlerinin IPv4 TTL/IP kimliği ve gönderim hataları gösterilir.

`drop_suspect_rst` varsayılan olarak `false`: ölçülen bağlantıda RST'yi düşürmek curl hatasını yalnızca zaman aşımına çevirdi, HTTPS yanıtı getirmedi. Deneysel olarak açıldığında **yalnızca parçalanmış seçili alan adı bağlantılarında**, ClientHello gönderildikten sonraki 8 saniyede gelen ve kaydedilmiş SYN-ACK'e göre `ip_id=0 → ip_id≠0`, `TTL → TTL-1` örüntüsünü taşıyan RST paketini düşürür. Bu örüntü gönderenin kimliğini kanıtlamaz; gerçek sunucunun RST'si de eşleşebilir. Başarılı HTTPS yanıtı alınmadan erişim sağlandı sayılmaz.

Windows DNS sorgusunu DPIveil TLS paketini görmeden önce yapar. Yanlış adrese yönlendirilmiş bir DNS sonucunu paket parçalama düzeltemez. Sadece curl denemesinde şifreli DNS kullanmak için DPIveil çalışırken ayrı bir terminalde aşağıdaki komutu çalıştırın:

```powershell
curl.exe -4 --http1.1 --doh-url https://cloudflare-dns.com/dns-query --resolve cloudflare-dns.com:443:1.1.1.1 --connect-timeout 10 --max-time 20 -I -v https://discord.com/
```

Uygulamaların tamamı için Windows 11'de etkin ağ bağdaştırıcısında şifreli DNS ayarlayın: Ayarlar > Ağ ve internet > Ethernet/Wi-Fi bağlantısı > DNS sunucusu ataması > Düzenle. IPv4 için `1.1.1.1` ve `1.0.0.1`, IPv6 için `2606:4700:4700::1111` ve `2606:4700:4700::1001` girin; Windows sunuyorsa **yalnızca şifreli DNS** seçeneğini kullanın. Önceki DNS ayarlarını kaydedin; gerekirse geri alabilirsiniz. Bağlantı yenilemesi ve `ipconfig /flushdns` gerekebilir. Tek başına düz DNS sunucusunu değiştirmek ağdaki müdahaleyi önlemeyebilir. [Cloudflare'ın Windows yönergesi](https://developers.cloudflare.com/1.1.1.1/setup/windows/).

Normal IPv4 HTTPS bağlantısını da `curl.exe -4 -I -v https://www.cloudflare.com/` ile kontrol edin. `TLS split` satırı paket gönderiminin denendiğini gösterir; sunucunun paketleri aldığı veya erişim engelinin aşıldığı anlamına gelmez. `Inbound TCP RST` gelen bir sıfırlamayı gösterir ama kimin gönderdiğini kanıtlamaz. Sertifika denetimini kapatıp yönlendirme sayfasını başarı saymayın.

### Ağda çalışan stratejiyi bulma

SNI bölme ve RST düşürme ölçülen Discord bağlantısını açmadı. Yeni bir strateji seçmeden önce, DPIveil'i durdurup [Flowseal'in resmî Windows zapret paketinin](https://github.com/Flowseal/zapret-discord-youtube) [son sürümünü](https://github.com/Flowseal/zapret-discord-youtube/releases/latest) ayrı çalıştırın. Şifreli DNS açıkken `service.bat` → `Run Tests` → `Standard tests` → `All configs` yoluyla toplu testi başlatın. Hizmet kurmaya gerek yoktur. Çalışan yapılandırmanın adını ve Discord için sonuç satırlarını kaydedin; bu bilgi DPIveil'e hangi paket stratejisinin uyarlanacağını belirler. Testin başarılı sayılması için o yapılandırma ile gerçek HTTPS yanıtı ve sertifika doğrulaması da alınmalıdır. Hiçbir yapılandırma çalışmıyorsa TCP parçalamanın tek başına çözüm olacağı varsayılmamalıdır.
