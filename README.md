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

## DNS yönlendirme

Varsayılan profilde DPIveil, Windows'un giden IPv4/IPv6 **UDP/53** DNS sorgularını [GoodbyeDPI'nin yönlendirme yöntemine](https://github.com/ValdikSS/GoodbyeDPI) benzer biçimde yapılandırılmış çözümleyiciye yönlendirir; sorgu kimliği, soru ve istemci portu eşleşen yanıtların kaynak IP/portunu özgün DNS sunucusuna çevirip istemciye teslim eder. IPv4 hedefi `77.88.8.8:1253`, IPv6 hedefi `[2a02:6b8::feed:0ff]:1253` olarak ayarlıdır; [Yandex DNS](https://dns.yandex.com/) çözümleyici adreslerini yayınlar. DNS WinDivert katmanı otomatik HTTPS seçimi başlamadan açılır, ardından `ipconfig /flushdns` çalıştırılır. Açılışta DNS katmanı veya önbellek temizliği başarısız olursa DPIveil hata vererek durur.

`profiles/default.json` içindeki `dns_redirect` bölümünden IPv4 ve IPv6 hedeflerini değiştirebilir veya `enabled: false` ile bu özelliği kapatabilirsiniz. Günlükte DNS sorgu/yanıt sayıları ve beklenmeyen yanıtlar gösterilir. DNS yönlendirme **yalnızca UDP/53** için geçerlidir; TCP/53 veya uygulamaların kendi DoH/DoT bağlantıları bu katmandan geçmez. UDP DNS şifreli ya da kriptografik olarak doğrulanmış değildir; standart dışı porta yönlendirme DNS müdahalesini azaltabilir ama ağ bu hedefi de engelliyor ya da taklit ediyorsa şifreli DNS kullanılması gerekir. TLS sertifika denetimi ve HSTS değiştirilmez. IPv6 çözümleyicisine erişiminiz yoksa IPv6 sorguları yanıt alamayabilir; çözümleyiciyi ağınıza uygun bir IPv6 adres/portuyla değiştirin.

## HTTPS stratejileri ve test

DPIveil v0.7.0 açıldığında önce Windows'un mevcut DNS yanıtıyla Discord'a **doğrudan HTTPS** isteği gönderir. En az bir adreste sertifikası doğrulanan bir HTTPS yanıtı gelirse paket motorunu başlatmaz. Doğrudan erişim başarısızsa şifreli DNS ile doğrulanan IPv4 adreslerinde aşağıdaki adayları sırayla dener:

- `multisplit`: TLS ClientHello'yu sabit TCP payload konumundan böler. Blockcheck'in ilk tercihi olan `--dpi-desync=multisplit --dpi-desync-split-pos=2` karşılığıdır.
- `multidisorder`: aynı bölmeyi yapar ancak ikinci TCP parçasını önce gönderir. Blockcheck'te `--dpi-desync=multidisorder --dpi-desync-split-pos=2` çalışmıştır.
- `fake_ttl`: gerçek ClientHello'dan önce aynı TLS yapısını taşıyan, SNI içeriği değiştirilmiş ve düşük TTL'li bir sahte paket gönderir. Blockcheck'teki `--dpi-desync=fake --dpi-desync-ttl=1` fikrinin DPIveil uyarlamasıdır.

Her aday için yalnızca TCP bağlantısı veya paket gönderimi yeterli değildir: TLS sertifikası `discord.com` için doğrulanmalı ve sunucu geçerli bir HTTP yanıtı vermelidir. Birden fazla aday çalışırsa önce daha çok IP'de yanıt veren, eşitlikte daha düşük `priority` değerine sahip olan seçilir. `profiles/default.json` aday listesinden yeni bir aday eklenebilir; desteklenen `kind` değerleri `multisplit`, `multidisorder`, `fake_ttl` şeklindedir. Bir aday başarısızsa diğerleri de denenir. Hiçbiri çalışmazsa paket motoru durdurulur ve açıkça hata yazılır.

Varsayılan profil:

```json
{
  "strategy": "auto",
  "strategy_options": {
    "host": "discord.com",
    "timeout": 6,
    "max_ips": 2,
    "candidates": [
      {"name": "multisplit-2", "kind": "multisplit", "priority": 1, "split_pos": 2},
      {"name": "multidisorder-2", "kind": "multidisorder", "priority": 2, "split_pos": 2},
      {"name": "fake-ttl-1", "kind": "fake_ttl", "priority": 3, "ttl": 1}
    ]
  }
}
```

Problar yalnızca geçici deneme bağlantısının kaynak TCP portuna uygulanır. Seçilen yöntem oturumun geri kalanında `discord.com` ve alt alan adları için kullanılır. Normal uygulamalar sistem DNS ayarlarını kullanmaya devam eder; DNS yanıtları zehirleniyorsa Windows veya tarayıcıda şifreli DNS ayarı ayrıca gereklidir.

Tek stratejiyle elle çalışmak için `zapret_compat`, eski SNI bölme stratejisi için `tls_client_hello_fragment` profil seçeneği korunmuştur. Otomatik strateji seçiminin Windows üzerinde gerçek ağda henüz doğrulanmadığını dikkate alın.

### Test notları

Blockcheck sonucunda Discord için IPv4 TCP/443 bağlantısı kurulabiliyor; TLS 1.2 bypass olmadan başarısız olurken `multisplit`, `multidisorder`, `fake ttl=1` ve başka bazı desync varyasyonları çalışmıştır. TLS 1.3 ise testte bypass olmadan çalışmıştır. HTTP/3/QUIC için ayrı olarak `ipfrag2` yöntemi çalışmıştır; DPIveil'in mevcut motoru TCP odaklı olduğu için UDP/QUIC `ipfrag2` henüz bu sürüme eklenmemiştir.

Blockcheck başka bir DPI bypass yazılımı açıkken çalıştırılırsa sonuçlar kirlenebilir. Testten önce DPIveil, Zapret/GoodbyeDPI ve diğer WinDivert tabanlı bypass süreçlerini kapatın.

Windows DNS sorgusunu DPIveil TLS paketini görmeden önce yapar. Yanlış adrese yönlendirilmiş bir DNS sonucunu paket parçalama düzeltemez. Sadece curl denemesinde şifreli DNS kullanmak için DPIveil çalışırken ayrı bir terminalde aşağıdaki komutu çalıştırın:

```powershell
curl.exe -4 --http1.1 --doh-url https://cloudflare-dns.com/dns-query --resolve cloudflare-dns.com:443:1.1.1.1 --connect-timeout 10 --max-time 20 -I -v https://discord.com/
```

Normal IPv4 HTTPS bağlantısını da `curl.exe -4 -I -v https://www.cloudflare.com/` ile kontrol edin. DPIveil günlüğündeki strateji satırları paket manipülasyonunun denendiğini gösterir; tek başına erişimin başarıyla açıldığını kanıtlamaz.
