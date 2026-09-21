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

## HTTPS stratejileri ve test

DPIveil v0.6.0 ile birlikte Zapret `blockcheck` sonucunda bu ağda Discord TLS 1.2 için çalışan yöntemlerden üçü programa doğrudan uyarlanmıştır:

- `multisplit`: TLS ClientHello'yu sabit TCP payload konumundan böler. Blockcheck'in ilk tercihi olan `--dpi-desync=multisplit --dpi-desync-split-pos=2` karşılığıdır.
- `multidisorder`: aynı bölmeyi yapar ancak ikinci TCP parçasını önce gönderir. Blockcheck'te `--dpi-desync=multidisorder --dpi-desync-split-pos=2` çalışmıştır.
- `fake_ttl`: gerçek ClientHello'dan önce aynı TLS yapısını taşıyan, SNI içeriği değiştirilmiş ve düşük TTL'li bir sahte paket gönderir. Blockcheck'teki `--dpi-desync=fake --dpi-desync-ttl=1` fikrinin DPIveil uyarlamasıdır.

Varsayılan profil `multisplit` + `split_pos=2` kullanır ve yalnızca `discord.com` ile alt alan adlarını hedefler:

```json
{
  "strategy": "zapret_compat",
  "strategy_options": {
    "mode": "multisplit",
    "split_pos": 2,
    "fake_ttl": 1,
    "target_domains": ["discord.com"]
  }
}
```

Diğer yöntemi denemek için yalnızca `profiles/default.json` içindeki `mode` değerini `multidisorder` veya `fake_ttl` yapın. `fake_ttl` kullanırken `fake_ttl` değeri de değiştirilebilir.

Eski SNI-aware parçalama stratejisi kaldırılmadı. Geri dönmek için profil stratejisini `tls_client_hello_fragment` yapabilirsiniz.

### Test notları

Blockcheck sonucunda Discord için IPv4 TCP/443 bağlantısı kurulabiliyor; TLS 1.2 bypass olmadan başarısız olurken `multisplit`, `multidisorder`, `fake ttl=1` ve başka bazı desync varyasyonları çalışmıştır. TLS 1.3 ise testte bypass olmadan çalışmıştır. HTTP/3/QUIC için ayrı olarak `ipfrag2` yöntemi çalışmıştır; DPIveil'in mevcut motoru TCP odaklı olduğu için UDP/QUIC `ipfrag2` henüz bu sürüme eklenmemiştir.

Blockcheck başka bir DPI bypass yazılımı açıkken çalıştırılırsa sonuçlar kirlenebilir. Testten önce DPIveil, Zapret/GoodbyeDPI ve diğer WinDivert tabanlı bypass süreçlerini kapatın.

Windows DNS sorgusunu DPIveil TLS paketini görmeden önce yapar. Yanlış adrese yönlendirilmiş bir DNS sonucunu paket parçalama düzeltemez. Sadece curl denemesinde şifreli DNS kullanmak için DPIveil çalışırken ayrı bir terminalde aşağıdaki komutu çalıştırın:

```powershell
curl.exe -4 --http1.1 --doh-url https://cloudflare-dns.com/dns-query --resolve cloudflare-dns.com:443:1.1.1.1 --connect-timeout 10 --max-time 20 -I -v https://discord.com/
```

Normal IPv4 HTTPS bağlantısını da `curl.exe -4 -I -v https://www.cloudflare.com/` ile kontrol edin. DPIveil günlüğündeki strateji satırları paket manipülasyonunun denendiğini gösterir; tek başına erişimin başarıyla açıldığını kanıtlamaz.
