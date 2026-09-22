# DPIveil

DPIveil, Windows üzerinde Discord bağlantısında görülen DNS zehirleme ve HTTPS/TLS tabanlı DPI engellerini otomatik olarak aşmayı amaçlayan hafif bir araçtır.

Program açıldığında geçici DNS politikasını uygular, desteklenen DPI stratejilerini otomatik test eder ve o oturum için çalışan yöntemi seçer. Kullanıcının manuel strateji seçmesi gerekmez.

> DPIveil yalnızca Windows 10/11 üzerinde çalışır ve yönetici yetkisi ister.

## Kullanıcılar için hızlı başlangıç

Release sürümünü kullanıyorsanız klasörde şu üç dosyanın birlikte bulunması yeterlidir:

```text
DPIveil.exe
WinDivert64.dll
WinDivert64.sys
```

`DPIveil.exe` dosyasını çalıştırın ve Windows'un yönetici izni isteğini onaylayın.

DPIveil başlangıçta:

1. Discord için geçici Windows DNS politikasını etkinleştirir.
2. DNS önbelleğini temizler.
3. Discord HTTPS bağlantısını test eder.
4. Çalışan DPI stratejisini otomatik seçer.
5. Seçilen stratejiyi program açık kaldığı sürece kullanır.

Durdurmak için konsol penceresinde `Ctrl+C` kullanabilirsiniz.

Program normal şekilde kapatıldığında oluşturduğu geçici DNS kurallarını kaldırır ve önceki DoH durumunu geri yükler.

## Nasıl çalışıyor?

DPIveil iki katmanı birlikte kullanır:

### 1. DNS

Discord alan adları Windows'un yerleşik **NRPT + DNS-over-HTTPS (DoH)** sistemi üzerinden güvenilir DNS çözümleyicisine yönlendirilir.

Varsayılan yapılandırma:

- DNS çözümleyici: `1.1.1.1`
- DoH: `https://cloudflare-dns.com/dns-query`
- Düz UDP DNS fallback: kapalı
- Ağ bağdaştırıcısının DNS ayarları değiştirilmez
- Yerel DNS proxy çalıştırılmaz
- Başlangıçta ve çıkışta DNS cache temizlenir
- DPIveil yalnızca kendi oluşturduğu NRPT kurallarını kaldırır

TLS sertifika doğrulaması ve HSTS devre dışı bırakılmaz.

### 2. DPI stratejisi

DPIveil Discord'a doğrulanmış HTTPS bağlantıları göndererek aday stratejileri tek tek test eder.

Varsayılan adaylar:

```text
multisplit-2
multidisorder-2
fake-ttl-1
fake+badseq
syndata
ipfrag2-8 (QUIC/UDP)
```

Her aday, gerçek ve sertifika doğrulamalı HTTPS yanıtı (QUIC adayı için
sertifika doğrulamalı HTTP/3 yanıtı) alınarak test edilir. Tüm adaylar
denendikten sonra `priority`, ardından ad sırasına göre en az müdahaleci
başarılı yöntem o oturum için etkinleştirilir. Hiçbir aday çalışmazsa program
başarılıymış gibi rastgele bir yöntem seçmez.

Discord masaüstü istemcisinin bazı ek endpoint'leri de seçimden sonra tanılama amacıyla kontrol edilir. Bu kontroller strateji seçimini değiştirmez.

## Loglar

EXE sürümünde loglar uygulama klasörüne yazılmaz.

Konum:

```text
%LOCALAPPDATA%\DPIveil\logs\dpiveil.log
```

Bir sorun bildirirken bu log dosyasını paylaşmak tanılamayı kolaylaştırır.

Başarılı otomatik strateji, aynı ağda sonraki açılışları hızlandırmak için
strategy-cache.json dosyasına kaydedilir. Cache yalnızca gerçek ve sertifika
doğrulamalı Discord probe'u başarılı olursa kullanılır; ağ rotası değişirse,
aday profili değişirse, kayıt yedi günden eskiyse veya dosya bozuksa yok
sayılır ve tam otomatik tarama çalışır.

## Antivirüs uyarıları hakkında

DPIveil paket trafiğini işlemek için **WinDivert** kullanır.

WinDivert meşru bir ağ sürücüsüdür ancak paket yakalama/değiştirme yeteneği nedeniyle bazı antivirüs ürünleri onu `RiskTool` veya benzeri düşük seviyeli bir uyarıyla işaretleyebilir.

Örneğin Kaspersky şu tür bir sınıflandırma gösterebilir:

```text
not-a-virus:RiskTool.Multi.WinDivert
```

Bu sınıflandırma WinDivert'in doğrudan virüs olduğu anlamına gelmez; güvenlik yazılımının kötüye kullanılabilecek meşru araç kategorisidir.

DPIveil dağıtımında WinDivert dosyaları EXE içine gizlenmez veya değiştirilmez. Release paketinde ayrı ve orijinal halleriyle tutulurlar.

Antivirüsü kapatmanız önerilmez.

## Kaynaktan çalıştırma

Geliştirme sürümünü çalıştırmak için:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Gereksinimler:

- Windows 10/11
- Python 3.10+
- Yönetici yetkisi

## Yapılandırma

Varsayılan profil:

```text
profiles/default.json
```

Örnek DNS yapılandırması:

```json
{
  "dns_policy": {
    "enabled": true,
    "resolver": "1.1.1.1",
    "doh_template": "https://cloudflare-dns.com/dns-query",
    "allow_fallback_to_udp": false
  }
}
```

`domains` alanı belirtilmezse DNS politikası ve otomatik strateji ortak `DISCORD_DOMAINS` listesini kullanır.

Varsayılan otomatik strateji yapılandırması:

```json
{
  "strategy": "auto",
  "strategy_options": {
    "host": "discord.com",
    "timeout": 6,
    "candidate_timeout": 4,
    "max_ips": 2,
    "candidates": [
      {"name": "multisplit-2", "kind": "multisplit", "priority": 1, "split_pos": 2},
      {"name": "multidisorder-2", "kind": "multidisorder", "priority": 2, "split_pos": 2},
      {"name": "fake-ttl-1", "kind": "fake_ttl", "priority": 3, "ttl": 1},
      {"name": "fake+badseq", "kind": "fake+badseq", "priority": 4},
      {"name": "syndata", "kind": "syndata", "priority": 5},
      {"name": "ipfrag2-8", "kind": "ipfrag2-8", "priority": 6, "ipfrag_pos": 8, "transport": "udp"}
    ]
  }
}
```

## Proje yapısı

```text
dpiveil/
  app.py          uygulama yaşam döngüsü
  autoselect.py   otomatik aday/oturum stratejisi seçimi ve fallback akışı
  probes.py       sertifika doğrulamalı HTTPS/WebSocket/QUIC ve DNS probe'ları
  strategy_cache.py  ağ-bağımlı başarılı strateji cache'i
  constants.py    ortak Discord alan adı listesi
  dns_policy.py   Windows NRPT + DoH politikası
  engine.py       WinDivert paket motoru
  profiles.py     profil yükleme
  strategies/     DPI stratejileri
    advanced.py    fake+badseq, syndata ve QUIC ipfrag2

profiles/
  default.json    varsayılan yapılandırma

scripts/
  build.ps1       Windows EXE build scripti
```

## Teknik mimari

DPIveil'in temel akışı:

```text
Windows DNS
   │
   ├── NRPT
   └── DoH
       │
       ▼
Doğrulanmış Discord IP'leri
       │
       ▼
Otomatik HTTPS strateji testi
       │
       ▼
WinDivert paket motoru
       │
       ▼
Oturum boyunca seçilen strateji
```

WinDivert motoru TCP/443 ve QUIC için UDP/443 trafiğini işler. `ipfrag2-8`
yalnızca IPv4 UDP paketlerini iki gerçek IP parçasına ayırır; IPv6 ve TFO SYN
paketleri değiştirilmeden geçirilir. DNS paketleri WinDivert üzerinden
yakalanmaz; DNS tarafı Windows'un kendi NRPT + DoH altyapısına bırakılmıştır.

---

DPIveil geliştirme aşamasındadır. Yeni sürümleri kullanırken release notlarını ve bilinen sorunları kontrol etmeniz önerilir.
