# DPIveil

DPIveil, Windows'ta Discord bağlantısında görülen DNS zehirleme ve DPI engellerini otomatik olarak yönetir. Program, çalışan yöntemi bulup yalnızca o oturum boyunca kullanır.

> Windows 10/11 ve yönetici yetkisi gerekir.

## Hızlı başlangıç

### Release sürümü

Aynı klasörde şu üç dosyanın bulunduğundan emin olun:

```text
DPIveil.exe
WinDivert64.dll
WinDivert64.sys
```

`DPIveil.exe` dosyasını çalıştırın ve Windows'un yönetici iznini onaylayın. Durdurmak için konsol penceresinde `Ctrl+C` kullanın.

### Kaynaktan çalıştırma

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Nasıl çalışır?

DPIveil başlangıçta:

1. Discord alan adları için geçici NRPT + DNS-over-HTTPS (DoH) politikasını etkinleştirir.
2. DNS önbelleğini temizler.
3. Doğrudan HTTPS bağlantısını kontrol eder.
4. Gerekirse aday DPI yöntemlerini gerçek bağlantıyla test eder.
5. Başarılı ve en az müdahaleci yöntemi otomatik olarak etkinleştirir.

Başarılı yöntem ağla ilişkilendirilerek yerel cache'e kaydedilir. Sonraki açılışta önce gerçek Discord probe'u ile doğrulanır; çalışmıyorsa cache yok sayılır ve tam otomatik tarama yapılır.

TLS sertifika doğrulaması ve HSTS devre dışı bırakılmaz. Düz UDP DNS fallback kapalıdır; program normal kapandığında geçici DNS ayarlarını geri yükler.

## Desteklenen yöntemler

```text
multisplit-2
multidisorder-2
fake-ttl-1
fake+badseq
syndata
ipfrag2-8 (QUIC/UDP)
```

Adaylar gerçek, sertifika doğrulamalı HTTPS yanıtı ile karşılaştırılır. QUIC adayı için sertifika doğrulamalı HTTP/3 kullanılır. Hiçbir yöntem çalışmazsa program rastgele seçim yapmaz.

## Loglar

Log dosyası:

```text
%LOCALAPPDATA%\DPIveil\logs\dpiveil.log
```

Strateji cache'i aynı klasördeki `strategy-cache.json` dosyasında tutulur. Dosya bozulur, eski kalır veya ağ değişirse güvenle yok sayılır.

Bağlantı sorunu yaşarsanız programı yönetici olarak çalıştırıp bu log dosyasını paylaşın. Release dosyalarının aynı klasörde olduğunu da kontrol edin.

## Antivirüs uyarıları

DPIveil paket trafiği için WinDivert kullanır. Bu nedenle bazı antivirüsler WinDivert'i `RiskTool` olarak gösterebilir. Bu, tek başına virüs olduğu anlamına gelmez; yine de antivirüsü tamamen kapatmak yerine yalnızca güvendiğiniz kaynaktan gelen dosyaları kullanın.

## Yapılandırma

Varsayılan profil `profiles/default.json` dosyasındadır. Otomatik seçim varsayılan olarak açıktır; yeni strateji adayları bu profilden eklenebilir.
