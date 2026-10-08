# ReconBot: ilk kullanım ve son kontrol

## Kurulum

Mac’te eski ReconBot’u tamamen kapat. Yeni DMG’yi aç, uygulamayı Applications’a sürükle ve değiştirmeyi seç. Geçmişi korumak için Application Support klasörünü silme. Linux için DEB veya AppImage kullan; bu bilgisayarda fiziksel Linux masaüstü kontrolü yapılmadı. Mac paketi imzasız ve notarize edilmemiştir.

Uygulama Python’u içerir. Seçtiğin tarayıcı araçları, SQLmap, wordlist dosyaları ve isteğe bağlı AI sunucusu ayrıca gerekir. Configure’da yalnız kullanacağın araçları seç. Eksik seçili araç uyarısını çöz; kapattığın araç otomatik olarak başarısız sayılmaz.

Wordlist için Browse → dosyayı seç → Save and lock. Programı kapatıp açınca yol/ kilit korunur. Başka liste için Unlock path kullan. Kilit dosyanın içeriğini değiştirmez.

## Tarama ve sonuçları okuma

Hedefi tam adresle gir: örneğin `http://127.0.0.1:8088`. Tarama başlayınca Dashboard/Terminal’den ilerlemeyi izle, Report’ta kanıtları oku. Geçmişten başka çalışma seçersen sonuçların hedefinin de değiştiğini kontrol et.

Nuclei eşleşmesi otomatik istismar kanıtı değildir. Tamamlanmamış çalışma negatif sonuç vermez. Kapsam, seçilen araçlar ve gerçekten tamamlanan kontroller birlikte değerlendirilir. Rapor anlatımı Türkçe; arayüzde İngilizce/Türkçe seçeneği vardır.

## SQLmap ve giriş testleri

Ana taramanın hedefini seçtikten sonra Validation veya Authentication’a geç. Bu işler bağımsızdır; ana risk skorunu değiştirmez.

SQL örneği: `http://127.0.0.1:8088/item?id=1`, GET, Parameter `id`. Korunan kontrol: `/clean?id=1`. Payload alanı SQLmap’in kullandığı test değerini gösterir; tek başına veritabanı dökümü değildir.

HTTP Basic örneği: `/basic`, Single username `operator`, kısa `passwords.txt`. Basic, tarayıcının kullanıcı/şifre penceresi açtığı HTTP kimlik doğrulama biçimidir.

Form örneği: `/login`, Login form (POST), alan adları `username` ve `password`, ek değerler boş. Alan adları HTML’deki `name` değeridir. Kök adresi yerine gerçek form action adresini kullan. Automatic response comparison modunda başarı metni zorunlu değildir. Üçüncü denemede `operator / reconbot-demo-2026` aday olarak görünür; tarayıcıda elle giriş yaparak doğrula. Bilinen başarı metniyle test etmek için Response contains text → `Welcome operator`; yanlış giriş metni `Invalid credentials`.

`HTTP 405` POST kabul edilmeyen adres demektir; hiç wordlist denemesi yapılmamış olabilir. 404 adresi, bağlantı hatası sunucuyu/portu kontrol ettirir. Technical details altında özgün hata korunur. Otomatik referans eşleşmesi kesin reddedilme değildir; aday bulunmaması kesin güvenlik kanıtı değildir.

Docker nowasp örneği: `http://127.0.0.1:8082/index.php?page=login.php`, POST, `username` / `password`, ek değer **`login-php-submit-button=Login`**. Bu laboratuvar hesabı `admin / adminpass`; demo listesi `desktop/build/nowasp-auth-demo/passwords.txt`. Seçili tarama host/portu da 127.0.0.1:8082 olmalı. Mutillidae’nin gönder düğmesi değeri olmadan giriş işlenmeyebilir.

Dört sitenin tam ayarları ve wordlist yolları: [yerel test rehberi](testing.md). Siteler yalnız bu bilgisayarda çalışır; yayınlanacak uygulamanın gerçek hedefleri değildir.

## AI kontrolünün mevcut sonucu

Gerçek model sohbetlerinde Mistral 7B ve kurulu Qwen Q4 yanlış CVE/ürün eşleştirmeleri ve doğrulama yorumları üretti. Qwen karşılaştırması ayrıca bir sonraki yanıtı beklerken testin süresini aştı. Test connection yalnız bağlantıyı kontrol eder; teknik doğruluk onayı değildir. AI teknik doğruluk kabulünü geçmedi; beta sürümde deneysel olarak sunuluyor. Giriş adayı kesin başarı, test metninin yanıtta görünmesi RCE kanıtı değildir. Özgün model cevapları saklanır; maskeleme veya yerel cevapla değiştirme yapılmaz.

## Senin son kabul kontrolün

- [ ] Yeni kurulu uygulamada 8085/8086/8087/8088 taramalarını ayrı çalıştır. Korunan/yapılandırma açıkları/SQL-giriş farklarını rehberdeki beklenen kanıtlarla karşılaştır.
- [ ] SQL açık ve korunan parametreyi; Basic ve otomatik formu; yanlış listeyi ve Stop düğmesini dene. Başarı/aday üstte, diğer denemeler açılır bölmede olmalı.
- [ ] Küçük pencerede Authentication/Validation başlangıç düğmesine eriş. Ayar değiştirirken sayfa zıplamamalı. Tarama sürerken rapor konumun korunmalı.
- [ ] Gerçek touchpad ile grafik yakınlaştırmasını dene. Aynı düğüm/boş alan/Escape/Reset vurgu temizlemeli; grup detayları sağda okunmalı.
- [ ] Uygulamayı kapatıp aç: geçmiş, AI ayarı ve kilitli wordlist geri gelsin. Açık görünmesine rağmen durmuş bir iş kalmasın.
- [ ] AI sunucusunda model yüklüyken Test connection ve doğal rapor sohbetini dene. Hedef/kanıt doğru; aday veya şablon eşleşmesi kesin exploit diye anlatılmamalı.

Hata olursa hedef + çalışma kimliği + beklenen/görülen davranışı gönder. Depo: [mpol4t/Reconbot](https://github.com/mpol4t/Reconbot). Beta sınırları ve test kanıtları [test rehberinde](testing.md) yer alır.
