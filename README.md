Genel Bilgiler

Wireshark, Linux, macOS, *BSD ve diğer Unix-tabanlı işletim sistemleri ile Windows için geliştirilmiş bir ağ trafiği analiz aracıdır. Qt grafiksel arayüz kütüphanesi ve libpcap/npacap paket yakalama ve filtreleme kütüphanelerini kullanır.

Wireshark ile birlikte gelen TShark, komut satırı tabanlı bir trafik izleyicisidir ve Wireshark ile aynı veri analizi, paket kayıt okuma/yazma ve filtreleme altyapısını kullanır. Ayrıca, kayıt dosyalarını farklı formatlarda düzenlemeye yarayan editcap aracı da bu paketle birlikte gelir.

Wireshark'ın resmi sitesi: https://www.wireshark.org
En güncel sürüm indirme sayfası: https://www.wireshark.org/download

Kurulum

Wireshark projesi, aşağıdaki platformlarda düzenli olarak test edilmektedir:

Linux (Ubuntu)

Microsoft Windows

macOS

Resmi kurulum paketleri Windows ve macOS için mevcuttur. Ayrıca Debian, Ubuntu, Fedora, CentOS, Arch, Gentoo, openSUSE, FreeBSD ve diğer popüler Linux dağıtımlarında standart veya ek paket olarak sunulmaktadır.

Bazı işletim sistemleri için mevcut Wireshark sürümü desteklenmeyebilir. Örneğin, Windows XP Wireshark 1.10 ve daha önceki sürümler tarafından desteklenmektedir.

Wireshark'ı oluşturmak için Python 3 gereklidir. Belgeleri oluşturmak için AsciiDoctor, bazı kaynak kodlarını üretmek için Perl ve GNU "flex" (standart "lex" yerine) kullanılmalıdır.

Tam kurulum talimatlarına INSTALL dosyasından ve geliştirici rehberinden ulaşabilirsiniz: https://www.wireshark.org/docs/wsdg_html_chunked/

Kullanım

Ağ trafiğini yakalamak için dumpcap programını root yetkileriyle çalıştırmalı ya da sisteminize uygun yetkilere sahip olmalısınız. Ancak, Wireshark veya TShark'ı root olarak çalıştırmak önerilmez, çünkü dumpcap daha güvenli bir yakalama süreci sunar.

Tüm komut satırı seçenekleri ve arayüz detayları için kılavuzu inceleyebilirsiniz.

Desteklenen Dosya Formatları

Wireshark birçok farklı dosya formatını destekler. Ayrıca aşağıdaki sıkıştırma formatlarını doğrudan açabilir:

GZIP

LZ4

ZSTD

Bu sıkıştırma formatları derleme sürecinde devre dışı bırakılabilir.

Ad Çözümleme

Wireshark, IPv4 ve IPv6 paketlerini analiz ederken ters ad çözümleme kullanabilir.

Eğer ad çözümlemeyi devre dışı bırakmak istiyorsanız:

-n parametresi ile tüm çözümleme işlemlerini kapatabilirsiniz.

-N mt parametresi ile yalnızca ağ katmanı adresleri için ad çözümlemeyi devre dışı bırakabilirsiniz.

Bu ayarı kalıcı yapmak için Tercihler menüsünden "Ad Çözümleme" seçeneklerini düzenleyebilirsiniz.

SNMP Desteği

Wireshark, SNMP paketlerini analiz edebilir ve libsmi kütüphanesini kullanarak MIB dosyalarından bilgi okuyabilir. Libsmi'yi devre dışı bırakmak için -DENABLE_SMI=OFF parametresi ile derleme yapabilirsiniz.

Hata Bildirimi

Wireshark sürekli geliştirilen bir proje olduğundan, zaman zaman hatalarla karşılaşabilirsiniz. Hataları bildirmek için şu sayfayı ziyaret edebilirsiniz: https://gitlab.com/wireshark/wireshark/-/issues

Lütfen bildirirken aşağıdaki bilgileri ekleyin:

"Wireshark Hakkında" bölümünden veya wireshark -v komutundan alınan tam sürüm bilgisi.

Linux kullanıyorsanız, dağıtımınızın adı ve sürümü.

Wireshark veya TShark'ı nasıl çalıştırdığınız ve hatayı nasıl ürettiğiniz.

Lisans

Wireshark, GNU GPLv2 lisansı altında sunulmuştur. Detaylı bilgiler için COPYING dosyasını inceleyebilirsiniz.

Feragatname

Bu yazılım herhangi bir garanti sunmamaktadır. Kullanım tamamen kullanıcı sorumluluğundadır.
