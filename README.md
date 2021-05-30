Honey Pot
==

Schritt 1
--

Ein Wlan-Router mit OpenWRT, der als dump Switch agiert indem alle Interfaces
gebridged sind. Eine Beschreibung für die Konfiguration ist hier:

[dumbap](https://openwrt.org/docs/guide-user/network/wifi/dumbap)

An diesen Router verbindet man einen Rechner per Ethernet und kann nun schauen,
was die Geräte so treiben.

Schritt 2
--

Als erstes melden sich die Geräte mit einer DHCP Anfrage. Diese muss mit einer
validen IP, einem Standardgateway und einem Nameserver beantwortet werden.

Ich habe keinen brauchbaren und funktionierenden DHCP Server gefunden, darum
habe ich (unter Verwendung von Teilen aus anderen Projekten) einen eigenen
erstellt.

In guter Python-Manier beginnt er zu arbeiten auf `serve_forever()` und ist in
drei Schichten umgesetzt:

- Senden & Empfangen der UDP Pakete
- Decoden & Encoden der Pakete
- Beantworten der Fragen der Geräte

Es fehlt fehlt die Schicht für die Vergabe der IPs, die im Hauptmodul
kontrolliert wird.

`lib/dhcp.py`

Schritt 3
--

Als nächstes versuchen die Geräte, Namen aufzulösen. Ein DNS Server leistet
dies. Ein einigermassen brauchbares Modul existierte und findet Verwendung. Auch
dieses startet mit `serve_forever()` und die wirkliche Zuordnung der IPs findet
wiederum im Hauptmodul statt.

Manche Geräte nutzen tcp domain-s (port 853). Dies ist (noch) nicht
implementiert.

`lib/dns.py`

Schritt 4
--

Viele Geräte erfragen dann die Uhrzeit, also sollte NTP gesprochen werden.
Wiederum startet der Dienst mit Aufruf von `serve_forever()` und erhält seine
Antwort aus dem Hauptmodul. So kann jedem Gerät eine eigene Uhrzeit
untergejubelt werden.

`lib/ntp.py`

Schritt 5
--

Die Welt spricht HTTP und HTTPS. Als erstes Prüfen die Geräte ob das Netz
wirklich Zugriff auf das Internet erlaubt. Dazu erfragen Android-Telefone
[generate 204](http://connectivitycheck.gstatic.com/generate_204) oder
[generate 204](http://google.com/generate_204) und erwarten einen
HTTP-Statuscode von 204.

Für TLS beinhaltet das https module die Möglichkeit, Zertifikate 'on the fly'
zu generieren. Damit diese akzeptiert werden, muss auf dem Gerät das
Root-Zertifikat `pemdb/open.net-ca-cert.cer` installiert werden.

Das Modul http_ verwendet den `CertStore` des `mitmproxy.certs`, "mitmproxy"
muss also installiert sein.

`lib/http_.py`

Nächste Schritte
--

Dieses Projekt ist bei weitem nicht fertig, das spannende kommt ja erst.

Da die Geräte so die Zertifikate nicht akzeptieren sollten die 204-Anfragen
ausgeleitet werden, um sie valide zu beantworten. Hierfür kann ein
transparenter SOCKS Proxy implementiert werden. Diese Anfragen werden nicht nur
vom System selbst sondern auch zB vom Firefox gestellt.

DNS over HTTP(S) ist ein weiteres Problem. SNI bietet eine gute Möglichkeit
bereits zu erkennen, was das Gerät vorhat, sodass diese Anfragen blockiert
werden können.

Lizenz
--

Meine Teile stehen unter der [GPLv2](LICENSE). Teile die ich übernommen habe, stehen unter
der jeweiligen Lizenz, die Module und die jeweilige Herkunft sind dokumentiert.

