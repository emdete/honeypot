Honey Pot
==

Schritt 1
--

Vorraussetzung ist ein WLAN-Access-Point, der lediglich als Switch
agiert, indem alle Interfaces gebridged sind. Ich nutze OpenWRT, eine
Beschreibung für die Konfiguration ist hier:

[Wireless Access Point / Dumb Access Point / Dumb AP](https://openwrt.org/docs/guide-user/network/wifi/dumbap)

An diesen AP verbindet man einen Rechner per Ethernet und kann nun schauen,
was die Geräte so treiben:

```
tcpdump -i eth0 -vvv
```

Schritt 2
--

Als erstes melden sich die Geräte mit einer DHCP Anfrage. Diese muss mit einer
validen IP, einem Standard-Gateway und einem Namens-Server beantwortet werden.

Ich habe keinen für mich brauchbaren und funktionierenden DHCP Server gefunden,
darum habe ich (unter Verwendung von Teilen aus anderen Projekten) einen
eigenen erstellt.

In guter Python-Manier beginnt er zu arbeiten auf `serve_forever()` und ist in
drei Schichten aufgeteilt:

- Senden & Empfangen der UDP Pakete
- Decoden & Encoden der Pakete
- Korrektes Beantworten der Fragen der Geräte

Es beinhaltet nicht die Schicht für die Vergabe der IPs, die im Hauptmodul
kontrolliert wird.

`lib/dhcp.py`

Schritt 3
--

Als nächstes versuchen die Geräte, Namen aufzulösen. Ein DNS Server leistet
dies. Ein einigermassen brauchbares Modul existierte und findet Verwendung. Auch
dieses startet mit `serve_forever()`.

Es beinhaltet nicht die Zuordnung der IPs, die wiederum im Hauptmodul
stattfindet.

Manche Geräte nutzen tcp domain-s (port 853). Dies ist (noch) nicht
implementiert.

`lib/dns.py`

Schritt 4
--

Viele Geräte erfragen dann die Uhrzeit, also sollte NTP gesprochen werden.
Wiederum startet der Dienst mit Aufruf von `serve_forever()`.

Es beinhaltet nicht die Rückgabe der Zeit, diese kommt wiederum aus dem
Hauptmodul.

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

IPv6 ist nicht beachtet.

Lizenz
--

Meine Teile stehen unter der [GPLv2](LICENSE). Teile die ich übernommen habe,
stehen unter der jeweiligen Lizenz, die Module und die jeweilige Herkunft sind
dokumentiert.

