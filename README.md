Honey Pot
==

Schritt 1
--

Ein Wlan-Router mit OpenWRT, der als dump Switch agiert indem alle Interfaces
gebridged sind. Eine Beschreibung für die Konfiguration ist hier:

	[dumbap](https://openwrt.org/docs/guide-user/network/wifi/dumbap)

An diesen Router verbindet man einen Rechner per Kabel und kann nun schauen,
was die Geräte so treiben.

Schritt 2
--

Als erstes melden sich die Geräte mit einer DHCP Anfrage. Diese muss mit einer
validen IP und einem Standardgateway beantwortet werden.

Ich habe keinen brauchbaren und funktionierenden DHCP Server gefunden, darum
habe ich (unter Verwendung von Teilen aus anderen Projekten) einen eigenen
erstellt.

In guter Python-Manier beginnt er zu arbeiten auf `serve_forever()` und ist in
drei Schichten umgesetzt:

- Senden & Empfangen der UDP Pakete
- Decoden & Encoden der Pakete
- Beantworten der Fragen der Geräte

Es fehlt die Vergabe der IPs, die im Hauptmodul kontrolliert wird.

Schritt 3
--

Als nächstes versuchen die Geräte, Namen aufzulösen. Ein DNS Server leistet
dies. Ein einigermassen brauchbares Modul existierte und findet Verwendung. Auch
dieses startet mit `serve_forever()` und die wirkliche Zuordnung der IPs findet
im Hauptmodul statt.

Manche Geräte nutzen tcp domain-s (port 853).

Schritt 4
--

Viele Geräte erfragen dann die Uhrzeit, also sollte NTP gesprochen werden.
Wiederum startet der Dienst mit Aufruf von `serve_forever()` und erhält seine
Antwort aus dem Hauptmodul. So kann jedem Gerät eine eigene Uhrzeit
untergejubelt werden.

Schritt 5
--

Die Welt spricht HTTP und HTTPS. Als erstes Prüfen die Geräte ob das Netz
wirklich Zugriff auf das Internet erlaubt. Dazu erfragen Android-Telefone
(http://connectivitycheck.gstatic.com/generate_204) oder
(http://google.com/generate_204) und erwarten einen HTTP-Statuscode von 204.


