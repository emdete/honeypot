# see https://mitmproxy.org/
# see https://www.kuketz-blog.de/android-captive-portal-check-204-http-antwort-von-captiveportal-kuketz-de/
# wireshark filter: !udp.port == 53 && !(ip.addr == 13.248.212.111) && !(ip.addr == 76.223.92.165) && !arp && !dhcp
# curl -v --cacert open.net-ca-cert.cer --connect-to emdete.de:443:172.16.66.1:443 https://emdete.de
# adb shell settings put global captive_portal_mode 0

all:
	adb push pemdb/open.net-ca-cert.pem /sdcard/Downloads/.

run:
	PYTHONPATH=lib \
	python3 -u ./honey.py

dbg:
	chgrp -R www-data .git
	rsync \
		--archive \
		--verbose \
		--delete \
		.git/. littlun.emdete.de:/var/www/belphegor.emdete.de/honeypot/.

