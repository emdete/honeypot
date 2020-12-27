# see https://mitmproxy.org/

all:
	adb push pemdb/open.net-ca-cert.pem /sdcard/Downloads/.

run:
	PYTHONPATH=lib \
	python3 -u ./honey.py

dbg:
	chgrp -R www-data . | true
	rsync \
		--archive \
		--verbose \
		--delete \
		. littlun.emdete.de:/var/www/belphegor.emdete.de/honeypot/.

