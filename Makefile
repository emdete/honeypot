# see https://openwrt.org/docs/guide-user/network/wifi/dumbap
# see https://mitmproxy.org/

all:
	./s.py

run:
	PYTHONPATH=lib \
	python3 -u ./honey.py

dbg:
	adb push pemdb/open.net-ca-cert.pem /sdcard/Downloads/.

