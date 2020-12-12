#
# see https://mitmproxy.org/
all:

run:
	PYTHONPATH=../../../oss/python/FakeDns:lib \
	python3 -u ./honey.py

dbg:

