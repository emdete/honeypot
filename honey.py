#!/usr/bin/env python3
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime
from random import choice
from signal import signal, SIGINT
from subprocess import call
import logging as log
import sys

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)

def signal_handler(sig, frame):
	print('Exiting...')
	exit(0)
signal(SIGINT, signal_handler)


if 0:
	import fakedns

	class Args(object):
		authoritative = False
		noforward = None
		dns = None
	fakedns.args = Args

	class Rules(object):
		def match(self, query, addr):
			response = fakedns.CASE[query.type](query, '127.0.0.1')
			print('match', str(query.domain, 'ascii'), fakedns.TYPE[query.type], addr, response)
			return response.make_packet()
	fakedns.rules = Rules()

	fake_dns = fakedns.ThreadedUDPServer(('127.0.0.1', int(OFFSET+53)), fakedns.UDPHandler)
	fake_dns.daemon = True
	fake_dns.serve_forever()
	server_thread.join()

if 1:
	from dhcp_server import DHCP_Server
	import threading

	class FakeServer(object):
		def __init__(self, server_ip, interface):
			self.dhcp_server = None
			self.dhcp_server = DHCP_Server(server_ip, interface)
			self.dhcp_server.set_server_name('free')
			self.dhcp_server.set_dns('172.16.0.1')
			self.dhcp_server.set_server_lease_time(60*30)
			self.server_thread = threading.Thread(target=self.dhcp_server.start_server)
			self.server_thread.daemon = True
			self.server_thread.start()

		def __del__(self):
			if self.dhcp_server:
				self.dhcp_server.stop_server()

		def get_ip_for_mac(self, mac):
			return '172.16.66.22'


try:
	interface = 'eth0'
	net_bits = 24
	network = IPv4Network('172.16.66.0/{}'.format(net_bits)) # define the network we are in
	server_ip = next(network.hosts()) # take the first one
	if call('ip l set dev {} up'.format(interface), shell=True):
		raise Exception()
	if call('ip a add dev {} {}/{}'.format(interface, server_ip, net_bits), shell=True):
		raise Exception()
	fake_dhcp = FakeServer(server_ip, interface)
	fake_dhcp.server_thread.join()
finally:
	if call('ip a del dev {} {}/{}'.format(interface, server_ip, net_bits), shell=True):
		raise Exception()
#	if call('ip l set dev {} down'.format(interface), shell=True):
#		raise Exception()

