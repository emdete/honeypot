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
	from l3 import LevelThree

	class FakeDhcp(LevelThree):
		def get_ip_for_mac(self, message_type, client_hardware_address, package):
			return IPv4Address('172.16.66.111')

	try:
		interface = 'eth0'
		net_bits = 24
		network = IPv4Network('172.16.66.0/{}'.format(net_bits)) # define the network we are in
		server_ip_address = next(network.hosts()) # take the first one
		if call('ip l set dev {} up'.format(interface), shell=True):
			raise Exception()
		if call('ip a add dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
			raise Exception()
		FakeDhcp(
			interface=interface,
			server_ip_address=server_ip_address,
			subnet_mask=network.netmask,
			broadcast_address=network.broadcast_address,
			lease_time=60*30,
			).run()
	finally:
		if call('ip a del dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
			raise Exception()
	#	if call('ip l set dev {} down'.format(interface), shell=True):
	#		raise Exception()

