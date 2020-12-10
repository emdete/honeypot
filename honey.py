#!/usr/bin/env python3
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime
from random import choice
from signal import signal, SIGINT
from subprocess import call

def signal_handler(sig, frame):
	print('Exiting...')
	sys.exit(0)
signal(SIGINT, signal_handler)


OFFSET = 1000

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

	server = fakedns.ThreadedUDPServer(('127.0.0.1', int(OFFSET+53)), fakedns.UDPHandler)
	server.daemon = True
	server.serve_forever()
	server_thread.join()

if 1:
	from dhcp import DhcpServer
	# see https://tools.ietf.org/html/rfc2131

	class Lease(object):
		def __init__(self, client_id, server, address, netmask, broadcast_address):
			self.client_id = client_id
			self.client_ip = '0.0.0.0'
			self.your_ip = address
			self.next_server_ip = None
			self.relay_agent_ip = None
			self.lease_time = 86400 # 24h
			self.renewal_time = 43200 # 12h
			self.rebinding_time = 75600 # 21h
			self.subnet_mask = netmask
			self.broadcast_address = broadcast_address
			self.dns = server
			self.domain_name = 'localdomain'
			self.timestamp = datetime.now()
		def __str__(self):
			return '{0.your_ip}'.format(self)

	class LeaseDB(dict):
		def __init__(self, server, network):
			self.db = dict()
			self.ips = {server: Lease(None, server, server, network.netmask, network.broadcast_address), }
			self.server = server
			self.network = network
		def client_config(self, client_id, hostname, vendor_class, ):
			if not client_id in self.db:
				your_ip = choice(list(network.hosts()))
				while your_ip in self.db:
					your_ip = choice(list(network.hosts()))
				lease = Lease(client_id, server, your_ip, network.netmask, network.broadcast_address)
				self.db[client_id] = lease
				self.ips[lease.your_ip] = lease
			return self.db[client_id]

	class FakeDhcp(DhcpServer):
		def create_lease_db(self):
			self.leases = LeaseDB(IPv4Address('172.16.66.1'), IPv4Network('172.16.66.0/24'))

	if not OFFSET:
		if call('ip l set dev eth0 up', shell=True):
			raise Exception()
		if call('ip a add dev eth0 {}'.format(IPv4Address('172.16.66.1')), shell=True):
			raise Exception()
	d = FakeDhcp(ip=IPv4Address('172.16.66.1').exploded, interface=b'eth0', port=OFFSET+67, subnet=IPv4Network('172.16.66.0/24'), start=100, end=200)
	d.start_server()
	if not OFFSET:
		if call('ip a del dev eth0 {}'.format(IPv4Address('172.16.66.1')), shell=True):
			raise Exception()
		if call('ip l set dev eth0 down', shell=True):
			raise Exception()

