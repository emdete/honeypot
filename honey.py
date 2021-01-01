#!/usr/bin/env python3
import logging as log
from sys import stderr
from os.path import exists
log.basicConfig(stream=stderr, level=log.INFO, format='%(asctime)s %(levelname)s: %(message)s')
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from signal import signal, SIGINT
from random import choice
from subprocess import call
from threading import Thread
from time import ctime, sleep, time
from email.utils import formatdate
from http import HTTPStatus
from json import load, dump
# fake bases:
from dhcp import LevelThree as Dhcp
from ntp import Ntp
from dns import Dns, Dns_s, CASE, TYPE
from http_ import Http, Https


class FakePersistence(object):
	client_macs = dict()

	client_ips = dict()

	@staticmethod
	def dump():
		# json doesnt code sets
		for n in FakePersistence.client_macs.values():
			if 'visited' in n:
				n['visited'] = sorted(list(n['visited']))
		with open('honey.json', 'w') as f:
			dump(FakePersistence.client_macs, f, indent=4)

	@staticmethod
	def load():
		if exists('honey.json'):
			with open('honey.json') as f:
				FakePersistence.client_macs = load(f)
			# json doesnt code sets
			for n in FakePersistence.client_macs.values():
				n['visited'] = set(n['visited'])
			# have a ip lookup
			for n in FakePersistence.client_macs.values():
				FakePersistence.client_ips[n['your_ip_address']] = n

	@staticmethod
	def add_visited(ip, host):
		if host[-1] == '.':
			host = host[:-1]
		FakePersistence.client_ips[ip]['visited'].add(host)


class FakeDhcp(Dhcp):
	mac2oui = dict()

	def get_oui(self, mac):
		if not self.mac2oui:
			with open('/usr/share/arp-scan/ieee-oui.txt') as f:
				for l in f.readlines():
					l = l.strip()
					if l and l[0] != '#':
						mac_prefix, vendor = l.split('\t')
						self.mac2oui[mac_prefix.lower()] = vendor
		mac_prefix = ''.join(mac.split(':'))[:6].lower()
		return self.mac2oui.get(mac_prefix, None)

	def get_ip_for_mac(self, message_type, client_hardware_address, packet):
		log.debug('get_ip_for_mac %s %s %s', message_type, client_hardware_address, packet)
		client_id = packet['options']['client_id'] if 'client_id' in packet['options'] else ''
		class_id = packet['options']['class_id']
		if client_hardware_address in FakePersistence.client_macs:
			config = FakePersistence.client_macs[client_hardware_address]
		else:
			config = dict(your_ip_address=self.get_free_ip().exploded, visited=set())
			FakePersistence.client_macs[client_hardware_address] = config
		config['class_id'] = class_id
		config['vendor'] = self.get_oui(client_hardware_address)
		config['client_id'] = client_id
		config['client_hardware_address'] = client_hardware_address
		config['timestamp'] = datetime.now().isoformat()
		your_ip_address = config['your_ip_address']
		FakePersistence.client_ips[your_ip_address] = config
		log.info('%s: get_ip_for_mac %s -> %s', your_ip_address, client_hardware_address, config, )
		return IPv4Address(your_ip_address)

	def get_free_ip(self):
		ip = choice(list(self.network.hosts()))
		while ip in FakePersistence.client_ips:
			ip = choice(list(self.network.hosts()))
		return ip


class FakeDns(Dns):
	# /usr/share/publicsuffix/effective_tld_names.dat
	def get_A_for_name(self, client_address, query, ):
		log.debug('get_A_for_name %s %s', client_address, query, )
		try:
			response = CASE[query.type](query, record=self.server_ip_address.exploded)
			log.info('%s: get_A_for_name %s -> %s', client_address[0], str(query.domain, 'ascii'), self.server_ip_address.exploded)
			FakePersistence.add_visited(client_address[0], str(query.domain, 'ascii'))
			return response.make_packet()
		except Exception as e:
			log.warn('error %s', e)


class FakeNtp(Ntp):
	def get_time(self, packet, client_address):
		log.debug('get_time %s %s', packet, client_address)
		response = super(FakeNtp, self).get_time(packet, client_address)
		log.info('%s: get_time -> %s', client_address[0], ctime(response))
		return response


class FakeHttp(Http):
	def get_response(self, client_address, host, headers, path, ):
		# captive portal checks
		if (host, path, ) in (
			('connectivitycheck.gstatic.com', '/generate_204', ),
			('play.googleapis.com', '/generate_204', ),
		):
			response = HTTPStatus.NO_CONTENT, {
				'Content-Length': '0',
				'Date': formatdate(time(), usegmt=True),
				}, ''
		elif (host, path, ) in (
			('example.org', '/', ),
			('ipv4only.arpa', '/', ),
		):
			response = HTTPStatus.OK, {}, ''
		elif (host, path, ) in (
			('www.google.com', '/gen_204', ),
		):
			response = HTTPStatus.NO_CONTENT, {
				'Content-Length': '0',
				'Date': formatdate(time(), usegmt=True),
				'Content-Type': 'text/html; charset=ISO-8859-1',
				'P3P': 'CP="This is not a P3P policy! See g.co/p3phelp for more info."',
				'Server': 'gws',
				'X-XSS-Protection': '0',
				'X-Frame-Options': 'SAMEORIGIN',
				'Set-Cookie': 'NID=205=MjzCFJGqVviNCJwJvOWZzwBp4C5w5K45BKE7vjSK-Gl_wpKfqslpqY-ZL0su_r1Ml4KQMqKFTYGHLpGrQ2ZnUdfBSWUcFeI8lR2hilTTQgiIo1da4CQTJEbJxguk9MeEoGwdi6E-nPnzjIPaBxBZQ1cWmaMcwrxMYeF1scB0mL0; expires=Mon, 28-Jun-2021 22:36:22 GMT; path=/; domain=.google.com; HttpOnly',
				}, ''
		elif (host, path, ) in (
			('detectportal.firefox.com', '/success.txt?ipv4', ),
		):
			response = HTTPStatus.OK, {
				"Content-type": "text/plain",
				'Server': 'nginx',
				'Content-Length': '8',
				'Via': '1.1 google',
				'Age': '14287',
				'Date': formatdate(time(), usegmt=True),
				'Cache-Control': 'public, must-revalidate, max-age=0, s-maxage=86400',
				}, 'success\n\r'
		else:
			response = HTTPStatus.NOT_FOUND, None, None
		log.info('%s: get_response http://%s%s -> %s %s %s', client_address[0], host, path, *response)
		FakePersistence.add_visited(client_address[0], host)
		return response


class FakeHttps(Https):
	def get_response(self, client_address, host, headers, path, ):
		response = HTTPStatus.NOT_FOUND, None, None
		log.info('%s: get_response https://%s%s -> %s %s %s', client_address[0], host, path, *response)
		FakePersistence.add_visited(sock.getpeername()[0], host)
		return response

	def sni(self, sock, name, context):
		if name:
			FakePersistence.add_visited(sock.getpeername()[0], name)
		log.info('%s: sni for %s', sock.getpeername()[0], name, )
		return super(FakeHttps, self).sni(sock, name, context)


def main(interface='eth0', network='172.16.66.0', net_bits=24, ):
	FakePersistence.load() # TODO: network change?!?
	network = IPv4Network('{}/{}'.format(network, net_bits)) # define the network we are in
	server_ip_address = next(network.hosts()) # take the first one
	try:
		if call('ip l set dev {} up'.format(interface), shell=True):
			raise Exception()
		if call('ip a add dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
			raise Exception()
		Thread(target=FakeDns(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=Dns_s(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=FakeNtp(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=FakeHttp(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=FakeHttps(server_ip_address).serve_forever, daemon=True).start()
		FakeDhcp(
			interface=interface,
			server_ip_address=server_ip_address,
			network=network,
			domain_name='open.net',
			lease_time=60*30,
			).serve_forever()
	finally:
		FakePersistence.dump()
		if call('ip a del dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
			raise Exception()
	#	if call('ip l set dev {} down'.format(interface), shell=True):
	#		raise Exception()

def signal_handler(sig, frame):
	log.info('Exiting...')
	exit(0)
signal(SIGINT, signal_handler)

if __name__ == '__main__':
	from sys import argv
	main(*argv[1:])
# vim:tw=0:nowrap
