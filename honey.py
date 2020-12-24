#!/usr/bin/env python3
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime
from random import choice
from signal import signal, SIGINT
from time import ctime
from subprocess import call
from sys import stderr
from ssl import SSLContext, AlertDescription, HAS_SNI, PROTOCOL_TLS_SERVER
from threading import Thread
from dhcp import LevelThree as Dhcp
from dns import Dns, CASE, TYPE
from ntp import Ntp
import logging as log
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

log.basicConfig(stream=stderr, level=log.INFO, format='%(asctime)s %(levelname)s: %(message)s')
interface = 'eth0'
net_bits = 24
network = IPv4Network('172.16.66.0/{}'.format(net_bits)) # define the network we are in
server_ip_address = next(network.hosts()) # take the first one
client_pool = dict()

clients = {
	'48:5a:3f:14:d4:85': dict(
		your_ip_address = IPv4Address('172.16.66.11'),
		),
	'14:cc:20:71:53:e0': dict(
		your_ip_address = IPv4Address('172.16.66.111'),
		),
	}

def signal_handler(sig, frame):
	log.info('Exiting...')
	exit(0)
signal(SIGINT, signal_handler)

class FakeDhcp(Dhcp):
	def get_ip_for_mac(self, message_type, client_hardware_address, packet):
		log.debug('get_ip_for_mac %s %s %s', message_type, client_hardware_address, packet)
		client_id = packet['options']['client_id'] if 'client_id' in packet['options'] else ''
		class_id = packet['options']['class_id']
		config = clients[client_hardware_address]
		your_ip_address = config['your_ip_address']
		log.info('get_ip_for_mac %s (%s %s) -> %s', client_hardware_address, client_id, class_id, your_ip_address)
		return your_ip_address

class FakeDns(Dns):
	def get_A_for_name(self, query, client_address):
		log.debug('get_A_for_name %s %s', query, client_address)
		try:
			response = CASE[query.type](query, record=server_ip_address.exploded)
			log.info('get_A_for_name %s %s -> %s', client_address[0], str(query.domain, 'ascii'), server_ip_address.exploded)
			return response.make_packet()
		except:
			pass

class FakeNtp(Ntp):
	def get_time(self, packet, client_address):
		log.debug('get_time %s %s', packet, client_address)
		response = super(FakeNtp, self).get_time(packet, client_address)
		log.info('get_time %s %s', client_address[0], ctime(response))
		return response

class FakeHttpHandler(BaseHTTPRequestHandler):
	def version_string(self):
		return 'sffe'
	def do_POST(self):
		log.info('do_POST %s %s %s', self.client_address[0], self.headers['Host'], self.path, )
	def do_GET(self):
		log.debug('%s %s %s %s', self.client_address[0], self.headers['Host'], self.path, self.headers, )
		host = self.headers['Host']
		self.protocol_version = 'HTTP/1.1'
		self.close_connection = True
		if (host, self.path, ) in (
			('connectivitycheck.gstatic.com', '/generate_204', ),
			('www.google.com', '/gen_204', ),
			('play.googleapis.com', '/generate_204', ),
		):
			self.send_response(204, 'No Content')
			self.send_header('Content-Length', '0')
			#'alt-svc', 'h3-29=":443"; ma=2592000,h3-T051=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"')
			self.end_headers()
			log.info('do_GET %s %s:%s -> %s', self.client_address[0], host, self.path, 204)
		else:
			self.send_response(404, 'Not Found')
			self.end_headers()
			log.warning('do_GET %s %s:%s -> %s', self.client_address[0], host, self.path, 404)
	def log_request(self, *a): pass
	def log_error(self, *a): pass
	def log_message(self, *a): pass

class FakeHttp(ThreadingHTTPServer):
	def __init__(self, server_address):
		super(FakeHttp, self).__init__((server_address, 80), FakeHttpHandler)

class FakeHttps(ThreadingHTTPServer):
	def __init__(self, server_address):
		super(FakeHttps, self).__init__((server_address, 443), FakeHttpHandler)
		self.context = SSLContext(PROTOCOL_TLS_SERVER)
		self.context.load_cert_chain('open.net.selfsigned', 'open.net.key')
		if not HAS_SNI:
			raise Exception('sni missing')
		if self.context.sni_callback:
			self.context.sni_callback(self.sni)
		else:
			self.context.set_servername_callback(self.sni)
		self.socket = self.context.wrap_socket(self.socket, server_side=True)

	def sni(self, sock, name, context):
		log.info('sni %s %s', sock, name)
		return AlertDescription.ALERT_DESCRIPTION_INTERNAL_ERROR

try:
	if call('ip l set dev {} up'.format(interface), shell=True):
		raise Exception()
	if call('ip a add dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
		raise Exception()
	Thread(target=FakeDns(server_ip_address.exploded).serve_forever, daemon=True).start()
	Thread(target=FakeNtp(server_ip_address.exploded).serve_forever, daemon=True).start()
	Thread(target=FakeHttp(server_ip_address.exploded).serve_forever, daemon=True).start()
	Thread(target=FakeHttps(server_ip_address.exploded).serve_forever, daemon=True).start()
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

