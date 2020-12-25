#!/usr/bin/env python3
import logging as log
from sys import stderr
log.basicConfig(stream=stderr, level=log.INFO, format='%(asctime)s %(levelname)s: %(message)s')
from OpenSSL.crypto import dump_privatekey, FILETYPE_PEM
from datetime import datetime
from dhcp import LevelThree as Dhcp
from dns import Dns, CASE, TYPE
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from ipaddress import IPv4Address, IPv4Network
from mitmproxy.certs import CertStore
from ntp import Ntp
from os.path import exists
from random import choice
from signal import signal, SIGINT
from ssl import HAS_SNI, PROTOCOL_TLS_SERVER, _create_unverified_context
from subprocess import call
from threading import Thread
from time import ctime


def signal_handler(sig, frame):
	log.info('Exiting...')
	exit(0)
signal(SIGINT, signal_handler)

class FakeDhcp(Dhcp):
	client_macs = {
		'48:5a:3f:14:d4:85': dict(
			your_ip_address=IPv4Address('172.16.66.11'),
			client_hardware_address='48:5a:3f:14:d4:85',
			),
		'14:cc:20:71:53:e0': dict(
			your_ip_address=IPv4Address('172.16.66.111'),
			client_hardware_address='14:cc:20:71:53:e0',
			),
		}
	client_ips = {
		}

	def get_ip_for_mac(self, message_type, client_hardware_address, packet):
		log.debug('get_ip_for_mac %s %s %s', message_type, client_hardware_address, packet)
		client_id = packet['options']['client_id'] if 'client_id' in packet['options'] else ''
		class_id = packet['options']['class_id']
		if not client_hardware_address in self.client_macs:
			self.client_macs[client_hardware_address] = dict(
				client_hardware_address=client_hardware_address,
				your_ip_address=self.get_free_ip(),
				)
		config = self.client_macs[client_hardware_address]
		config['class_id'] = class_id
		config['client_id'] = client_id
		your_ip_address = config['your_ip_address']
		log.info('get_ip_for_mac %s (%s %s) -> %s', client_hardware_address, client_id, class_id, your_ip_address)
		return your_ip_address

	def get_free_ip(self):
		pass


class FakeDns(Dns):
	def get_A_for_name(self, client_address, query, ):
		log.debug('get_A_for_name %s %s', client_address, query, )
		try:
			response = CASE[query.type](query, record=self.server_ip_address.exploded)
			log.info('get_A_for_name %s %s -> %s', client_address[0], str(query.domain, 'ascii'), self.server_ip_address.exploded)
			return response.make_packet()
		except Exception as e:
			log.warn('error %s', e)


class FakeNtp(Ntp):
	def get_time(self, packet, client_address):
		log.debug('get_time %s %s', packet, client_address)
		response = super(FakeNtp, self).get_time(packet, client_address)
		log.info('get_time %s -> %s', client_address[0], ctime(response))
		return response


class FakeHttpHandler(BaseHTTPRequestHandler):
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
			self.send_response(404, 'Not found')
			#self.send_response(204, 'No content')
			self.send_header('Content-Length', '0')
			#'alt-svc', 'h3-29=":443"; ma=2592000,h3-T051=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"')
			self.end_headers()
			log.info('do_GET %s %s:%s -> %s', self.client_address[0], host, self.path, 204)
		else:
			self.send_response(404, 'Not Found')
			self.end_headers()
			log.warning('do_GET %s %s:%s -> %s', self.client_address[0], host, self.path, 404)
	def version_string(self): return 'sffe'
	def log_request(self, *a): pass
	def log_error(self, *a): pass
	def log_message(self, *a): pass


class FakeHttp(ThreadingHTTPServer):
	def __init__(self, server_address):
		super(FakeHttp, self).__init__((server_address.exploded, 80), FakeHttpHandler)


class FakeHttps(ThreadingHTTPServer):
	def __init__(self, server_address):
		super(FakeHttps, self).__init__((server_address.exploded, 443), FakeHttpHandler)
		if not HAS_SNI:
			raise Exception('sni missing here')
		self.certstore = CertStore.from_store('pemdb', 'open.net', 2048, None)
		self.context = _create_unverified_context(PROTOCOL_TLS_SERVER,
			certfile='pemdb/open.net-ca-cert.pem',
			keyfile='pemdb/open.net-ca.pem', )
		self.context.load_dh_params('pemdb/open.net-dhparam.pem')
		self.context.sni_callback = self.sni
		self.socket = self.context.wrap_socket(self.socket, server_side=True)

	def sni(self, sock, name, context):
		log.info('sni from %s for %s', sock.getpeername()[0], name, )
		if name:
			chain_filename, cert_filename, privkey_filename = f'pemdb/{name}-ca-chain.pem', f'pemdb/{name}-ca-cert.pem', f'pemdb/{name}-ca.pem'
			if not exists(chain_filename) or not exists(cert_filename) or not exists(privkey_filename):
				cert, privkey, cert_chain = self.certstore.get_cert(name.encode(), list())
				with open(chain_filename, 'wb') as f:
					f.write(cert.to_pem())
				with open(cert_filename, 'wb') as f:
					f.write(cert.to_pem())
				with open(privkey_filename, 'wb') as f:
					f.write(dump_privatekey(FILETYPE_PEM, privkey))
			sock.context = _create_unverified_context(PROTOCOL_TLS_SERVER, certfile=cert_filename, keyfile=privkey_filename, )


def main(interface='eth0', network='172.16.66.0', net_bits=24, ):
	network = IPv4Network('{}/{}'.format(network, net_bits)) # define the network we are in
	server_ip_address = next(network.hosts()) # take the first one
	try:
		if call('ip l set dev {} up'.format(interface), shell=True):
			raise Exception()
		if call('ip a add dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
			raise Exception()
		Thread(target=FakeDns(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=FakeNtp(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=FakeHttp(server_ip_address).serve_forever, daemon=True).start()
		Thread(target=FakeHttps(server_ip_address).serve_forever, daemon=True).start()
		FakeDhcp(
			interface=interface,
			server_ip_address=server_ip_address,
			network=network,
			lease_time=60*30,
			).serve_forever()
	finally:
		if call('ip a del dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
			raise Exception()
	#	if call('ip l set dev {} down'.format(interface), shell=True):
	#		raise Exception()

if __name__ == '__main__':
	from sys import argv
	main(*argv[1:])
# vim:tw=0:nowrap
