#!/usr/bin/env python3
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime
from random import choice
from signal import signal, SIGINT
from subprocess import call
from sys import stdout
from threading import Thread
from l3 import LevelThree
from fakedns import DNS, CASE, TYPE
import logging as log

log.basicConfig(stream=stdout, level=log.INFO, format='%(asctime)s %(levelname)s: %(message)s')
interface = 'eth0'
net_bits = 24
network = IPv4Network('172.16.66.0/{}'.format(net_bits)) # define the network we are in
server_ip_address = next(network.hosts()) # take the first one
client_pool = dict()

def signal_handler(sig, frame):
	log.info('Exiting...')
	exit(0)
signal(SIGINT, signal_handler)

class FakeDns(DNS):
	def get_response(self, query, client):
		try:
			response = CASE[query.type](query, record=server_ip_address.exploded)
			log.info('get_response %s %s %s %s', str(query.domain, 'ascii'), TYPE[query.type], client, response)
			return response.make_packet()
		except:
			pass

class FakeDhcp(LevelThree):
	def get_ip_for_mac(self, message_type, client_hardware_address, package):
		log.info('get_ip_for_mac %s %s %s', message_type, client_hardware_address, package)
		return IPv4Address('172.16.66.111')

try:
	if call('ip l set dev {} up'.format(interface), shell=True):
		raise Exception()
	if call('ip a add dev {} {}/{}'.format(interface, server_ip_address, net_bits), shell=True):
		raise Exception()
	fake_dns = FakeDns(server_ip_address.exploded)
	Thread(target=fake_dns.serve_forever, daemon=True).start()
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

