#!/usr/bin/env python3
import logging as log
from ipaddress import IPv4Address, IPv4Network
from l2 import LevelTwo, Opcode, MessageType

class LevelThree(LevelTwo):
	def __init__(self, interface,
			server_ip_address=IPv4Address('172.16.66.1'),
			subnet_mask=IPv4Address('172.16.66.0'),
			broadcast_address=IPv4Address('172.16.66.255'),
			lease_time=60*30):
		super(LevelThree, self).__init__(interface)
		self.server_ip_address = server_ip_address
		self.subnet_mask = subnet_mask
		self.broadcast_address = broadcast_address
		self.lease_time = lease_time

	def do_discover(self, client_hardware_address, **packet):
		transaction_id = packet.get('transaction_id')
		options = packet.get('options')
		request_list = options.get('request_list', None)
		your_ip_address = self.get_ip_for_mac('discover', client_hardware_address, packet)
		log.debug('do_discover %s %s %s %s', client_hardware_address, transaction_id, request_list, your_ip_address)
		packet = dict(
			opcode=Opcode.REPLY,
			hardware_type=1,
			hardware_address_length=6,
			hops=0,
			transaction_id=transaction_id,
			seconds_elapsed=0,
			boot_flags=0,
			client_ip_address=IPv4Address('0.0.0.0'),
			your_ip_address=your_ip_address,
			server_ip_address=self.server_ip_address,
			gateway_ip_address=self.server_ip_address,
			client_hardware_address=client_hardware_address,
			server_name='',
			boot_filename='',
			magic_cookie=1669485411,
			options=dict(
				message_type=MessageType.OFFER,
				lease_time = self.lease_time,
				renewal_time = self.lease_time // 2,
				rebinding_time = self.lease_time * 7 // 8,
				router=self.server_ip_address,
				dns=self.server_ip_address,
				ntp_servers=self.server_ip_address,
				subnet_mask=self.subnet_mask,
				broadcast_address=self.broadcast_address,
				),
			)
		self.respond(packet)

	def do_request(self, client_hardware_address, **packet):
		transaction_id = packet.get('transaction_id')
		options = packet.get('options')
		requested_ip = options.get('requested_ip', None)
		log.debug('do_request %s %s', client_hardware_address, requested_ip)
		your_ip_address = self.get_ip_for_mac('request', client_hardware_address, packet)
		if your_ip_address:
			packet = dict(
				opcode=Opcode.REPLY,
				hardware_type=1,
				hardware_address_length=6,
				hops=0,
				transaction_id=transaction_id,
				seconds_elapsed=0,
				boot_flags=0,
				client_ip_address=IPv4Address('0.0.0.0'),
				your_ip_address=your_ip_address,
				server_ip_address=self.server_ip_address,
				gateway_ip_address=self.server_ip_address,
				client_hardware_address=client_hardware_address,
				server_name='',
				boot_filename='',
				magic_cookie=1669485411,
				options=dict(
					message_type=MessageType.ACK,
					lease_time = self.lease_time,
					renewal_time = self.lease_time // 2,
					rebinding_time = self.lease_time * 7 // 8,
					router=self.server_ip_address,
					dns=self.server_ip_address,
					ntp_servers=self.server_ip_address,
					subnet_mask=self.subnet_mask,
					broadcast_address=self.broadcast_address,
					),
				)
			self.respond(packet)

	def get_ip_for_mac(self, message_type, client_hardware_address, packet):
		' dummy single address for testing '
		return IPv4Address('172.16.66.2')

if __name__ == '__main__':
	from sys import stderr
	from signal import signal, SIGINT
	log.basicConfig(stream=stderr, level=log.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
	def signal_handler(sig, frame):
		log.debug('Exiting...')
		exit(0)
	signal(SIGINT, signal_handler)
	ds = LevelThree('eth0').run()

