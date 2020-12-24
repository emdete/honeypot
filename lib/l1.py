#!/usr/bin/env python3
import logging as log
from select import select
from socket import inet_aton, socket, AF_INET, SOCK_DGRAM, SO_BROADCAST, SO_REUSEADDR, SOL_SOCKET

class LevelOne(object):
	' Level to receive and send UDP packets for DHCP '
	source = '0.0.0.0', 67,
	destination = '255.255.255.255', 68,
	max_bytes = 1024
	recv_timeout = 5

	def __init__(self, interface):
		self.interface = interface
		self.server_socket = socket(AF_INET, SOCK_DGRAM)
		self.server_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.server_socket.setsockopt(SOL_SOCKET, 25, self.interface.encode('ascii') + b'\0')
		self.server_socket.bind(self.source)

	def run(self):
		while self.run:
			if select([self.server_socket], [], [], self.recv_timeout)[0]:
				self.request(*self.server_socket.recvfrom(self.max_bytes))

	def request(self, data, address, ):
		log.debug('%s %s', address, len(data))
		self.respond(data)

	def respond(self, packet):
		self.server_socket.sendto(packet, self.destination)


if __name__ == '__main__':
	from sys import stderr
	from signal import signal, SIGINT
	log.basicConfig(stream=stderr, level=log.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
	def signal_handler(sig, frame):
		log.debug('Exiting...')
		exit(0)
	signal(SIGINT, signal_handler)
	ds = LevelOne('eth0').run()

