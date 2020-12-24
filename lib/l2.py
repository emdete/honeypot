#!/usr/bin/env python3
import logging as log
from ipaddress import IPv4Address, IPv4Network
from enum import IntEnum
from l1 import LevelOne

class Opcode(IntEnum):
	NONE = 0
	REQUEST = 1
	REPLY = 2

class MessageType(IntEnum):
	NONE = 0
	DISCOVER = 1
	OFFER = 2
	REQUEST = 3
	DECLINE = 4
	ACK = 5
	NAK = 6
	RELEASE = 7
	INFORM = 8

class Option(IntEnum):
	PADDING = 0
	SUBNETMASK = 1
	TIME_OFFSET = 2
	ROUTER = 3
	NAME_SERVER = 5
	DNS = 6
	LOG_SERVER = 7
	HOSTNAME = 12
	DOMAIN_NAME = 15
	SRCRTE = 20
	MTU_INTERFACE = 26
	BROADCAST_ADDRESS = 28
	NTP_SERVERS = 42
	VENDOR_SPECIFIC = 43
	REQUESTED_IP = 50
	LEASE_TIME = 51
	MESSAGE_TYPE = 53
	SERVER_ID = 54
	PARAM_REQ_LIST = 55
	MAX_SIZE = 57
	RENEWAL_TIME = 58
	REBINDING_TIME = 59
	CLASS_ID = 60
	CLIENT_ID = 61
	SERVER_NAME = 66
	CLASSLESS_STATIC_ROUTE = 121
	V_I_VENDOR_CLASS = 124
	END = 255
	UNKNOWN = 256

# decoders
def decode_int(value: bytes) -> int:
	return int.from_bytes(value, byteorder='big', signed=False)

def decode_ip(value: bytes) -> IPv4Address:
	ip = '.'.join(str(int(x)) for x in value)
	return IPv4Address(ip)

def decode_str(value: bytes) -> str:
	try:
		result = value.decode("utf-8")
	except UnicodeDecodeError:
		try:
			result = value.decode("latin")
		except UnicodeDecodeError:
			result = ':'.join("{:0>2s}".format(hex(x)[2:]) for x in int_array)
	return result.replace('\0', '')

def decode_mac(value: bytes) -> str:
	int_array = [int(x) for x in value]
	mac = ':'.join("{:0>2s}".format(hex(x)[2:]) for x in int_array)
	return mac

def decode_Opcode(value: bytes) -> Opcode:
	return Opcode(int(value[0]))

def decode_MessageType(value: bytes) -> MessageType:
	return MessageType(int(value[0]))

def decode_Option(value: bytes) -> Option:
	try:
		return Option(int(value[0]))
	except:
		log.warning('Unknown option %d', value[0])
		return Option.UNKNOWN

def decode_request_list(value: bytes) -> list:
	return [decode_Option((n, )) for n in value]

# encoders
def encode_int(value: int, length: int = 1) -> bytes:
	return value.to_bytes(length, 'big')

def encode_hex(value, length: int = 4) -> bytes:
	return value.to_bytes(length, 'big')

def encode_ip(value: IPv4Address, length: int = 4) -> bytes:
	return value.packed

def encode_str(value: str, length: int) -> bytes:
	temp = str.encode(value)
	return temp + (length - len(temp)) * b'\x00'

def encode_mac(value: str, length: int = 6) -> bytes:
	result = bytes.fromhex(value.replace(':', '').lower())
	return result + (length - result.__len__()) * b'\x00'

def encode_Opcode(value: Opcode) -> bytes:
	return encode_int(value)

def encode_Option(value: Option, length: int = 1) -> bytes:
	return encode_int(value.value, length)

def encode_request_list(value: list, length: int = 0) -> bytes:
	pass # TODO

class LevelTwo(LevelOne):
	def request(self, data, address, ):
		#log.debug('request: %s', data)
		packet = self.decode(data)
		#log.debug('request: %s %s', packet, address)
		if packet.pop('opcode') == Opcode.REQUEST:
			method = getattr(self, 'do_' + packet['options'].pop('message_type').name.lower(), None)
			if method:
				return method(**packet)
		log.warn('unhandled request: %s', packet)

	def respond(self, packet):
		#log.debug('respond: %s', packet)
		data = self.encode(packet)
		#log.debug('respond: %s', data)
		super(LevelTwo, self).respond(data)

	_option_coders = {
		Option.MESSAGE_TYPE: {'name': 'message_type', 'length': 1, 'encoder': encode_Option, 'decoder': decode_MessageType},
		Option.PADDING: {'name': None, 'length': None, 'encoder': None, 'decoder': None},
		Option.TIME_OFFSET: {'name': 'time_offset', 'length': 4, 'encoder': encode_int, 'decoder': decode_int},
		Option.LEASE_TIME: {'name': 'lease_time', 'length': 4, 'encoder': encode_int, 'decoder': decode_int},
		Option.RENEWAL_TIME: {'name': 'renewal_time', 'length': 4, 'encoder': encode_int, 'decoder': decode_int},
		Option.MAX_SIZE: {'name': 'max_size', 'length': 4, 'encoder': encode_int, 'decoder': decode_int},
		Option.REBINDING_TIME: {'name': 'rebinding_time', 'length': 4, 'encoder': encode_int, 'decoder': decode_int},
		Option.CLASS_ID: {'name': 'class_id', 'length': 0, 'encoder': encode_str, 'decoder': decode_str},
		Option.SRCRTE: {'name': 'srcrte', 'length': 1, 'encoder': encode_int, 'decoder': decode_int},
		Option.CLIENT_ID: {'name': 'client_id', 'length': 0, 'encoder': encode_str, 'decoder': decode_str},
		Option.ROUTER: {'name': 'router', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.NAME_SERVER: {'name': 'name_server', 'length': 0, 'encoder': encode_str, 'decoder': decode_str},
		Option.DNS: {'name': 'dns', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.SUBNETMASK: {'name': 'subnet_mask', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.BROADCAST_ADDRESS: {'name': 'broadcast_address', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.REQUESTED_IP: {'name': 'requested_ip', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.NTP_SERVERS: {'name': 'ntp_servers', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.SERVER_ID: {'name': 'server_id', 'length': 4, 'encoder': encode_ip, 'decoder': decode_ip},
		Option.PARAM_REQ_LIST: {'name': 'request_list', 'length': 0, 'encoder': encode_request_list, 'decoder': decode_request_list},
		Option.HOSTNAME: {'name': 'hostname', 'length': 0, 'encoder': encode_str, 'decoder': decode_str},
		Option.SERVER_NAME: {'name': 'server_name', 'length': 0, 'encoder': encode_str, 'decoder': decode_str},
		Option.DOMAIN_NAME: {'name': 'domain_name', 'length': 0, 'encoder': encode_str, 'decoder': decode_str},
		}

	_name_coders = dict(dict([(di['name'], dict(di, option=op), ) for op, di in _option_coders.items()]),
		# the folowing fields are contained in the static head only:
		opcode={'length': 1, 'encoder': encode_int},
		hardware_type={'length': 1, 'encoder': encode_int},
		hardware_address_length={'length': 1, 'encoder': encode_int},
		hops={'length': 1, 'encoder': encode_int},
		transaction_id={'length': 4, 'encoder': encode_hex},
		seconds_elapsed={'length': 2, 'encoder': encode_int},
		boot_flags={'length': 2, 'encoder': encode_hex},
		client_ip_address={'length': 4, 'encoder': encode_ip},
		your_ip_address={'length': 4, 'encoder': encode_ip},
		server_ip_address={'length': 4, 'encoder': encode_ip},
		gateway_ip_address={'length': 4, 'encoder': encode_ip},
		client_hardware_address={'length': 16, 'encoder': encode_mac},
		server_name={'length': 64, 'encoder': encode_str},
		boot_filename={'length': 128, 'encoder': encode_str},
		magic_cookie={'length': 4, 'encoder': encode_hex},
		)

	@staticmethod
	def encode(packet):
		data = b''
		for name in ('opcode', 'hardware_type', 'hardware_address_length', 'hops', 'transaction_id', 'seconds_elapsed', 'boot_flags',
				'client_ip_address', 'your_ip_address', 'server_ip_address',
				'gateway_ip_address', 'client_hardware_address', 'server_name',
				'boot_filename', 'magic_cookie', ):
			eop = LevelTwo._name_coders[name]
			data += eop['encoder'](packet.pop(name), eop['length'])
		data += LevelTwo.encoder_options(packet.pop('options'))
		if packet:
			log.warn('residual values %s', packet)
		return data

	@staticmethod
	def encoder_options(options):
		data = b''
		for name, value in options.items():
			eop = LevelTwo._name_coders[name]
			data += encode_Option(eop['option'])
			length = eop['length']
			if not length:
				length = len(value)+1
			data += encode_int(length, 1)
			data += eop['encoder'](value, length)
		data += encode_Option(Option.END)
		return data

	@staticmethod
	def decode(data):
		return dict(
			opcode = decode_Opcode(data[0:1]),
			hardware_type = decode_int(data[1:2]),
			hardware_address_length = decode_int(data[2:3]),
			hops = decode_int(data[3:4]),
			transaction_id = decode_int(data[4:8]),
			seconds_elapsed = decode_int(data[8:10]),
			boot_flags = decode_int(data[10:12]),
			client_ip_address = decode_ip(data[12:16]),
			your_ip_address = decode_ip(data[16:20]),
			server_ip_address = decode_ip(data[20:24]),
			gateway_ip_address = decode_ip(data[24:28]),
			client_hardware_address = decode_mac(data[28:34]),
			server_name = decode_str(data[44:108]),
			boot_filename = decode_str(data[108:236]),
			magic_cookie = decode_int(data[236:240]),
			options = LevelTwo.decode_options(data[240:]),
			)

	@staticmethod
	def decode_options(data):
		options = dict()
		index = 0
		while index < len(data):
			option = decode_Option(data[index:index+1])
			if option is None:
				log.warn('Unknown option %s', int(data[index]))
			index += 1
			if option == Option.END:
				break
			if option == Option.PADDING:
				continue
			if option in LevelTwo._option_coders:
				dop = LevelTwo._option_coders[option]
			else:
				log.warn('No decoder for option %s', option)
				dop = None
			length = decode_int(data[index:index+1])
			index += 1
			if dop:
				options[dop['name']] = dop['decoder'](data[index:index+length])
			index += length
		return options


if __name__ == '__main__':
	#sample = b'\x01\x01\x06\x00\x17\x16\x06\xfd\x83K\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\xcc qS\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x012\x04\xac\x10B\x029\x02\x02@7\x08\x01\x03\x06\x0c\x0f\x1c*y<\x0cudhcp 1.28.4\x0c\x07OpenWrt\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	#print([int(b) for b in sample])
	#print(LevelTwo.decode(sample))
	#exit(0)
	from sys import stderr
	from signal import signal, SIGINT
	log.basicConfig(stream=stderr, level=log.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
	def signal_handler(sig, frame):
		log.debug('Exiting...')
		exit(0)
	signal(SIGINT, signal_handler)
	ds = LevelTwo('eth0').run()


