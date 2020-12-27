#!/usr/bin/env python3
# from https://github.com/Crypt0s/FakeDns, MIT, main portions copyright (c) 2020 Bryan "Crypt0s" Halfpap
from socket import getaddrinfo, AF_INET6, AF_INET
from socketserver import ThreadingUDPServer, BaseRequestHandler
from struct import pack
from random import getrandbits
import configparser as ConfigParser
import logging as log
from socket import socket, AF_INET, SOCK_STREAM
from ssl import HAS_SNI, PROTOCOL_TLS_SERVER, _create_unverified_context, AlertDescription

class DNSQuery:
	def __init__(self, data):
		self.data = data
		self.domain = b''
		tipo = (data[2] >> 3) & 15 # Opcode bits
		if tipo == 0: # Standard query
			ini = 12
			lon = data[ini]
			while lon != 0:
				self.domain += data[ini + 1:ini + lon + 1] + b'.'
				ini += lon + 1 # you can implement CNAME and PTR
				lon = data[ini]
			self.type = data[ini:][1:3]
		else:
			self.type = data[-4:-2]

TYPE = {
	b"\x00\x01": "A",
	b"\x00\x1c": "AAAA",
	b"\x00\x05": "CNAME",
	b"\x00\x0c": "PTR",
	b"\x00\x10": "TXT",
	b"\x00\x0f": "MX",
	b"\x00\x06": "SOA"
	}


def _get_question_section(query):
	# Query format is as follows: 12 byte header, question section (comprised
	# of arbitrary-length name, 2 byte type, 2 byte class), followed by an
	# additional section sometimes. (e.g. OPT record for DNSSEC)
	start_idx = 12
	end_idx = start_idx

	num_questions = (query.data[4] << 8) | query.data[5]

	while num_questions > 0:
		while query.data[end_idx] != 0:
			end_idx += query.data[end_idx] + 1
		# Include the null byte, type, and class
		end_idx += 5
		num_questions -= 1

	return query.data[start_idx:end_idx]


class DNSFlag:
	# qr opcode aa tc rd ra z	rcode
	# 1 0000 0	0 1 1 000 0000
	# accept a series of kwargs to build a proper flags segment.
	def __init__(self,
				qr=0b1, # query record, 1 if response
				opcode=0b0000, # 0 = query, 1 = inverse query, 2 = status request 3-15 unused
				aa=0b0, # authoritative answer = 1
				tc=0b0, # truncation - 1 if truncated
				rd=0b1, # recursion desired?
				ra=0b1, # recursion available
				z=0b000, # Reserved, must be zero in queries and responsed
				rcode=0b0000 # errcode, 0 none, 1 format, 2 server, 3 name, 4 not impl, 5 refused, 6-15 unused
				):

		# pack the elements into an integer
		flag_field = qr
		flag_field = flag_field << 4
		flag_field ^= opcode
		flag_field = flag_field << 1
		flag_field ^= aa
		flag_field = flag_field << 1
		flag_field ^= tc
		flag_field = flag_field << 1
		flag_field ^= rd
		flag_field = flag_field << 1
		flag_field ^= ra
		flag_field = flag_field << 3
		flag_field ^= z
		flag_field = flag_field << 4
		flag_field ^= rcode

		self.flag_field = flag_field

	# return char rep.
	def pack(self):
		return pack(">H", self.flag_field)


class DNSResponse(object):
	def __init__(self, query):
		self.id = query.data[:2] # Use the ID from the request.
		self.flags = DNSFlag(aa=False).pack()
		self.questions = query.data[4:6] # Number of questions asked...
		# Answer RRs (Answer resource records contained in response) 1 for now.
		self.rranswers = b"\x00\x01"
		self.rrauthority = b"\x00\x00" # Same but for authority
		self.rradditional = b"\x00\x00" # Same but for additionals.
		# Include the question section
		self.query = _get_question_section(query)
		# The pointer to the resource record - seems to always be this value.
		self.pointer = b"\xc0\x0c"
		# This value is set by the subclass and is defined in TYPE dict.
		self.type = None
		self.dnsclass = b"\x00\x01" # "IN" class.
		# TODO: Make this adjustable - 1 is good for noobs/testers
		self.ttl = b"\x00\x00\x00\x01"
		# Set by subclass because is variable except in A/AAAA records.
		self.length = None
		self.data = None # Same as above.

	def make_packet(self):
		log.debug('%s', (self.__class__.__name__, self.id, self.flags,
			self.questions, self.rranswers, self.rrauthority,
			self.rradditional, self.query, self.pointer, self.type,
			self.dnsclass, self.ttl, self.length, self.data))
		try:
			return self.id + self.flags + self.questions + self.rranswers + \
				self.rrauthority + self.rradditional + self.query + \
				self.pointer + self.type + self.dnsclass + self.ttl + \
				self.length + self.data
		except Exception as e: #(TypeError, ValueError):
			log.exception("%s", e)

# All classes need to set type, length, and data fields of the DNS Response
class A(DNSResponse):
	def __init__(self, query, record):
		super(A, self).__init__(query)
		self.type = b"\x00\x01"
		self.length = b"\x00\x04"
		self.data = self.get_ip(record)

	@staticmethod
	def get_ip(dns_record):
		ip = dns_record
		# Convert to hex
		return b''.join(int(x).to_bytes(1, 'little') for x in ip.split('.'))

class AAAA(DNSResponse):
	def __init__(self, query, address):
		super(AAAA, self).__init__(query)
		self.type = b"\x00\x1c"
		self.length = b"\x00\x10"
		# Address is already encoded properly for the response at rule-builder
		self.data = address

	# Thanks, stackexchange!
	# http://stackoverflow.com/questions/16276913/reliably-get-ipv6-address-in-python
	def get_ip_6(host, port=0):
		# search only for the wanted v6 addresses
		result = getaddrinfo(host, port, AF_INET6)
		# Will need something that looks like this:
		# just returns the first answer and only the address
		ip = result[0][4][0]

class CNAME(DNSResponse):
	def __init__(self, query, domain):
		super(CNAME, self).__init__(query)
		self.type = b"\x00\x05"

		self.data = b""
		for label in domain.split('.'):
			self.data += chr(len(label)).encode() + label.encode()
		self.data += b"\x00"

		self.length = chr(len(self.data)).encode()
		# Must be two bytes.
		if len(self.length) < 2:
			self.length = b"\x00" + self.length

class PTR(DNSResponse):
	def __init__(self, query, ptr_entry):
		super(PTR, self).__init__(query)
		if type(ptr_entry) != bytes:
			ptr_entry = ptr_entry.encode()

		self.type = b"\x00\x0c"
		self.ttl = b"\x00\x00\x00\x00"
		ptr_split = ptr_entry.split(b'.')
		ptr_entry = b"\x07".join(ptr_split)

		self.data = b"\x09" + ptr_entry + b"\x00"
		self.length = chr(len(ptr_entry) + 2)
		# Again, must be 2-byte value.
		if self.length < "0xff":
			self.length = b"\x00" + self.length.encode()

class TXT(DNSResponse):
	def __init__(self, query, txt_record):
		super(TXT, self).__init__(query)
		self.type = b"\x00\x10"
		self.data = txt_record.encode()
		self.length = chr(len(txt_record) + 1).encode()
		# Must be two bytes. This is the better, more python-3 way to calculate length. Swap to this later.
		if len(self.length) < 2:
			self.length = b"\x00" + self.length 
		# Then, we have to add the TXT record length field! We utilize the
		# length field for this since it is already in the right spot
		self.length += chr(len(txt_record)).encode()


class MX(DNSResponse):
	def __init__(self, query, txt_record):
		super(MX, self).__init__(query)
		self.type = b"\x00\x0f"
		self.data = b"\x00\x01" + self.get_domain(txt_record) + b"\x00"
		self.length = chr(len(txt_record) + 4)
		if self.length < '\xff':
			self.length = "\x00" + self.length

	@staticmethod
	def get_domain(dns_record):
		domain = dns_record
		ret_domain=[]
		for x in domain.split('.'):
			st = "{:02x}".format(len(x))
			ret_domain.append( st.decode("hex"))
			ret_domain.append(x)
		return "".join(ret_domain)

class SOA(DNSResponse):
	def __init__(self, query, config_location):
		super(SOA, self).__init__(query)

		self.type = b"\x00\x06"
		self.mname = 'ns1' # name server that was original or primary source for this zone
		self.rname = 'mx' # domain name which specified mailbox of person responsible for zone
		self.serial = int(getrandbits(32)) # 32-bit long version number of the zone copy
		self.refresh = 60 # 32-bit time interval before zone refresh
		self.retry = 60 # 32-bit time interval before retrying failed refresh
		self.expire = 60 # 32-bit time interval after which the zone is not authoritative
		self.minimum = 60 # The unsigned 32 bit minimum TTL for any RR from this zone.

		# convert the config entries into DNS format. Convenient conversion function will be moved up to module later.
		def convert(fqdn):
			tmp = b""
			for domain in fqdn.split('.'):
				tmp += chr(len(domain)).encode() + domain.encode()
			tmp += b"\xc0\x0c"
			return tmp

		self.data = b""

		self.mname = convert(self.mname)
		self.data += self.mname

		self.rname = convert(self.rname)
		self.data += self.rname # already is a bytes object.

		# pack the rest of the structure
		self.data += pack('>I', self.serial)
		self.data += pack('>I', self.refresh)
		self.data += pack('>I', self.retry)
		self.data += pack('>I', self.refresh)
		self.data += pack('>I', self.minimum)

		# get length of the answers area
		self.length = chr(len(self.data))

		# length is always two bytes - add the extra blank byte if we're not large enough for two bytes.
		if self.length < "0xff":
			self.length = b"\x00" + self.length.encode()


CASE = {
	b"\x00\x01": A,
	b"\x00\x1c": AAAA,
	b"\x00\x05": CNAME,
	b"\x00\x0c": PTR,
	b"\x00\x10": TXT,
	b"\x00\x0f": MX,
	b"\x00\x06": SOA,
	}

# Technically this is a subclass of A
class NONEFOUND(DNSResponse):
	def __init__(self, query):
		super(NONEFOUND, self).__init__(query)
		self.type = query.type
		self.flags = b"\x81\x83"
		self.rranswers = b"\x00\x00"
		self.length = b"\x00\x00"
		self.data = b"\x00"
		log.debug("Built NONEFOUND response")


class Handler(BaseRequestHandler):
	def handle(self):
		log.debug('handle %s', self.request)
		data, socket, = self.request
		query = DNSQuery(data)
		self.server.handle(self.client_address, query, socket)


class Dns(ThreadingUDPServer):
	def __init__(self, server_ip_address):
		self.server_ip_address = server_ip_address
		self.address_family = AF_INET
		super(Dns, self).__init__((server_ip_address.exploded, 53), Handler)

	def handle(self, client_address, query, socket):
		method = getattr(self, 'get_{}_for_name'.format(TYPE[query.type]), None)
		if method:
			response = method(client_address, query, )
			if response:
				socket.sendto(response, client_address)
				return
		log.info('handle %s %s NONEFOUND', str(query.domain, 'ascii'), TYPE[query.type])
		socket.sendto(NONEFOUND(query).make_packet(), client_address)

	def get_A_for_name(self, client_address, query, ):
		return CASE[query.type](query, record='127.0.0.1').make_packet()


class Dns_s(object):
	def sni(self,sock, name, context):
		log.info('sni from %s for domain-s://%s', sock.getpeername()[0], name, )
		return AlertDescription.ALERT_DESCRIPTION_ACCESS_DENIED

	def __init__(self, server_ip_address):
		if not HAS_SNI:
			raise Exception('sni missing here')
		self.context = _create_unverified_context(PROTOCOL_TLS_SERVER,
			certfile='pemdb/open.net-ca-cert.pem',
			keyfile='pemdb/open.net-ca.pem', )
		self.context.load_dh_params('pemdb/open.net-dhparam.pem')
		self.context.sni_callback = self.sni
		self.socket = socket(AF_INET, SOCK_STREAM, 0)
		self.socket.bind((server_ip_address.exploded, 853))
		self.socket.listen(5)
		self.socket = self.context.wrap_socket(self.socket, server_side=True)

	def serve_forever(self):
		while True:
			try:
				client_socket, address = self.socket.accept()
				log.info('%s %s', client_socket, address)
				client_socket.close()
			except:
				pass
