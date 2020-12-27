from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from OpenSSL.crypto import dump_privatekey, FILETYPE_PEM
from mitmproxy.certs import CertStore
from os.path import exists
from socket import socket, AF_INET, SOCK_STREAM
from ssl import HAS_SNI, PROTOCOL_TLS_SERVER, _create_unverified_context, AlertDescription
import logging as log

class HttpHandler(BaseHTTPRequestHandler):
	def do_POST(self):
		log.info('do_POST %s %s %s', self.client_address[0], self.headers['Host'], self.path, )
	def do_GET(self):
		log.debug('%s %s %s %s', self.client_address[0], self.headers['Host'], self.path, self.headers, )
		code, headers, content = self.server.get_response(self.headers['Host'], self.path, self.headers)
		self.protocol_version = 'HTTP/1.1'
		self.close_connection = True
		self.send_response(code)
		if headers:
			for n,v in headers.items():
				self.send_header(n, v)
			self.end_headers()
		self.wfile.write(content.encode())

	def version_string(self): return 'sffe'

	def log_request(self, *a): pass

	def log_error(self, *a): pass

	def log_message(self, *a): pass


class Http(ThreadingHTTPServer):
	def __init__(self, server_address):
		super(Http, self).__init__((server_address.exploded, 80), HttpHandler)


class Https(ThreadingHTTPServer):
	def __init__(self, server_address):
		super(Https, self).__init__((server_address.exploded, 443), HttpHandler)
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
		log.info('sni from %s for https://%s', sock.getpeername()[0], name, )
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


