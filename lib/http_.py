from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from OpenSSL.crypto import dump_privatekey, FILETYPE_PEM
from mitmproxy.certs import CertStore
from os.path import exists
from socket import socket, AF_INET, SOCK_STREAM
from ssl import HAS_SNI, PROTOCOL_TLS_SERVER, _create_unverified_context, AlertDescription

class FakeHttpHandler(BaseHTTPRequestHandler):
	def do_POST(self):
		log.info('do_POST %s %s %s', self.client_address[0], self.headers['Host'], self.path, )
	def do_GET(self):
		log.debug('%s %s %s %s', self.client_address[0], self.headers['Host'], self.path, self.headers, )
		host = self.headers['Host']
		self.protocol_version = 'HTTP/1.1'
		self.close_connection = True
		# captive portal checks
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
		elif (host, self.path, ) in (
			('detectportal.firefox.com', '/success.txt?ipv4', ),
		):
			self.send_response(200, 'OK')
			self.send_header("Content-type", "text/plain")
			self.end_headers()
			self.wfile.write('success\n\r'.encode())
			log.info('do_GET %s %s%s -> %s %s', self.client_address[0], host, self.path, 200, 'success')
		else:
			self.send_response(404, 'Not Found')
			self.end_headers()
			log.warning('do_GET %s %s%s -> %s', self.client_address[0], host, self.path, 404)
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


