#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple File Server
@todo: fix:  wait until all connections are closed cleanly when shutdown
@todo: task: listen incoming local connections in another thread
@todo: task: add verbose logging if SSL enabled
"""

__author__	= 'warcraft.stranger@gmail.com'
__license__	= 'GPLv2'
__status__	= 'development'
__version__	= '0.1a'

import os, sys, time, signal, socket, select, atexit, collections
import customlogging as logging
from pickle import dumps as cpickle_dumps
from base64 import b64decode
from socketserver import ThreadingTCPServer
from http.server import BaseHTTPRequestHandler
from sfutils import *
from sfdaemon import *

CONFIG_FILE = 'server.cfg'
CFG_PATH = os.path.realpath(os.path.dirname(sys.argv[0])) + '/' + CONFIG_FILE


class AsyncHTTPServer(ThreadingTCPServer, Daemon):
	"""Main server class inherited from threading server and
	generic daemon classes in order."""

	def __init__(self, config, handler_class):
		server_address = (config['server']['ip'], config['server']['port'],)
		# Bind and activate server in I{activate} method
		ThreadingTCPServer.__init__(self, server_address, handler_class, 0)
		Daemon.__init__(self, config['server']['pid'])

		# Signals not catched in serve_forever, we need to execute serve_forever
		# again because signals are raised exception in I{main} method
		self.__by_signal_do = 0
		self.__local_sock = None
		self.allow_reuse_address = 1
		self._config = config.copy()
		self._aliases = {}
		self.timeout = config['server']['timeout']

	def cfg_ssl_enabled(self):
		"""Check if SSL enabled on server"""
		return self._config['ssl'].get('enable', 0)

	def cfg_certs_used(self):
		"""Check if SSL enabled and clients certificate used"""
		return self.cfg_ssl_enabled() and \
			self._config['ssl'].get('verify_client', 0)

	def _create_local_socket(self, init=0):
		"""Create local Unix-socket to listen commands instead of signals. If
		I{init} is set then close old socket"""

		if init and self.__local_sock:
			try:
				os.unlink(self.__local_sock.getsockname())
				self.__local_sock.shutdown(socket.SHUT_RDWR)
				logging.info('old local socket closed')
			except Exception as e:
				logging.warn('old local socket is already closed')

		try:
			os.unlink(self._config['server']['sock'])
		except:
			pass

		try:
			self.__local_sock = \
				socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
			# Non-blocking mode
			self.__local_sock.settimeout(0.0)
			self.__local_sock.bind(self._config['server']['sock'])
			self.__local_sock.listen(1)		# Max num of queued connections
		except Exception as e:
			logging.critical('cannot create local socket')
			logging.error(e)
			raise e

		logging.info('local socket created and binded on %s' % \
			self.__local_sock.getsockname())

	def _create_bind_activate(self, init=0):
		"""Create socket, bind and activate server"""

		try:
			self._create_new_socket(init)
		except Exception as e:
			logging.critical('cannot create new socket')
			logging.error(e)
			raise e

		try:
			self.server_bind()
			self.server_activate()
		except Exception as e:
			logging.critical('cannot bind/activate server: %s' %e)
			raise e
		logging.info('server binded and activated on %s:%s' % \
			self.socket.getsockname())

	def _create_new_socket(self, init):
		"""Create new socket. I{init} >0 if need to replace internal server
		address used in the base class to create and bind socket"""

		if init:
			self.server_address = \
				(self._config['server']['ip'], self._config['server']['port'],)
			self.socket = socket.socket(self.address_family, self.socket_type)
			self.socket.settimeout(self._config['server']['timeout'])
			logging.info('network socket created')

		if self._config['ssl'].get('enable', 0) ==0:
			logging.info('SSL disabled')
			return

		logging.info('SSL enabled')
		try:
			logging.info('socket replaced by SSLSocket')
			import ssl
			if self._config['ssl'].get('verify_client', 0) ==0:
				logging.info('clients certificates not used')
				self.socket = ssl.SSLSocket(None,
					self._config['ssl']['pkey_file'],
					self._config['ssl']['cert_file'], True,
					ssl.CERT_NONE, ssl.PROTOCOL_SSLv3)
			else:
				logging.info('clients certificate required')
				self.socket = ssl.SSLSocket(None,
					self._config['ssl']['pkey_file'],
					self._config['ssl']['cert_file'], True,
					ssl.CERT_REQUIRED, ssl.PROTOCOL_SSLv3,
					self._config['ssl']['verify_loc'])
			self.socket.settimeout(self._config['server']['timeout'])
		except Exception as e:
			logging.error(e)
			raise RuntimeError('SSL error')

	def handle_sigusr2(self, signum, frame):
		"""Handle signal SIGUSR2 to reload aliases configuration"""

		logging.info('reload aliases configuration (by signal)')
		# Catch received signal in the I{main} method
		self.__by_signal_do = 1

		aliases = get_aliases(self._config['get']['aliases_file'])
		try:
			check_aliases(self._config['get']['base_dir'], aliases)
			self._aliases = aliases.copy()
			logging.info('aliases configuration reloaded')
		except Exception as e:
			logging.warn('aliases configuration error')
		del aliases

	def handle_sigusr1(self, signum, frame):
		"""Handle signal SIGUSR1 to reload server configuration"""

		logging.info('reload server configuration (by signal)')
		# Catch exception in the I{main} method caused by received signal
		self.__by_signal_do = 1
		config = get_conf(CFG_PATH)

		# PID file cannot be changed
		config['server']['pid'] = self._config['server']['pid']

		# Log file path changed
		if self._config['server']['log'] != config['server']['log']:
			logging.close(0)
			logging.init(0, filename=config['server']['log'])

		# Local socket path changed
		init_loc = (config['server']['sock'] != self._config['server']['sock'])

		# SSL option changed and/or server ip/port, we need to
		# shutdown current socket and open new one
		init_srv = (config['ssl'] != self._config['ssl'] \
			or config['server']['port'] != self._config['server']['port'] \
			or config['server']['ip'] != self._config['server']['ip'])

		self._config = config.copy()

		if init_srv:
			try:
				self.socket.shutdown(socket.SHUT_RDWR)
				self._create_bind_activate(1)
			except Exception as e:
				# @todo: fix: if cannot bind new socket, do not reload config
				self.__by_signal_do = 0
				logging.error(e)

		if init_loc:
			try:
				self._create_local_socket(1)
			except Exception as e:
				pass

		self.socket.settimeout(config['server']['timeout'])
		# Non-blocking mode
		self.__local_sock.settimeout(0.0)
		logging.info('server configuration reloaded')
		del config

	def handle_local_request(self):
		"""Accept local socket connections"""

		c = None
		is_quit = 0
		try:
			# Are we have connection try?
			r, w, e = select.select([self.__local_sock.fileno()], [], [],
				self._config['server']['wait'])
			if not r:
				return
			c, addr, = self.__local_sock.accept()
			logging.info('local connection accepted')

			# Check if socket is ready for reading
			msg = b''
			r, w, e = select.select([c.fileno()], [], [], 0)
			if r:
				msg = c.recv(32, socket.MSG_DONTWAIT)
			else:
				logging.warn('socket not ready for reading')
				raise socket.error(100, 'socket not ready for reading')

			reply = b'unknown command'
			if msg == b'config':
				logging.info('request server configuration')
				reply = cpickle_dumps(self._config)
			elif msg == b'status':
				logging.info('request server status')
				reply = b'started'
			elif msg == b'shutdown':
				logging.info('request server shutdown')
				is_quit = 1
				reply = b'stopped'
			elif not msg:
				logging.info('no request')
			else:
				logging.info('unknown request')

			# Check if socket is ready for writing
			r, w, e = select.select([], [c.fileno()], [], 0)
			if w:
				c.send(reply, socket.MSG_DONTWAIT)
			else:
				logging.warn('socket not ready for writing')
				raise socket.error(101, 'socket not ready for writing')

		except Exception as e:
			logging.error(e)

		if c and not c._closed:
			c.close()
			logging.info('local connection closed')

		return is_quit

	def activate(self):
		"""Activate network and local sockets"""

		try:
			self._create_bind_activate()
			self._create_local_socket()
		except Exception as e:
			# All logging actions in called method
			return
		return 1

	def main(self):
		"""Start main loop. From that moment the process will loop forever
		in this method"""

		logging.info('*' *50)
		logging.info('python %s' % sys.version.replace('\n', ''))
		logging.info('server started on %s:%s' % self.socket.getsockname())
		logging.info('SSL enabled' if self.cfg_ssl_enabled() else \
			'SSL disabled')
		logging.info('clients certificate ' + \
			('used' if self.cfg_certs_used() else 'not used'))
		logging.info(
			'local socket activated on %s' % self.__local_sock.getsockname())
		logging.info('pid (%d) written to %s' % (os.getpid(), self.pidfile))

		while 1:
			try:
				self.handle_request()
				# If we received shutdown request from local socket
				is_quit = self.handle_local_request()
				if is_quit:
					logging.info('stopping daemon')
					break
			except Exception as e:
				if self.__by_signal_do:
					self.__by_signal_do = 0
					continue
				from traceback import format_exception
				i = sys.exc_info()
				logging.error('\n'.join(format_exception(i[0], i[1], i[2])))
				del i
				break

	def get_request(self):
		sock, addr = ThreadingTCPServer.get_request(self)
		logging.info('%s:%s incoming request' % addr)
		return sock, addr

	def finish_request(self, request, client_address):
		try:
			return ThreadingTCPServer.finish_request(self, request,
				client_address)
		except Exception as e:
			from traceback import format_exception
			i = sys.exc_info()
			logging.error('\n'.join(format_exception(i[0], i[1], i[2])).strip())
			#logging.error('%s:%s ' % client_address + \
			#	'exception in <finish request>: %r' % e)


class SFSHTTPHandler(BaseHTTPRequestHandler):
	"""Process request handler"""

	def version_string(self):
		"""Version string (returned in "Server" header)"""
		return self.server._config['server'].get('version', 'unknown')

	def date_time_string(self, timestamp=None):
		"""Local time on the server (returned in "Date" header)"""
		return self.server._config['server'].get('datetime', 'unknown')

	def log_message(self, format, *args):
		"""Rewrite default log handler. Log client IP address/port and verbose
		response of HTTP response code"""

		format = '%s:%s ' % self.client_address + format
		if args and len(args) >2 and args[1].isdigit() and \
				self.responses.get(int(args[1])):
			format += ' %s'
			args += (self.responses.get(int(args[1]))[0],)
		logging.info(format % args)

	def log_my_message(self, obj, msg_type='info'):
		"""Log message in format: <client_address> <message>"""

		if msg_type not in logging.LEVELS:
			logging.error('<log_my_message>: msg_type unknown')
			return
		c_addr = '%s:%s ' % self.client_address
		if hasattr(obj, '__str__') and isinstance(getattr(obj, '__str__'),
				collections.Callable):
			logging._log(msg_type, c_addr + str(obj))
		else:
			logging._log(msg_type, c_addr + repr(obj))

	def _send_default_reply(self, code):
		"""Internal method: send code and message to client"""

		if str(code) not in self.server._config['http_codes']:
			self.log_my_message('<_send_default_reply>: code %d unknown' % \
				code, 'warn')
			code = int(self.server._config['http_codes']['default'])

		reply = bytes(self.server._config['http_codes'][str(code)], 'utf8')
		self.protocol_version = 'HTTP/1.1'
		self.send_response(code)
		self.send_header('Content-Type', 'text/plain')
		self.send_header('Content-Length', len(reply))
		self.end_headers()
		self.wfile.write(reply)

	def do_POST(self):
		"""Getting file from client and save it on a local fs"""

		if not self.headers['content-length']:
			self.log_my_message('header <content-type> not received', 'error')
			self._send_default_reply(404)
			return

		# Local file name must be specified in URL after last slash /
		# File encoding must be specified in URL after prelast slash /
		# File encoding can be 'b' (b64 encoded) or 'p' (plain/binary)
		#	(if not specified then default to 'p')
		# Example: http://0.0.0.0/b/hello.txt, http://0.0.0.0/passwd

		# First, extract file name
		url_parts = self.path.split('/')
		fname = url_parts[-1]
		fname = check_url_fname(
			fname, self.server._config['put']['fname_max_len'])
		if not fname:
			self.log_my_message('incorrect file name', 'error')
			self._send_default_reply(404)
			return

		# Secondary, extract file encoding
		file_enc = self.server._config['put']['files_enc_default']
		if len(url_parts) >1 and url_parts[-2] in ['b', 'p']:
			file_enc = url_parts[-2]

		clen = int(self.headers['content-length'])
		if not clen:
			self.log_my_message('incorrect Content-Length header', 'error')
			self._send_default_reply(404)
			return

		# @todo: task: if we can't receive specified content-length from client
		#	then forcely break connection!
		self.log_my_message(
			'reading %d bytes from POST (according to Content-Length header)' %\
			clen)
		# Accept POST data according to received Content-Length header
		content = self.rfile.read(clen)

		if file_enc =='b':
			self.log_my_message('trying to b64decode POST')
			try:
				content = b64decode(content)
			except:
				self.log_my_message('incorrect POST data', 'error')
				self._send_default_reply(404)
				return
			self.log_my_message('POST b64-decoded')

		self.log_my_message('saving content to file <%s>' %fname)
		try:
			if not os.path.isdir(self.server._config['put']['base_dir']):
				self.log_my_message('save dir not exist, creating', 'warn')
				os.makedirs(self.server._config['put']['base_dir'],
					self.server._config['put']['dirs_mode'])
				self.log_my_message('save dir created')
			fpath = self.server._config['put']['base_dir'] + '/' + fname
			f = open(fpath, 'wb')
			f.write(content)
			f.close()
			self.log_my_message('file <%s> saved' % fname)
			self.log_my_message('set file permissions')
			os.chmod(fpath, self.server._config['put']['files_mode'])
			self._send_default_reply(200)
			del fpath
		except:
			i = sys.exc_info()
			from traceback import format_exception
			self.log_my_message('\n'.join(format_exception(i[0], i[1], i[2])),
				'error')
			self._send_default_reply(500)
			del i
		del content, file_enc, clen, fname

	def do_GET(self):
		"""Return file content based on URL"""

		self.log_my_message(self.headers.as_string().strip())

		fhttp = self.path.lower().split('/')[-1]
		fhttp = re_sub('../', '', fhttp)
		fhttp = re_sub('[\x00-\x19/]', '', fhttp)

		fdir = self.server._config['get']['base_dir'] + '/'
		# Detect file on file system
		fs_file = fhttp if os.path.isfile(fdir + fhttp) else None

		# Detect file in aliases
		alias_file = None
		if fhttp in list(list(self.server._aliases.keys())):
			self.log_my_message('key <%s> declared in aliases' % fhttp)
			if os.path.isfile(fdir + self.server._aliases[fhttp]):
				alias_file = self.server._aliases[fhttp]
			else:
				self.log_my_message(
					'file <%s> not found' % self.server._aliases[fhttp], 'warn')
				self._send_default_reply(500)
				return

		if not alias_file and not fs_file:
			#self.log_my_message('file not found', 'warn')
			self._send_default_reply(404)
			return

		fsend = None
		if alias_file and not fs_file:
			fsend = alias_file
		elif not alias_file and fs_file:
			fsend = fs_file
		else:
			# File detection order (default is alias then file system)
			order = self.server._config['get']['order']
			self.log_my_message(
				'file exist on FS and in aliases, use %s' % order[0], 'warn')
			fsend = fs_file if order[0] =='fs' else alias_file

		fpath = fdir + fsend
		self.log_my_message('sending file <%s>' % fsend)

		self.protocol_version = 'HTTP/1.1'
		self.send_response(200)
		f = open(fpath, 'rb')
		fdata = f.read()
		f.close()
		self.send_header('Content-Type', self.server._config['get']['ctype'])
		self.send_header('Content-Length', len(fdata))
		self.end_headers()
		self.wfile.write(fdata)


def msg_sock(cfg_server, msg, status_msg=1):
	"""L{sfutils.send_socket_msg} call to server local socket"""

	err, err_msg = send_socket_msg(cfg_server['sock'], msg,
		cfg_server['timeout'] + cfg_server['wait'] *10)
	msg_pre = ' \033[31;1m*\033[0m' if err else ' \033[32;1m*\033[0m'
	if status_msg:
		print (msg_pre, 'status:', err_msg)
	else:
		print (msg_pre, err_msg)

def print_usage():
	"""Show script usage"""
	print('start | reload | aliases | status | stop')

def clean_on_exit(fp_sock):
	"""Method executed on process exit"""

	logging.info('clean up on process exit')
	try:	os.remove(fp_sock)
	except:	pass
	logging.info('shutdown logging system')
	logging.close()


if len(sys.argv) <2:
	print_usage()
	sys.exit()

# Init logging to console
logging.init(3)

try:
	config = get_conf(CFG_PATH)

	if sys.argv[1].lower() == 'start':
		msg_stdout('Running on Python %s' % sys.version.replace('\n', ''))

		aliases = get_aliases(config['get']['aliases_file'])
		check_aliases(config['get']['base_dir'], aliases)
		if not aliases:
			msg_stdout('File aliases absent', 1)
		else:
			msg_stdout('%d file aliases loaded' % len(aliases))

		server = AsyncHTTPServer(config, SFSHTTPHandler)
		msg_stdout('Network socket created')
		server._aliases = aliases.copy()

		# Catch SIGUSR1 signal to reload server configuration
		signal.signal(signal.SIGUSR1, server.handle_sigusr1)
		# Catch SIGUSR2 signal to reload aliases configuration
		signal.signal(signal.SIGUSR2, server.handle_sigusr2)
		msg_stdout('Signal handlers registered')

		if server.activate():
			msg_stdout('Server activated', flush_buf=1)
			# Send message to local socket in the first parent process
			r = server.daemonize()
			if r:
				logging.info('forked as daemon process')
				# Close logging, init new to file
				logging.close(0)
				logging.init(0, filename=config['server']['log'])
				# Delete local socket on FS when process exit
				atexit.register(clean_on_exit, config['server']['sock'])
				# Start main loop
				server.main()
			else:
				msg_stdout('Error: can\'t daemonize', 2)

	elif sys.argv[1].lower() == 'stop':
		msg_sock(config['server'], 'shutdown', 0)

	elif sys.argv[1].lower() == 'reload':
		signal_to_daemon(config['server']['pid'], signal.SIGUSR1)

	elif sys.argv[1].lower() == 'aliases':
		signal_to_daemon(config['server']['pid'], signal.SIGUSR2)

	elif sys.argv[1].lower() == 'status':
		msg_sock(config['server'], 'status')

	else:
		print_usage()

except Exception as e:
	info = sys.exc_info()
	from traceback import print_exception
	print_exception(info[0], info[1], info[2])
	sys.exit(1)

logging.close()
