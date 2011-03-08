# -*- coding: utf-8 -*-

"""
Utils
"""

__all__ = ['check_url_fname', 'get_conf', 're_sub', 'check_aliases',
	'get_aliases', 'send_socket_msg']

__author__	= 'warcraft.stranger@gmail.com'
__license__	= 'GPLv2'
__status__	= 'development'
__version__	= '0.1a'

import socket, select
from stat import S_ISSOCK
from os import stat as os_stat
from os.path import isfile
from re import sub as re_sub
from configparser import ConfigParser

def send_socket_msg(sock, msg, timeout):
	"""Send command to server through local socket"""

	if not hasattr(socket, 'AF_UNIX'):
		return (1, 'AF_UNIX socket type not defined')

	# Check that socket exist
	try:
		if not S_ISSOCK(os_stat(sock).st_mode):
			raise (2, 'not a socket')
	except Exception as e:
		return (2, 'stopped')

	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
	try:
		s.connect(sock)
		# We must to send bytes to socket not str
		if type(msg) != type(b''):
			msg = bytes(msg, 'utf8')
		s.send(msg)
		r, w, e = select.select([s], [], [], timeout)
		if not r:
			raise socket.error('error (socket not ready for reading)')
		r = s.recv(256, socket.MSG_DONTWAIT)
		if not r:
			raise socket.error('error (no response from server)')
		s.close()
		return (0, r.decode('utf8'))

	except Exception as e:
		if not s._closed:
			s.close()
		# Connection refused
		if e.args[0] == 111:
			return (0, 'stopped')
		return (3, e)

def check_aliases(base_dir, aliases):
	"""Check files aliases"""

	for fkey, fname in aliases.items():
		fpath = base_dir + '/' + fname
		if not fpath:
			msg = 'aliases: empty file for key <%s>' % fkey
			logging.error(msg)
			raise RuntimeError(msg)
		if not isfile(fpath):
			msg = 'aliases: file <%s> not found for key <%s>' % (fpath,fkey,)
			logging.error(msg)
			raise RuntimeError(msg)
	return 1

def check_url_fname(fname, fname_max_len):
	"""Check file name given in URL after last slash / and remove not allowed
	chars"""

	# Remove unprinted chars and strip it
	fname = re_sub('[\x00-\x19/]', '', fname).strip()
	if len(fname) > fname_max_len:
		return 0
	return fname

def get_aliases(fpath):
	"""Parse file aliases configuration file and return it as dict"""

	if not isfile(fpath):
		return {}

	conf = ConfigParser()
	conf.read(fpath)

	if not conf.has_section('aliases'):
		return {}

	ret = {}
	for alias in conf.options('aliases'):
		ret[alias] = conf.get('aliases', alias).strip()
	return ret

def get_conf(fpath):
	"""Parse configuration file and return as dict"""

	assert isfile(fpath), 'config file not found'

	conf = ConfigParser()
	conf.read(fpath)

	assert conf.has_section('server'), '<server> section not found'
	assert conf.has_section('http_codes'), '<http_codes> section not found'
	assert conf.has_section('get'), '<get> section not found'
	assert conf.has_section('put'), '<put> section not found'
	assert conf.has_section('ssl'), '<ssl> section not found'

	ret = {}
	for section in conf.sections():
		ret[section] = {}
		for option in conf.options(section):
			ret[section][option] = conf.get(section, option).strip()

	# Remove slashes in the end of paths
	paths = (('get', 'base_dir'), ('put', 'base_dir'), ('ssl', 'verify_loc'))
	for section, option in paths:
		ret[section][option] = re_sub('/+$', '', ret[section][option])

	# Convert some options to integer
	opts_to_int = (('server', 'port'), ('ssl', 'enable'),
		('ssl', 'verify_client'), ('put', 'fname_max_len'))
	for section, option in opts_to_int:
		ret[section][option] = int(ret[section][option])

	# Convert some options to float
	opts_to_float = (('server', 'timeout'), ('server', 'wait'))
	for section, option in opts_to_float:
		ret[section][option] = float(ret[section][option])

	# Convert some options to octal
	opts_to_oct = (('put', 'dirs_mode'), ('put', 'files_mode'))
	for section, option in opts_to_oct:
		ret[section][option] = int(ret[section][option], 8)

	# Convert some options to lists
	opts_to_list = (('get', 'order',),)
	for section, option in opts_to_list:
		ret[section][option] = [i.strip().lower() \
			for i in ret[section][option].split(',')]

	if not ret['server']['timeout']:
		ret['server']['timeout'] = None
	if not ret['server']['wait']:
		ret['server']['wait'] = None

	return ret
