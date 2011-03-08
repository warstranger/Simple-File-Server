# -*- coding: utf-8 -*-

"""
Logging to stdout/file and/or syslog
"""

__author__	= 'warcraft.stranger@gmail.com'
__license__	= 'GPLv2'
__status__	= 'development'
__version__	= '0.1a'

import sys, syslog, logging, logging.handlers
import collections

LEVELS = {
	'debug':	syslog.LOG_DEBUG,
	'info':		syslog.LOG_INFO,
	'warn':		syslog.LOG_WARNING,
	'warning':	syslog.LOG_WARNING,
	'error':	syslog.LOG_ERR,
	'critical':	syslog.LOG_CRIT,
	'fatal':	syslog.LOG_CRIT,
}

# Default logging is syslog
LOG_TYPE = 1

LOGGER_NAME = 'sfserver'
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.DEBUG)

# Log to:
#	TYPE_FILE     - file
#	TYPE_SYS      - syslog
#	TYPE_FILE_SYS - file and syslog
#	TYPE_STD      - stdout
#	TYPE_FILE_STD - file and stdout
(TYPE_FILE, TYPE_SYS, TYPE_FILE_SYS, TYPE_STD, TYPE_FILE_STD) = range(5)


def close(on_exit=1):
	"""Close logging system. I{on_exit} """

	global LOG_TYPE, logger

	if LOG_TYPE in [TYPE_FILE, TYPE_FILE_SYS, TYPE_STD, TYPE_FILE_STD]:
		if on_exit:
			logging.shutdown()
		else:
			for h in logger.handlers:
				h.flush()
				if not isinstance(h, logging.StreamHandler):
					h.close()
				logger.removeHandler(h)

	if LOG_TYPE in [TYPE_SYS, TYPE_FILE_SYS]:
		syslog.closelog()

def init(logtype, **kwargs):
	"""Logging params. Accept I{only} keyword arguments except the first -
	C{logtype}."""

	global LOG_TYPE, logger
	LOG_TYPE = logtype

	if logtype in [TYPE_FILE, TYPE_FILE_SYS]:
		"""Write to log file"""
		if not kwargs.get('filename'):
			raise 'for log type %d a filename must be set' %logtype
		if kwargs.get('maxbytes') and kwargs['maxbytes'] >0:
			handler = logging.handlers.RotatingFileHandler(
				kwargs['filename'], maxBytes=kwargs['maxbytes'],
				backupCount=kwargs['count'])
		else:
			handler = logging.FileHandler(kwargs['filename'])
		fmt = logging.Formatter(
			'%(asctime)s %(process)d %(levelname)s %(message)s')
		handler.setFormatter(fmt)
		logger.addHandler(handler)

	if logtype in [TYPE_STD, TYPE_FILE_STD]:
		"""Write to stdout"""
		handler = logging.StreamHandler(sys.stdout)
		logger.addHandler(handler)

	if logtype in [TYPE_SYS, TYPE_FILE_SYS]:
		"""Write to syslog"""
		syslog.openlog(LOGGER_NAME, 0, syslog.LOG_USER)

def _log(level, obj, *args, **kwargs):
	if level not in LEVELS:
		return

	if LOG_TYPE in [TYPE_FILE, TYPE_FILE_SYS]:
		func = getattr(logger, level)
		func(obj, *args, **kwargs)

	if LOG_TYPE in [TYPE_STD, TYPE_FILE_STD]:
		func = getattr(logger, level)
		msg_pre = ' \033[32;1m*\033[0m '
		if level in ['warn', 'warning']:
			msg_pre = ' \033[33;1m*\033[0m '
		elif level not in ['debug', 'info']:
			msg_pre = ' \033[31;1m*\033[0m '

		if hasattr(obj, '__str__') and \
				isinstance(getattr(obj, '__str__'), collections.Callable):
			msg = str(obj)
			if msg:
				msg = msg[0].upper() + msg[1:]
		else:
			msg = repr(obj)
		func(msg_pre + msg, *args, **kwargs)
		del msg, msg_pre

	if LOG_TYPE in [TYPE_SYS, TYPE_FILE_SYS]:
		if hasattr(obj, '__str__') and \
				isinstance(getattr(obj, '__str__'), collections.Callable):
			msg = str(obj)
			if msg:
				msg = msg[0].upper() + msg[1:]
		else:
			msg = repr(obj)
		syslog.syslog(LEVELS[level], msg)

def debug(obj, *args, **kwargs):
	_log('debug', obj, *args, **kwargs)

def info(obj, *args, **kwargs):
	_log('info', obj, *args, **kwargs)

def warn(obj, *args, **kwargs):
	_log('warn', obj, *args, **kwargs)

def warning(obj, *args, **kwargs):
	_log('warning', obj, *args, **kwargs)

def error(obj, *args, **kwargs):
	_log('error', obj, *args, **kwargs)

def critical(obj, *args, **kwargs):
	_log('critical', obj, *args, **kwargs)

def fatal(obj, *args, **kwargs):
	_log('fatal', obj, *args, **kwargs)
