# -*- coding: utf-8 -*-

"""
Base daemon class
"""

__author__ = 'Unknown'
__copyright__ = 'Unknown'
__all__ = ['msg_stdout', 'Daemon', 'signal_to_daemon']

import os, sys, atexit, signal
from time import sleep
import customlogging as logging


def msg_stdout(msg, msg_type=0, show_pid=0, flush_buf=0):
	"""Print message on stdout. I{msg_type}: 0 - info, 1 - warning,
	2 - error"""

	msg_pre = b' \033[32;1m*\033[0m'
	if msg_type ==1:
		msg_pre = b' \033[33;1m*\033[0m'
	elif msg_type ==2:
		msg_pre = b' \033[31;1m*\033[0m'
	if type(msg) != type(b''):
		msg = msg.encode('utf8')
	if show_pid:
		pid = '%d:' % os.getpid()
		msg_pre = pid.encode('utf8') + msg_pre
		del pid
	sys.stdout.buffer.write(msg_pre + b' ' + msg + b'\n')
	# Write immediately
	if flush_buf:
		sys.stdout.flush()


class Daemon:
	"""Generic daemon"""

	def __init__(self, pid_file):
		self.pidfile = pid_file

	def daemonize(self, parent1=None, parent2=None):
		"""
		Do the UNIX double-fork magic, see Stevens' I{"Advanced Programming in
		the UNIX Environment"} for details (B{ISBN 0201563177}) on
		U{http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16}.
		I{parent1}, I{parent2} - continue parent process with this functions.
		"""

		# Check for a pidfile to see if the daemon already runned
		if os.path.isfile(self.pidfile):
			msg_stdout('PID-file %s found! Remove it manually' % self.pidfile)
			return

		#logging.info('fork #1 process')
		try:
			pid = os.fork()
			if pid >0:
				if parent1:
					parent1(pid)
				# Exit first parent
				sys.exit()
		except OSError as e:
			logging.error('fork #1 failed: %d (%s)' % (e.errno, e.strerror))
			sys.exit(1)

		# Decouple from parent environment
		os.setsid()
		os.umask(0)

		# Do second fork
		#logging.info('fork #2 process')
		try:
			pid = os.fork()
			if pid >0:
				if parent2:
					parent2(pid)
				# Exit from second parent
				sys.exit()
		except OSError as e:
			logging.error('fork #2 failed: %d (%s)' % (e.errno, e.strerror))
			sys.exit(1)

		atexit.register(self.delpid)
		pid = str(os.getpid())
		open(self.pidfile,'w+').write('%s\n' % pid)
		logging.info('write PID (%s) to %s' % (pid, self.pidfile))

		return 1

	def delpid(self):
		"""Delete PID file"""

		try:	os.remove(self.pidfile)
		except:	pass

	def stop(self):
		logging.info('stopping daemon')
		# Get the pid from the pidfile
		try:
			pf = open(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
		except IOError:
			pid = None

		#print (sys.stderr, sys.stdout)
		if not pid:
			logging.warn('daemon is already stopped')
			sys.stderr.write('daemon is already stopped\n')
			return

		# Try killing the daemon process
		try:
			while 1:
				os.kill(pid, signal.SIGTERM)
				sleep(0.1)
		except OSError as err:
			# PID file is present, but no process!
			err = '%s' %err
			if err.find('No such process') >0:
				if os.path.isfile(self.pidfile):
					os.remove(self.pidfile)
			else:
				sys.stderr.write(err)
				sys.exit(1)


def signal_to_daemon(pidfile, signum):
	"""Send signal to daemon"""

	# Get the pid from the pidfile
	if not os.path.isfile(pidfile):
		msg_stdout('PID file <%s> is absent' % pidfile, 1)
		return

	try:
		pf = open(pidfile, 'r')
		pid = int(pf.read().strip())
		pf.close()
	except IOError:
		pid = None

	if not pid:
		msg_stdout('daemon is already stopped', 1)
		return

	stop = (signum == signal.SIGTERM)
	msg_stdout('stopping daemon' if stop else \
		'send signal %d to process' % signum)

	try:
		if stop:
			while 1:
				os.kill(pid, signum)
				sleep(0.1)
		else:
			os.kill(pid, signum)
	except OSError as err:
		err = '%s' %err
		if err.find('No such process') >0:
			if os.path.exists(pidfile):
				os.remove(pidfile)
		else:
			print (err)
