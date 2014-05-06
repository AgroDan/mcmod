#!/usr/local/bin/python

import struct
import socket

class MCRcon:
	def __init__(self, host, port, pwd, uid=500, wsize=1446):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.host = host
		self.port = port
		self.pwd = pwd
		self.uid = uid
		self.wsize = wsize
		self.logged_in = False
		self.s.connect((self.host, self.port,))
	
	def _send_recv(self, t, data):
		"""
		Internal command, sends and receives data.
		"""
		dlen = len(data) + 10
		buff = struct.pack('<iii', dlen, self.uid, t)
		buff += data
		buff += "\x00\x00"
		self.s.send(buff)
		
		# Now receive, we want the first 12 bytes to unpack
		r_dlen, r_uid, r_t = struct.unpack('<iii', self.s.recv(12))
		r_data = self.s.recv(r_dlen-8)

		# Strip the \x00 nulls, raise exception otherwise
		if r_data[-2:] != "\x00\x00":
			raise Exception("Protocol failure, WTF")
		r_data = r_data[:-2]

		# Now find out the type. If -1 is passed, authentication failure.
		if r_t == -1:
			raise Exception("Authentication failure.")

		# Do we have more data?
		# worry about this later
		return r_data

	def _login(self):
		try:
			self._send_recv(3, self.pwd)
			self.logged_in = True
			return True
		except:
			self.logged_in = False
			return False
	
	def _cmd(self, cmd):
		# Runs a command on the server, gets raw data
		#first, make sure we're logged in
		if not self.logged_in:
			if not self._login():
				return None

		return self._send_recv(2, cmd)


	def list(self):
		# Lists users on server
		 ret_str = self._cmd('/list')
		 userstr = ret_str.split(':')[1]
		 if len(userstr):
			 return [user.strip() for user in userstr.split(',')]
		 else:
			 return []

	def toggledownfall(self):
		# Simply toggles rain
		ret_str = self._cmd('/toggledownfall')
		return ret_str

	def wtf(self):
		# prints help?
		return self._cmd('/help')

	def close(self):
		# Closes connection
		self.s.close()

if __name__ == '__main__':
	conn = MCRcon('127.0.0.1', 25575, 'blah')
	for user in conn.list():
		print "User: %s" % user
	conn.close()
