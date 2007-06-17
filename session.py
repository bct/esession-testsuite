import xmpp

import uuid
import sys
import time

class SessionDispatcher:
	def __init__(self, jid, password, session_class):
		self.jid = xmpp.protocol.JID(jid)
		self.password = password
		self.session_class = session_class

		self.sessions = {}

	def run(self):
		self.conn = xmpp.Client(self.jid.getDomain(), debug=[])

		res = self.conn.connect()
		if not res:
			print 'Unable to connect.'
			sys.exit(1)

		res = self.conn.auth(self.jid.getNode(), self.password)
		if not res:
			print 'Unable to authorize.'
			sys.exit(1)

		self.conn.RegisterHandler('message', self.messageCB)
		self.conn.RegisterHandler('presence', self.presenceCB)
		self.conn.sendInitPresence()

		print 'Listening.'

		while 1:
			self.conn.Process(1)

	def start_new_session(self, jid, thread_id = None, type = 'chat'):
		sess = self.session_class(self, self.conn, jid, thread_id, type)
		thread_id = sess.thread_id

		if not jid in self.sessions:
			self.sessions[jid] = {}

		self.sessions[jid][thread_id] = sess

		return sess

	def presenceCB(self, conn, msg):
		# automatically approve subscription requests
		if msg.getType() == 'subscribe':
			conn.send(xmpp.dispatcher.Presence(to=msg.getFrom(), typ='subscribed'))

	def messageCB(self, conn, msg):
		thread_id = msg.getThread()
		sender = msg.getFrom()
		type = msg.getType()
		if not type:
			type = 'normal'

		try:
			if type == 'chat' and not thread_id:
				sess = self.find_null_session(sender)
			else:
				sess = self.sessions[sender][thread_id]
		except KeyError:
			sess = self.start_new_session(sender, thread_id, type)

		if thread_id and not sess.received_thread_id:
			sess.received_thread_id = True

		sess.handle_message(msg)

	def find_null_session(self, jid):
		all = self.sessions[jid].values()
		null_sessions = filter(lambda s: not s.received_thread_id, all)
		null_sessions.sort(self.sort_by_last_send)

		return null_sessions[-1]

	def sort_by_last_send(self, x, y):
		# if they happen to have identical times, meh.
		if x.last_send > y.last_send:
			return 1
		else:
			return -1

class Session(object):
	def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
		self.dispatcher = dispatcher
		self.conn = conn
		self.jid = jid
		self.type = type
		self.status = 'new'

		if thread_id:
			self.received_thread_id = True
			self.thread_id = thread_id
		else:
			self.received_thread_id = False
			if type == 'normal':
				self.thread_id = None
			else:
				self.thread_id = self.generate_thread_id()

		self.last_send = 0

	def generate_thread_id(self):
		return 'urn:uuid:' + str(uuid.uuid1())

	def send(self, msg, add_type = True):
		if isinstance(msg, str) or isinstance(msg, unicode):
			msg = xmpp.Message(body=msg)

		if self.thread_id:
			msg.setThread(self.thread_id)

		if add_type and self.type != 'normal':
			msg.setType(self.type)

		msg.setAttr('to', self.jid)
		self.conn.send(msg)

		self.last_send = time.time()

	def handle_message(self, msg):
		pass

	def terminate(self):
		self.status = 'terminated'
		pass
