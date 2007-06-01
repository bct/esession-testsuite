import xmpp

import uuid
import sys

class BaseBot:
	def __init__(self, jid, password):
		self.jid = xmpp.protocol.JID(jid)
		self.password = password
		self.sessions = {}
		self.nullsessions = {}

	def run(self):
		self.cl = xmpp.Client(self.jid.getDomain(), debug=[])

		res = self.cl.connect()

		if not res:
			print "Unable to connect."
			sys.exit(1)

		res = self.cl.auth(self.jid.getNode(), self.password)

		if not res:
			print "unable to authorize."
			sys.exit(1)

		self.cl.RegisterHandler('message', self.messageCB)
		self.cl.RegisterHandler('presence', self.presenceCB)
		self.cl.sendInitPresence()

		print "listening."

		while 1:
			self.cl.Process(1)

	def make_thread_id(self):
		return "urn:uuid:" + str(uuid.uuid1())

	def new_session(self, jid, thread_id = None):
		jid = str(jid)

		if not thread_id:
			thread_id = self.make_thread_id()

		if not self.sessions.has_key(jid):
			self.sessions[jid] = {}

		sess = { 'thread_id': thread_id }
		self.sessions[jid][thread_id] = sess
		return sess

	def get_session(self, jid, thread_id):
		try:
			return self.sessions[str(jid)][thread_id]
		except KeyError:
			return None

	def terminate_session(self, jid, thread_id):
		# XXX terminate it 0155-style
		del self.sessions[jid][thread_id]

	def messageCB(self, cl, msg):
		pass

	def presenceCB(self, cl, msg):
		if msg.getType() == "subscribe":
			# automatically approve subscription requests
			cl.send(xmpp.dispatcher.Presence(to=msg.getFrom(), typ="subscribed"))
