#!/usr/bin/python

import xmpp
import random, string

class NegotioBot:
	def __init__(self, jid, password):
		self.jid = xmpp.protocol.JID(jid)
		self.password = password
		self.sessions = {}

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

	def make_threadid(self):
		return "".join([random.choice(string.letters) for x in xrange(3000)])

	def make_initiate(self, to):
		reply = xmpp.Message(to)
		reply.NT.thread = self.make_threadid()
		feature = reply.NT.feature
		feature.setNamespace(xmpp.NS_FEATURE)

		x = xmpp.DataForm(title = "Open chat with Negotiobot?", typ="form")
		x.addChild(node=xmpp.DataField("FORM_TYPE", typ="hidden", value="urn:xmpp:ssn"))

		accept = xmpp.DataField(name="accept", typ="boolean", required=1, value="true")
		accept.setAttr("label", "Accept this session?")

		x.addChild(node=accept)

		goofy = xmpp.DataField(name="x-politeness", typ="boolean", required=1, value="true")

		x.addChild(node=goofy)

		# xmpp.DataField(options=[["English", "en"], ["Italiano", "it"]]

		feature.addChild(node = x)
 # <amp xmlns='http://jabber.org/protocol/amp'>
 #	 <rule action='drop' condition='deliver' value='stored'/>
 # </amp>

		return reply

	def terminate(self, jid):
		# XXX
		pass

	def presenceCB(self, cl, msg):
		if msg.getType() == "subscribe":
			# automatically approve subscription requests
			cl.send(xmpp.dispatcher.Presence(to=msg.getFrom(), typ="subscribed"))

	def sessionExists(self, jid, threadid):
		if not jid in self.sessions:
			return False

		sess = self.sessions[jid]

		# XXX multiple threads :(
		return sess

	def messageCB(self, cl, msg):
		sender = msg.getFrom()
		body = msg.getBody()
		threadid = msg.getTag("thread")

		if self.sessionExists(sender, threadid) and not "please" in body:
			cl.send(xmpp.Message(sender, "tsk tsk tsk, you didn't say 'please'. terminating session."), typ="chat")
			self.terminate(sender)
			return

		if body.startswith("help"):
			reply = 'type "begin" to have me initiate a session (as described in XEP-0155)'
		elif body.startswith("begin"):
			if self.sessionExists(sender, threadid):
				cl.send(xmpp.Message(sender, 'a session has already begun, thank you.'))

			cl.send(self.make_initiate(sender))
		elif not body:
			 pass # XXX
		else:
			reply = "message acknowledged."

		if reply:
			if self.sessionExists(sender, threadid):
				reply += " thank you."

			cl.send(xmpp.Message(sender, reply, typ="chat")

NegotioBot("test@necronomicorp.com", "test").run()
