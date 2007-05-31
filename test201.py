#!/usr/bin/python

import xmpp
import random, string
import uuid

# -> reply directly to this message[@type="normal"]
# -> ok, the thread id matches the one i sent. your client should recognize this message as part of the same thread. i'm going to terminate the session now, you should get an "ok" message shortly.
# -> ok, i got your acknowledgement.

# -> send me a message that's part of a new thread
# -> ok, that's a new thread. your client should recognize this message as part of the same thread. now terminate the session
# -> ok, session terminated.

# -> this message is from another resource using the same ThreadID. it should be considered part of a new session

class ThreadBot:
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

	def make_threadid(self):
		thr = "urn:uuid:" + str(uuid.uuid1())
		self.sessions[thr] = True
		return thr

	def do_help(self, cl, msg):
		cl.send(xmpp.Message(msg.getFrom(), """this particular testbot tries to tell you something about your XEP-0201 (Best Practices for Message Threads) implementation.

'help': this message
'newthread': i send you a message (of the same type that you sent) with a new ThreadID
<any other message>: details about what thread your message belongs to
			""", typ=msg.getType()))

	def do_newthread(self, cl, msg):
		threadid = self.make_threadid()
		res = xmpp.Message(msg.getFrom(), """this is the first message of thread '%s'. if you reply directly to it, your message should be part of the same thread.""" % threadid, typ=msg.getType())
		res.NT.thread = threadid

		cl.send(res)

	def presenceCB(self, cl, msg):
		if msg.getType() == "subscribe":
			# automatically approve subscription requests
			cl.send(xmpp.dispatcher.Presence(to=msg.getFrom(), typ="subscribed"))

	def messageCB(self, cl, msg):
		threadid = msg.getTagData("thread")

		sender = msg.getFrom()
		body = msg.getBody()

		if body == "help":
			self.do_help(cl, msg)
			return

		if body == "newthread":
			self.do_newthread(cl, msg)
			return

		if not msg.getType() or msg.getType() == "normal":
			if not threadid:
				reply = "your message had no <thread/>, so it's not part of one (and neither is this message)"
			elif threadid in self.sessions:
				reply = ("your message was part of thread '%s' (and so is this one)" % threadid)
			else:
				self.sessions[threadid] = True
				reply = ("you have started a new thread '%s', this message is part of it" % threadid)

			if reply:
				res = xmpp.Message(sender, reply)
				if threadid:
					res.NT.thread = threadid

				cl.send(res)

			return

		if msg.getType() == "chat":
			if not threadid:
				if sender in self.nullsessions:
					reply = "your message had no <thread/>, I've already got a null-thread session for you so I'm considering it to be part of that (this reply is too)"
					threadid = self.nullsessions[sender]
				else:
					reply = "your message had no <thread/>, and I have no existing sessions with you in which you haven't sent a <thread/>, so I'm starting a new thread (that this reply is part of)"
					threadid = self.make_threadid()
					self.nullsessions[sender] = threadid

			else:
				if threadid in self.sessions:
					reply = "your message is part of an existing thread (and so is this reply)"
				else:
					reply = "you started a new thread with your message (this reply is in it too)"
					self.sessions[threadid] = True

					if sender in self.nullsessions:
						del self.nullsessions[sender]

			if reply:
				res = xmpp.Message(sender, reply, typ="chat")
				res.NT.thread = threadid

				cl.send(res)

			return

ThreadBot("test@necronomicorp.com", "test").run()
