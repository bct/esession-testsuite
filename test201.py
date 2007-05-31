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
		m = msg.buildReply("""this particular testbot tries to tell you something about your XEP-0201 (Best Practices for Message Threads) implementation.

different types of messages are handled differently. unless noted otherwise, you should be able to send either a message[@type='normal'] or a message[@type='chat'] and have me respond via the same method.

'help': this message
'newthread': i send a message starting a new session
'run': (chat only) i run through a series of scenarios to check your client's compliance
<any other message>: details about what thread your message belongs to
			""")
		m.setType(msg.getType())
		cl.send(m)

	def do_newthread(self, cl, msg):
		thread_id = self.make_threadid()
		m = msg.buildReply("""this is the first message of thread '%s'. if you reply directly to it, your message should be part of the same thread.""" % thread_id)
		m.setType(msg.getType())
		m.setThread(thread_id)
		cl.send(m)

	def do_run_chat_1(self, cl, msg, session):
		if session['thread_id'] == msg.getThread():
			reply = 'ok, your message contained the same thread ID. this message contains a different thread ID, so your client should recognize it as part of a new session. reply to this message to continue.'

			thread_id = self.make_threadid()
			self.sessions[thread_id] = { 'thread_id': thread_id, 'continue': self.do_run_chat_2 }
		else:
			reply = '''!!! i expected you to send thread_id '%s', but you sent '%s'.''' % (session['thread_id'], msg.getThread())
			del self.sessions[session['thread_id']]

		m = msg.buildReply(reply)
		m.setType('chat')
		if thread_id:
			m.setThread(thread_id)
		cl.send(m)

	def do_run_chat_2(self, cl, msg, session):
		if session['thread_id'] == msg.getThread():
			reply = 'ok, your client responded with the thread ID i was expecting. this is as far as the test goes for now.'

			# XXX send with the same thread ID from another resource
			# XXX terminate session
			# XXX go offline (session should continue)
			del self.sessions[session['thread_id']]
		else:
			reply = '''!!! i expected you to send thread_id '%s', but you sent '%s'.''' % (session['thread_id'], msg.getThread())
			del self.sessions[session['thread_id']]

		m = msg.buildReply(reply)
		m.setType('chat')
		cl.send(m)

	def presenceCB(self, cl, msg):
		if msg.getType() == "subscribe":
			# automatically approve subscription requests
			cl.send(xmpp.dispatcher.Presence(to=msg.getFrom(), typ="subscribed"))

	def messageCB(self, cl, msg):
		thread_id = msg.getThread()

		if self.sessions.has_key(thread_id) and isinstance(self.sessions[thread_id], dict):
			session = self.sessions[thread_id]
			session['continue'](cl, msg, session)
			return

		sender = msg.getFrom()
		body = msg.getBody()

		if body == 'run':
			if msg.getType() != 'chat':
				m = msg.buildReply("""this command is only supported for chat messages. 'help' for more details.""")
				m.setType(msg.getType())
				cl.send(m)
				return

			if not thread_id:
				m = msg.buildReply('''!!! your message didn't contain a thread ID at all. i doubt your client supports any of XEP-0201, so i'm aborting the rest of the test.''')
				m.setType('chat')
				cl.send(m)
				return

			m = msg.buildReply('''ok, your message contained a thread ID. this one contains the same one, so your client should recognize it as part of the same session. reply to this message to continue''')
			m.setType('chat')
			cl.send(m)

			self.sessions[thread_id] = { 'continue': self.do_run_chat_1, 'thread_id' : thread_id }

			return

		if body == "help":
			self.do_help(cl, msg)
			return

		if body == "newthread":
			self.do_newthread(cl, msg)
			return

		if not msg.getType() or msg.getType() == "normal":
			if not thread_id:
				reply = "your message had no <thread/>, so it's not part of one (and neither is this message)"
			elif thread_id in self.sessions:
				reply = "your message was part of thread '%s' (and so is this one)" % thread_id
			else:
				self.sessions[thread_id] = True
				reply = "you have started a new thread '%s', this message is part of it" % thread_id

			if reply:
				cl.send(msg.buildReply(reply))

			return

		if msg.getType() == "chat":
			if not thread_id:
				if sender in self.nullsessions:
					reply = "your message had no <thread/>, I've already got a null-thread session for you so I'm considering it to be part of that (this reply is too)"
					thread_id = self.nullsessions[sender]
				else:
					reply = "your message had no <thread/>, and I have no existing sessions with you in which you haven't sent a <thread/>, so I'm starting a new thread (that this reply is part of)"
					thread_id = self.make_threadid()
					self.nullsessions[sender] = thread_id

			else:
				if thread_id in self.sessions:
					reply = "your message is part of an existing thread (and so is this reply)"
				else:
					reply = "you started a new thread with your message (this reply is in it too)"
					self.sessions[thread_id] = True

					if sender in self.nullsessions:
						del self.nullsessions[sender]

			if reply:
				m = msg.buildReply(reply)
				m.setType('chat')
				m.setThread(thread_id)

				cl.send(m)

			return

ThreadBot("test@necronomicorp.com", "test").run()
