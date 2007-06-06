#!/usr/bin/python

import xmpp
import session

class FancySession(session.Session):
	def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
		session.Session.__init__(self, dispatcher, conn, jid, thread_id, type)

		self.status = 'new'

	def do_help(self):
		self.send("""this particular testbot tries to tell you something about your XEP-0201 (Best Practices for Message Threads) implementation.

different types of messages are handled differently. unless noted otherwise, you should be able to send either a message[@type='normal'] or a message[@type='chat'] and have me respond via the same method.

'help': this message
'newthread': i send a message starting a new session
'status': details about the sessions i have with your resource
'run': (chat only) i run through a series of scenarios to check your client's compliance
<any other message>: details about what thread your message belongs to""")

	def do_newthread(self):
		new_sess = self.dispatcher.start_new_session(self.jid, type=self.type)
		thread_id = new_sess.thread_id

		new_sess.send("""this is the first message of thread '%s'. if you reply directly to it, your message should be part of the same thread.""" % thread_id)
		new_sess.status = 'existing'

	def do_status(self):
		if self.dispatcher.sessions.has_key(self.jid):
			text = 'I have the following sessions with the Full JID "%s":\n' % self.jid

			for session in self.dispatcher.sessions[self.jid].values():
				text += '\n' + str(session)

			self.send(text)
		else:
		  self.send('i have no sessions with the Full JID "%s".' % self.jid)

	def do_normal(self):
		if self.received_thread_id:
			if self.status == 'new':
				self.send('''you have started a new thread '%s', this message is part of it.''' % self.thread_id)
				self.status = 'existing'
			else:
				self.send('''your message was part of thread '%s' (and so is this one)''' % self.thread_id)
		else:
			self.send("your message had no <thread/>, so it's not part of one (and neither is this message)") # XXX this is a lie

	def do_chat(self):
		if self.status == 'new':
			if self.received_thread_id:
				self.send("you started a new thread (id '%s') with your message (this reply is in it too)" % self.thread_id)
			else:
				self.send("your message had no <thread/>, and I have no existing sessions with you in which you haven't sent a <thread/>, so I'm starting a new thread (id '%s') (that this reply is part of)" % self.thread_id)

			self.status = 'existing'
		else:
			if self.received_thread_id:
				self.send("your message is part of existing thread '%s' (and so is this reply)" % self.thread_id)
			else:
				self.send("your message had no <thread/>, I've already got a null-thread session for you so I'm considering it to be part of that (id '%s') (this reply is in it too)" % self.thread_id)

	def do_run_chat_0(self):
		if not self.received_thread_id:
			self.send('''!!! your message didn't contain a thread ID at all. i doubt your client supports any of XEP-0201, so i'm aborting the rest of the test.''')
			return

		self.send('''ok, your message contained a thread ID. this one contains the same one, so your client should recognize it as part of the same session.

reply to this message to continue. the next message you receive should begin with 'ok'.''')

		self.status = 'run'
		self.proceed = self.do_run_chat_1

	def do_run_chat_1(self, msg):
		if not self.received_thread_id:
			self.send('''!!! you replied to the message, but you didn't include a <thread/> (as RECOMMENDed by XEP-0201)''')
			self.terminate()
			return

		self.terminate()

		new_sess = self.dispatcher.start_new_session(self.jid, type='chat')
		new_sess.status = 'run'
		new_sess.proceed = new_sess.do_run_chat_2

		new_sess.send('ok, your message contained the same thread ID. this message contains a different thread ID, so your client should recognize it as part of a new session. reply to this message to continue.')

	def do_run_chat_2(self, msg):
		if not self.received_thread_id:
			self.send('''!!! you replied to the message, but you didn't include a <thread/> (as RECOMMENDed by XEP-0201)''')
			self.terminate()
			return

		self.send('ok, your client responded with the thread ID i was expecting. this is as far as the test goes for now.')

		# XXX send with the same thread ID from another resource
		# XXX terminate session
		# XXX go offline (session should continue)

	def terminate(self):
		session.Session.terminate(self)
		self.proceed = self.terminated

	def terminated(self, msg):
		self.send('''!!! this session was terminated, you shouldn't send any more messages to it.''')

	def handle_message(self, msg):
		if self.status == 'run':
			self.proceed(msg)
			return

		body = msg.getBody()

		if body == 'run':
			if msg.getType() != 'chat':
				self.send('''this command is only supported for chat messages. 'help' for more details.''')
				return

			self.do_run_chat_0()
		elif body == 'help':
			self.do_help()
		elif body == 'newthread':
			self.do_newthread()
		elif body == 'status':
			self.do_status()
		elif not msg.getType() or msg.getType() == 'normal':
			self.do_normal()
		elif msg.getType() == "chat":
			self.do_chat()

session.SessionDispatcher("bot2@necronomicorp.com", "silenceotss", FancySession).run()
