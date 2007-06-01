#!/usr/bin/python

import xmpp

# -> reply directly to this message[@type="normal"]
# -> ok, the thread id matches the one i sent. your client should recognize this message as part of the same thread. i'm going to terminate the session now, you should get an "ok" message shortly.
# -> ok, i got your acknowledgement.

# -> send me a message that's part of a new thread
# -> ok, that's a new thread. your client should recognize this message as part of the same thread. now terminate the session
# -> ok, session terminated.

# -> this message is from another resource using the same ThreadID. it should be considered part of a new session

from basebot import BaseBot

class ThreadBot(BaseBot):
	def do_help(self, cl, msg):
		m = msg.buildReply("""this particular testbot tries to tell you something about your XEP-0201 (Best Practices for Message Threads) implementation.

different types of messages are handled differently. unless noted otherwise, you should be able to send either a message[@type='normal'] or a message[@type='chat'] and have me respond via the same method.

'help': this message
'newthread': i send a message starting a new session
'status': details about the sessions i have with your resource
'run': (chat only) i run through a series of scenarios to check your client's compliance
<any other message>: details about what thread your message belongs to
			""")
		m.setType(msg.getType())
		cl.send(m)

	def do_newthread(self, cl, msg):
		new_sess = self.new_session(msg.getFrom())
		thread_id = new_sess['thread_id']

		m = msg.buildReply("""this is the first message of thread '%s'. if you reply directly to it, your message should be part of the same thread.""" % thread_id)
		m.setType(msg.getType())
		m.setThread(thread_id)
		cl.send(m)

	def do_status(self, cl, msg):
		if self.sessions.has_key(msg.getFrom()):
			text = 'I have the following sessions with the Full JID "%s":\n' % msg.getFrom()

			for thread_id in self.sessions[msg.getFrom()]:
				text += '\n%s: %s' % (thread_id, self.sessions[msg.getFrom()][thread_id])

			m = msg.buildReply(text)
			cl.send(m)
		else:
		  cl.send(msg.buildReply('i have no sessions with the Full JID "%s".' % msg.getFrom()))

	# state machine test
	def do_run_chat_1(self, cl, msg, session):
		if session['thread_id'] == msg.getThread():
			reply = 'ok, your message contained the same thread ID. this message contains a different thread ID, so your client should recognize it as part of a new session. reply to this message to continue.'

			self.terminate_session(msg.getFrom(), session['thread_id'])

			sess = self.new_session(msg.getFrom())
			sess['status'] = 'run'
			sess['continue'] = self.do_run_chat_2
			new_thread_id = sess['thread_id']
		else:
			reply = '''!!! i expected you to send thread_id '%s', but you sent '%s'.''' % (session['thread_id'], msg.getThread())
			self.terminate_session(msg.getFrom(), session['thread_id'])

		m = msg.buildReply(reply)
		m.setType('chat')
		if new_thread_id:
			m.setThread(new_thread_id)
		cl.send(m)

	def do_run_chat_2(self, cl, msg, session):
		if session['thread_id'] == msg.getThread():
			reply = 'ok, your client responded with the thread ID i was expecting. this is as far as the test goes for now.'

			# XXX send with the same thread ID from another resource
			# XXX terminate session
			# XXX go offline (session should continue)
			self.terminate_session(msg.getFrom(), session['thread_id'])
		else:
			reply = '''!!! i expected you to send thread_id '%s', but you sent '%s'.''' % (session['thread_id'], msg.getThread())
			self.terminate_session(msg.getFrom(), session['thread_id'])

		m = msg.buildReply(reply)
		m.setType('chat')
		cl.send(m)

	def messageCB(self, cl, msg):
		thread_id = msg.getThread()

		created_new_sess = False
		sess = self.get_session(msg.getFrom(), thread_id)
		if sess and sess.has_key('status') and sess['status'] == 'run':
			sess['continue'](cl, msg, sess)
			return

		if thread_id and not sess:
			created_new_sess = True
			sess = self.new_session(msg.getFrom(), thread_id)

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

			sess['status'] = 'run'
			sess['continue'] = self.do_run_chat_1

			return

		if body == 'help':
			self.do_help(cl, msg)
			return

		if body == 'newthread':
			self.do_newthread(cl, msg)
			return

		if body == 'status':
			self.do_status(cl, msg)
			return

		if not msg.getType() or msg.getType() == "normal":
			if thread_id:
				if created_new_sess:
					reply = "you have started a new thread '%s', this message is part of it" % thread_id
				else:
					reply = "your message was part of thread '%s' (and so is this one)" % thread_id
			else:
				reply = "your message had no <thread/>, so it's not part of one (and neither is this message)"

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
					sess = self.new_session(msg.getFrom())
					sess['type'] = 'null'
					thread_id = sess['thread_id']
					self.nullsessions[sender] = thread_id

			else:
				if created_new_sess:
					reply = "you started a new thread with your message (this reply is in it too)"

					if sender in self.nullsessions:
						del self.nullsessions[sender]
				else:
					reply = "your message is part of an existing thread (and so is this reply)"

			if reply:
				m = msg.buildReply(reply)
				m.setType('chat')
				m.setThread(thread_id)

				cl.send(m)

			return

ThreadBot("bot2@necronomicorp.com", "silenceotss").run()
