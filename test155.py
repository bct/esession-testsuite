#!/usr/bin/python

import xmpp

from basebot import BaseBot

class NegotioBot(BaseBot):
	def do_begin(self, cl, msg, sess):
		if sess and sess.has_key('status') and sess['status'] == 'agreed':
			cl.send(msg.buildReply('we\'re in a session, but i\'ll start a new one.'))

		to = msg.getFrom()
		sess = self.new_session(to)
		reply = xmpp.Message(to)
		reply.NT.thread = sess['thread_id']
		feature = reply.NT.feature
		feature.setNamespace(xmpp.NS_FEATURE)

		x = xmpp.DataForm(title = "Open chat with Negotiobot?", typ="form")
		x.addChild(node=xmpp.DataField("FORM_TYPE", typ="hidden", value="urn:xmpp:ssn"))

		accept = xmpp.DataField(name="accept", typ="boolean", required=1, value="true")
		accept.setAttr("label", "Accept this session?")

		x.addChild(node=accept)

		goofy = xmpp.DataField(name="x-politeness", typ="boolean", required=1, value="true")
		goofy.setAttr("label", "Promise to be polite?")

		x.addChild(node=goofy)

		# xmpp.DataField(options=[["English", "en"], ["Italiano", "it"]]

		feature.addChild(node=x)
 # <amp xmlns='http://jabber.org/protocol/amp'>
 #	 <rule action='drop' condition='deliver' value='stored'/>
 # </amp>

		sess['status'] = 'requested'
		cl.send(reply)

	def presenceCB(self, cl, msg):
		if msg.getType() == "subscribe":
			# automatically approve subscription requests
			cl.send(xmpp.dispatcher.Presence(to=msg.getFrom(), typ="subscribed"))

	def handle_rejection(self, cl, msg, sess):
		m = msg.buildReply('you rejected the session negotiation.')
		m.setType('chat')
		cl.send(m)

		sess['status'] = 'rejected'

	def handle_acceptance(self, cl, msg, sess, form):
		acceptance = msg.buildReply()
		feature = acceptance.NT.feature
		feature.setNamespace(xmpp.NS_FEATURE)

		x = xmpp.DataForm(typ='result')
		x.addChild(node=xmpp.DataField('FORM_TYPE', value='urn:xmpp:ssn', typ='hidden'))
		x.addChild(node=xmpp.DataField('accept', value='true', typ='boolean'))

		feature.addChild(node=x)

		cl.send(acceptance)

		sess['status'] = 'agreed'
		if form['x-politeness'] in ('0', 'false'):
			sess['polite'] = False
		elif form['x-politeness'] in ('1', 'true'):
			sess['polite'] = True

		if sess['polite']:
			reply = 'you accepted my session and promised to be polite. please say \'please\' with all your messages, thank you.'
		else:
			reply = 'you accepted my session, but didn\'t promise to be polite.'

		m = msg.buildReply(reply)
		m.setThread(sess['thread_id'])

		cl.send(m)

	def messageCB(self, cl, msg):
		sender = msg.getFrom()
		body = msg.getBody()
		if not body:
			body = ""

		thread_id = msg.getThread()

		created_new_sess = False
		sess = self.get_session(sender, thread_id)
		if sess and sess.has_key('status') and sess['status'] == 'agreed' and sess['polite']:
			if not "please" in body:
				m = msg.buildReply("tsk tsk tsk, you didn't say 'please'. terminating session.")
				m.setType("chat")
				cl.send(m)
				self.terminate_session(sender, thread_id)
				return

		if sess and sess.has_key('status') and sess['status'] == 'requested':
			if msg.getTag('feature') and msg.getTag('feature').namespace == xmpp.NS_FEATURE:
				form = xmpp.DataForm(node=msg.getTag('feature').getTag('x'))
				if form['FORM_TYPE'] == 'urn:xmpp:ssn':
					if form.getType() != 'submit':
						cl.send(msg.buildReply('your form was of type \'%s\', it should be of type \'submit\'.' % form.getType()))

					if form['accept'] in ('0', 'false'):
						self.handle_rejection(cl, msg, sess)
					elif form['accept'] in ('1', 'true'):
						self.handle_acceptance(cl, msg, sess, form)
					else:
						cl.send(msg.buildReply('''!!! field[@var='accept'] must be '0', '1', 'false' or 'true'. you sent '%s'.''' % form['accept']))

					return
				else:
					reply = msg.buildReply()
					reply.setType('error')

					reply.addChild(feature)
					reply.addChild(node=xmpp.ErrorNode('service-unavailable', typ='cancel'))

					cl.send(reply)

					return

		if thread_id and not sess:
			created_new_sess = True
			sess = self.new_session(sender, thread_id)

		reply = None
		if body.startswith("help"):
			reply = 'type "negotiate" to have me initiate a session (as described in XEP-0155)'
		elif body.startswith("begin"):
			self.do_begin(cl, msg, sess)
		elif not body:
			 pass # XXX
		else:
			reply = "message acknowledged."

		if reply:
			if sess and sess.has_key('status') and sess['status'] == 'agreed' and sess['polite']:
				reply += " thank you."

			m = msg.buildReply(reply)
			m.setType('chat')
			cl.send(m)

NegotioBot("bot2@necronomicorp.com", "silenceotss").run()
