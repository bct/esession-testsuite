#!/usr/bin/python

import xmpp
import session

class FancySession(session.Session):
	def do_begin(self, msg):
		if self.status == 'agreed':
			self.send('''we've negotiated a session already, but i'll start a new one anyways.''')

		new_sess = self.dispatcher.start_new_session(self.jid, type=self.type)
		new_sess.status = 'requested'
		request = xmpp.Message()
		feature = request.NT.feature
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

		self.status = 'requested'
		new_sess.send(request, False)

	def handle_rejection(self, msg):
		self.send('you rejected the session negotiation.')

		self.status = 'rejected'

	def handle_acceptance(self, msg, form):
		acceptance = xmpp.Message()
		feature = acceptance.NT.feature
		feature.setNamespace(xmpp.NS_FEATURE)

		x = xmpp.DataForm(typ='result')
		x.addChild(node=xmpp.DataField('FORM_TYPE', value='urn:xmpp:ssn', typ='hidden'))
		x.addChild(node=xmpp.DataField('accept', value='true', typ='boolean'))

		feature.addChild(node=x)

		self.send(acceptance, False)

		self.status = 'agreed'
		if form['x-politeness'] in ('0', 'false'):
			self.polite = False
		elif form['x-politeness'] in ('1', 'true'):
			self.polite = True

		if self.polite:
			self.send('you accepted my session and promised to be polite. please say \'please\' with all your messages, thank you.')
		else:
			self.send('you accepted my session, but didn\'t promise to be polite.')

	def handle_message(self, msg):
		body = msg.getBody()

		if self.status == 'agreed' and self.polite and not 'please' in body:
			self.send('''tsk tsk tsk, you didn't say 'please'. terminating session.''')
			self.terminate()
			return

		if self.status == 'requested':
			if msg.getTag('feature') and msg.getTag('feature').namespace == xmpp.NS_FEATURE:
				form = xmpp.DataForm(node=msg.getTag('feature').getTag('x'))
				if form['FORM_TYPE'] == 'urn:xmpp:ssn':
					if form.getType() != 'submit':
						self.send('''your form was of type '%s', it should be of type 'submit'.''' % form.getType())

					if form['accept'] in ('0', 'false'):
						self.handle_rejection(msg)
					elif form['accept'] in ('1', 'true'):
						self.handle_acceptance(msg, form)
					else:
						self.send('''!!! field[@var='accept'] must be '0', '1', 'false' or 'true'. you sent '%s'.''' % form['accept'])

					return
				else:
					reply = xmpp.Message()
					reply.setType('error')

					reply.addChild(feature)
					reply.addChild(node=xmpp.ErrorNode('service-unavailable', typ='cancel'))

					self.send(reply, False)

					return

		reply = None
		if body.startswith("help"):
			reply = 'type "negotiate" to have me initiate a session (as described in XEP-0155).'
		elif body.startswith("begin"):
			self.do_begin(msg)
		elif not body:
			 pass # XXX
		else:
			reply = "message acknowledged."

		if reply:
			if self.status == 'agreed' and self.polite:
				reply += " thank you."

			self.send(reply)
