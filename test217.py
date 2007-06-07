#!/usr/bin/python

import session
import dh

import xmpp

import base64

# could use binascii.hexify
def _encode(n):
	if n >= 256:
		return _encode(n / 256) + chr(n % 256)
	else:
		return chr(n)

def _decode(s):
	if len(s) == 0:
		return 0
	else:
		return 256 * _decode(n[:-1]) + ord(n[-1])

class ESession(session.Session):
	def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
		session.Session.__init__(self, dispatcher, conn, jid, thread_id, type = 'chat')

		self.state = {}

	def bob_responds(self, request_form):
		response = xmpp.Message()
		response.NT.feature
		feature.setNamespace(xmpp.NS_FEATURE)

		x = xmpp.DataForm(typ='submit')

		fixed = { 'disclosure': 'never',
								'security': 'e2e',
							'crypt_algs': 'aes128-ctr',
							'hash_algs': 'sha256',
								'compress': 'none',
								'stanzas': 'message',
						'init_pubkey': 'none',
						'resp_pubkey': 'none',
										'ver': '1.0',
								'sas_algs': 'sas28x5' }

		for name, field in request_form.asDict().items():
			options = map(lambda x: x[1], field.getOptions())

			if name in fixed:
				assert fixed[name] in options
				x.addChild(node=xmpp.DataField(name='name', value=fixed[name]))
			elif name == 'FORM_TYPE':
				if field.getValue() != 'urn:xmpp:ssn':
					self.error('''I was expecting an 'urn:xmpp:ssn' FORM_TYPE, not '%s'.''' % field.getValue())
				x.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn'))
			elif name == 'accept':
				x.addChild(node=xmpp.DataField(name='accept', value='true'))
			elif name == 'logging':
				# we don't log anyways, just pick the preferred
				preferred = field.getOptions[0][1]
				x.addChild(node=xmpp.DataField(name='logging', value=preferred))
			elif name == 'modp':
				group_order = 0
				group = int(field.getOptions[group_order][1])
				x.addChild(node=xmpp.DataField(name='modp', value=group))
				g = dh.generators[preferred]
				p = dh.primes[preferred]
			elif name == 'rekey_freq':
				preferred = int(field.getOptions[0][1])
				x.addChild(node=xmpp.DataField(name='rekey_freq', value=preferred))
				self.state['rekey_freq'] = preferred
			elif name == 'my_nonce':
				self.state['N_a'] = field.getValue()
				pass
			elif name == 'dhhashes':
				pass
			else:
				pass # XXX we don't support this field

		self.state['He'] = request_form.asDict()['dhhashes'].getOptions()[group_order][1]

		n = 128 # number of bits
		bytes = bits / 8

		C_a = _decode(os.urandom(bytes)) # n-bit random number
		C_b = C_a ^ 2 ** (n-1)

		bottom = 2 ** (2 * n - 1)
		top = p - 1

		# minimum number of bytes needed to represent that range
		bytes = math.ceil(math.log(top - bottom, 256))

		# a random number between 'bottom' and 'top'
		y = (_decode(os.urandom(bytes)) % (top - bottom)) + bottom

		my_nonce = os.urandom(8) # XXX length?
		dhkeys = (g ** y) % p

		to_add = { 'my_nonce': my_nonce, 'dhkeys': dhkeys, 'counter': C_a, 'nonce': self.state['N_a'] }

	  for name in to_add:
			b64ed = base64.b64encode(_encode(to_add[name]))
			x.addChild(node=xmpp.DataField(name='name', value=b64ed))

		feature.addChild(node=x)
		self.send(response, False)

	def bob_accepts(self, request_form)
		response = xmpp.Message()

		response.NT.feature
		feature.setNamespace(xmpp.NS_FEATURE)

		x = xmpp.DataForm(typ='submit')

		for name, field in request_form.asDict().items():
			options = map(lambda x: x[1], field.getOptions())
