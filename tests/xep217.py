#!/usr/bin/python

import session
import esession

import dh

import xmpp

import c14n

import base64

class FancySession(esession.ESession):
  def __init__(self, **args):
    esession.ESession.__init__(self, **args)

    self.xes = {}
    self.es = {}

    self.status = 'waiting'

  def make_dhhash(self, modp):
    p = dh.primes[modp]
    g = dh.generators[modp]

    x = self.srand(2 ** (2 * self.n - 1), p - 1)

    # XXX this may be a source of performance issues
    e = self.powmod(g, x, p)

    self.xes[modp] = x
    self.es[modp] = e

    He = self.sha256(self.encode_mpi(e))

    return base64.b64encode(He)

  # 4.1 esession request (alice)
  def alice_initiates(self, msg):
    request = xmpp.Message()
    feature = request.NT.feature
    feature.setNamespace(xmpp.NS_FEATURE)

    x = xmpp.DataForm(typ='form')

    x.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn', typ='hidden'))
    x.addChild(node=xmpp.DataField(name='accept', value='1', typ='boolean', required=True))

    # this field is incorrectly called 'otr' in XEPs 0116 and 0217
    # unsupported options: 'mustnot'
    x.addChild(node=xmpp.DataField(name='logging', typ='list-single', options=['may'], required=True))

    # unsupported options: 'disabled', 'enabled'
    x.addChild(node=xmpp.DataField(name='disclosure', typ='list-single', options=['never'], required=True))
    x.addChild(node=xmpp.DataField(name='security', typ='list-single', options=['e2e'], required=True))
    x.addChild(node=xmpp.DataField(name='crypt_algs', value='aes128-ctr', typ='hidden'))
    x.addChild(node=xmpp.DataField(name='hash_algs', value='sha256', typ='hidden'))
    x.addChild(node=xmpp.DataField(name='compress', value='none', typ='hidden'))

    # unsupported options: 'iq', 'presence'
    x.addChild(node=xmpp.DataField(name='stanzas', typ='list-multi', options=['message']))

    x.addChild(node=xmpp.DataField(name='init_pubkey', value='none', typ='hidden'))
    x.addChild(node=xmpp.DataField(name='resp_pubkey', value='none', typ='hidden'))
    x.addChild(node=xmpp.DataField(name='ver', value='1.0', typ='hidden'))

    x.addChild(node=xmpp.DataField(name='rekey_freq', value='4294967295', typ='hidden'))

    x.addChild(node=xmpp.DataField(name='sas_algs', value='sas28x5', typ='hidden'))

    self.n_s = self.generate_nonce()
  
    x.addChild(node=xmpp.DataField(name='my_nonce', value=base64.b64encode(self.n_s), typ='hidden'))

    modp_options = [ 5, 14, 2, 1 ]

    x.addChild(node=xmpp.DataField(name='modp', typ='list-single', options=map(lambda x: [ None, x ], modp_options)))

    dhhashes = map(lambda x: self.make_dhhash(x), modp_options)
    x.addChild(node=xmpp.DataField(name='dhhashes', typ='hidden', value=dhhashes))

    self.form_a = ''.join(map(lambda el: c14n.c14n(el), x.getChildren()))

    feature.addChild(node=x)

    self.status = 'initiated'

    self.send(request, False)

  # 4.3 esession response (bob)
  def bob_responds(self, request_form):
    response = xmpp.Message()
    feature = response.NT.feature
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

    for name, field in map(lambda name: (name, request_form.getField(name)), request_form.asDict().keys()):
      options = map(lambda x: x[1], field.getOptions())
      values = field.getValues()

      if field.getType() in ('list-single', 'list-multi'):
        assert len(options) >= len(values), 'field %s is a %s, and should contains <option/>s rather than <value/>s'
      else:
        assert len(options) == 0, "field %s is a %s, so it shouldn't contain any <option>s" % (repr(name), repr(field.getType()))
        options = values

      if name in fixed:
        assert fixed[name] in options, 'Expected value %s in field %s; you sent %s' % (repr(fixed[name]), repr(name),  options)
        x.addChild(node=xmpp.DataField(name=name, value=fixed[name]))
      elif name == 'FORM_TYPE':
        if field.getValue() != 'urn:xmpp:ssn':
          self.error('''I was expecting an 'urn:xmpp:ssn' FORM_TYPE, not '%s'.''' % field.getValue())
        x.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn'))
      elif name == 'accept':
        x.addChild(node=xmpp.DataField(name='accept', value='true'))
      elif name == 'logging':
        # we don't log anyways, just pick the preferred
        preferred = options[0]
        x.addChild(node=xmpp.DataField(name='logging', value=preferred))
      elif name == 'modp':
        # the offset of the group we chose (need it to match up with the dhhash)
        group_order = 0
        self.modp = int(options[group_order])
        x.addChild(node=xmpp.DataField(name='modp', value=self.modp))
        g = dh.generators[self.modp]
        p = dh.primes[self.modp]
      elif name == 'rekey_freq':
        preferred = int(options[0])
        x.addChild(node=xmpp.DataField(name='rekey_freq', value=preferred))
        self.rekey_freq = preferred
      elif name == 'my_nonce':
        self.n_o = base64.b64decode(field.getValue())
      elif name == 'dhhashes':
        pass
      else:
        pass # XXX we don't support this field

    self.He = base64.b64decode(request_form.getField('dhhashes').getValues()[group_order].encode("utf8"))

    n = 128 # number of bits
    bytes = int(n / 8)

    self.n_s = self.generate_nonce()

    self.c_o = self.decode_mpi(self.random_bytes(bytes)) # n-bit random number
    self.c_s = self.c_o ^ (2 ** (n-1))

    self.y = self.srand(2 ** (2 * n - 1), p - 1)
    self.d = self.powmod(g, self.y, p)

    self.send('''d = g ** y mod p
d: %s
g: %s
y: %s
p: %s''' % (repr(self.d), repr(g), repr(self.y), repr(p)))

    to_add = { 'my_nonce': self.n_s, 'dhkeys': self.encode_mpi(self.d), 'counter': self.encode_mpi(self.c_o), 'nonce': self.n_o }

    for name in to_add:
      b64ed = base64.b64encode(to_add[name])
      x.addChild(node=xmpp.DataField(name=name, value=b64ed))

    self.form_a = ''.join(map(lambda el: c14n.c14n(el), request_form.getChildren()))

    self.status = 'responded'
    
    self.form_b = ''.join(map(lambda el: c14n.c14n(el), x.getChildren()))

    feature.addChild(node=x)
    self.send(response, False)

  # 4.4 esession accept (alice)
  def alice_accepts(self, form):
    # 4.4.1 diffie-hellman preparation

    for field in ('FORM_TYPE', 'accept', 'logging', 'disclosure', 'security', 'crypt_algs', 'hash_algs', 'compress', 'stanzas', 'init_pubkey', 'resp_pubkey', 'ver', 'rekey_freq', 'sas_algs', 'my_nonce', 'dhkeys', 'nonce', 'counter'):
      assert field in form.asDict(), "your response form didn't have a %s field" % repr(field)

    # Verify that the ESession options selected by Bob are acceptable
    assert form.getType() == 'submit', 'x/@type was %s, should have been "submit"' % repr(form.getType())
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))
    assert form['accept'] in ('1', 'true'), "'accept' was %s, should have been '1' or 'true'" % repr(form['accept'])

    self.d = self.decode_mpi(base64.b64decode(form['dhkeys']))

    mod_p = int(form['modp'])
    p = dh.primes[mod_p]
    x = self.xes[mod_p]
    e = self.es[mod_p]

    # Return a <not-acceptable/> error
    assert self.d > 1, "the value you gave for 'd' wasn't greater than 1."
    assert self.d < (p - 1), "the value you gave for 'd' wasn't less than p - 1."
    
    self.form_b = ''.join(map(lambda el: c14n.c14n(el), form.getChildren()))

    accept = xmpp.Message()
    feature = accept.NT.feature
    feature.setNamespace(xmpp.NS_FEATURE)

    result = xmpp.DataForm(typ='result')

    self.c_s = self.decode_mpi(base64.b64decode(form['counter']))
    self.c_o = self.c_s ^ (2 ** (self.n - 1))

    self.n_o = base64.b64decode(form['my_nonce'])

    self.k = self.sha256(self.encode_mpi(self.powmod(self.d, x, p)))

    # 4.4.2 generating session keys
    self.kc_s, self.km_s, self.ks_s = self.generate_initiator_keys(self.k)
    
    # MUST securely destroy K unless it will be used later to generate the final shared secret
    result.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn'))
    result.addChild(node=xmpp.DataField(name='accept', value='1'))
    result.addChild(node=xmpp.DataField(name='nonce', value=base64.b64encode(self.n_o)))
    result.addChild(node=xmpp.DataField(name='dhkeys', value=base64.b64encode(self.encode_mpi(e))))

    # TODO: store and return rshashes, or at least randomly generate some
    result.addChild(node=xmpp.DataField(name='rshashes', value=[]))

    # 4.4.3 hiding alice's identity
    form_a2 = ''.join(map(lambda el: c14n.c14n(el), result.getChildren()))

    old_c_s = self.c_s

    mac_a = self.hmac(self.ks_s, self.n_o + self.n_s + self.encode_mpi(e) + self.form_a + form_a2)
    id_a = self.encrypt(mac_a)

    m_a = self.hmac(self.km_s, self.encode_mpi(old_c_s) + id_a)

    result.addChild(node=xmpp.DataField(name='identity', value=base64.b64encode(id_a)))
    result.addChild(node=xmpp.DataField(name='mac', value=base64.b64encode(m_a)))

    feature.addChild(node=result)
    self.send(accept, False)
    
    self.status = 'initiator-accepted'
 
  # 4.5 esession accept (bob)
  def bob_accepts(self, form):
    response = xmpp.Message()

    init = response.NT.init
    init.setNamespace('http://www.xmpp.org/extensions/xep-0116.html#ns-init')

    x = xmpp.DataForm(typ='result')

    for field in ('FORM_TYPE', 'accept', 'nonce', 'dhkeys', 'rshashes', 'identity', 'mac'):
      assert field in form.asDict(), "your acceptance form didn't have a %s field" % repr(field)

    assert form.getType() == 'result', 'x/@type was %s, should have been "result"' % repr(form.getType())
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))
    assert form['accept'] in ('1', 'true'), "'accept' was %s, should have been '1' or 'true'" % repr(form['accept'])

    # 4.5.1 generating provisory session keys
    e = self.decode_mpi(base64.b64decode(form['dhkeys']))
    p = dh.primes[self.modp]

    # return <feature-not-implemented/>
    assert self.sha256(self.encode_mpi(e)) == self.He, "your 'e' doesn't match the hash you sent previously (SHA256(%s) != %s)" % (repr(self.encode_mpi(e)), self.He)

    # return <feature-not-implemented/> 
    assert e > 1, "your 'e' should be bigger than 1."
    assert e < (p - 1), "your 'e' is bigger than than the prime 'p' we agreed upon."

    k = self.sha256(self.encode_mpi(self.powmod(e, self.y, p)))

    self.send('''k = e ** y mod p
k: %s 
e: %s
y: %s
p: %s''' % (repr(k), repr(e), repr(self.y), repr(p)))

    self.kc_o, self.km_o, self.ks_o = self.generate_initiator_keys(k)

    # 4.5.2 verifying alice's identity
    id_a = base64.b64decode(form['identity'])

    m_a = base64.b64decode(form['mac'])

    failed = False
    try:
      # return <feature-not-implemented/>
      self.assert_correct_hmac(self.km_o, self.encode_mpi(self.c_o) + id_a, 'm_a', m_a)
    except AssertionError, args:
      failed = True
      original_failure_args = args
    
    mac_a = self.decrypt(id_a)

    if failed:
      try:
        # return <feature-not-implemented/>
        self.assert_correct_hmac(self.km_o, self.encode_mpi(self.c_o) + id_a, 'm_a', m_a)
      except AssertionError:
        raise AssertionError, original_failure_args
      else:
        raise AssertionError, 'The HMAC for M_A failed because you calculated it using the current value of C_A, rather than the value before you encrypted ID_A.'

    form_a2_with_extras = ''.join(map(lambda el: c14n.c14n(el), form.getChildren()))

    macable_children = filter(lambda x: x.getVar() not in ('mac', 'identity'), form.getChildren())
    form_a2 = ''.join(map(lambda el: c14n.c14n(el), macable_children))

    try:
      # return <feature-not-implemented/>
      self.assert_correct_hmac(self.ks_o, self.n_s + self.n_o + self.encode_mpi(e) + self.form_a + form_a2, 'mac_a', mac_a)
    except AssertionError, args:
      try:
        self.assert_correct_hmac(self.ks_o, self.n_s + self.n_o + self.encode_mpi(e) + self.form_a + form_a2_with_extras, 'mac_a', mac_a)
      except AssertionError, args2:
        raise AssertionError, args
      else:
        raise AssertionError, 'The HMAC for mac_A failed because you included the <identity/> and <mac/> fields in the hashed content.'

    # TODO: 4.5.3

    # 4.5.4 generating bob's final session keys
    self.srs = ''
    oss = ''

    k = self.sha256(k + self.srs + oss)

    # XXX I can skip generating ks_o here
    self.kc_s, self.km_s, self.ks_s = self.generate_responder_keys(k)
    self.kc_o, self.km_o, self.ks_o = self.generate_initiator_keys(k)

    self.send('''final keys:

my KC: %s
my KM: %s

your KC: %s
your KM: %s''' % (repr(self.kc_s), repr(self.km_s), repr(self.kc_o), repr(self.km_o)))

    # 4.5.5
    if self.srs:
      srshash = self.hmac(self.srs, 'Shared Retained Secret')
    else:
      srshash = self.random_bytes(32)

    x.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn'))
    x.addChild(node=xmpp.DataField(name='nonce', value=base64.b64encode(self.n_o)))
    x.addChild(node=xmpp.DataField(name='srshash', value=base64.b64encode(srshash)))

    form_b2 = ''.join(map(lambda el: c14n.c14n(el), x.getChildren()))

    old_c_s = self.c_s
    mac_b = self.hmac(self.n_o + self.n_s + self.encode_mpi(self.d) + self.form_b + form_b2, self.ks_s)
    id_b = self.encrypt(mac_b)

    m_b = self.hmac(self.km_s, self.encode_mpi(old_c_s) + id_b)

    x.addChild(node=xmpp.DataField(name='identity', value=base64.b64encode(id_b)))
    x.addChild(node=xmpp.DataField(name='mac', value=base64.b64encode(m_b)))

    init.addChild(node=x)

    self.send(response, False)

    # destroy all copies of srs

    self.srs = self.hmac(k, 'New Retained Secret')

    # destroy k
    self.status = 'encrypted'
    self.enable_encryption = True

    self.send("Congratulations! If you can read this, we've successfully negotiated an encrypted session.")

  # 4.6 final steps (alice)
  def final_steps_alice(self, form):
    for field in ('FORM_TYPE', 'nonce', 'srshash', 'identity', 'mac'):
      assert field in form.asDict(), "your response form didn't have a %s field" % repr(field)

    assert form.getType() == 'result', 'x/@type was %s, should have been "result"' % repr(form.getType())
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))

    # 4.6.1 generating alice's final session keys
    # Alice MUST identify the shared retained secret (SRS) by selecting from her client's list of the secrets it retained from sessions with Bob's clients (the most recent secret for each of the clients he has used to negotiate ESessions with Alice's client).

    # Alice does this by using each secret in the list in turn as the key to calculate the HMAC (with SHA256) of the string "Shared Retained Secret", and comparing the calculated value with the value in the 'srshash' field she received from Bob (see Sending Bob's Identity). Once she finds a match, and has confirmed that the secret has not expired (because it is older than an implementation-defined period of time), then she has found the SRS.

    srs = ''
    oss = ''
    self.k = self.sha256(self.k + srs + oss)

    # Alice MUST destroy all her copies of the old retained secret (SRS) she was keeping for Bob's client, and calculate a new retained secret for this session:

    srs = self.hmac('New Retained Secret', self.k)

    # Alice MUST securely store the new value along with the retained secrets her client shares with Bob's other clients.

    # don't need to calculate ks_s here

    self.kc_s, self.km_s, self.ks_s = self.generate_initiator_keys(self.k)
    self.kc_o, self.km_o, self.ks_o = self.generate_responder_keys(self.k) 

    # 4.6.2 Verifying Bob's Identity

    id_b = base64.b64decode(form['identity'])

    m_b = self.hmac(self.encode_mpi(self.c_o) + id_b, self.km_o)

    mac_b = self.decrypt(id_b)

    form_b2 = ''.join(map(lambda el: c14n.c14n(el), form.getChildren()))

    mac_b = self.hmac(self.n_s + self.n_o + self.encode_mpi(self.d) + self.form_b + form_b2, self.ks_o)

    # Note: If Alice discovers an error then she SHOULD ignore any encrypted content she received in the stanza.
    # XXX check for MAC equality?

    self.status = 'encrypted'
    self.enable_encryption = True

    self.send("Congratulations! If you can read this, we've successfully negotiated an encrypted session.")

  def assert_correct_hmac(self, key, content, name, expected):
    calculated = self.hmac(key, content) # XXX stick the hash name in here

    assert calculated == expected, '''HMAC mismatch for the %s field.

key: %s
content: %s
expected: %s
calculated: %s'''  % (repr(name), repr(key), repr(content), repr(expected), repr(calculated))

  def show_help(self, msg):
    self.send('''this bot tests XEP-0217.

please attempt to initiate a XEP-0217 session with me.

'begin' will have me attempt to initiate a session with you.''')

  def handle_message(self, msg):
    c = msg.getTag(name='c', namespace='http://www.xmpp.org/extensions/xep-0200.html#ns')

    if c:
      was_encrypted = True
      try:
        self.decrypt_stanza(msg)
      except esession.DecryptionError, err:
        self.send('''you sent an encrypted message, but can't decrypt it: %s''' % err)
    else:
      was_encrypted = False

    if session.Session.handle_message(self, msg):
      return

    feature = msg.getTag(name='feature', namespace=xmpp.NS_FEATURE)
    init = msg.getTag(name='init', namespace='http://www.xmpp.org/extensions/xep-0116.html#ns-init')
    if feature:
      form = xmpp.DataForm(node=feature.getTag('x'))
      assert form['FORM_TYPE'] == 'urn:xmpp:ssn'

      try:
        if self.status == 'waiting':
          self.bob_responds(form)
        elif self.status == 'initiated':
          self.alice_accepts(form)
        elif self.status == 'responded':
          self.bob_accepts(form)
      except AssertionError, err:
        self.send('''failed to negotiate a session: %s''' % err)
    elif self.status == 'initiator-accepted' and init:
      form = xmpp.DataForm(node=init.getTag('x'))
      try:
        self.final_steps_alice(form)
      except AssertionError, err:
        self.send('''failed to complete the negotiation: %s''' % err)
    else:
      if was_encrypted:
        self.send('''received an encrypted message. 'help' for assistance.''')
      else:
        self.send('''received an unencrypted message. 'help' for assistance.''')
  
  handlers = { 'help': show_help,
               'begin': alice_initiates,
      }

