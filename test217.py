#!/usr/bin/python

import session
import esession

import dh

import xmpp

import c14n

import base64

class FancySession(esession.ESession):
  def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
    esession.ESession.__init__(self, dispatcher, conn, jid, thread_id, type = 'chat')

    self.status = 'waiting'
    self.state = {}

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
        self.state['rekey_freq'] = preferred
      elif name == 'my_nonce':
        self.n_o = base64.b64decode(field.getValue())
        pass
      elif name == 'dhhashes':
        pass
      else:
        pass # XXX we don't support this field

    self.state['He'] = request_form.getField('dhhashes').getValues()[group_order]

    n = 128 # number of bits
    bytes = int(n / 8)

    self.c_o = self.decode_mpi(self.random_bytes(bytes)) # n-bit random number
    self.c_s = self.c_o ^ (2 ** (n-1))

    self.y = self.srand(2 ** (2 * n - 1), p -1)

    self.n_s = self.random_bytes(8)

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

  def bob_accepts(self, form):
    response = xmpp.Message()

    init = response.NT.init
    init.setNamespace('http://www.xmpp.org/extensions/xep-0116.html#ns-init')

    x = xmpp.DataForm(typ='result')

    assert form.getType() == 'result', 'x/@type was %s, should have been %s' % (repr(form.getType()), repr(form.getType()))
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))
    assert form['accept'] in ('1', 'true'), "'accept' was %s, should have been '1' or 'true'" % repr(form['accept'])

    for field in ('nonce', 'dhkeys', 'rshashes', 'identity', 'mac'):
      assert field in form.asDict(), "your acceptance form doesn't have a %s field" % repr(field)

    e = self.decode_mpi(base64.b64decode(form['dhkeys']))
    p = dh.primes[self.modp]


    # return <feature-not-implemented/> unless SHA256(e) = self.state["He"]
    # return <feature-not-implemented/> unless 1 < e < p - 1

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

    # 4.5.4
    # TODO: actually *retain* secrets
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

    self.send(response)

    # destroy all copies of srs

    self.srs = self.hmac(k, 'New Retained Secret')

    # destroy k

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

  def do_help(self):
    self.send('''this bot tests XEP-0217.

please attempt initiate a XEP-0217 session with me.''')

  def handle_message(self, msg):
    c = msg.getTag(name='c', namespace='http://www.xmpp.org/extensions/xep-0200.html#ns')

    if c:
      encrypted = True
      self.decrypt_stanza(msg)

    body = msg.getBody()

    if body and body.strip() == 'help':
      self.do_help()
      return

    feature = msg.getTag(name='feature', namespace=xmpp.NS_FEATURE)
    if feature:
      form = xmpp.DataForm(node=feature.getTag('x'))
      assert form['FORM_TYPE'] == 'urn:xmpp:ssn'

      try:
        if self.status == 'waiting':
          self.bob_responds(form)
        elif self.status == 'responded':
          self.bob_accepts(form)
      except AssertionError, err:
        self.send('''failure: %s''' % err)
    else:
      if encrypted:
        self.send('''received an encrypted message. 'help' for assistance.''')
      else:
        self.send('''received an unencrypted message. 'help' for assistance.''')

session.SessionDispatcher('bot2@necronomicorp.com', 'silenceotss', FancySession).run()
