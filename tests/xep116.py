#!/usr/bin/python

import session
import esession

import dh

import xmpp

import c14n

import base64

from Crypto.PublicKey import RSA

XmlDsig = 'http://www.w3.org/2000/09/xmldsig#'

class EncryptedSessionNegotiation(esession.ESession):
  def __init__(self, **args):
    esession.ESession.__init__(self, **args)

    self.xes = {}
    self.es = {}

    self.status = 'waiting'

    self.verbose = False

    self.my_pubkey = self.dispatcher.pubkey

  def set_verbose(self, msg):
    if not self.verbose:
      self.verbose = True
      self.send('''ok, being verbose.''')
    else:
      self.send('''already verbose!''')

  def set_terse(self, msg):
    if self.verbose:
      self.verbose = False
      self.send('''ok, being terse.''')
    else:
      self.send('''already terse!''')

  # 4.1 esession request (alice)
  def alice_initiates(self, msg, extra_options={}):
    request = xmpp.Message()
    feature = request.NT.feature
    feature.setNamespace(xmpp.NS_FEATURE)

    x = xmpp.DataForm(typ='form')

    required = [ 'accept', 'logging', 'disclosure', 'security' ]

    options = { 'FORM_TYPE': 'urn:xmpp:ssn',
                'accept': '1',
    # this field is incorrectly called 'otr' in XEPs 0116 and 0217
    # unsupported options: 'mustnot'
                'logging': ['may'],
    # unsupported options: 'disabled', 'enabled'
                'disclosure': ['never'],
                'security': ['e2e'],
                'crypt_algs': 'aes128-ctr',
                'hash_algs': 'sha256',
                'compress': 'none',
                'sign_algs': XmlDsig + 'rsa-sha256',
                'init_pubkey': ['none', 'key', 'hash'],
    # we don't store remote keys for now, so make them send it every time
                'resp_pubkey': ['none', 'key'],
                'ver': '1.0',
                'rekey_freq': '4294967295',
                'sas_algs': 'sas28x5'
              }

    options.update(extra_options)

    for name in options:
      value = options[name]
      if isinstance(value, list):
        node = xmpp.DataField(name=name, typ='list-single', options=value, required=(name in required))
      else:
        node = xmpp.DataField(name=name, typ='hidden', value=value, required=(name in required))

      x.addChild(node=node)

    # unsupported options: 'iq', 'presence'
    x.addChild(node=xmpp.DataField(name='stanzas', typ='list-multi', options=['message']))

    self.n_s = self.generate_nonce()

    x.addChild(node=xmpp.DataField(name='my_nonce', value=base64.b64encode(self.n_s), typ='hidden'))

    modp_options = [ 5, 14, 2, 1 ]

    x.addChild(node=xmpp.DataField(name='modp', typ='list-single', options=map(lambda x: [ None, x ], modp_options)))

    # XXX implement sigmai initiation
    self.sigmai = False
    x.addChild(node=self.make_dhfield(modp_options, self.sigmai))

    self.form_s = c14n.c7l_children(x)
    
    feature.addChild(node=x)

    self.status = 'initiated'

    self.send(request)

  # 4.3 esession response (bob)
  def bob_responds(self, request_form, extra_fixed = {}):
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
                    'ver': '1.0',
                'sas_algs': 'sas28x5' }

    fixed.update(extra_fixed)

    self.recv_pubkey = None
    self.send_pubkey = None

    for name, field in map(lambda name: (name, request_form.getField(name)), request_form.asDict().keys()):
      options = map(lambda x: x[1], field.getOptions())
      values = field.getValues()

      if field.getType() in ('list-single', 'list-multi'):
        assert len(options) >= len(values), 'field %s is a %s, and should contains <option/>s rather than <value/>s' % (name, field.getType())
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
        self.sigmai = False
      elif name == 'dhkeys':
        self.sigmai = True
      elif name == 'init_pubkey':
        if 'key' in options:
          self.recv_pubkey = 'key'
        elif not 'none' in options:
          raise 'unsupported init_pubkey'

        x.addChild(node=xmpp.DataField(name='init_pubkey', value=self.recv_pubkey))
      elif name == 'resp_pubkey':
        for o in ('key', 'hash'):
          if o in options:
            self.send_pubkey = o

        if not self.send_pubkey and not 'none' in options:
          raise 'unsupported resp_pubkey'

        x.addChild(node=xmpp.DataField(name='resp_pubkey', value=self.send_pubkey))
      elif name == 'sign_algs':
        if 'http://www.w3.org/2000/09/xmldsig#rsa-sha256' in options:
          self.sign_algs = 'http://www.w3.org/2000/09/xmldsig#rsa-sha256'
        else:
          raise 'unsupported sign_algs'

        x.addChild(node=xmpp.DataField(name='sign_algs', value=self.sign_algs))
      else:
        raise 'unsupported field %s' % repr(name)

    fields = self.init_bobs_cryptographic_values(g, p, self.n_o)

    for name in fields:
      b64ed = base64.b64encode(fields[name])
      x.addChild(node=xmpp.DataField(name=name, value=b64ed))
     
    self.form_o = ''.join(map(lambda el: c14n.c14n(el), request_form.getChildren()))

    self.form_s = ''.join(map(lambda el: c14n.c14n(el), x.getChildren()))

    if self.sigmai:
      bin = request_form.getField('dhkeys').getValues()[group_order].encode("utf8")
      self.e = self.decode_mpi(base64.b64decode(bin))
      k = self.get_shared_secret(self.e, self.y, p)

      self.kc_s, self.km_s, self.ks_s = self.generate_responder_keys(k)
      self.kc_o, self.km_o, self.ks_o = self.generate_initiator_keys(k)

      # K MUST be securely destroyed, unless it will be used later to generate the final shared secret

      for datafield in self.make_identity(x, self.d):
        x.addChild(node=datafield)

    else:
      self.He = base64.b64decode(request_form.getField('dhhashes').getValues()[group_order].encode("utf8"))

    feature.addChild(node=x)
    self.send(response)

    self.status = 'responded'
  
  def init_bobs_cryptographic_values(self, g, p, n_o):
    n = 128
    bytes = int(n / 8)

    self.n_s = self.generate_nonce()

    self.c_o = self.decode_mpi(self.random_bytes(bytes)) # n-bit random number
    self.c_s = self.c_o ^ (2 ** (n-1))

    self.y = self.srand(2 ** (2 * n - 1), p - 1)
    self.d = self.powmod(g, self.y, p)

    return { 'my_nonce': self.n_s,\
             'dhkeys': self.encode_mpi(self.d),\
             'counter': self.encode_mpi(self.c_o),\
             'nonce': n_o }

  # 4.4 esession accept (alice)
  def alice_accepts(self, form):
    for field in ('FORM_TYPE', 'accept', 'logging', 'disclosure', 'security', 'crypt_algs', 'hash_algs', 'compress', 'stanzas', 'init_pubkey', 'resp_pubkey', 'ver', 'rekey_freq', 'sas_algs', 'my_nonce', 'dhkeys', 'nonce', 'counter'):
      assert field in form.asDict(), "your response form didn't have a %s field" % repr(field)

    # 4.4.1 diffie-hellman preparation
    # Verify that the ESession options selected by Bob are acceptable
    assert form.getType() == 'submit', 'x/@type was %s, should have been "submit"' % repr(form.getType())
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))
    assert form['accept'] in ('1', 'true'), "'accept' was %s, should have been '1' or 'true'" % repr(form['accept'])

    self.send_pubkey = form['init_pubkey']
    self.recv_pubkey = form['resp_pubkey']

    if self.send_pubkey == 'none':
      self.send_pubkey = None

    if self.recv_pubkey == 'none':
      self.recv_pubkey = None

    self.d = self.decode_mpi(base64.b64decode(form['dhkeys']))

    mod_p = int(form['modp'])
    p = dh.primes[mod_p]
    x = self.xes[mod_p]
    e = self.es[mod_p]

    self.k = self.get_shared_secret(self.d, x, p)

    accept = xmpp.Message()
    feature = accept.NT.feature
    feature.setNamespace(xmpp.NS_FEATURE)

    result = xmpp.DataForm(typ='result')

    self.c_s = self.decode_mpi(base64.b64decode(form['counter']))
    self.c_o = self.c_s ^ (2 ** (self.n - 1))

    self.n_o = base64.b64decode(form['my_nonce'])

    # 4.4.2 generating session keys
    self.kc_s, self.km_s, self.ks_s = self.generate_initiator_keys(self.k)

    if self.sigmai:
      self.kc_o, self.km_o, self.ks_o = self.generate_responder_keys(self.k)
      self.verify_identity(form, self.d, True, 'b')
    else:
      secrets = self.dispatcher.list_secrets(self.my_jid, self.eir_jid)
      rshashes = [self.hmac(self.n_s, rs) for rs in secrets]

      # XXX add random fake rshashes
      rshashes.sort()

      rshashes = [base64.b64encode(rshash) for rshash in rshashes]
      result.addChild(node=xmpp.DataField(name='rshashes', value=rshashes))
      result.addChild(node=xmpp.DataField(name='dhkeys', value=base64.b64encode(self.encode_mpi(e))))
    
      self.form_o = ''.join(map(lambda el: c14n.c14n(el), form.getChildren()))

    # MUST securely destroy K unless it will be used later to generate the final shared secret
    result.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn'))
    result.addChild(node=xmpp.DataField(name='accept', value='1'))
    result.addChild(node=xmpp.DataField(name='nonce', value=base64.b64encode(self.n_o)))

    # 4.4.3 hiding alice's identity
    for datafield in self.make_identity(result, e):
      result.addChild(node=datafield)

    feature.addChild(node=result)
    self.send(accept)

    self.status = 'initiator-accepted'

  # 4.5 esession accept (bob)
  def bob_accepts(self, form):
    response = xmpp.Message()

    init = response.NT.init
    init.setNamespace('http://www.xmpp.org/extensions/xep-0116.html#ns-init')

    x = xmpp.DataForm(typ='result')

    for field in ('FORM_TYPE', 'accept', 'nonce', 'identity', 'mac'):
      assert field in form.asDict(), "your acceptance form didn't have a %s field" % repr(field)

    assert form.getType() == 'result', 'x/@type was %s, should have been "result"' % repr(form.getType())
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))
    assert form['accept'] in ('1', 'true'), "'accept' was %s, should have been '1' or 'true'" % repr(form['accept'])

    if self.sigmai:
      self.verify_identity(form, self.e, True, 'a')

      self.status = 'encrypted'
      self.enable_encryption = True

      self.send("Congratulations! If you can read this, we've successfully negotiated a 3-message encrypted session.")

      return

    for field in ('dhkeys', 'rshashes'):
      assert field in form.asDict(), "your acceptance form didn't have a %s field and this is not a 3 message negotiation" % repr(field)

    # 4.5.1 generating provisory session keys
    e = self.decode_mpi(base64.b64decode(form['dhkeys']))
    p = dh.primes[self.modp]

    # return <feature-not-implemented/>
    assert self.sha256(self.encode_mpi(e)) == self.He, "your 'e' doesn't match the hash you sent previously (SHA256(%s) != %s)" % (repr(self.encode_mpi(e)), self.He)

    k = self.get_shared_secret(e, self.y, p)

    self.kc_o, self.km_o, self.ks_o = self.generate_initiator_keys(k)

    self.verify_identity(form, e, False, 'a')

    # TODO: 4.5.3

    # 4.5.4 generating bob's final session keys
    srs = ''

    secrets = self.dispatcher.list_secrets(self.my_jid, self.eir_jid)
    terminated = self.dispatcher.srs['terminated']

    rshashes = [base64.b64decode(rshash) for rshash in form.getField('rshashes').getValues()]

    if not rshashes:
      self.send('''! even if we've never spoken before, you should throw some random values into the rshashes field.''')

    for secret in terminated:
      if self.hmac(self.n_o, secret) in rshashes:
        self.send('''! you offered secret %s that should have been destroyed''' % repr(secret))

    for secret in secrets:
      if self.hmac(self.n_o, secret) in rshashes:
        srs = secret
        break

    oss = ''

    k = self.hash(k + srs + oss)

    if self.verbose:
      self.send('''k = %s''' % repr(k))

    # XXX I can skip generating ks_o here
    self.kc_s, self.km_s, self.ks_s = self.generate_responder_keys(k)
    self.kc_o, self.km_o, self.ks_o = self.generate_initiator_keys(k)

    if self.verbose:
      self.send('''chosen SRS = %s''' % repr(srs))

    # 4.5.5
    if srs:
      srshash = self.hmac(srs, 'Shared Retained Secret')
    else:
      srshash = self.random_bytes(32)

    x.addChild(node=xmpp.DataField(name='FORM_TYPE', value='urn:xmpp:ssn'))
    x.addChild(node=xmpp.DataField(name='nonce', value=base64.b64encode(self.n_o)))
    x.addChild(node=xmpp.DataField(name='srshash', value=base64.b64encode(srshash)))

    for datafield in self.make_identity(x, self.d):
      x.addChild(node=datafield)

    init.addChild(node=x)

    self.send(response)

    self.do_srs(k, srs)

    # destroy k
    self.status = 'encrypted'
    self.enable_encryption = True

    self.send("if you can read this, then we've successfully negotiated a 4-message encrypted session.")

  # 4.6 final steps (alice)
  def final_steps_alice(self, form):
    for field in ('FORM_TYPE', 'nonce', 'srshash', 'identity', 'mac'):
      assert field in form.asDict(), "your response form didn't have a %s field" % repr(field)

    assert form.getType() == 'result', 'x/@type was %s, should have been "result"' % repr(form.getType())
    assert form['FORM_TYPE'] == 'urn:xmpp:ssn', 'FORM_TYPE was %s, should have been %s' % (repr(form['FORM_TYPE'], repr('urn:xmpp:ssn')))

    # 4.6.1 generating alice's final session keys
    srs = ''

    secrets = self.dispatcher.list_secrets(self.my_jid, self.eir_jid)
    srshash = base64.b64decode(form['srshash'])

    for secret in secrets:
      if self.hmac(secret, 'Shared Retained Secret') == srshash:
        srs = secret
        break

    oss = ''

    if self.verbose:
      self.send('''chosen SRS = %s''' % repr(srs))

    self.k = self.hash(self.k + srs + oss)

    if self.verbose:
      self.send('''k = %s''' % repr(self.k))

    # Alice MUST destroy all her copies of the old retained secret (SRS) she was keeping for Bob's client, and calculate a new retained secret for this session:

    self.do_srs(self.k, srs)

    # Alice MUST securely store the new value along with the retained secrets her client shares with Bob's other clients.

    # don't need to calculate ks_s here

    self.kc_s, self.km_s, self.ks_s = self.generate_initiator_keys(self.k)
    self.kc_o, self.km_o, self.ks_o = self.generate_responder_keys(self.k)

    # 4.6.2 Verifying Bob's Identity
    self.verify_identity(form, self.d, False, 'b')

    # Note: If Alice discovers an error then she SHOULD ignore any encrypted content she received in the stanza.

    self.status = 'encrypted'
    self.enable_encryption = True

    self.send("Congratulations! If you can read this, we've successfully negotiated an encrypted session.")

  def verify_identity(self, form, dh_i, sigmai, i_o):
    id_o = base64.b64decode(form['identity'])
    m_o = base64.b64decode(form['mac'])

    if i_o == 'a':
      self.send_sas(m_o, self.form_s)

    failed = False
    try:
      self.assert_correct_hmac(self.km_o, self.encode_mpi(self.c_o) + id_o, 'm_' + i_o, m_o)
    except AssertionError, args:
      failed = True
      original_failure_args = args

    plaintext = self.decrypt(id_o)

    if failed:
      try:
        self.assert_correct_hmac(self.km_o, self.encode_mpi(self.c_o) + id_o, 'm_' + i_o, m_o)
      except AssertionError:
        # it still failed, raise the original error
        raise AssertionError, original_failure_args
      else:
        raise AssertionError, 'The HMAC for m_%s failed because you calculated it using the current value of c_%s, rather than the value before you encrypted id_%s.' % (i_o, i_o, i_o)

    if self.recv_pubkey:
      try:
        parsed = xmpp.Node(node='<node>' + plaintext + '</node>')
      except:
        raise AssertionError, 'the following value of id_%s was not parseable as XML: %s' % (i_o, repr(plaintext))

      if self.recv_pubkey == 'hash':
        fingerprint = parsed.getTagData('fingerprint')

        # XXX find stored pubkey or terminate
        raise "unimplemented"
      else:
        if self.sign_algs == 'http://www.w3.org/2000/09/xmldsig#rsa-sha256':
          keyvalue = parsed.getTag(name='RSAKeyValue', namespace='http://www.w3.org/2000/09/xmldsig#')

          n, e = map(lambda x: self.decode_mpi(base64.b64decode(keyvalue.getTagData(x))), ('Modulus', 'Exponent'))
          eir_key = RSA.construct((n,long(e)))

          pubkey_o = c14n.c14n(keyvalue)
        else:
          # XXX DSA, etc.
          raise "unimplemented"

      enc_sig = parsed.getTag(name='SignatureValue', namespace='http://www.w3.org/2000/09/xmldsig#').getData()
      signature = (self.decode_mpi(base64.b64decode(enc_sig)),)

    else:
      mac_o = plaintext
      pubkey_o = ''

    c7l_form = self.c7lize_mac_id(form)

    content = self.n_s + self.n_o + self.encode_mpi(dh_i) + pubkey_o
  
    if not sigmai:
      content += self.form_o

    content += c7l_form

    if self.recv_pubkey:
      mac_o_calculated = self.hmac(self.ks_o, content)

      if self.sign_algs == 'http://www.w3.org/2000/09/xmldsig#rsa-sha256':
        hash = self.sha256(mac_o_calculated)

      assert eir_key.verify(hash, signature), 'signature could not be verified!\nhashed: %s' % repr(content)
    else:
      self.assert_correct_hmac(self.ks_o, content, 'mac_' + i_o, mac_o)

  def make_mac_s(self, form, dh_i, pubkey_s):
    c7lform = ''.join(map(lambda el: c14n.c14n(el), form.getChildren()))
    content = self.n_o + self.n_s + self.encode_mpi(dh_i) + pubkey_s

    if form.getType() == 'result':
      content += self.form_s + c7lform
    else:
      content += c7lform

    return self.hmac(self.ks_s, content)

  def make_identity(self, form, dh_i):
    if self.send_pubkey:
      if self.sign_algs == 'http://www.w3.org/2000/09/xmldsig#rsa-sha256':
        fields = (self.my_pubkey.n, self.my_pubkey.e)
        cb_fields = map(lambda f: base64.b64encode(self.encode_mpi(f)), fields)

        pubkey_s = '<RSAKeyValue xmlns="http://www.w3.org/2000/09/xmldsig#"><Modulus>%s</Modulus><Exponent>%s</Exponent></RSAKeyValue>' % tuple(cb_fields)
    else:
      pubkey_s = ''

    mac_s = self.make_mac_s(form, dh_i, pubkey_s)
    
    old_c_s = self.c_s

    if self.send_pubkey:
      signature = self.sign(mac_s)
      sign_s = '<SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">%s</SignatureValue>' % base64.b64encode(signature)

      if self.send_pubkey == 'hash':
        b64ed = base64.b64encode(self.hash(pubkey_s))
        pubkey_s = '<fingerprint>%s</fingerprint>' % b64ed

      id_s = self.encrypt(pubkey_s + sign_s)
    else:
      id_s = self.encrypt(mac_s)

    m_s = self.hmac(self.km_s, self.encode_mpi(old_c_s) + id_s)

    if self.status == 'initiated':
      self.send_sas(m_s, self.form_o)

    return (xmpp.DataField(name="identity", value=base64.b64encode(id_s)), \
            xmpp.DataField(name="mac", value=base64.b64encode(m_s)))

  def assert_correct_hmac(self, key, content, name, expected):
    calculated = self.hmac(key, content)

    # XXX <feature-not-implemented>
    assert calculated == expected, '''HMAC mismatch for the %s field.

HMAC key: %s

content: %s

expected: %s

calculated: %s'''  % (repr(name), repr(key), repr(content), repr(expected), repr(calculated))

  def send_sas(self, m_a, form_b):
    self.send('''calculated SAS: %s''' % self.sas_28x5(m_a, form_b))

  def do_srs(self, k, old_srs):
    new_srs = self.hmac(k, 'New Retained Secret')

    if self.verbose:
      self.send('''new SRS = %s''' % repr(new_srs))

    if old_srs:
      self.dispatcher.replace_secret(self.my_jid, self.eir_jid, old_srs, new_srs)
    else:
      self.dispatcher.save_new_secret(self.my_jid, self.eir_jid, new_srs)

  def get_shared_secret(self, e, y, p):
    if self.status == 'initiated':
      name = 'd'
    else:
      name = 'e'

    # return <feature-not-implemented/>
    assert e > 1, ("your '%s' should be bigger than 1." % name)
    assert e < (p - 1), ("your '%s' is bigger than p - 1." % name)

    k = self.hash(self.encode_mpi(self.powmod(e, y, p)))

    if self.verbose:
      self.send('''k = %s''' % repr(k))

    return k

  def terminate(self):
    self.status = 'terminated'

  def handle_message(self, msg):
    if not msg.T.thread:
      self.send('''your message did not contain a thread id, ignoring it''')
      return

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
        if form.getType() == 'form' and self.status == 'waiting':
          self.bob_responds(form)
        elif self.status == 'initiated':
          if msg.T.error and msg.T.error.feature:
            not_acceptable = map(lambda x: x['var'], msg.T.error.T.feature.getChildren())

            res = '''ending negotiation because your client said I didn't offer acceptable values for these fields:

'''
            for f in not_acceptable:
              res += '- ' + f

            self.send(res)
            self.terminate()
            return

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
