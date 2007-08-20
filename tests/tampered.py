import tests.xep116

import xmpp
import dh
import base64

class TamperedIDSession(tests.xep116.EncryptedSessionNegotiation):
  def __init__(self, **args):
    tests.xep116.EncryptedSessionNegotiation.__init__(self, **args)

    self.mode = None
    self.expect_not_implemented = False

  def show_help(self, msg):
    msg = '''this bot tests a XEP-0116 implementation's response to a (4 message) negotiation that has been tampered with.

you can begin a session negotiation with me several times in succession to run different tests with you as the initiator.

commands:
'begin-badhe': i'll initiate an esession where SHA256(e) != He
'begin-bade': i'll initiate an esession with e > (p - 1) or e < 1
'begin-badma': i'll initiate an esession with a faulty m_a
'begin-badida': i'll initiate an esession with a faulty mac_a (or sign_a if we agree to use public keys in the negotiation)
'''

    if self.verbose:
      msg += "'terse': give fewer details"
    else:
      msg += "'verbose': give more details"

    self.send(msg)

  def begin_badhe(self, msg):
    self.mode = 'badhe'
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)
  
  def begin_bade(self, msg):
    self.mode = 'bade'
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)
  
  def begin_badma(self, msg):
    self.mode = 'badm'
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

  def begin_badida(self, msg):
    self.mode = 'badid'
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

#  def alice_initiates(self, msg):
#    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

  def bob_responds(self, form):
    if not self.mode:
      self.mode = 'badd'
      self.expect_not_implemented = True

    tests.xep116.EncryptedSessionNegotiation.bob_responds(self, form)

  def alice_accepts(self, form):
    tests.xep116.EncryptedSessionNegotiation.alice_accepts(self, form)
    self.expect_not_implemented = True

  def bob_accepts(self, form):
    tests.xep116.EncryptedSessionNegotiation.bob_accepts(self, form)

    if self.mode:
      self.send('!!! the negotiation should have failed, your client should not display this message.')
      self.expect_not_implemented = True

  def final_steps_alice(self, form):
    if self.expect_not_implemented:
      self.send('!!! you tried to continue the negotiation despite the evidence that my message had been tampered with!')
      self.terminate()
    else:
      tests.xep116.EncryptedSessionNegotiation.final_steps_alice(self, form)

  def set_verbose(self, msg):
    tests.xep116.EncryptedSessionNegotiation.set_verbose(self, msg)

  def set_terse(self, msg):
    tests.xep116.EncryptedSessionNegotiation.set_terse(self, msg)

  handlers = { 'help': show_help,
#               'begin': alice_initiates,
               'verbose': set_verbose,
               'terse': set_terse,
               'begin-badhe': begin_badhe,
               'begin-bade': begin_bade,
               'begin-badma': begin_badma,
               'begin-badida': begin_badida,
      }

  def terminate(self):
    self.mode = None
    self.status = 'waiting'
    self.enable_encryption = False
    self.expect_not_implemented = False

  def handle_message(self, msg):
    if self.expect_not_implemented:
      oldmode = self.mode

      self.terminate()

      if msg.T.error and msg.T.error.getTag('feature-not-implemented'):
        if oldmode == 'badd':
          self.send('good, you responded with a feature-not-implemented error to a message where d > (p - 1) or < -1.')
          self.send('you can begin another negotiation to run another test.')
          self.mode = 'badm'
        elif oldmode == 'badm':
          self.send('good, you responded with a feature-not-implemented error to a message with a tampered m_b.')
          self.send('you can begin another negotiation to run another test.')
          self.mode = 'badid'
        elif oldmode == 'badid':
          self.send('good, you responded with a feature-not-implemented error to a message with a tampered id_b.')
          self.send('''this is the end of the tests for Alice.
if you begin another negotiation I will return to the previous test.''')
          self.mode = None
        else:
          self.send('good, you responded to the tampered message with a feature-not-implemented error. negotiation ended.')

        return
      else:
        if self.expect_not_implemented == 'still':
          self.send('i am STILL expecting you to respond with a feature-not-implemented error message, but you sent something else.')
        else:
          self.expect_not_implemented = 'still'
          self.send('i am expecting you to respond with a feature-not-implemented error message, but you sent something else.')

    tests.xep116.EncryptedSessionNegotiation.handle_message(self, msg)

  # special modifications of existing functions

  def make_dhfield(self, modp_options, sigmai=False):
    dhs = []

    for modp in modp_options:
      p = dh.primes[modp]
      g = dh.generators[modp]

      x = self.srand(2 ** (2 * self.n - 1), p - 1)

      if self.mode == 'bade':
        e = p + 1
      else:
        e = self.powmod(g, x, p)

      self.xes[modp] = x
      self.es[modp] = e

      if sigmai:
        dhs.append(base64.b64encode(self.encode_mpi(e)))
        name = 'dhkeys'
      else:
        if self.mode == 'badhe':
          He = self.random_bytes(32)
        else:
          He = self.sha256(self.encode_mpi(e))

        dhs.append(base64.b64encode(He))
        name = 'dhhashes'

    return xmpp.DataField(name=name, typ='hidden', value=dhs)

  def sign(self, string):
    if self.mode == 'badid':
      return self.random_bytes(32)
    else:
      return tests.xep116.EncryptedSessionNegotiation.sign(self, string)

  def make_mac_s(self, form, dh_i, pubkey_s):
    if self.mode == 'badid':
      return self.random_bytes(32)
    else:
      return tests.xep116.EncryptedSessionNegotiation.make_mac_s(self, form, dh_i, pubkey_s)

  def make_identity(self, form, dh_i):
    id, mac = tests.xep116.EncryptedSessionNegotiation.make_identity(self, form, dh_i)

    if self.mode == 'badm':
      # XXX length varies based on the hash used for the hmac
      fake_m_s = self.random_bytes(32)
      return (id, xmpp.DataField(name='mac', value=base64.b64encode(fake_m_s)))
    else:
      return (id, mac)
  
  def init_bobs_cryptographic_values(self, g, p, n_o):
    fields = tests.xep116.EncryptedSessionNegotiation.init_bobs_cryptographic_values(self, g, p, n_o)
 
    if self.mode == 'badd':
      fields['dhkeys'] = self.encode_mpi(p + 1)

    return fields

