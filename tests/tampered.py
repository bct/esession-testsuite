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
    self.mode = 'badma'
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

  def begin_badida(self, msg):
    self.mode = 'badida'
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

#  def alice_initiates(self, msg):
#    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

  def alice_accepts(self, form):
    tests.xep116.EncryptedSessionNegotiation.alice_accepts(self, form)
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
    self.expect_not_implemented = False

  def handle_message(self, msg):
    if self.expect_not_implemented:
      if msg.T.error and msg.T.error.getTag('feature-not-implemented'):
        self.send('good, you responded to the tampered message with a <feature-not-implemented/> error. terminating session.')

        self.terminate()

        return
      else:
        if self.expect_not_implemented == 'still':
          self.send('i am STILL expecting you to respond with a <feature-not-implemented/> error message, but you sent something else.')
        else:
          self.expect_not_implemented = 'still'
          self.send('i am expecting you to respond with a <feature-not-implemented/> error message, but you sent something else.')


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
    if self.mode == 'badida':
      return self.random_bytes(32)
    else:
      return tests.xep116.EncryptedSessionNegotiation.sign(self, string)

  def make_mac_s(self, form, dh_i, pubkey_s):
    if self.mode == 'badida':
      return self.random_bytes(32)
    else:
      return tests.xep116.EncryptedSessionNegotiation.make_mac_s(self, form, dh_i, pubkey_s)

  def make_identity(self, form, dh_i):
    id, mac = tests.xep116.EncryptedSessionNegotiation.make_identity(self, form, dh_i)

    if self.mode == 'badma':
      # XXX length varies based on the hash used for the hmac
      fake_m_s = self.random_bytes(32)
      return (id, xmpp.DataField(name='mac', value=base64.b64encode(fake_m_s)))
    else:
      return (id, mac)
