import tests.xep116

class ThreeMessageSession(tests.xep116.EncryptedSessionNegotiation):
  def show_help(self, msg):
    msg = '''this bot tests XEP-0116 Three Message (SIGMA-I) Negotiation.

if you attempt to initiate a XEP-0116 Three Message Negotation with me, i will respond.

'''

    if self.verbose:
      msg += "'terse': give fewer details"
    else:
      msg += "'verbose': give more details"

    self.send(msg)

  def alice_initiates(self, msg):
    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg)

  def set_verbose(self, msg):
    tests.xep116.EncryptedSessionNegotiation.set_verbose(self, msg)

  def set_terse(self, msg):
    tests.xep116.EncryptedSessionNegotiation.set_terse(self, msg)

  handlers = { 'help': show_help,
               'begin': alice_initiates,
               'verbose': set_verbose,
               'terse': set_terse,
      }
