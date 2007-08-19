#!/usr/bin/python

import tests.xep116

class SimplifiedE2E(tests.xep116.EncryptedSessionNegotiation):
  def set_verbose(self, msg):
    tests.xep116.EncryptedSessionNegotiation.set_verbose(self, msg)

  def set_terse(self, msg):
    tests.xep116.EncryptedSessionNegotiation.set_terse(self, msg)

  # 4.1 esession request (alice)
  def alice_initiates(self, msg):
    options = { 'init_pubkey': 'none',
                'resp_pubkey': 'none',
                'rekey_freq': '4294967295',
                'crypt_algs': 'aes128-ctr',
                'hash_algs': 'sha256',
                'compress': 'none'
              }

    tests.xep116.EncryptedSessionNegotiation.alice_initiates(self, msg, options)

  # 4.3 esession response (bob)
  def bob_responds(self, form):
    if 'dhkeys' in form.asDict():
      err = xmpp.Error(xmpp.Message(), xmpp.ERR_NOT_IMPLEMENTED)

      feature = xmpp.Node(xmpp.NS_FEATURE + ' feature')
      field = xmpp.Node('field')
      field['var'] = 'dhkeys'

      feature.addChild(node=field)
      err.addChild(node=feature)

      self.send(err)

      self.send('''your tried to initiate a 3 message negotiation, which isn't part of XEP-0217. ending negotiation.''')
      return

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

    tests.xep116.EncryptedSessionNegotiation.bob_responds(self, form, fixed)

  def show_help(self, msg):
    msg = '''this bot tests XEP-0217 (Simplified Encrypted Session Negotiation).

if you attempt to initiate a XEP-0217 session with me, i will respond.

'begin': i'll attempt to initiate a session with you.

'''
    if self.verbose:
      msg += "'terse': give fewer details"
    else:
      msg += "'verbose': give more details"

    self.send(msg)
 
  handlers = { 'help': show_help,
               'begin': alice_initiates,
               'verbose': set_verbose,
               'terse': set_terse,
      }
