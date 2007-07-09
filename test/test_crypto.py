#!/usr/bin/python

import unittest

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import xmpp
import base64

import sys

sys.path.append('..')

from esession import *

class DecryptionError(RuntimeError):
  pass

class Party(ESession):
  def __init__(self, en_key, de_key, en_counter, de_counter):
    ESession.__init__(self, None, None, None, None, None)

    bytes = self.n / 8

    if not len(en_key) == bytes and len(de_key) == bytes:
      raise 'wrong key length'

    self.kc_s = en_key
    self.kc_o = de_key

    self.c_s = en_counter
    self.c_o = de_counter

class TestCanonicalization(unittest.TestCase):
  def test_encrypt_decrypt(self):
    key = '0123456789abcdef'
    counter = 0

    alice = Party(key, key, counter, counter)

    self.assertEqual('hello', alice.decrypt(alice.encrypt('hello')).strip())

  def test_encrypt_decrypt_stanza(self):
    pass

  def test_two_parties(self):
    a_key = '0123456789abcdef'
    b_key = 'fedcba9876543210'

    a_counter = 234 # some 128-bit value
    b_counter = a_counter ^ 2 ** (128 - 1)

    alice = Party(a_key, b_key, a_counter, b_counter)
    bob =   Party(b_key, a_key, b_counter, a_counter)

    msg = xmpp.Message(node='''<message from='alice@example.org/pda'
         to='bob@example.com/laptop'
         type='chat'>
  <thread>ffd7076498744578d10edabfe7f4a866</thread>
  <body>Hello, Bob!</body>
  <amp xmlns='http://jabber.org/protocol/amp'>
    <rule action='error' condition='match-resource' value='exact'/>
  </amp>
  <active xmlns='http://jabber.org/protocol/chatstates'/>
</message>''')

    alice.km_s = a_key
    alice.km_o = b_key

    bob.km_s = b_key
    bob.km_o = a_key

    encrypted = alice.encrypt_stanza(msg)

    self.assert_(isinstance(encrypted, xmpp.Message))
    self.assertEqual('ffd7076498744578d10edabfe7f4a866', encrypted.getThread())
    self.assert_(isinstance(encrypted.getTag('amp'), xmpp.Node)) 

    self.assertEqual(None, encrypted.getTag('body'))
    self.assertEqual(None, encrypted.getTag('active'))

    c = encrypted.getTag('c')
    self.assertEqual('http://www.xmpp.org/extensions/xep-0200.html#ns', c.getNamespace())
    self.assert_(isinstance(c.getTag('data'), xmpp.Node))
    self.assert_(isinstance(c.getTag('mac'), xmpp.Node))

    restored = bob.decrypt_stanza(msg)

    self.assertEqual('Hello, Bob!', restored.getBody())
    self.assertEqual(None, restored.getTag('c'))
    self.assert_(isinstance(encrypted.getTag('amp'), xmpp.Node)) 
    self.assert_(isinstance(encrypted.getTag('active'), xmpp.Node)) 

    msg = xmpp.Message(node='''<message to='alice@example.org/pda'
         from='bob@example.com/laptop'
         type='chat'>
  <thread>ffd7076498744578d10edabfe7f4a866</thread>
  <body>Hello, Alice!</body>
</message>''')

    self.assertEqual('Hello, Alice!', alice.decrypt_stanza(bob.encrypt_stanza(msg)).getBody())

if __name__ == '__main__':
	unittest.main()
