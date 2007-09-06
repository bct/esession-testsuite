#!/usr/bin/python

import unittest

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import xmpp
import base64

class Party:
  def encode_mpi(self, n):
    if n >= 256:
      return self.encode_mpi(n / 256) + chr(n % 256)
    else:
      return chr(n)

  def encode_mpi_with_padding(self, n):
    ret = self.encode_mpi(n)

    mod = len(ret) % 16
    if mod != 0:
      ret = ((16 - mod) * '\x00') + ret

    return ret

  def decode_mpi(self, s):
    if len(s) == 0:
      return 0
    else:
      return 256 * self.decode_mpi(n[:-1]) + ord(n[-1])

  def __init__(self, en_key, de_key, en_counter, de_counter):
    self.n = 128   # number of bits
    bytes = self.n / 8

    if not len(en_key) == bytes and len(de_key) == bytes:
      raise 'wrong key length'

    self.en_key = en_key 
    self.de_key = de_key

    self.en_counter = en_counter
    self.de_counter = de_counter

    self.cipher = AES
    self.hash_alg = SHA256

    self.encrypter = self.cipher.new(self.en_key, self.cipher.MODE_CTR, counter=self.encryptcounter)
    self.decrypter = self.cipher.new(self.de_key, self.cipher.MODE_CTR, counter=self.decryptcounter)

    self.compression = None

  def encryptcounter(self):
    self.en_counter = (self.en_counter + 1) % 2 ** self.n

    # XXX correct representation of the counter?
    return self.encode_mpi_with_padding(self.en_counter)

  def decryptcounter(self):
    self.de_counter = (self.de_counter + 1) % 2 ** self.n

    return self.encode_mpi_with_padding(self.de_counter)

  def encrypt_stanza(self, stanza):
    # all children except <error/>, <amp/>, <thread>, XXX
    #  <defined-condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/> child elements of <error/> elements.
    encryptable = filter(lambda x: x.getName() not in ('error', 'amp', 'thread'), stanza.getChildren())

    old_en_counter = self.en_counter

    for element in encryptable:
      stanza.delChild(element)

    plaintext = ''.join(map(str, encryptable))

    compressed = self.compress(plaintext)
    m_final = self.encrypt(compressed)

    c = stanza.NT.c
    c.setNamespace('http://www.xmpp.org/extensions/xep-0200.html#ns')
    c.NT.data = base64.b64encode(m_final)

    # XXX <key/> elements ?

    m_content = str(c.getTag('data'))
    c.NT.mac = base64.b64encode(self.hmac(m_content, old_en_counter, self.en_key))

    return stanza

  def hmac(self, content, counter, key):
    return HMAC.new(key, content + self.encode_mpi_with_padding(counter), self.hash_alg).digest()

  def compress(self, plaintext):
    if self.compression == None:
      return plaintext

  def decompress(self, compressed):
    if self.compression == None:
      return compressed 

  def encrypt(self, encryptable):
    # XXX spec says this shouldn't require padding, but this library requires it
    len_padding = 16 - (len(encryptable) % 16)
    encryptable += len_padding * ' '

    return self.encrypter.encrypt(encryptable)

  def decrypt_stanza(self, stanza):
    c = stanza.T.c
    # XXX check namespace

    stanza.delChild(c)

    # contents of <c>, minus <mac>, minus whitespace
    macable = ''.join(map(str, filter(lambda x: x.getName() != 'mac', c.getChildren())))

    received_mac = base64.b64decode(c.getTagData('mac'))
    calculated_mac = self.hmac(macable, self.de_counter, self.de_key)

    if not calculated_mac == received_mac:
      raise 'bad signature (%s != %s)' % (repr(received_mac), repr(calculated_mac))

    m_final = base64.b64decode(c.getTagData('data'))
    m_compressed = self.decrypt(m_final)
    plaintext = self.decompress(m_compressed)

    try:
      parsed = xmpp.Node(node='<node>' + plaintext + '</node>')
    except:
      raise '''looks like i couldn't decrypt your <data/>'''

    for child in parsed.getChildren():
      stanza.addChild(node=child)

    return stanza

  def decrypt(self, ciphertext):
    return self.decrypter.decrypt(ciphertext)

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
