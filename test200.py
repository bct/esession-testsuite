#!/usr/bin/python

import xmpp
import session
import esession

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

class FancySession(esession.ESession):
  def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
    esession.ESession.__init__(self, dispatcher, conn, jid, thread_id, type = 'chat')
    
    self.n = 128   # number of bits
    bytes = self.n / 8

    self.cipher = AES
    self.hash_alg = SHA256

    self.de_key = '................'
    self.en_key = '----------------'

    self.de_counter = 777
    self.en_counter = 777 ^ (2 ** (self.n - 1))

    self.encrypter = self.cipher.new(self.en_key, self.cipher.MODE_CTR, counter=self.encryptcounter)
    self.decrypter = self.cipher.new(self.de_key, self.cipher.MODE_CTR, counter=self.decryptcounter)

    self.compression = None

  def do_help(self):
    self.send("""this bot tests your client's ability to exchange encrypted messages.

this is intended to be used before you've implemented XEPs 0217 or 0116, so values that are normally negotiated should be hardcoded.

inital values:

cipher: aes128-ctr
hash: sha256

your key: '................' (16 periods)
my key: '----------------' (16 dashes)

your counter: 777
my counter: 777 xor 2 ^ (128 - 1) (ie. 170141183460469231731687303715884106505)

send me an encrypted message to run the tests.""")

  def terminate(self):
    session.Session.terminate(self)
    self.proceed = self.terminated

  def terminated(self, msg):
    self.send('''!!! this session was terminated, you shouldn't send any more messages to it.''')

  def handle_message(self, msg):
    if self.status == 'run':
      self.proceed(msg)
      return

    body = msg.getBody()
    c = msg.getTag(name='c', namespace='http://www.xmpp.org/extensions/xep-0200.html#ns')

    if body == 'help':
      self.do_help()
    elif body:
      self.send('''your message was not encrypted. 'help' for more details.''')
    elif c:
      try:
        msg = self.decrypt_stanza(msg)
        self.enable_encryption = True

        self.send('''ok, i just successfully decrypted the message you sent. :) if you get this one, we should be gravy. ''')
      except esession.DecryptionError:
        self.send('''!!! I couldn't decrypt your message!

- is your counter set correctly? (should be: XXX)
- are you using the correct representation of your counter? (big-endian bitstring, padded with zeroes to 16 bytes)
- are you using the right key? (should be: XXX)''')
      except esession.BadSignature:
        self.send('''!!! I calculated a different <mac/> than the one you gave!

- is your counter set correctly?
- are you using the correct representation of your counter?
- are you using the right key?
- did you include all the contents of <c/>, except <mac/>, with whitespace removed?''')

session.SessionDispatcher("bot2@necronomicorp.com", "silenceotss", FancySession).run()
