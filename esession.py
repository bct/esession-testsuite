import session

import xmpp

import base64

import os
import math

from Crypto.Cipher import AES 
from Crypto.Hash import HMAC, SHA256

class DecryptionError(RuntimeError):
  pass

class BadSignature(RuntimeError):
  pass

class ESession(session.Session):
  def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
    session.Session.__init__(self, dispatcher, conn, jid, thread_id, type = 'chat')

    self.n = 128

    self.cipher = AES
    self.hash_alg = SHA256

    self.compression = None

    self.enable_encryption = False

    self._kc_o = None
    self._kc_s = None

  def set_kc_s(self, kc_s):
    self._kc_s = kc_s
    self.encrypter = self.cipher.new(self._kc_s, self.cipher.MODE_CTR, counter=self.encryptcounter)

  def get_kc_s(self):
    return self._kc_s

  def set_kc_o(self, kc_o):
    self._kc_o = kc_o
    self.decrypter = self.cipher.new(self._kc_o, self.cipher.MODE_CTR, counter=self.decryptcounter)
  
  def get_kc_o(self):
    return self._kc_o

  kc_s = property(get_kc_s, set_kc_s)
  kc_o = property(get_kc_o, set_kc_o)

  # add encryption to a message
  def send(self, msg, add_type = True):
    if isinstance(msg, str) or isinstance(msg, unicode):
      msg = xmpp.Message(body=msg)

    if self.enable_encryption:
      msg = self.encrypt_stanza(msg)
    
    session.Session.send(self, msg, add_type)

  # convert a large integer to a big-endian bitstring
  def encode_mpi(self, n):
    if n >= 256:
      return self.encode_mpi(n / 256) + chr(n % 256)
    else:
      return chr(n)

  # convert a large integer to a big-endian bitstring, padded with \x00s to 16 bytes
  def encode_mpi_with_padding(self, n):
    ret = self.encode_mpi(n)

    mod = len(ret) % 16
    if mod != 0:
      ret = ((16 - mod) * '\x00') + ret

    return ret

  # convert a big-endian bitstring to an integer
  def decode_mpi(self, s):
    if len(s) == 0:
      return 0
    else:
      return 256 * self.decode_mpi(s[:-1]) + ord(s[-1])

  def encryptcounter(self):
    self.c_s = (self.c_s + 1) % (2 ** self.n)
    return self.encode_mpi_with_padding(self.c_s)

  def decryptcounter(self):
    self.c_o = (self.c_o + 1) % (2 ** self.n)
    return self.encode_mpi_with_padding(self.c_o)

  def encrypt_stanza(self, stanza):
    encryptable = filter(lambda x: x.getName() not in ('error', 'amp', 'thread'), stanza.getChildren())

    # XXX can also encrypt contents of <error/> elements in stanzas @type = 'error'
    # (except for <defined-condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/> child elements)

    old_en_counter = self.c_s

    for element in encryptable:
      stanza.delChild(element)

    plaintext = ''.join(map(str, encryptable))

    compressed = self.compress(plaintext)
    m_final = self.encrypt(compressed)

    c = stanza.NT.c
    c.setNamespace('http://www.xmpp.org/extensions/xep-0200.html#ns')
    c.NT.data = base64.b64encode(m_final)

    # XXX check for rekey, handle <key/> elements

    m_content = ''.join(map(str, c.getChildren()))
    mac = self.hmac(self.km_s, m_content + self.encode_mpi_with_padding(old_en_counter))

    c.NT.mac = base64.b64encode(mac)

    return stanza

  def decrypt_stanza(self, stanza):
    c = stanza.getTag(name='c', namespace='http://www.xmpp.org/extensions/xep-0200.html#ns')

    stanza.delChild(c)

    # contents of <c>, minus <mac>, minus whitespace
    macable = ''.join(map(str, filter(lambda x: x.getName() != 'mac', c.getChildren())))

    received_mac = base64.b64decode(c.getTagData('mac'))
    calculated_mac = self.hmac(self.km_o, macable + self.encode_mpi_with_padding(self.c_o))

    if not calculated_mac == received_mac:
      raise BadSignature #, received_mac, calculated_mac

    if not (self.km_o and self.kc_o and self.c_o):
      raise DecryptionError, "encryption keys aren't set yet!"

    m_final = base64.b64decode(c.getTagData('data'))
    m_compressed = self.decrypt(m_final)
    plaintext = self.decompress(m_compressed)

    try:
      parsed = xmpp.Node(node='<node>' + plaintext + '</node>')
    except:
      raise DecryptionError, "decrypted message wasn't parseable as XML."

    for child in parsed.getChildren():
      stanza.addChild(node=child)

    return stanza

  def hmac(self, key, content):
    return HMAC.new(key, content, self.hash_alg).digest()

  # i think i need this to be more generic to implement other hashes
  def sha256(self, string):
    sh = SHA256.new()
    sh.update(string)
    return sh.digest()

  def generate_initiator_keys(self, k):
    return (self.hmac(k, 'Initiator Cipher Key'),
            self.hmac(k, 'Initiator MAC Key'),
            self.hmac(k, 'Initiator SIGMA Key')    )

  def generate_responder_keys(self, k):
    return (self.hmac(k, 'Responder Cipher Key'),
            self.hmac(k, 'Responder MAC Key'),
            self.hmac(k, 'Responder SIGMA Key')    )

  def compress(self, plaintext):
    if self.compression == None:
      return plaintext

  def decompress(self, compressed):
    if self.compression == None:
      return compressed 

  def encrypt(self, encryptable):
    # XXX spec says this shouldn't require padding, but this library requires it
    len_padding = 16 - (len(encryptable) % 16)
    if len_padding != 16:
      encryptable += len_padding * ' '

    return self.encrypter.encrypt(encryptable)
  
  # generate a random number between 'bottom' and 'top'
  def srand(self, bottom, top):
    # minimum number of bytes needed to represent that range
    bytes = int(math.ceil(math.log(top - bottom, 256)))

    # FIXME: use a real PRNG
    return self.decode_mpi(os.urandom(bytes)) % (top - bottom) + bottom

  def generate_nonce(self):
    return self.random_bytes(8)

  def random_bytes(self, bytes):
    return os.urandom(bytes)
  
  # a faster version of (base ** exp) % mod
  #   taken from <http://lists.danga.com/pipermail/yadis/2005-September/001445.html> 
  def powmod(self, base, exp, mod):
    square = base % mod
    result = 1

    while exp > 0:
      if exp & 1: # exponent is odd
        result = (result * square) % mod

      square = (square * square) % mod
      exp /= 2

    return result

  def decrypt(self, ciphertext):
    return self.decrypter.decrypt(ciphertext)