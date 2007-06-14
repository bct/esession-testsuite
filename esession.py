import session

import xmpp

import base64

from Crypto.Hash import HMAC

class DecryptionError(RuntimeError):
  pass

class BadSignature(RuntimeError):
  pass

class ESession(session.Session):
  def __init__(self, dispatcher, conn, jid, thread_id, type = 'chat'):
    session.Session.__init__(self, dispatcher, conn, jid, thread_id, type = 'chat')

    self.enable_encryption = False

  def send(self, msg, add_type = True):
    if isinstance(msg, str) or isinstance(msg, unicode):
      msg = xmpp.Message(body=msg)

    if self.enable_encryption:
      msg = self.encrypt_stanza(msg)
    
    session.Session.send(self, msg, add_type)

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
      return 256 * self.decode_mpi(s[:-1]) + ord(s[-1])

  def encryptcounter(self):
    self.en_counter = (self.en_counter + 1) % 2 ** self.n
    return self.encode_mpi_with_padding(self.en_counter)

  def decryptcounter(self):
    self.de_counter = (self.de_counter + 1) % 2 ** self.n
    return self.encode_mpi_with_padding(self.de_counter)

  def encrypt_stanza(self, stanza):
    encryptable = filter(lambda x: x.getName() not in ('error', 'amp', 'thread'), stanza.getChildren())

    # XXX can also encrypt contents of <error/> elements in stanzas @type = 'error'
    # (except for <defined-condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/> child elements)

    old_en_counter = self.en_counter

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
    c = stanza.getTag(name='c', namespace='http://www.xmpp.org/extensions/xep-0200.html#ns')

    stanza.delChild(c)

    # contents of <c>, minus <mac>, minus whitespace
    macable = ''.join(map(str, filter(lambda x: x.getName() != 'mac', c.getChildren())))

    received_mac = base64.b64decode(c.getTagData('mac'))
    calculated_mac = self.hmac(macable, self.de_counter, self.de_key)

    if not calculated_mac == received_mac:
      raise BadSignature #, received_mac, calculated_mac

    m_final = base64.b64decode(c.getTagData('data'))
    m_compressed = self.decrypt(m_final)
    plaintext = self.decompress(m_compressed)

    try:
      parsed = xmpp.Node(node='<node>' + plaintext + '</node>')
    except:
      raise DecryptionError

    for child in parsed.getChildren():
      stanza.addChild(node=child)

    return stanza

  def decrypt(self, ciphertext):
    return self.decrypter.decrypt(ciphertext)
