import xmpp

import uuid
import sys
import time

class Session(object):
  def __init__(self, dispatcher, conn, my_jid, eir_jid, thread_id):
    self.dispatcher = dispatcher

    self.conn = conn

    self.my_jid = my_jid

    self.eir_jid = eir_jid

    self.status = 'new'

    if thread_id:
      self.received_thread_id = True
      self.thread_id = thread_id
    else:
      self.received_thread_id = False
      self.thread_id = self.generate_thread_id()

    self.last_send = 0

  def generate_thread_id(self):
    return 'urn:uuid:' + str(uuid.uuid1())

  def send(self, msg):
    if isinstance(msg, str) or isinstance(msg, unicode):
      msg = xmpp.Message(body=msg)

    if self.thread_id:
      msg.setThread(self.thread_id)

    msg.setAttr('from', self.my_jid)
    msg.setAttr('to', self.eir_jid)
    self.conn.send(msg)

    self.last_send = time.time()

  def handle_message(self, msg):
    pass

  def terminate(self):
    self.status = 'terminated'
    pass
