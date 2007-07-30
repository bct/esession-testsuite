#!/usr/bin/python

# usage: ./main.py <component-name> <server> <port> <secret>

#name = 'testsuite'
#server = 'mi-go'
#port = 5350

from xmpp import *

from tests import *

import sys

jids = { 'xep155': xep155.SessionNegotiation,
         'xep200': xep200.FancySession,
         'xep201': xep201.FancySession,
         'xep217': xep217.SimplifiedE2E, 
         'sigmai': sigmai.ThreeMessageSession 
                            }
class TestSuite:
  def __init__(self, name, server, port, secret, handlers):
    self.name = name
    self.server = server
    self.port = port
    self.secret = secret
    self.handlers = handlers

    self.conn = client.Component(name)

    self.sessions = {}
 
    # retained secret storage:

    # terminated: [terminated_secrets],
    # [my_jid]:
    #   [eir_jid]: [secrets]
    self.srs = { 'terminated': [] }

  def list_secrets(self, my_jid, eir_jid):
    try:
      return self.srs[my_jid][eir_jid]
    except KeyError:
      return []

  def replace_secret(self, my_jid, eir_jid, old_srs, new_srs):
    self.srs['terminated'].append(old_srs)
    pos = self.srs[my_jid][eir_jid].index(old_srs)
    self.srs[my_jid][eir_jid][pos] = new_srs

  def save_new_secret(self, my_jid, eir_jid, srs):
    if not my_jid in self.srs:
      self.srs[my_jid] = {}

    if not eir_jid in self.srs[my_jid]:
      self.srs[my_jid][eir_jid] = []

    self.srs[my_jid][eir_jid].append(srs)

  def xmpp_connect(self):
    self.conn.connect((self.server,self.port))

    self.conn.auth(self.name, self.secret)

    self.conn.RegisterHandler('message', self.messageCB)
    self.conn.RegisterHandler('presence', self.presenceCB)

   # for node in self.handlers:
   #     self.conn.send(Presence(frm=node + '@testsuite.necronomicorp.com')) # XXX
    
    while 1:
      self.conn.Process(1)

  def presenceCB(self, conn, event):
    fromjid = event.getFrom()
    type = event.getType()
    to = event.getTo()
    if type == 'subscribe':
      self.conn.send(Presence(to=fromjid, frm = to, typ = 'subscribe'))
    elif type == 'subscribed':
      self.conn.send(Presence(to=fromjid, frm = to, typ = 'subscribed'))
    elif type == 'unsubscribe':
      self.conn.send(Presence(to=fromjid, frm = to, typ = 'unsubscribe'))
    elif type == 'unsubscribed':
      self.conn.send(Presence(to=fromjid, frm = to, typ = 'unsubscribed'))
    elif type == 'probe':
      self.conn.send(Presence(to=fromjid, frm = to))
    elif type == 'unavailable':
      self.conn.send(Presence(to=fromjid, frm = to, typ = 'unavailable'))
    elif type == 'error':
      return
    else:
      self.conn.send(Presence(to=fromjid, frm = to))

  def messageCB(self, conn, msg):
    thread_id = msg.getThread()
    my_jid = str(msg.getTo())
    eir_jid = str(msg.getFrom())
    type = msg.getType()

    if not type:
      type = 'normal'

    try:
      if (type == 'chat' and not thread_id):
        sess = self.find_null_session(my_jid, eir_jid)
      else:
        sess = self.sessions[my_jid][eir_jid][thread_id]
    except KeyError:
      handler = self.handlers[my_jid.split('@')[0]]

      sess = self.start_new_session(my_jid, eir_jid, handler, thread_id)

    if thread_id and not sess.received_thread_id:
      sess.received_thread_id = True

    sess.handle_message(msg)

  def find_null_session(self, my_jid, eir_jid):
    all = self.sessions[my_jid][eir_jid].values()
    null_sessions = filter(lambda s: not s.received_thread_id, all)
    null_sessions.sort(self.sort_by_last_send)

    return null_sessions[-1]

  def sort_by_last_send(self, x, y):
    if x.last_send > y.last_send:
      return 1
    else:
      return -1

  def start_new_session(self, my_jid, eir_jid, klass, thread_id = None):
    sess = klass(dispatcher=self, conn=self.conn, my_jid=my_jid, eir_jid=eir_jid, thread_id=thread_id)
    thread_id = sess.thread_id

    if not my_jid in self.sessions:
      self.sessions[my_jid] = {}

    if not eir_jid in self.sessions[my_jid]:
      self.sessions[my_jid][eir_jid] = {}

    self.sessions[my_jid][eir_jid][thread_id] = sess

    return sess

if __name__ == '__main__':
  transport = TestSuite(name=sys.argv[1], server=sys.argv[2], port=sys.argv[3], secret=sys.argv[4], handlers=jids)
  transport.xmpp_connect()
