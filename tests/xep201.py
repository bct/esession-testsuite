#!/usr/bin/python

import xmpp
import session

class FancySession(session.Session):
  def show_help(self, msg):
    self.send("""this particular testbot tries to tell you something about your XEP-0201 (Best Practices for Message Threads) implementation.

different types of messages are handled differently. unless noted otherwise, you should be able to send either a message[@type='normal'] or a message[@type='chat'] and have me respond via the same method.

'help': this message
'newthread': i send a message starting a new session
'status': details about the sessions i have with your resource
'run': (chat only) i run through a series of scenarios to check your client's compliance
<any other message>: details about what thread your message belongs to""")

  def do_newthread(self, msg):
    new_sess = self.dispatcher.start_new_session(self.my_jid, self.eir_jid, self.__class__)
    thread_id = new_sess.thread_id

    new_sess.send("""this is the first message of thread '%s'. if you reply directly to it, your message should be part of the same thread.""" % thread_id)
    new_sess.status = 'existing'

  def do_status(self, msg):
    if self.my_jid in self.dispatcher.sessions and self.eir_jid in self.dispatcher.sessions[self.my_jid]:
      text = 'I have the following sessions with the Full JID "%s":\n' % self.eir_jid

      for session in self.dispatcher.sessions[self.my_jid][self.eir_jid].values():
        text += '\n' + str(session.thread_id)

      self.send(text)
    else:
      self.send('i have no sessions with the Full JID "%s".' % self.eir_jid)

  def do_normal(self):
    if self.received_thread_id:
      if self.status == 'new':
        self.send('''you have started a new thread '%s', this message is part of it.''' % self.thread_id)
        self.status = 'existing'
      else:
        self.send('''your message was part of thread '%s' (and so is this one)''' % self.thread_id)
    else:
      self.send("your message had no <thread/>, so it's not part of one (and neither is this message)") # XXX this is a lie

  def do_chat(self):
    if self.status == 'new':
      if self.received_thread_id:
        self.send("you started a new thread (id '%s') with your message (this reply is in it too)" % self.thread_id)
      else:
        self.send("your message had no <thread/>, and I have no existing sessions with you in which you haven't sent a <thread/>, so I'm starting a new thread (id '%s') (that this reply is part of)" % self.thread_id)

      self.status = 'existing'
    else:
      if self.received_thread_id:
        self.send("your message is part of existing thread '%s' (and so is this reply)" % self.thread_id)
      else:
        self.send("your message had no <thread/>, I've already got a null-thread session for you so I'm considering it to be part of that (id '%s') (this reply is in it too)" % self.thread_id)

  def do_run_chat_0(self, msg):
    if msg.getType() != 'chat':
      self.send('''this command is only supported for chat messages. 'help' for more details.''')
      return

    if not self.received_thread_id:
      self.send('''!!! your message didn't contain a thread ID at all. i doubt your client supports any of XEP-0201, so i'm aborting the rest of the test.''')
      return

    self.send('''ok, your message contained a thread ID. this one contains the same one, so your client should recognize it as part of the same session.

reply to this message to continue. the next message you receive should begin with 'ok'.''')

    self.status = 'run'
    self.proceed = self.do_run_chat_1

  def do_run_chat_1(self, msg):
    if not self.received_thread_id:
      self.send('''!!! you replied to the message, but you didn't include a <thread/> (as RECOMMENDed by XEP-0201)''')
      self.terminate()
      return

    self.terminate()

    new_sess = self.dispatcher.start_new_session(self.my_jid, self.eir_jid, self.__class__)
    new_sess.status = 'run'
    new_sess.proceed = new_sess.do_run_chat_2

    new_sess.send('ok, your message contained the same thread ID. this message contains a different thread ID, so your client should recognize it as part of a new session. reply to this message to continue.')

  def do_run_chat_2(self, msg):
    if not self.received_thread_id:
      self.send('''!!! you replied to the message, but you didn't include a <thread/> (as RECOMMENDed by XEP-0201)''')
      self.terminate()
      return

    self.send('ok, your client responded with the thread ID i was expecting. this is as far as the test goes for now.')

    # XXX send with the same thread ID from another resource
    # XXX terminate session
    # XXX go offline (session should continue)

  def terminate(self):
    session.Session.terminate(self)
    self.proceed = self.terminated

  def terminated(self, msg):
    self.send('''!!! this session was terminated, you shouldn't send any more messages to it.''')

  def handle_message(self, msg):
    if not msg.getType() or msg.getType() == 'normal':
      self.do_normal()
    elif msg.getType() == "chat":
      self.do_chat()

    if session.Session.handle_message(self, msg):
      return

    if self.status == 'run':
      self.proceed(msg)
      return
  
  handlers = { 'help': show_help,
               'run': do_run_chat_0,
               'newthread': do_newthread,
               'status': do_status,
      }
