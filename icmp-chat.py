#!/usr/bin/python
#
# P2P ICMP-based Chat Client
#
# Issues:
#  * currently no encryption support.
#  * Will not work through a proxy, you won't be able to receive your messages.
#  * Cannot be used through a NAT, have had trouble with DMZ'd computers.
#
# Dependencies:
#  * scapy
#  * urwid
# 
# Note, must be run as root.
# Thanks to pr0f for recommending urwid.
# 
# Run with:
#  ./icmp-chat.py <encryption key (currently not used, put anything for now)>
#
# (c) infodox (http://twitter.com/#!/info_dox) and vorbis (http://twitter.com/#!/v0rbis)


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
import urwid
from itertools import izip, cycle
 
class CustomEdit(urwid.Edit):
  __metaclass__ = urwid.signals.MetaSignals
  signals = ['done']

  def keypress(self, size, key):
    if key == 'enter':
      urwid.emit_signal(self, 'done', self.get_edit_text())
      return
    elif key == 'esc':
      urwid.emit_signal(self, 'done', None)
      return

    urwid.Edit.keypress(self, size, key)

class chat(object):
  def __init__(self, key):
    self.header_box = urwid.Text(u"ICMP Secure Chat")
    self.header = urwid.AttrMap(self.header_box, 'header')

    self.txt = urwid.Text(u"")
    self.fill = urwid.Filler(self.txt, 'top')
    self.body = urwid.AttrMap(self.fill, 'body')
    
    self.inputbox = urwid.Text("> ")
    self.footer = urwid.AttrMap(self.inputbox, 'footer')

    self.box = urwid.Frame(self.body, footer=self.footer, header=self.header)
    self.friends = {}
    self.key = key
    self.nick = "me"

    receive_thread = threading.Thread(target=self.receive_message)
    receive_thread.start()

    self.loop = urwid.MainLoop(self.box, unhandled_input=self.start_typing)
    self.loop.run()

 
  def edit(self):
    self.foot = CustomEdit('> ')
    self.box.set_footer(self.foot)
    self.box.set_focus('footer')
    urwid.connect_signal(self.foot, 'done', self.edit_done)

  def edit_done(self, content):
    self.box.set_focus('body')
    urwid.disconnect_signal(self, self.foot, 'done', self.edit_done)
    if content:
      if content[0] == "/":
        self.parse_self_command(content[1:])
      else:
        for friend in self.friends:
          self.send_message(friend, content)
      self.txt.set_text(self.txt.get_text()[0] + "\n<" + self.nick + "> " + content)
    self.inputbox.set_text("> ")
    self.loop.draw_screen()

  def encrypt_decrypt(self, data):
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data.encode('ascii', 'ignore'), cycle(self.key)))

  def generate_message(self, message):
    return message

  def parse_self_command(self, command):
    command = command.split()
    if command[0] == "add_user" and len(command) == 2:
      self.friends[command[1]] = command[1]
      self.send_command(command[1], "!request")
    if command[0] == "nick" and len(command) == 2:
      self.nick = command[1]
      for friend in self.friends:
        self.send_command(friend, "!nick " + self.nick)

  def parse_incoming_command(self, command, ip, friend):
    command = command.split()
    if command[0] == "request" and not friend and len(command) == 2:
      self.print_message(nick, "has sent you a chat request. Type /add_user " + nick + " to accept, ignore to reject.")
    elif command[0] == "request" and friend and len(command) == 2:
      self.print_message(nick, "has accepted your chat request.")
    elif command[0] == "nick" and friend and len(command) == 2:
      self.friends[nick] = command[1]
      self.print_message(self.friends[nick], "is now known as " + command[1])
      
  def parse_packet(self, pkt):
    if(pkt.sprintf("%IP.proto%") == "icmp" and pkt.sprintf("%ICMP.type%") == "echo-request"):
      message = pkt.sprintf("%Raw.load%")[1:-1]
      if pkt.sprintf("%IP.src%") in self.friends:
        if message[0] == "!":
          self.parse_incoming_command(message[1:], pkt.sprintf("%IP.src%"), 1)
        else:
          self.print_message(pkt.sprintf("IP.src%"), pkt.sprintf("%Raw.load%"))
      else:
        if message[0] == "!":
          self.parse_incoming_command(message[:], pkt.sprintf("%IP.src%"), 0)

  def print_message(self, nick, message):
    #message = self.encrypt_decrypt(message[1:-1])
    self.txt.set_text(self.txt.get_text()[0] + "\n<" + self.friends[nick] + "> " + message[1:-1])
    self.loop.draw_screen()

  def receive_message(self):
    while 1:
      sniff(prn=lambda pkt:self.parse_packet(pkt), store=0)

  def start_typing(self, input):
    if input != 'q':
      self.edit()
    else:
      raise urwid.ExitMainLoop()

  def send_command(self, destination, message):
    send(IP(dst=destination)/ICMP()/self.generate_message(message))

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print "Usage: " + sys.argv[0] + " <encryption key>"
    exit(0)

  if os.getuid() != 0:
    print "Please run as root."
    exit(0)

  chat(sys.argv[1])
  os._exit(0)

