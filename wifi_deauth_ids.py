import socket
import Queue
from threading import Thread
from collections import Counter

q1 = Queue.Queue()
co = Counter()

try:
  sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
  sniff.bind(("mon0", 0x0003))
except Exception as e :
  print e
  
def ids():
  global q1
  while True :
    fm1 = sniff.recvfrom(6000)
  fm = fm1[0]
  radio_tap_lenght = ord(fm[2])
  if ord(fm[radio_tap_lenght]) == 192:
    bssid1 = fm[radio_tap_lenght + 4 + 6 + 6 : radio_tap_lenght + 4 + 6 + 6 + 6]
  bssid = ':'.join('%02x' % ord(b) for b in bssid1)
  q1.put(bssid)
  
def insert_frame():
  global q1
  while True:
    mac = q1.get()
  list1 = [mac]
  co.update(list1)
  print dict(co)
  
i = Thread(target = ids)
f = Thread(target = insert_frame)
i.start()
f.start()
