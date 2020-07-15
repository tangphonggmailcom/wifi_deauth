#!/usr/bin/env python
from scapy.all import *
 
interface = 'wlan0'
known={}

def callback(frame):
  if frame.haslayer(Dot11):
    if frame.haslayer(Dot11Beacon):
      source=frame[Dot11].addr2
      if source not in known:
        ssid = frame[Dot11Elt][0].info
        channel = frame[Dot11Elt][2].info
        channel = int(channel.encode('hex'), 16)
        print "Beacon >> SSID: '{}', BSSID: {}, channel: {}".format(ssid, source, channel)
        known[source]=True
    elif frame.haslayer(Dot11ProbeResp):
      source=frame[Dot11].addr2
      if source not in known:
        ssid = frame[Dot11Elt][0].info
        channel = frame[Dot11Elt][2].info
        channel = int(channel.encode('hex'), 16)
        dest=frame[Dot11].addr1
        print "Probe reponse >> SSID: '{}', BSSID: {}, channel: {}, MAC: {}".format(ssid, source, channel, dest)
        known[source]=True

print "Detecting unknown access point..."
sniff(iface=interface, prn=callback)
