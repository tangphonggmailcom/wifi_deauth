from scapy.all import *
 
detected = {}
expiration = 60
delay = -256
 
def callback(frame):
  if frame.haslayer(Dot11Deauth):
    recipient = frame[Dot11].addr1
    source = frame[Dot11].addr2
 
    print "{} deauth attack from adress {} to {}".format(time.time(), source, recipient)
 
sniff(iface='wlan0', prn=callback)
