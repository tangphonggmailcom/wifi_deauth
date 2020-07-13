from scapy.all import *
 
detected = {}
expiration = 60
delay = -256
 
def callback(frame):
  if frame.haslayer(Dot11Deauth):
    recipient = frame[Dot11].addr1
    source = frame[Dot11].addr2
 
    if detected.has_key(recipient) and (time.time() - detected[recipient]['time'] < expiration):
        detected[recipient]['quantity']+=1
    else:
      detected[recipient]={'quantity':0, 'time':time.time()}
 
    if detected[recipient]['quantity'] > 10:
      print "deauth attack from adress {} to {}".format(source, recipient)
      detected[recipient]['quantity'] = delay
 
sniff(iface='wlan0', prn=callback)
