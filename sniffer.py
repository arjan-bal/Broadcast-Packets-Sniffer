#Broadcast Sysytem Finder
 
import socket, sys
from struct import *
 
#Returns MAC address in readable form
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

print 'Broadcast Sysytem Finder'

#create a AF_PACKET type raw socket, packet level
s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

# start receiving packets

while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #parse ethernet header

#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       Ethernet destination address (first 32 bits)            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       Ethernet source address (last 32 bits)                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |        Type code              |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ethLength = 14
     
    ethHeader = packet[:ethLength]
    eth = unpack('!6s6sH' , ethHeader)
    ethProtocol = socket.ntohs(eth[2])
    sourceMac = eth_addr(packet[6:12])
    destMac = eth_addr(packet[0:6])
    if str(destMac) != 'ff:ff:ff:ff:ff:ff':
        continue 
    print 'Source MAC : ' + str(sourceMac) + ' Destination MAC : ' + str(destMac) +  ' Protocol : ' + str(ethProtocol)
 
    #Parse IP packets
#     0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |Type of Service|          Total Length         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment Offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to Live |    Protocol   |         Header Checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    #Exterior Gateway Protocol
    if ethProtocol == 8 :
        #Parse IP header
        #first 20 characters are for the ip header
        IPheader = packet[ethLength:20+ethLength]
        
        #unpack them
        iph = unpack('!BBHHHBBH4s4s' , IPheader)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iphLength = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        sourceIP = socket.inet_ntoa(iph[8]);
        destIP = socket.inet_ntoa(iph[9]);
 
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + '\nSource Address : ' + str(sourceIP) + ' Destination Address : ' + str(destIP)
 
        #TCP protocol

#         0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Data |           |U|A|P|R|S|F|                               |
# | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
# |       |           |G|K|H|T|N|N|                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             data                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        if protocol == 6 :
            t = iphLength + ethLength
            tcpHeader = packet[t:t+20]
 
            #unpack them
            tcph = unpack('!HHLLBBHHH' , tcpHeader)
             
            source_port = tcph[0]
            destPort = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doffReserved = tcph[4]
             
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(destPort) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement)
 
        #ICMP Packets

        
 #        0      7 8     15 16    23 24    31  
 # +--------+--------+--------+--------+ 
 # |     Source      |   Destination   | 
 # |      Port       |      Port       | 
 # +--------+--------+--------+--------+ 
 # |                 |                 | 
 # |     Length      |    Checksum     | 
 # +--------+--------+--------+--------+ 
 # |                                     
 # |          data octets ...            
 # +---------------- ...

        elif protocol == 1 :
            u = iphLength + ethLength
            icmphLength = 4
            icmpHeader = packet[u:u+4]
 
            #unpack them
            icmph = unpack('!BBH' , icmpHeader)
             
            icmpType = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code)
 
        #UDP packets

#  0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             unused                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Internet Header + 64 bits of Original Data Datagram      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        elif protocol == 17 :
            u = iphLength + ethLength
            udphLength = 8
            udpHeader = packet[u:u+8]
 
            #unpack them
            udph = unpack('!HHHH' , udpHeader)
             
            source_port = udph[0]
            destPort = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(destPort) + ' Length : ' + str(length)
 
        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
             
        print '\n'
