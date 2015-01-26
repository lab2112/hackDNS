#!/usr/bin/python
from scapy.all import *
import argparse

'''
parser = argparse.ArgumentParser()
parser.add_argument("targetsite",  help="the webiste that your are faking the DNS repsonse")
parser.add_argument("evilIP", help="IP of evil website")
parser.add_argument("dnsserver", help="spoofed DNS server")
parser.add_argument("target", help="your target")
args = parser.parse_args()
'''

#sniff the traffic for at least a minute to try to capture DNS server
def sniff_dns():
	print "filler"

#spam client with DNS replies
def spam_replies():
	print "filler"

#sit and wait for DNS requests and try to reply first
def surgical_strike():
	print "filler"

def main():
	#Args -w <website>, -e <IP of site to redirect user>, -d <DNS Server if known>
	# -t <target>, -n <noisy>


if __name__=="__main__":
	main()