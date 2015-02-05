#!/usr/bin/python
from scapy.all import *
import argparse


#sniff the traffic for at least a minute to try to capture DNS server
def sniff_dns(intime):
	print "sniffing for DNS requests"
	dns_filter = "udp port 53"
	sniff_time = 60
		
	sniff(filter=dns_filter, prn=announce(pkt), time=sniff_time)

#proud announcement and packet breakdown
def announce(pkt):
	print "got one"

#spam client with DNS replies
def spam_replies():
	print "filler"

#sit and wait for DNS requests and try to reply first
def surgical_strike():
	print "filler"

def main():
	#Args -e <IP of site to redirect user>, -d <DNS Server if known>
	# -t <target>, -n <noisy>
	parser = argparse.ArgumentParser(description='Some fun stuff with DNS')

	parser.add_argument("-e", "--evil", help="ip of website to redirect user")
	parser.add_argument("-d", "--DNS", help="DNS Server of target, if known")
	parser.add_argument("-n", "--noisy", help="Spam the target with responses")
	parser.add_argument("-s", "--secs", help="the amount of spent sniffing")
	parser.add_argument("-t", "--target", help="the target IP")
	args = parser.parse_args()

	#print args
	sniff_dns(args.secs)



if __name__=="__main__":
	main()