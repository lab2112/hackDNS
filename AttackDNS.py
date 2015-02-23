#!/usr/bin/python
from scapy.all import *
import argparse
import thread

#sniff the traffic for at least a minute to try to capture DNS server
def sniff_dns(sniff_time):
	
	#filter used to grab DNS packets
	dns_filter = "dst port 53"
	
	#checking time to run the filter
	if sniff_time==None:
		sniff_time =300
	else:
		sniff_time = int(sniff_time)
	
	print "sniffing for DNS requests for " + str(sniff_time) + " seconds"
	sniff(prn=attack, store=1, timeout=sniff_time, filter=dns_filter)
	print "TIME IS UP"
#packet breakdown
def attack(packet):
	ip_info=packet[IP]
	dns_info=packet[DNS]
	
	#Get IP info
	dns_server = ip_info.dst
	victim = ip_info.src 

	#Get DNS info
	print "---------DNS STUFF----------"
	print dns_info.qd.qname
	#print dns_info.an 
	#print dns_info.ns 
	#print dns_info.ar 

#spam client with DNS replies
def spam_replies(evil_ip, target):
	print "About to spam " + target + " with IP: " + evil_ip

	#spam_response = IP(dst=target)\UDP(dport=53)

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
	
	
	sniff_dns(args.secs)
	#if args.noisy != None:
	#	spam_replies(args.evil, args.target)



if __name__=="__main__":
	main()