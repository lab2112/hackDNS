from scapy.all import *

#testfile to try things out
sniff_filter='udp port 53'

def sendfunc():
	ip = IP(src="1.1.1.1", dst="2.2.2.2")

sniff(filter=sniff_filter, prn=sendfunc())