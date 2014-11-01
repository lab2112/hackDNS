from scapy.all import *

#testfile to try things out
sniff_filter='tcp port 80'

def sendfunc():
	#ip = IP(src="1.1.1.1", dst="2.2.2.2")
	print "Caught a packet"
def main():
	print "starting the sniffer for UDP packets"
	a=sniff(prn=sendfunc())
	print a 
if __name__=='__main__':
	main()
