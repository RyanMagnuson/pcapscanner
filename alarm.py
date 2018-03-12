#!/usr/bin/python

from scapy.all import *
import pcapy
import argparse



def checkForPortScans(packet):

    try:
        F = packet['TCP'].flags
        if (F == 0): 
            print "ALERT NUL SCAN"
    except:
        pass

def packetcallback(packet):
    checkForPortScans(packet)

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:

    try:
        print "Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile}
        sniff(offline=args.pcapfile, prn=packetcallback)    
    except:
        print "Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile}
else:
    print "Sniffing on %(interface)s... " % {"interface" : args.interface}
    try:
        sniff(iface=args.interface, prn=packetcallback)
    except pcapy.PcapError:
        print "Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface}
    except:
        print "Sorry, can\'t read network traffic. Are you root?"
