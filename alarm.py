#!/usr/bin/python

from scapy.all import *
import pcapy
import argparse
import base64

num = 1
user = ""

def alert(incident, sourceIP, protocol, loot):
    global num
    print "ALERT #" +str( num) + ": " + incident + " from " + sourceIP + protocol + loot
    num = num + 1

def checkForPortScans(packet):

    try:
        F = packet['TCP'].flags
        if (F == 0):
            alert('NUL scan', packet['IP'].src, "(TCP) ", "")
        elif (F == 1):
            alert('FIN scan', packet['IP'].src, "(TCP) ", "")
        elif (F == (0x01 + 0x08 + 0x20)):
            alert('XMAS scan', packet['IP'].src, "(TCP) ", "")
    except:
        pass

def checkForPasswords(packet):
    global user
    if packet.haslayer('TCP') and packet.haslayer('Raw'):
        if packet['TCP'].dport == 21 or packet['TCP'].sport == 21:
            data = packet['Raw'].load
            if 'USER' in data:
                user = data.split('USER ')[1]
            if 'PASS' in data:
                alert('USER/PASS sent in clear', packet['IP'].src, '(23) ', ('(' + user.rstrip() + '/' + data.split('PASS ')[1].rstrip() + ')') )
        if (packet['TCP'].dport == 143 or packet['TCP'].sport == 143):
            data = str(packet['TCP'].payload)
            if 'LOGIN ' in data:
                user = data.split()
                data = user[2] + '/' + user[3].rstrip().strip('\"') 
                alert("USER/PASS sent in clear", packet['IP'].src, '(143) ', '(' +  data + ')')
        if (packet['TCP'].dport == 80 or packet['TCP'].sport == 80):
            data = str(packet['TCP'].payload)
            if 'Authorization: Basic ' in data:
                user = data.split('\n')
                for line in user:
                    if 'Authorization: Basic ' in line:
                        data = line.split('Basic ')[1]
                        if data != '':
                            data = data.decode("base64")
                            alert("USER/PASS sent in clear", packet['IP'].src, '(80) ', '(' + data.replace(':', '/') + ')')
        payload = str(packet['TCP'].payload)
        if 'Nikto' in payload:
            alert('Nikto scan detected', packet['IP'].src, '(' +str(packet['TCP'].dport) + ')', '')
        if ('() { :;};'or '() { :; };' or '() {:; };' or '() {:;};' ) in payload:
            alert('Shellshock vulnerability scan', packet['IP'].src, '(' + str(packet['TCP'].dport) + ')' , '')
        

def packetcallback(packet):
    checkForPortScans(packet)
    checkForPasswords(packet)

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
