#!/usr/bin/env python

import argparse
from base64 import b64decode
from datetime import date, time, datetime
import os
import pcapy
from re import findall
import pyfiglet
from scapy.all import *
from subprocess import call
import uuid


#Banner design
ascii_banner = pyfiglet.figlet_format("Sharlock")
print(ascii_banner)




print("Loading...")

#ALERT generators
log = []
alerts_count = 0
def call_alert(type_scan, ip_src, ip_dst, packet_n):
    global alerts_count
    alerts_count +=1
    log.append("ALERT #" + str(alerts_count) + " " + str(type_scan) + " from: " +  str(ip_src) + " to IP: " + str(ip_dst) + ". Packet number: " + str(packet_n))
    if len(log) < 1:
        log.append("OK - No Stealthy scans detected") 



#Parsing pcap. Getting 5 tuple data from each packet.
def parsing_pcap(pcap):
    flags=0x00
    count = 1
    data = []
    brute_force_counter = 0
    brute_force_log = {}
    for pkt in pcap:
        if IP in pkt: 
            ip_src=pkt[IP].src
            ip_dst=pkt[IP].dst
        if TCP in pkt:
            sport=pkt[TCP].sport
            dport=pkt[TCP].dport
            flags = pkt[TCP].flags
        if UDP in pkt:
            sport=pkt[UDP].sport
            dport=pkt[UDP].dport
        #Brute force session:
        raw = pkt.getlayer(Raw)
        rawr = str(Raw(raw))
        #Searching for Brute Force attacks:
        if "530 Login incorrect" in rawr:
            brute_force_counter +=1
            brute_force_log = {brute_force_counter : ip_src}
            if brute_force_counter % 5 == 0:
                call_alert("BRUTE FORCE - Login incorrect more than 5 times", ip_src, ip_dst, count)
        

        data.append([int(count), str(ip_src), str(ip_dst), str(sport), str(dport), str(flags)])    #
        sport=""
        dport=""
        count+=1
        
    #https://nmap.org/book/scan-methods-null-fin-xmas-scan.html        
    #When scanning systems compliant with this RFC text, any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open. As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK. Nmap exploits this with three scan types:
    #Null scan (-sN)
    #Does not set any bits (TCP flag header is 0)
    #FIN scan (-sF)
    #Sets just the TCP FIN bit.
    #Xmas scan (-sX)
    #Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree. 

    # Checks given Packet object for traces of a NULL, FIN, or XMAS nmap stealthy scan. Does this by checking what flags are
    # set in the TCP layer, which will allow for the detection of a stealthy scan

    ### def call_alert(type, ip_src, ip_dst, packet_n):
    for pack in data:
        if pack[5] == '':  # NULL SCAN
            call_alert("NULL SCAN", str(pack[1]), str(pack[2]), str(pack[0]))
        elif pack[5] == "F":  # FIN SCAN
            call_alert("FIN", str(pack[1]), str(pack[2]), str(pack[0]))
        elif pack[5] == "FPU":  # XMAS SCAN
            call_alert("XMAS SCAN", str(pack[1]), str(pack[2]), str(pack[0]))

    #Title format
    def creating_title(message):
        f.write("*"*80 + "\n")
        f.write(str(message) + "\n")
        f.write("*"*80 + "\n")


         
    #Creating new ALERT file and Transfering logs to new File. 
    global log
    filename = "ALERTS_" + str(uuid.uuid4().hex  + ".txt")    
    f = open(filename, "wb")
    f.write("*"*80 + '\n')
    f.write("        Date: {}, File Name: {}".format(datetime.now(),(pcapfile) + "\n"))
    f.write("*"*80 + '\n')

    f.write("               Stealthy Scans (FIN, NULL, XMAS) and Brute Force:        " + '\n')
    f.write("*"* 80 + '\n')

    for line in log:
        f.write(line + '\n')
    
    #Searching for URLs; extract urls from HTTP GET Requests
    first = True
    a = pcap
    sessions = a.sessions()  
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.1")].decode("utf8")
                    http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                    http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                    url = http_header_parsed["Host"] + url_path + "\n"
                    if first:
                        creating_title("            Files and URLs found in .pcap           ")
                        first = False
                    f.write(url.encode())
            except:
                pass
    
    f.close()
    
    print("Log created. Check file: " + str(filename) ) 

    #Opening wireshark file if the user wishes.
    def ask_user():
        check = str(raw_input("Would you like to open {} in wireshark? [Y/n]".format(pcapfile))).lower().strip()
        try:
            if check[0] == 'y':
                print("Opening Wireshark")
                os.system("wireshark {}".format(pcapfile))
                return True
            elif check[0] == 'n':
                return False
            else:
                print('Invalid Input')
                return ask_user()
        except Exception as error:
            print("Please enter valid inputs")
            print(error)
            return ask_user()

    ask_user()



#Beggining: Parsing Pcap file
pcapfile = (sys.argv[1])
pcap = rdpcap(pcapfile)
parsing_pcap(pcap)




