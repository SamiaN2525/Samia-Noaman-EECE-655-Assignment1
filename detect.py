from scapy.all import *
import netifaces # retrieves info about the network interfaces in a system
from scapy.layers.dns import IP, UDP, DNS, DNSQR, DNSRR
import datetime # to put a time stamp corresponding with each log

legitimate_responses = {}# Dictionary to store legitimate responses

def log_spoofing_attempt(packet, original_response):# Function that logs a message when detetcting a DNS spoofing attack
    print(datetime.datetime.now(), "DNS spoofing attack detected!") #prints date and time with each log message 
    print("Domain:", packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname)
    #extracts the domaine name from the request and converts it into redadable string which will be stored in query_name
    print("Spoofed Response:", packet[DNSRR].rdata.decode() if isinstance(packet[DNSRR].rdata, bytes) else packet[DNSRR].rdata)
    #Extracts and print the spoofed IP form the DNS resource record layer of the packet 

    print("Source IP:", packet[IP].src) #Extracts and prints the source IP of the intercepted packet from the IP layer.
    print("\n")



def detect_dns_spoof(packet):#Function that analyze paclets to ckeck for DNS spoofing 
    if packet.haslayer(DNS) and packet[DNS].ancount > 0:  # Checks if it is a DNS response
        
        if packet.haslayer(DNSQR):# Checks if DNSQR layer exists
            domain = packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname
            #extracts the domaine name from the request and converts it into redadable string which will be stored in query_name

            
            if domain in legitimate_responses:# Check if the domain is in legitimate responses
                original_ip = legitimate_responses[domain]

                
                if original_ip != (packet[DNSRR].rdata.decode() if isinstance(packet[DNSRR].rdata, bytes) else packet[DNSRR].rdata):
                    log_spoofing_attempt(packet, original_ip)# Compare original IP with the response
            else:
                
                if packet.haslayer(DNSRR):# Stores the legitimate response for future uses and trying to make it statful
                    legitimate_responses[domain] = packet[DNSRR].rdata.decode() if isinstance(packet[DNSRR].rdata, bytes) else packet[DNSRR].rdata

print("Starting DNS Spoofing Detector...")
sniff(filter="udp port 53", prn=detect_dns_spoof, iface="eth0")
#Starts a packet sniffer that captures UDP packets on port 53 which is the DNS port on my eth0 interface
#prn specifies the function dns_spoofingth at will be called for each captured packet