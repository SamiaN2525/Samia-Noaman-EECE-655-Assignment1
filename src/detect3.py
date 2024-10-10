from scapy.all import *
import netifaces
from scapy.layers.dns import IP, UDP, DNS, DNSQR, DNSRR
import datetime

# Dictionary to store legitimate responses
legitimate_responses = {}

def log_spoofing_attempt(pkt, original_response):
    print(datetime.datetime.now(), "Potential DNS Spoofing Attempt Detected!")
    print("Domain:", pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname)
    print("Original Response:", original_response)
    print("Spoofed Response:", pkt[DNSRR].rdata.decode() if isinstance(pkt[DNSRR].rdata, bytes) else pkt[DNSRR].rdata)
    print("Source IP:", pkt[IP].src)
    print("\n")

def detect_dns_spoof(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].ancount > 0:  # If it's a DNS response
        # Check if DNSQR layer exists
        if pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname

            # Check if the domain is in legitimate responses
            if domain in legitimate_responses:
                original_ip = legitimate_responses[domain]

                # Compare original IP with the response
                if original_ip != (pkt[DNSRR].rdata.decode() if isinstance(pkt[DNSRR].rdata, bytes) else pkt[DNSRR].rdata):
                    log_spoofing_attempt(pkt, original_ip)
            else:
                # Store the legitimate response for future reference
                if pkt.haslayer(DNSRR):
                    legitimate_responses[domain] = pkt[DNSRR].rdata.decode() if isinstance(pkt[DNSRR].rdata, bytes) else pkt[DNSRR].rdata

print("Starting DNS Spoofing Detector...")
sniff(filter="udp port 53", iface="eth0", store=0, prn=detect_dns_spoof)
