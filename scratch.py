import pycurl
import sys
import re
import csv
from io import BytesIO
from ipwhois import IPWhois
from pprint import pprint

#Function to transform IP address to binary format
def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

#Function to define Network CIDR notation address size
def get_addr_network(address, net_size):
    #Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    #Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]
    return network

#Function to define if IP is in Prefix
def ip_in_prefix(ip_address, prefix):
    #CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    #Convert string to int
    net_size = int(net_size)
    #Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network

b_obj = BytesIO()
crl = pycurl.Curl()
#Set cmd argument to variable for IP
clientIP = str(sys.argv[1])
#Filename for PoP list
filename = 'pops.csv'


# Set URL value
crl.setopt(crl.URL, 'https://dns.google/resolve?name=gateway-gtm-global.goskope.com&type=A&edns_client_subnet=' + clientIP)

# Write bytes that are utf-8 encoded
crl.setopt(crl.WRITEDATA, b_obj)

# Perform a file transfer
crl.perform()

# End curl session
crl.close()

# Get the content stored in the BytesIO object (in byte characters)
get_body = b_obj.getvalue()

# Decode the bytes stored in get_body to HTML and store result on variable
responseStr = get_body.decode('utf8')

#Split response to extract PoP address using regex
pattern = "\"data\"\: \"(.*?)\"\}\]\,\"Addi"
popIP = re.search(pattern, responseStr).group(1)


#Run thru pop list csv to match pop location
with open(filename) as f:
    reader = csv.reader(f)

    for row in reader:
        #Map pop IP to city and Pop name
        if ip_in_prefix(popIP, row[1]):
            city=row[2]
            popName=row[0]
            break

#run whois on EGRESS IP for informational purposes
whois = IPWhois(clientIP)
#Map whois response to variable - this variable must be printed with pprint or parsed to be printed
whoisRes = whois.lookup_whois()


print('NETSKOPE PoP Lookup tool results:\n')
print('The informed EGRESS IP Address: '+ clientIP + '\n')
print('Closest PoP City: '+ city +'\n')
print('PoP name and IP: '+ popName +' '+ popIP +'\n')
print('Whois details from EGRESS IP: ')
pprint(whoisRes)

