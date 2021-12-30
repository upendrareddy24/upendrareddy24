import argparse
import socket
from scapy.all import *
import base64
import requests
import sys

server_name = socket.gethostname()+".cs.uga.edu"
parser = argparse.ArgumentParser(description='')
group = parser.add_mutually_exclusive_group()
group.add_argument('-d', dest = 'DST_IP', 
                    help='Destination DNS server IP')
parser.add_argument('-f', dest = 'DENY_LIST_FILE', 
                    help='File containing domains to block')
parser.add_argument('-l', dest = 'LOG_FILE', 
                    help='Append-only log file')
group.add_argument('--doh', action = 'store_true',
                    help='Use default upstream DoH server')
parser.add_argument('--doh_server', dest='DOH_SERVER',
                    help='Use this upstrehhhham DoH server')
args = parser.parse_args()

deny_file = args.DENY_LIST_FILE
log_file = args.LOG_FILE
is_doh_server = args.doh
doh_server = args.DOH_SERVER
dest_ip = args.DST_IP
if dest_ip and doh_server:
    print("Provide either DST_IP or DOH_SERVER")
    sys.exit(1)
if log_file:
    if not os.path.isfile(log_file):
        try:
            with open(log_file, "w") as fd:
                pass
        except:
            print("Log file creation Failed")
            sys.exit(1)

BLOCK_LIST = []
if deny_file:
    if os.path.isfile(deny_file):
        with open(deny_file, "r") as fd:
            BLOCK_LIST = fd.read().splitlines()
    else:
        BLOCK_LIST = []
        print("Deny File path does not exist")
        sys.exit(1)
if dest_ip :
    server_ip = dest_ip
if is_doh_server:
    if doh_server:
        server_ip = doh_server
    else:
        server_ip = "8.8.8.8"
else:
    server_ip = "1.1.1.1"

DNS_TYPES = []

def add_into_log_file(d_data, BLOCK_LIST=None, is_block_list=False):
    with open(log_file, "a") as fd:
        if d_data[DNS].ancount:
            for i in range(d_data[DNS].ancount):
                ani = d_data[DNS].an[i]
                dname = str(ani.rrname.decode()[:-1])
                dtype = ani.get_field('type').i2repr(ani, ani.type)
                entry_type = "ALLOW"
                if dname in BLOCK_LIST:
                    entry_type = "DENY"
                fd.write(dname + " "+dtype + " "+entry_type+"\n")
        else:
            for i in range(d_data[DNS].qdcount):
                ani = d_data[DNS].qd[i]
                dname = str(ani.qname.decode()[:-1])
                dtype = ani.get_field('qtype').i2repr(ani, ani.qtype)
                entry_type = "ALLOW"
                if dname in BLOCK_LIST:
                    entry_type = "DENY"
                fd.write(dname + " "+dtype + " "+entry_type+"\n")
    if is_block_list:
        with open(log_file, "a") as fd:
            for i in range(d_data[DNS].qdcount):
                ani = d_data[DNS].qd[i]
                dname = str(ani.qname.decode()[:-1])
                dtype = ani.get_field('qtype').i2repr(ani, ani.qtype)
                entry_type = "DENY"
                fd.write(dname + " "+dtype + " "+entry_type+"\n")


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)       
print ("Socket successfully created")
port = 53
s.bind((server_name, port))        
print ("socket binded to %s" %(port))
BPF_FILTER = f"udp host 127.0.0.1"

while True:
    data, address = s.recvfrom(1024)
    dns_data=DNS(data)
    domain_name = dns_data[DNS].qd.qname
    domain_name = domain_name.decode()[:-1]
    type_of_record = dns_data[DNS].qd.qtype
    if domain_name not in BLOCK_LIST:
        if is_doh_server:
            pkt_bytes = bytes(DNS(rd=1, qd=DNSQR(qtype=type_of_record, qname=domain_name)))
            encoded_q = base64.b64encode(pkt_bytes).decode().rstrip('=')
            r=requests.get("https://"+server_ip+"/dns-query?dns="+encoded_q)
            #print(r.status_code, r.headers)
            gh = DNS(r.content)
            response_packet =  DNS(id=dns_data[DNS].id,
            qd=dns_data[DNS].qd,
            ar=gh[DNS].ar, an=gh[DNS].an,
            ra=gh[DNS].ra, rd=gh[DNS].rd, qr=gh[DNS].qr, qdcount=gh[DNS].qdcount,
            ancount=gh[DNS].ancount, 
            nscount=gh[DNS].nscount, rcode=gh[DNS].rcode, arcount=gh[DNS].arcount)   
            send_data_packet = response_packet.build()
        else:
            c_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
            c_socket.sendto(data, (server_ip, port))
            ddata, server = c_socket.recvfrom(1024)
            response_packet = DNS(ddata)
            send_data_packet = ddata
    else:
        response_packet =  DNS(id=dns_data[DNS].id,
        qd=dns_data[DNS].qd, 
        ar=dns_data[DNS].ar, ra=1, rd=1, qr=1, qdcount=1, 
        ancount=0, nscount=0, rcode=3, arcount=1) 
        send_data_packet = response_packet.build()
        if log_file: add_into_log_file(response_packet, is_block_list = True)
    
    if log_file: add_into_log_file(response_packet, BLOCK_LIST)
    s.sendto(send_data_packet, address)


    
   
