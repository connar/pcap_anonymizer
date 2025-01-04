import os
import sys
from scapy.all import rdpcap, wrpcap, TCP, Ether, IP
import random

# Dictionary for storing randomized values
randomized_mac_addresses = {}
randomized_ip_addresses = {}
ip_port_pairs = {}
non_localhost_ip = {}
mac_port_pairs = {}

def show_help():
    print("""
Usage: python script.py --inpcap <input_pcap_file> --outpcap <output_pcap_file> [--whitelist <file>] [--mod_null_mac <yes|no>] [--mod_localhost <yes|no>]

Options:
    --inpcap            Input PCAP file to anonymize.
    --outpcap           Output PCAP file name for anonymized packets.
    --whitelist         Optional file containing IP addresses to exclude from anonymization.
    --mod_null_mac      Set to 'yes' to anonymize MAC address '00:00:00:00:00:00', 'no' to preserve it. Default: no.
    --mod_localhost     Set to 'yes' to anonymize localhost IPs ('127.0.0.1'), 'no' to preserve them. Default: no.
""")
    sys.exit(1)

def parse_args():
    args = sys.argv
    if "--help" in args or len(args) < 5:
        show_help()

    arg_dict = {
        "inpcap": None,
        "outpcap": None,
        "whitelist": None,
        "mod_null_mac": "no",
        "mod_localhost": "no"
    }

    for i, arg in enumerate(args):
        if arg == "--inpcap":
            arg_dict["inpcap"] = args[i + 1]
        elif arg == "--outpcap":
            arg_dict["outpcap"] = args[i + 1]
        elif arg == "--whitelist":
            arg_dict["whitelist"] = args[i + 1]
        elif arg == "--mod_null_mac":
            arg_dict["mod_null_mac"] = args[i + 1].lower()
        elif arg == "--mod_localhost":
            arg_dict["mod_localhost"] = args[i + 1].lower()

    if not arg_dict["inpcap"] or not arg_dict["outpcap"]:
        show_help()

    return arg_dict

def get_anon_mac(mac):
    return mac[0:8] + ':' + os.urandom(1).hex() + ':' + os.urandom(1).hex() + ':' + os.urandom(1).hex()

def get_anon_ip(ip):
    ip_parts = ip.split(".")
    if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
        return ip  # Return original if not a valid IP

    # Multicast addresses start with 224-239
    if 224 <= int(ip_parts[0]) <= 239:
        randomized_ip = ip_parts[0] + '.' + '.'.join([str(random.randint(0, 255)) for _ in range(3)])
    # Private IP addresses
    elif ip_parts[0] == "192" and ip_parts[1] == "168":
        randomized_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
    elif ip_parts[0] == "10":
        randomized_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    elif ip_parts[0] == "172" and 16 <= int(ip_parts[1]) <= 31:
        randomized_ip = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    else:
        randomized_ip = '.'.join([str(random.randint(0, 255)) for _ in range(4)])

    return randomized_ip

def anonymize_ip_addresses(ip_address, srcport, modify_localhost):
    if ip_address == "127.0.0.1" and modify_localhost == "no":
        return ip_address

    if ip_address != "127.0.0.1":
        if ip_address not in non_localhost_ip.keys():
            non_localhost_ip[ip_address] = get_anon_ip(ip_address)
        
        return non_localhost_ip[ip_address]

    key = f"{ip_address}:{srcport}"
    if key not in ip_port_pairs:
        ip_port_pairs[key] = get_anon_ip(ip_address)
    return ip_port_pairs[key]

def anonymize_mac_addresses(mac_address, srcport, modify_null_mac):
    if mac_address == "00:00:00:00:00:00" and modify_null_mac == "no":
        return mac_address

    key = f"{mac_address}:{srcport}"
    if key not in mac_port_pairs:
        mac_port_pairs[key] = get_anon_mac(mac_address)
    return mac_port_pairs[key]

def get_src_dst(packet, layer_name):
    layer = packet[layer_name]
    return layer.src, layer.dst, layer

def main():
    args = parse_args()

    # Read exclude addresses if provided
    excluded_ips = set()
    if args["whitelist"]:
        with open(args["whitelist"], "r") as f:
            excluded_ips = set(line.strip() for line in f)

    pkts = rdpcap(args["inpcap"])
    for p in pkts:
        if p.haslayer(TCP):
            tcp_layer = p[TCP]
            dst_port = tcp_layer.dport
            src_port = tcp_layer.sport

        # Anonymize MAC Addresses
        if p.haslayer(Ether):
            src_mac, dst_mac, layer = get_src_dst(p, "Ether")
            layer.src = anonymize_mac_addresses(src_mac, src_port, args["mod_null_mac"])
            layer.dst = anonymize_mac_addresses(dst_mac, dst_port, args["mod_null_mac"])

        # Anonymize IP Addresses
        if p.haslayer(IP):
            src_ip, dst_ip, layer = get_src_dst(p, "IP")
            if src_ip not in excluded_ips:
                layer.src = anonymize_ip_addresses(src_ip, src_port, args["mod_localhost"])
            if dst_ip not in excluded_ips:
                layer.dst = anonymize_ip_addresses(dst_ip, dst_port, args["mod_localhost"])

        if p.haslayer('ARP'):
            arp_layer = p['ARP']

            if hasattr(arp_layer, 'hwsrc'):
                arp_layer.hwsrc = anonymize_mac_addresses(arp_layer.hwsrc, 0, args["mod_null_mac"])

            if hasattr(arp_layer, 'hwdst'):
                arp_layer.hwdst = anonymize_mac_addresses(arp_layer.hwdst, 0, args["mod_null_mac"])

            if hasattr(arp_layer, 'psrc'):
                if arp_layer.psrc not in excluded_ips:
                    arp_layer.psrc = anonymize_ip_addresses(arp_layer.psrc, 0, args["mod_localhost"])

            if hasattr(arp_layer, 'pdst'):
                if arp_layer.pdst not in excluded_ips:
                    arp_layer.pdst = anonymize_ip_addresses(arp_layer.pdst, 0, args["mod_localhost"])

    wrpcap(args["outpcap"], pkts)

if __name__ == '__main__':
    main()
