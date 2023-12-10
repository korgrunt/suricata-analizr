import sys
import os
import ipaddress

def extract_ip_network_and_netmask(eve_lines_parsed):
    src_ips = []
    for objet in eve_lines_parsed:
        if "src_ip" in objet:
            src_ips.append(objet["src_ip"])
    # Extract dest ips
    dest_ips = []
    for objet in eve_lines_parsed:
        if "dest_ip" in objet:
            dest_ips.append(objet["dest_ip"])

    
    # Private range of ip
    private_ranges = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16")
    ]

    ips_src_prviate = set()
    ips_dest_prviate = set()
    for ip_str in src_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            for private_range in private_ranges:
                if ip in private_range:
                    ips_src_prviate.add(str(ip))
                    break  
        except ValueError:
            print(f"Invalide IP Adresse: {ip_str}")

    for ip_str in dest_ips:
        try:                    
            ip = ipaddress.ip_address(ip_str)
            for private_range in private_ranges:
                if ip in private_range:
                    ips_dest_prviate.add(str(ip))
                    break  
        except ValueError:
            print(f"Invalide IP Adresse: {ip_str}")

    private_ip = {
        "src_ip": list(ips_src_prviate),
        "dest_ip": list(ips_dest_prviate)
    }
    return private_ip

def find_network_and_netmask_if_ip_is_private(eve_lines_parsed):

    # filter ip from file on private range, and get network, netmask
    ips_prviate = extract_ip_network_and_netmask(eve_lines_parsed)
    
    # Prepare output for report
    ip_report = f"""
            2.Private IP Addresses:\n
            -IP SRC =>
    """
    for ip in ips_prviate["src_ip"]:
        ip_report += f"""
            Adresse IP source private: {ip}"

    """
    ip_report += """
            -IP DEST =>
    """
    for ip in ips_prviate["dest_ip"]:
        ip_report += f"""
            Adresse IP dest private: {ip}"

    """

    return ip_report, ips_prviate