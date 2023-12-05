import ipaddress
import datetime

def print_report(arguments_parsed, msg):
    if arguments_parsed['output_file'] is not None and isinstance(arguments_parsed['output_file'], str) and len(arguments_parsed['output_file']) > 0:
        with open(arguments_parsed['output_file'], 'w') as file:
            file.write(msg)
    else:
        print(msg)

def extract_oldest_and_newest_timestamp(eve_lines_parsed):

    timestamps = [obj["timestamp"] for obj in eve_lines_parsed]
    timestamps_datetime = [datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z") for ts in timestamps]

    return f"""
            1. Timestamps:\n
            - First timestamp: {min(timestamps_datetime)}
            - Last timestamp: {max(timestamps_datetime)}
    """
def extract_ip_network_and_netmask(ips):
    
    ips_data_formatted = []
    
    # Private range of ip
    private_ranges = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16")
    ]

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            for private_range in private_ranges:
                if ip in private_range:
                    ips_data_formatted.append(f"Adresse IP: {ip}, Network: {private_range.network_address}, NetMask: {private_range.netmask}")
                    break  
        except ValueError:
            print(f"Invalide IP Adresse: {ip_str}")
    return ips_data_formatted

def list_domaine_window_and_list_domain_controleur(eve_lines_parsed):
    dns_entries = [entry for entry in eve_lines_parsed if 'event_type' in entry and entry['event_type'] == 'flow' and 'app_proto' in entry and entry['app_proto'] == 'dns']

def find_network_and_netmask_if_ip_is_private(eve_lines_parsed):
    # Extract src ips
    src_ips = []
    for objet in eve_lines_parsed:
        if "src_ip" in objet:
            src_ips.append(objet["src_ip"])
    # Extract dest ips
    dest_ips = []
    for objet in eve_lines_parsed:
        if "dest_ip" in objet:
            dest_ips.append(objet["dest_ip"])

    # filter ip from file on private range, and get network, netmask
    ips_dest_prviate = extract_ip_network_and_netmask(dest_ips)
    ips_src_prviate =  extract_ip_network_and_netmask(src_ips)
    
    # Prepare output for report
    ip_report = f"""
            2.Private IP Addresses:\n
            -IP SRC =>
    """
    for ip_info in ips_src_prviate:
        ip_report += f"""
            {ip_info}
    """
    ip_report += """
            -IP DEST =>
    """
    for ip_info in ips_dest_prviate:
        ip_report += f"""
            {ip_info}
    """
    return ip_report





# mode visiblity
def analyze_visibility_mode(arguments_parsed, eve_lines_parsed):
    report = ''
 

    report += extract_oldest_and_newest_timestamp(eve_lines_parsed)

    report += find_network_and_netmask_if_ip_is_private(eve_lines_parsed)
    #report += find_network_and_netmask_if_ip_is_private(eve_lines_parsed)
    # Affichage des résultats
    print(report)
    print("visiblity mode")
