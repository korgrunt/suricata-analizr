import ipaddress
from src.iputils import *

def extract_uniq_alert(eve_lines_parsed):
    alerts = dict()
    
    for evenement in eve_lines_parsed:
        if(evenement["event_type"] == "alert"):
            alerts[evenement["alert"]["signature_id"]] = evenement["alert"]["signature"]
    
    # Prepare output for report
    alert_report = f"""
            ============================================
            Alert signature:\n
            List of user =>
    """
    for cle, valeur in alerts.items():
        alert_report += f"""
            signature id: {cle} with name  {valeur}    
        """
    
    return alert_report

def extract_ip_from_event(evenement):
    ips = []
    private_ranges = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16")
    ]
  
    if("flow" in evenement):
        if("src_ip" in evenement):
            ip = ipaddress.ip_address(evenement["src_ip"])
            for private_range in private_ranges:
                if ip in private_range:
                    ips.append(ip)
        if("dest_ip" in evenement):
            ip = ipaddress.ip_address(evenement["dest_ip"])
            for private_range in private_ranges:
                if ip in private_range:
                    ips.append(ip)
    return ips


def extract_malware_detected(eve_lines_parsed):
    malwares = dict()
    ips_in_danger = dict()
    
    for evenement in eve_lines_parsed:
        if("alert" in evenement):
            if("metadata" in evenement["alert"]):
                if("malware_family" in evenement["alert"]["metadata"]):
                    ips_in_danger[evenement["alert"]["metadata"]["malware_family"][0]] = extract_ip_from_event(evenement)    
                    if("affected_product" in evenement["alert"]["metadata"]):
                        malwares[evenement["alert"]["metadata"]["malware_family"][0]] = evenement["alert"]["metadata"]["affected_product"]

    # Prepare output for report
    malware_report = f"""
            ============================================
            Malwares detected:\n
            List of malware =>
    """
    for cle, valeur in malwares.items():
        malware_report += f"""
            Malware: {cle} can affect producte {valeur} and detected about ips {ips_in_danger[cle]}    
        """

    return malware_report




def extract_iocs_from_malware_alerts(eve_lines_parsed, private_ip):
    iocs = dict()

    for evenement in eve_lines_parsed:
        if(evenement["event_type"] == "alert"):
            hostname = ""
            if("http" in evenement):
                if("hostname" in evenement["http"]):
                    hostname = evenement["http"]["hostname"]
            if("tls" in evenement):
                if("sni" in evenement["tls"]):   
                    hostname = evenement["tls"]["sni"]
            if("src_ip" in evenement and evenement["src_ip"] not in private_ip["src_ip"]):
                iocs[hostname] = evenement["src_ip"]
            if("dest_ip" in evenement and evenement["dest_ip"] not in private_ip["dest_ip"]):
                iocs[hostname] = evenement["dest_ip"]

    # Prepare output for report
    iocs_report = f"""
            ============================================
            IOCS detected:\n
    """
    for ioc_hostname, ioc_ip in iocs.items():
        ioc_ip_print = ioc_ip if (ioc_ip is not None) and (len(ioc_ip) > 0) else "unknown"
        ioc_hostname_print = ioc_hostname if ioc_hostname is not None and (len(ioc_hostname) > 0)  else "unknown"
        iocs_report += f"""
            ip: '{ioc_ip_print}' with hostname:'{ioc_hostname_print}' detected    
    """

    return iocs_report

def display_tcp_ip_services(eve_lines_parsed):
    services = {}
    services_uniq = set()
    for evenement in eve_lines_parsed:
        if evenement['event_type'] == 'flow':
            src_ip = evenement['src_ip']
            src_port = evenement['src_port']
            dest_ip = evenement['dest_ip']
            dest_port = evenement['dest_port']
            protocol = evenement['proto']
            app_protocol = evenement['app_proto'] if 'app_proto' in evenement else None

            service_key = (src_ip, src_port, dest_ip, dest_port)

            if service_key not in services:
                services[service_key] = {'protocol': protocol, 'app_protocol': app_protocol }

    for key, value in services.items():
        src_ip, src_port, dest_ip, dest_port = key
        protocol = value['protocol']
        app_protocol = value['app_protocol']

        if app_protocol and app_protocol != None and app_protocol != "failed":
            services_uniq.add(f"Service: {app_protocol} on port:{dest_port} althrough Protocole: {protocol}")

    # Prepare output for report
    service_available_report = f"""
            ============================================
            Service available:\n
    """
    for service in services_uniq:
        service_available_report += f"""
            {service}
    """
    return service_available_report


def extract_file_hashes_from_malware_alerts(eve_lines_parsed):
    
    flow_id = set()

    for elements in eve_lines_parsed:
        if elements["event_type"] == "alert":
            if "flow_id" in elements:
                flow_id.add(elements["flow_id"])
           

    file_infos = set()
    for elements in eve_lines_parsed:
        if elements["event_type"] == "fileinfo":
            fileinfo_flow_id = elements["flow_id"]
            
            
            if fileinfo_flow_id in flow_id and "fileinfo" in elements:
                file_infos.add(f"{elements['fileinfo']}")

    # Prepare output for report
    file_infos_report = f"""
            ============================================
            File info of malware:\n
    """
    for file in file_infos:
        file_infos_report += f"""
            {file}
    """
    return file_infos_report


# mode detection
def analyze_detection_mode(eve_lines_parsed, private_ip=False):
    if private_ip == False:
        ip_report, ips_prviate = find_network_and_netmask_if_ip_is_private(eve_lines_parsed)
        private_ip = ips_prviate
    report = ''
    report += extract_uniq_alert(eve_lines_parsed)
    report += extract_malware_detected(eve_lines_parsed)
    report += extract_iocs_from_malware_alerts(eve_lines_parsed, private_ip)
    report += display_tcp_ip_services(eve_lines_parsed)
    report += extract_file_hashes_from_malware_alerts(eve_lines_parsed)

    print(report)


