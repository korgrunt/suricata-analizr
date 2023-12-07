import ipaddress

def extract_uniq_alert(eve_lines_parsed):
    alerts = dict()
    
    for evenement in eve_lines_parsed:
        if(evenement["event_type"] == "alert"):
            alerts[evenement["alert"]["signature_id"]] = evenement["alert"]["signature"]
    

    alert_report = f"""
            
            1.Alert signature:\n
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


def extract_malware_detected(eve_lines_parsed):
    malwares = dict()
    ips_in_danger = dict()
    
    for evenement in eve_lines_parsed:
        if("alert" in evenement):
            if("metadata" in evenement["alert"]):
                if("malware_family" in evenement["alert"]["metadata"]):
             
                    malwares[evenement["alert"]["metadata"]["malware_family"]] = evenement["alert"]["metadata"]["affected_product"]
                    ips_in_danger[evenement["alert"]["metadata"]["malware_family"]] = extract_ip_from_event(evenement)    

    malware_report = f"""
            
            1.Malwares detected:\n
            List of malware =>
    """
    for cle, valeur in malwares.items():
        malware_report += f"""
            Malware: {cle} can affect producte {valeur} and detected about ips {ips_in_danger[cle]}    
        """

    
    return malware_report






# mode detection
def analyze_detection_mode(arguments_parsed, eve_lines_parsed):
    report = ''
 
    report += extract_uniq_alert(eve_lines_parsed)
    report += extract_malware_detected(eve_lines_parsed)
    #report += find_network_and_netmask_if_ip_is_private(eve_lines_parsed)
    # Affichage des résultats
    print(report)
    print("detection mode")

