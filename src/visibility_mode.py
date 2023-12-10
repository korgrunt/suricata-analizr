import ipaddress
import datetime
import re
import sys
import os
from src.iputils import *


def extract_oldest_and_newest_timestamp(eve_lines_parsed):

    timestamps = [obj["timestamp"] for obj in eve_lines_parsed]
    timestamps_datetime = [datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z") for ts in timestamps]

    # Prepare output for report
    return f"""
            ============================================
             Timestamps:\n
            - First timestamp: {min(timestamps_datetime)}
            - Last timestamp: {max(timestamps_datetime)}
    """

def is_microsoft_domain(str):
    microsoft_keywords = ['windows', 'azure', 'microsoft']

    for keyword in microsoft_keywords:
        if keyword in str.lower():
            return True

    return False

def is_microsoft_domain_controller(str):
    microsoft_keywords = [ '_msdcs']

    for keyword in microsoft_keywords:
        if keyword in str.lower():
            return True

    return False

def extract_windows_domain(eve_lines_parsed):
    microsoft_domain = []
    
    for evenement in eve_lines_parsed:
        if(evenement["event_type"] == "dns"):
            if(is_microsoft_domain(evenement["dns"]["rrname"])):
                microsoft_domain.append(evenement["dns"]["rrname"])
    
    microsoft_domain = list(set(microsoft_domain))

    # Prepare output for report
    microsoft_domain_report = f"""
            ============================================
            Microsoft domain:\n
            List of domain detecter =>
    """
    for domain in microsoft_domain:
        microsoft_domain_report += f"""
            {domain}
    """
    
    return microsoft_domain_report

def extract_windows_domain_controller(eve_lines_parsed):
    domain_controller = []
    
    for evenement in eve_lines_parsed:
        if(evenement["event_type"] == "dns"):
            if(is_microsoft_domain_controller(evenement["dns"]["rrname"])):
                domain_controller.append(evenement["dns"]["rrname"])
    
    domain_controller = list(set(domain_controller))

    # Prepare output for report
    domain_controller_report = f"""
            ============================================
            Domain controller:\n
            List of domain controller detecter =>
    """
    for domain in domain_controller:
        domain_controller_report += f"""
            {domain}
    """
    
    return domain_controller_report

def find_probable_operating_system(eve_lines_parsed):
    src_ips_to_os = dict()
    dest_ips_to_os = dict()
    for objet in eve_lines_parsed:
        if (("src_ip" in objet) and (objet["event_type"] == "smb") and ("smb" in objet)):
            if "request" in objet["smb"]:
                if "native_os" in objet["smb"]["request"]:
                    src_ips_to_os[objet["src_ip"]] = objet["smb"]["request"]["native_os"]
            if "response" in objet["smb"]:
                if "native_os" in objet["smb"]["response"]:
                    src_ips_to_os[objet["dest_ip"]] = objet["smb"]["response"]["native_os"]
    

    # Prepare output for report
    ip_report = f"""
            ============================================
            Operating system for IP Addresses:\n
            -IP SRC =>
    """
    for key, value in src_ips_to_os.items():
        ip_report += f"""
            ip address: {key} has probably operating system version: {value if len(value) > 0 else 'Unknown'}
    """
    for key, value in dest_ips_to_os.items():
        ip_report += f"""
            ip address: {key} has probably operating system version: {value if len(value) > 0 else 'Unknown'}
    """
    return ip_report



def extract_user_from_smb_and_kerberos_requests(eve_lines_parsed):
    users = []
    
    for evenement in eve_lines_parsed:
        if(evenement["event_type"] == "smb" and "smb" in evenement):
            if("ntlmssp" in evenement["smb"]):
                users.append(evenement["smb"]["ntlmssp"]["user"])
    
    users = list(set(users))

    # Prepare output for report
    user_report = f"""
            ============================================
            Username from SMB and Kerberos request:\n
            List of user =>
    """
    for user in users:
        user_report += f"""
            {user}
    """
    
    return user_report



# mode visiblity
def analyze_visibility_mode(eve_lines_parsed):
    report = ''
 
    report += extract_oldest_and_newest_timestamp(eve_lines_parsed)
    ip_report, ip_private = find_network_and_netmask_if_ip_is_private(eve_lines_parsed)
    report += ip_report
    report += extract_windows_domain(eve_lines_parsed)
    report += extract_windows_domain_controller(eve_lines_parsed)
    report += extract_user_from_smb_and_kerberos_requests(eve_lines_parsed)
    report += find_probable_operating_system(eve_lines_parsed)

    # Display result
    print(report)

    return ip_private
