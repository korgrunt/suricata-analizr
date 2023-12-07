from typing import Optional
import binascii
import string
import sys
import os
import json
from base64 import b64encode
from src.help import *
from src.detection_mode import *
from src.visibility_mode import *
import json


# Parse arguments
def parse_arguments(argv):
    arguments_container = {}
    arguments_container['option'] = argv[1]
    arguments_container['pcap_file'] = argv[2]
    arguments_container['config_yaml_file'] = argv[3]
    arguments_container['rules_file'] = argv[4]
    arguments_container['output_file'] = argv[5] if len(argv) == 4 else False
    return arguments_container

def exec_suricata_on_pcap(arguments_parsed):
    try:
        os.system(f"suricata -c {arguments_parsed['config_yaml_file']} -r {arguments_parsed['pcap_file']} -v -S {arguments_parsed['rules_file']}   ")
        eve_lines_parsed = []
        with open('./eve.json', 'r') as file:
        # Itérez à travers chaque ligne du fichier
            for line in file:
                eve_lines_parsed.append(json.loads(line))
            return eve_lines_parsed
    except:
        print(f"Can't execute shell commande $> suricata -r {arguments_parsed['pcap_file']}")
        sys.exit(1)

def exec_suricata_analyzr(arguments_parsed):
    if(arguments_parsed['option'] == '-a' or arguments_parsed['option'] == '--all'):
        eve_file_parsed = exec_suricata_on_pcap(arguments_parsed)
        analyze_visibility_mode(arguments_parsed, eve_file_parsed)
        analyze_detection_mode(arguments_parsed, eve_file_parsed)
    elif(arguments_parsed['option'] == '--version'):
        print_version()
    elif(arguments_parsed['option'] == '-v' or arguments_parsed['option'] == '--visibility'):
        eve_file_parsed = exec_suricata_on_pcap(arguments_parsed)
        analyze_visibility_mode(arguments_parsed, eve_file_parsed)
    elif(arguments_parsed['option'] == '-d' or arguments_parsed['option'] == '--detection'):
        eve_file_parsed = exec_suricata_on_pcap(arguments_parsed)
        analyze_detection_mode(arguments_parsed, eve_file_parsed)
    else:
        print(ERR_BAD_ARGV)
        sys.exit(1)

# Bootstrap program  
def main(argv):
    if(argv[1] == '-h' or argv[1] == '--help'):
        print_help_page()
        sys.exit(0)
    if len(argv) < 5:
        print(ERR_BAD_ARGV) # bad arguments
        sys.exit(1)

    arguments_parsed = parse_arguments(argv)
    # to uncomment _ start
    exec_suricata_analyzr(arguments_parsed)
    # to uncomment _ end

    # to delete _start
    #eve_lines_parsed = []
    #with open('./eve.json', 'r') as file:
    # Itérez à travers chaque ligne du fichier
    #    for line in file:
    #        eve_lines_parsed.append(json.loads(line))
    #analyze_visibility_mode(arguments_parsed, eve_lines_parsed)
    #analyze_detection_mode(arguments_parsed, eve_lines_parsed)
    # to delete _end


    sys.exit(0)

# Start program
main(sys.argv)




