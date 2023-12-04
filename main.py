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


# Parse arguments
def parse_arguments(argv):
    arguments_container = {}
    arguments_container['option'] = argv[1]
    arguments_container['pcap_file'] = argv[2]
    arguments_container['output_file'] = argv[3] if len(argv) == 4 else False
    return arguments_container

def exec_suricata_on_pcap(arguments_parsed):
    try:
        os.system(f"suricata -r {arguments_parsed['pcap_file']}")
    except:
        print(f"Can't execute shell commande $> suricata -r {arguments_parsed['pcap_file']}")
        sys.exit(1)

def exec_suricata_analyzr(arguments_parsed):
    if(arguments_parsed['option'] == '-h' or arguments_parsed['option'] == '--help'):
        print_help_page()
    elif(arguments_parsed['option'] == '-a' or arguments_parsed['option'] == '--all'):
        exec_suricata_on_pcap(arguments_parsed)
        analyze_visibility_mode(arguments_parsed)
        analyze_detection_mode(arguments_parsed)
    elif(arguments_parsed['option'] == '--version'):
        print_version()
    elif(arguments_parsed['option'] == '-v' or arguments_parsed['option'] == '--visibility'):
        exec_suricata_on_pcap(arguments_parsed)
        analyze_visibility_mode(arguments_parsed)
    elif(arguments_parsed['option'] == '-d' or arguments_parsed['option'] == '--detection'):
        exec_suricata_on_pcap(arguments_parsed)
        analyze_detection_mode(arguments_parsed)
    else:
        print(ERR_BAD_ARGV)
        sys.exit(1)

# Bootstrap program  
def main(argv):
    if len(argv) < 2:
        print(ERR_BAD_ARGV) # bad arguments
        sys.exit(1)


    arguments_parsed = parse_arguments(argv)

    exec_suricata_analyzr(arguments_parsed)

    sys.exit(0)

# Start program
main(sys.argv)



