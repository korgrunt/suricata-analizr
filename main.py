import sys
import os
import json
from src.help import *
from src.detection_mode import *
from src.visibility_mode import *
from src.iputils import *
import json

# Parse arguments
def parse_arguments(argv):
    arguments_container = {}
    arguments_container['option'] = argv[1]
    arguments_container['pcap_file'] = argv[2]
    arguments_container['config_yaml_file'] = argv[3]
    arguments_container['rules_file'] = argv[4]
    return arguments_container

# Exec command shell suricata for build eve.json, then return parsed eve.jsoin
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
    # display all mode
    if(arguments_parsed['option'] == '-a' or arguments_parsed['option'] == '--all'):
        eve_file_parsed = exec_suricata_on_pcap(arguments_parsed)
        private_ip = analyze_visibility_mode(eve_file_parsed)
        analyze_detection_mode(eve_file_parsed, private_ip)
    # visibility mode only
    elif(arguments_parsed['option'] == '-v' or arguments_parsed['option'] == '--visibility'):
        eve_file_parsed = exec_suricata_on_pcap(arguments_parsed)
        analyze_visibility_mode(eve_file_parsed)
    # detection mode only
    elif(arguments_parsed['option'] == '-d' or arguments_parsed['option'] == '--detection'):
        eve_file_parsed = exec_suricata_on_pcap(arguments_parsed)
        analyze_detection_mode(eve_file_parsed)
    # bad mode provided
    else:
        print(ERR_BAD_ARGV)
        sys.exit(1)

# Bootstrap program  
def main(argv):
    if(argv[1] == '-h' or argv[1] == '--help'):
        print_help_page() # help page
        sys.exit(0)
    elif(argv[1] == '-V' or argv[1] == '--version'):
        print_version()
    if len(argv) < 5:
        print(ERR_BAD_ARGV) # bad arguments
        sys.exit(1)

    arguments_parsed = parse_arguments(argv)
    
    exec_suricata_analyzr(arguments_parsed)
    sys.exit(0)

# Start program
main(sys.argv)




