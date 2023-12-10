import sys
import os

# Help and verion
ERR_BAD_ARGV = """
        Please, provide valid arguments, for more informations, you can use: \n
        > python3 main.py -h, --help
        """

def print_help_page():
    os.system("less ./documentations/help.txt")
    sys.exit(0)

def print_version():
    print("Suricata-Analyzr v0.1\n")
    sys.exit(0)