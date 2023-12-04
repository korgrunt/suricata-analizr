import sys

# Help and verion
ERR_BAD_ARGV = """
        Please, provide valid arguments, for more informations, you can use: \n
        > python3 main.py -h, --help
        """

def print_help_page():
    help_page = open('./help.txt', 'r')
    print(help_page.read())
    sys.exit(0)

def print_version():
    print("Suricata-Analyze v0.1\n")
    sys.exit(0)