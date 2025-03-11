import os
import platform
import sys


def clear_terminal():
    if platform.system() == "Windows":
        os.system('cls')
    else:  # Pour Linux et MacOS
        os.system('clear')


def logo():
    clear_terminal()
    logo = """
╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮
┃                                                             ┃
┃   ██╗  ██╗    ██╗   ██╗    ██████╗     ██████╗     ██████╗  ┃
┃   ╚██╗██╔╝    ██║   ██║    ██╔══██╗    ╚════██╗    ██╔══██╗ ┃
┃    ╚███╔╝     ╚██╗ ██╔╝    ██████╔╝     █████╔╝    ██║  ██║ ┃
┃    ██╔██╗      ╚████╔╝     ██╔═══╝      ╚═══██╗    ██║  ██║ ┃
┃   ██╔╝ ██╗      ╚██╔╝      ██║         ██████╔╝    ██████╔╝ ┃
┃   ╚═╝  ╚═╝       ╚═╝       ╚═╝         ╚═════╝     ╚═════╝  ┃
┃                                                             ┃
┃                    Advanced Python Tool                     ┃
┃                                                             ┃
╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯
"""
    print(logo)


def menu_princi():
    # Import here to avoid circular imports
    from src.nmap import NmapTool
    from src.request import RequestsTool
    from src.menu import interactive_tool_scapy, interactive_tool_sql

    logo()
    print("1. Nmap")
    print("2. Scapy")
    print("3. SQL Injection")
    print("4. request")
    print("5. Exit")
    in_user = input("choisissez une lib : ")

    if in_user == "1":
        tool = NmapTool()
        try:
            tool.main_menu()
        except KeyboardInterrupt:
            print("\nProgramme interrompu par l'utilisateur")
            sys.exit(0)
    elif in_user == "2":
        interactive_tool_scapy()
    elif in_user == "3":
        interactive_tool_sql()
    elif in_user == "4":
        tool = RequestsTool()
        try:
            tool.main_menu()
        except KeyboardInterrupt:
            print("\nProgramme interrompu par l'utilisateur")
            sys.exit(0)
    elif in_user == "5":
        sys.exit(0)


# Only run if this file is the main entry point
if __name__ == "__main__":
    menu_princi()