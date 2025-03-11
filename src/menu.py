from tool.src.nmap import *
from tool.src.scap import *
from tool.src.request import *
from tool.src.sqlinject import *


def menu_princi():
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