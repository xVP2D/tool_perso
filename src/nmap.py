import os
import sys
import subprocess
import time
import re
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime

from tool.main import menu_princi


class NmapTool:
    def __init__(self):
        self.target = ""
        self.output_file = ""
        self.scan_type = ""
        self.ports = ""
        self.timing = "3"
        self.service_detection = False
        self.os_detection = False
        self.script_scan = False
        self.script_args = ""
        self.no_ping = False
        self.aggressive_scan = False
        self.version_intensity = "7"
        self.ipv6 = False
        self.verbose = False
        self.history = []

        try:
            self.nmap_version = subprocess.check_output(["nmap", "--version"], text=True).split('\n')[0]
        except:
            print("Nmap n'est pas installé ou n'est pas dans le PATH.")
            print("Veuillez installer Nmap avant d'utiliser cet outil.")
            sys.exit(1)

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_menu(self, title, options):
        self.clear_screen()
        print(f"\n===== {title} =====")
        for idx, option in enumerate(options, 1):
            print(f"{idx}. {option}")


        try:
            choice = int(input("\nChoisissez une option: "))
            if 1 <= choice <= len(options):
                return choice
            elif choice == len(options) + 1:
                return 0
            else:
                print("Option invalide")
                time.sleep(1)
                return -1
        except ValueError:
            print("Entrée invalide, veuillez entrer un nombre")
            time.sleep(1)
            return -1

    def validate_ip_or_hostname(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass

        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
                    target):
            return True

        return False

    def validate_ports(self, ports):
        if ports == "":
            return True

        if ports.lower() == "all":
            return True

        port_patterns = ports.split(",")
        for pattern in port_patterns:
            pattern = pattern.strip()

            if "-" in pattern:
                start, end = pattern.split("-")
                try:
                    start_port = int(start)
                    end_port = int(end)
                    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
                        return False
                except ValueError:
                    return False

            else:
                try:
                    port = int(pattern)
                    if not 0 <= port <= 65535:
                        return False
                except ValueError:
                    return False

        return True

    def set_target(self):
        self.clear_screen()
        print("\n===== Configuration de la cible =====")

        while True:
            target = input(
                "Entrez la cible (adresse IP, nom d'hôte, plage CIDR, plusieurs cibles séparées par des espaces): ")
            if target:
                targets = target.split()
                valid = True

                for t in targets:
                    if not self.validate_ip_or_hostname(t):
                        print(f"Cible invalide: {t}")
                        valid = False
                        break

                if valid:
                    self.target = target
                    print(f"Cible définie: {self.target}")
                    time.sleep(1)
                    break
            else:
                print("La cible ne peut pas être vide.")
                time.sleep(1)

    def set_ports(self):
        self.clear_screen()
        print("\n===== Configuration des ports =====")
        print("Options disponibles:")
        print("- Laisser vide pour les ports communs (top 1000)")
        print("- 'all' pour tous les ports (1-65535)")
        print("- Liste de ports séparés par des virgules (ex: 21,22,80,443)")
        print("- Plage de ports (ex: 1-1000)")
        print("- Combinaison des options ci-dessus (ex: 22,80,5000-6000)")

        while True:
            ports = input("\nEntrez les ports à scanner: ")
            if ports == "" or self.validate_ports(ports):
                self.ports = ports
                if ports == "":
                    print("Ports définis: ports communs (top 1000)")
                elif ports.lower() == "all":
                    print("Ports définis: tous les ports (1-65535)")
                else:
                    print(f"Ports définis: {self.ports}")
                time.sleep(1)
                break
            else:
                print("Format de ports invalide.")

    def set_scan_type(self):
        scan_types = [
            "Scan TCP SYN (furtif) [-sS]",
            "Scan TCP connect [-sT]",
            "Scan UDP [-sU]",
            "Scan TCP ACK [-sA]",
            "Scan TCP Window [-sW]",
            "Scan TCP Maimon [-sM]",
            "Scan TCP FIN [-sF]",
            "Scan TCP NULL [-sN]",
            "Scan TCP XMAS [-sX]",
            "Scan de découverte d'hôtes (ping) [-sn]"
        ]

        scan_flags = ["-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "-sF", "-sN", "-sX", "-sn"]

        choice = self.display_menu("Type de scan", scan_types)

        if choice > 0:
            self.scan_type = scan_flags[choice - 1]
            print(f"Type de scan défini: {scan_types[choice - 1]}")
            time.sleep(1)

    def set_timing(self):
        timing_options = [
            "T0 - Paranoïaque (très lent, détection d'intrusion évitée)",
            "T1 - Furtif (lent, utilise peu de ressources)",
            "T2 - Poli (lent, utilise peu de ressources, peu de bruit)",
            "T3 - Normal (par défaut)",
            "T4 - Agressif (rapide, nécessite bonne connexion et ressources)",
            "T5 - Insensé (très rapide, peut manquer des résultats)"
        ]

        choice = self.display_menu("Timing", timing_options)

        if choice > 0:
            self.timing = str(choice - 1)
            print(f"Timing défini: {timing_options[choice - 1]}")
            time.sleep(1)

    def toggle_option(self, option_name, option_var):
        self.clear_screen()
        print(f"\n===== {option_name} =====")
        print(f"État actuel: {'Activé' if option_var else 'Désactivé'}")

        options = ["Activer", "Désactiver"]
        choice = self.display_menu(f"Configuration {option_name}", options)

        if choice == 1:
            return True
        elif choice == 2:
            return False
        else:
            return option_var

    def set_output_file(self):
        self.clear_screen()
        print("\n===== Configuration du fichier de sortie =====")

        current = self.output_file if self.output_file else "Aucun (résultats affichés dans le terminal seulement)"
        print(f"Fichier de sortie actuel: {current}")

        options = ["Définir un fichier de sortie", "Désactiver la sortie vers un fichier"]
        choice = self.display_menu("Options de sortie", options)

        if choice == 1:
            filename = input("Nom du fichier de sortie (sans extension): ")
            if filename:
                self.output_file = filename
                print(f"Fichier de sortie défini: {filename}")
                time.sleep(1)
        elif choice == 2:
            self.output_file = ""
            print("Sortie vers un fichier désactivée")
            time.sleep(1)

    def set_script_args(self):
        self.clear_screen()
        print("\n===== Arguments de script NSE =====")
        print("Exemples:")
        print("- http.useragent=Mozilla/5.0")
        print("- dns-brute.domain=example.com")
        print("- smb-os-discovery.nmblookup=true")

        script_args = input("\nEntrez les arguments de script (format: arg1=value1,arg2=value2): ")
        self.script_args = script_args
        print(f"Arguments de script définis: {script_args if script_args else 'Aucun'}")
        time.sleep(1)

    def set_version_intensity(self):
        self.clear_screen()
        print("\n===== Intensité de la détection de version =====")
        print("Valeurs de 0 (légère) à 9 (très agressive):")
        print("0: légère (rapide)")
        print("5: par défaut")
        print("9: très agressive (plus lente)")

        while True:
            intensity = input("\nEntrez l'intensité (0-9): ")
            try:
                intensity_val = int(intensity)
                if 0 <= intensity_val <= 9:
                    self.version_intensity = intensity
                    print(f"Intensité définie: {intensity}")
                    time.sleep(1)
                    break
                else:
                    print("La valeur doit être entre 0 et 9")
            except ValueError:
                print("Veuillez entrer un nombre")

    def select_scripts(self):
        script_categories = [
            "auth - Scripts liés à l'authentification",
            "broadcast - Scripts de détection en broadcast",
            "brute - Scripts de force brute",
            "default - Scripts de base par défaut",
            "discovery - Scripts de découverte d'information",
            "dos - Scripts de déni de service (attention!)",
            "exploit - Scripts d'exploitation de vulnérabilités",
            "external - Scripts utilisant des ressources externes",
            "fuzzer - Scripts de fuzzing",
            "intrusive - Scripts intrusifs (peuvent être détectés)",
            "malware - Scripts de détection de malware",
            "safe - Scripts non intrusifs",
            "version - Scripts améliorant la détection de version",
            "vuln - Scripts de détection de vulnérabilités",
            "all - Tous les scripts disponibles (attention!)",
            "Script(s) personnalisé(s)"
        ]

        choice = self.display_menu("Catégories de scripts NSE", script_categories)

        if choice == 16:
            self.clear_screen()
            print("\n===== Scripts NSE personnalisés =====")
            print("Exemples:")
            print("- http-title")
            print("- smb-os-discovery")
            print("- ssl-enum-ciphers")
            print("- dns-brute")
            print("- multiple scripts: http-title,ssl-enum-ciphers")

            custom_scripts = input("\nEntrez le(s) nom(s) du/des script(s): ")
            if custom_scripts:
                return custom_scripts
        elif choice > 0:
            category = script_categories[choice - 1].split(" - ")[0]
            return category

        return None

    def configure_scripts(self):
        self.clear_screen()
        print("\n===== Configuration des scripts NSE =====")

        options = ["Activer/Désactiver les scripts", "Sélectionner des scripts spécifiques",
                   "Configurer des arguments de script"]
        choice = self.display_menu("Options de scripts", options)

        if choice == 1:
            self.script_scan = self.toggle_option("Scan de scripts", self.script_scan)
        elif choice == 2:
            scripts = self.select_scripts()
            if scripts:
                self.script_scan = True
                self.script_selection = scripts
                print(f"Scripts sélectionnés: {scripts}")
                time.sleep(1)
        elif choice == 3:
            self.set_script_args()

    def advanced_options(self):
        while True:
            options = [
                f"Détection de service [{'Activé' if self.service_detection else 'Désactivé'}]",
                f"Détection du système d'exploitation [{'Activé' if self.os_detection else 'Désactivé'}]",
                f"Scan sans ping [{'Activé' if self.no_ping else 'Désactivé'}]",
                f"Scan agressif (équivalent à -A) [{'Activé' if self.aggressive_scan else 'Désactivé'}]",
                f"Utiliser IPv6 [{'Activé' if self.ipv6 else 'Désactivé'}]",
                f"Mode verbeux [{'Activé' if self.verbose else 'Désactivé'}]",
                "Intensité de détection de version",
                "Configuration des scripts NSE"
            ]

            choice = self.display_menu("Options avancées", options)

            if choice == 1:
                self.service_detection = self.toggle_option("Détection de service", self.service_detection)
            elif choice == 2:
                self.os_detection = self.toggle_option("Détection du système d'exploitation", self.os_detection)
            elif choice == 3:
                self.no_ping = self.toggle_option("Scan sans ping", self.no_ping)
            elif choice == 4:
                self.aggressive_scan = self.toggle_option("Scan agressif", self.aggressive_scan)
            elif choice == 5:
                self.ipv6 = self.toggle_option("Utiliser IPv6", self.ipv6)
            elif choice == 6:
                self.verbose = self.toggle_option("Mode verbeux", self.verbose)
            elif choice == 7:
                self.set_version_intensity()
            elif choice == 8:
                self.configure_scripts()
            elif choice == 0:
                menu_princi()

    def build_command(self):
        if not self.target:
            print("Erreur: Aucune cible définie.")
            time.sleep(1)
            return None

        cmd = ["nmap"]

        if self.scan_type:
            cmd.append(self.scan_type)

        if self.ports:
            if self.ports.lower() == "all":
                cmd.extend(["-p-"])
            else:
                cmd.extend(["-p", self.ports])

        cmd.extend([f"-T{self.timing}"])

        if self.service_detection:
            cmd.append("-sV")
            cmd.extend([f"--version-intensity", self.version_intensity])

        if self.os_detection:
            cmd.append("-O")

        if self.no_ping:
            cmd.append("-Pn")

        if self.aggressive_scan:
            cmd.append("-A")

        if self.ipv6:
            cmd.append("-6")

        if self.verbose:
            cmd.append("-v")

        if self.script_scan:
            if hasattr(self, 'script_selection'):
                cmd.extend([f"--script={self.script_selection}"])
            else:
                cmd.append("--script=default")

            if self.script_args:
                cmd.extend([f"--script-args={self.script_args}"])

        if self.output_file:
            xml_output = f"{self.output_file}.xml"
            cmd.extend(["-oX", xml_output])
            cmd.extend(["-oN", f"{self.output_file}.txt"])

        cmd.append(self.target)

        return cmd

    def run_scan(self):
        cmd = self.build_command()
        if not cmd:
            return

        self.clear_screen()
        print("\n===== Lancement du scan Nmap =====")
        print("Commande :")
        print(" ".join(cmd))
        print("\nDémarrage du scan... Cela peut prendre un certain temps selon la cible et les options.")
        print("Appuyez sur Ctrl+C pour annuler le scan.")
        print("\n" + "=" * 60)

        start_time = datetime.now()

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            output = []
            for line in process.stdout:
                print(line, end='')
                output.append(line)

            process.wait()

            end_time = datetime.now()
            duration = end_time - start_time

            print("\n" + "=" * 60)
            print(f"\nScan terminé en {duration}")

            self.history.append({
                "command": " ".join(cmd),
                "target": self.target,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": str(duration),
                "output_file": self.output_file if self.output_file else "Aucun"
            })

            if self.output_file:
                print(f"Résultats enregistrés dans {self.output_file}.txt et {self.output_file}.xml")

            input("\nAppuyez sur Entrée pour continuer...")

        except KeyboardInterrupt:
            print("\nScan annulé par l'utilisateur.")
            time.sleep(1)
        except Exception as e:
            print(f"\nErreur lors de l'exécution de Nmap: {e}")
            time.sleep(2)

    def view_results(self):
        if not self.history:
            print("\nAucun scan n'a encore été effectué.")
            time.sleep(1)
            return

        last_scan = self.history[-1]
        if not last_scan.get("output_file") or last_scan.get("output_file") == "Aucun":
            print("\nLe dernier scan n'a pas été enregistré dans un fichier.")
            time.sleep(1)
            return

        xml_file = f"{last_scan['output_file']}.xml"
        if not os.path.exists(xml_file):
            print(f"\nFichier de résultats {xml_file} introuvable.")
            time.sleep(1)
            return

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            self.clear_screen()
            print("\n===== Résultats du dernier scan =====")

            print(f"Scan démarré le: {root.attrib.get('start', 'Non disponible')}")
            print(f"Arguments: {root.attrib.get('args', 'Non disponibles')}")

            hosts = root.findall('.//host')
            print(f"\nNombre d'hôtes scannés: {len(hosts)}")

            for host in hosts:
                addr_elem = host.find('.//address')
                if addr_elem is not None:
                    addr = addr_elem.attrib.get('addr', 'Inconnue')
                    addr_type = addr_elem.attrib.get('addrtype', 'Inconnu')
                    print(f"\n\nHôte: {addr} ({addr_type})")

                hostname_elem = host.find('.//hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.attrib.get('name', 'Inconnu')
                    print(f"Nom d'hôte: {hostname}")

                state_elem = host.find('.//status')
                if state_elem is not None:
                    state = state_elem.attrib.get('state', 'Inconnu')
                    reason = state_elem.attrib.get('reason', 'Inconnu')
                    print(f"État: {state} (raison: {reason})")

                ports = host.findall('.//port')
                if ports:
                    print("\nPorts:")
                    for port in ports:
                        port_id = port.attrib.get('portid', 'Inconnu')
                        protocol = port.attrib.get('protocol', 'Inconnu')

                        state_elem = port.find('.//state')
                        port_state = state_elem.attrib.get('state', 'Inconnu') if state_elem is not None else 'Inconnu'

                        service_elem = port.find('.//service')
                        service = service_elem.attrib.get('name', 'Inconnu') if service_elem is not None else 'Inconnu'
                        product = service_elem.attrib.get('product', '') if service_elem is not None else ''
                        version = service_elem.attrib.get('version', '') if service_elem is not None else ''

                        service_info = service
                        if product:
                            service_info += f" ({product}"
                            if version:
                                service_info += f" {version}"
                            service_info += ")"

                        print(f"  {protocol}/{port_id}: {port_state} - {service_info}")

                os_elem = host.find('.//os')
                if os_elem is not None:
                    print("\nSystème d'exploitation:")
                    os_matches = os_elem.findall('.//osmatch')
                    for osmatch in os_matches[:3]:
                        name = osmatch.attrib.get('name', 'Inconnu')
                        accuracy = osmatch.attrib.get('accuracy', 'Inconnu')
                        print(f"  {name} (précision: {accuracy}%)")

                script_elems = host.findall('.//script')
                if script_elems:
                    print("\nRésultats des scripts:")
                    for script in script_elems:
                        id = script.attrib.get('id', 'Inconnu')
                        output = script.attrib.get('output', 'Aucune sortie').strip()
                        print(f"  {id}: {output[:100]}...")

            input("\nAppuyez sur Entrée pour continuer...")

        except Exception as e:
            print(f"\nErreur lors de la lecture des résultats: {e}")
            time.sleep(2)

    def view_history(self):
        if not self.history:
            print("\nAucun scan n'a encore été effectué.")
            time.sleep(1)
            return

        self.clear_screen()
        print("\n===== Historique des scans =====")

        for idx, entry in enumerate(self.history, 1):
            print(f"\n{idx}. Scan du {entry['start_time']}")
            print(f"   Cible: {entry['target']}")
            print(f"   Durée: {entry['duration']}")
            print(f"   Commande: {entry['command']}")
            print(f"   Résultats: {entry['output_file']}")

        input("\nAppuyez sur Entrée pour continuer...")

    def configure_scan(self):
        while True:
            options = [
                f"Cible: {self.target or 'Non définie'}",
                f"Ports: {self.ports or 'Par défaut (top 1000)'}",
                f"Type de scan: {self.scan_type or 'Par défaut (-sS)'}",
                f"Timing: T{self.timing}",
                f"Fichier de sortie: {self.output_file or 'Aucun'}",
                "Options avancées"
            ]

            choice = self.display_menu("Configuration du scan", options)

            if choice == 1:
                self.set_target()
            elif choice == 2:
                self.set_ports()
            elif choice == 3:
                self.set_scan_type()
            elif choice == 4:
                self.set_timing()
            elif choice == 5:
                self.set_output_file()
            elif choice == 6:
                self.advanced_options()
            elif choice == 0:
                break

    def main_menu(self):
        while True:
            options = ["Configurer le scan", "Exécuter le scan", "Voir les résultats", "Historique des scans",
                       "À propos", "Quitter"]
            choice = self.display_menu("Menu Principal", options)

            if choice == 1:
                self.configure_scan()
            elif choice == 2:
                self.run_scan()
            elif choice == 3:
                self.view_results()
            elif choice == 4:
                self.view_history()
            elif choice == 5:
                self.clear_screen()
                print("\n===== À propos =====")
                print(f"Version de Nmap: {self.nmap_version}")
                print("\nCet outil est une interface Python pour Nmap, offrant:")
                print("- Une configuration simplifiée des scans Nmap")
                print("- Le support de toutes les méthodes de scan principales")
                print("- Une interface pour les scripts NSE")
                print("- Un affichage convivial des résultats")
                print("- Un historique des scans effectués")
                input("\nAppuyez sur Entrée pour continuer...")
            elif choice == 6:
              menu_princi()
            else:
                print("[!] Choix invalide. Essayez encore.")