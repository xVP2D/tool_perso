import requests
import json
import os
import time
from tool.main import menu_princi
class RequestsTool:
    def __init__(self):
        self.session = requests.Session()
        self.history = []
        self.headers = {}
        self.auth = None
        self.timeout = 30
        self.allow_redirects = True
        self.proxies = {}
        self.verify = True
        self.cert = None
        self.cookies = {}
        self.params = {}
        self.json_data = {}
        self.data = {}
        self.files = {}
        self.current_url = ""

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

    def get_request_params(self):
        params = {
            "url": self.current_url or input("URL: "),
            "params": self.params,
            "headers": self.headers,
            "cookies": self.cookies,
            "auth": self.auth,
            "timeout": self.timeout,
            "allow_redirects": self.allow_redirects,
            "proxies": self.proxies,
            "verify": self.verify,
            "cert": self.cert
        }
        return params

    def display_response(self, response):
        self.clear_screen()
        print("\n===== Réponse =====")
        print(f"Status Code: {response.status_code}")
        print(f"URL: {response.url}")
        print(f"Temps de réponse: {response.elapsed.total_seconds()} secondes")
        print("\n----- Headers -----")
        for key, value in response.headers.items():
            print(f"{key}: {value}")

        print("\n----- Contenu -----")
        try:
            if response.headers.get('Content-Type', '').find('json') != -1:
                pretty_json = json.dumps(response.json(), indent=2, ensure_ascii=False)
                print(pretty_json)
            elif response.headers.get('Content-Type', '').find('html') != -1 or response.headers.get('Content-Type',
                                                                                                     '').find(
                    'xml') != -1:
                print(f"Taille du contenu HTML/XML: {len(response.text)} caractères")
                print(f"Aperçu: {response.text[:500]}...")
            else:
                print(f"Taille du contenu: {len(response.text)} caractères")
                print(f"Aperçu: {response.text[:500]}...")
        except Exception as e:
            print(f"Erreur lors de l'affichage du contenu: {e}")
            print(f"Contenu brut (premiers 500 caractères): {response.content[:500]}")

        self.history.append({
            "method": response.request.method,
            "url": response.url,
            "status_code": response.status_code,
            "elapsed": response.elapsed.total_seconds()
        })

        input("\nAppuyez sur Entrée pour continuer...")

    def make_request(self, method, **kwargs):
        try:
            if method == "GET":
                response = self.session.get(**kwargs)
            elif method == "POST":
                response = self.session.post(**kwargs)
            elif method == "PUT":
                response = self.session.put(**kwargs)
            elif method == "DELETE":
                response = self.session.delete(**kwargs)
            elif method == "HEAD":
                response = self.session.head(**kwargs)
            elif method == "OPTIONS":
                response = self.session.options(**kwargs)
            elif method == "PATCH":
                response = self.session.patch(**kwargs)
            else:
                print(f"Méthode {method} non supportée")
                time.sleep(1)
                return

            self.current_url = response.url
            self.display_response(response)
        except Exception as e:
            self.clear_screen()
            print(f"\nErreur lors de la requête: {e}")
            input("\nAppuyez sur Entrée pour continuer...")

    def get_request(self):
        params = self.get_request_params()
        self.make_request("GET", **params)

    def post_request(self):
        params = self.get_request_params()

        content_menu_options = ["JSON", "Form Data", "Fichiers", "Texte brut"]
        content_choice = self.display_menu("Type de contenu", content_menu_options)

        if content_choice == 1:
            if not self.json_data:
                try:
                    json_input = input("Entrez le JSON (laissez vide pour annuler): ")
                    if json_input:
                        params["json"] = json.loads(json_input)
                except json.JSONDecodeError:
                    print("JSON invalide")
                    time.sleep(1)
                    return
            else:
                params["json"] = self.json_data

        elif content_choice == 2:
            if not self.data:
                data = {}
                while True:
                    key = input("Nom du champ (laissez vide pour terminer): ")
                    if not key:
                        break
                    value = input(f"Valeur pour {key}: ")
                    data[key] = value
                params["data"] = data
            else:
                params["data"] = self.data

        elif content_choice == 3:
            if not self.files:
                files = {}
                while True:
                    key = input("Nom du champ (laissez vide pour terminer): ")
                    if not key:
                        break
                    file_path = input(f"Chemin du fichier pour {key}: ")
                    if os.path.exists(file_path):
                        files[key] = open(file_path, 'rb')
                    else:
                        print(f"Fichier {file_path} introuvable")
                params["files"] = files
            else:
                params["files"] = self.files

        elif content_choice == 4:
            content = input("Contenu: ")
            content_type = input("Content-Type (par défaut: text/plain): ") or "text/plain"
            if "headers" not in params:
                params["headers"] = {}
            params["headers"]["Content-Type"] = content_type
            params["data"] = content

        elif content_choice == 0:
            return

        self.make_request("POST", **params)

    def put_request(self):
        params = self.get_request_params()

        content_menu_options = ["JSON", "Form Data", "Fichiers", "Texte brut"]
        content_choice = self.display_menu("Type de contenu", content_menu_options)

        if content_choice == 1:
            try:
                json_input = input("Entrez le JSON (laissez vide pour annuler): ")
                if json_input:
                    params["json"] = json.loads(json_input)
            except json.JSONDecodeError:
                print("JSON invalide")
                time.sleep(1)
                return

        elif content_choice == 2:
            data = {}
            while True:
                key = input("Nom du champ (laissez vide pour terminer): ")
                if not key:
                    break
                value = input(f"Valeur pour {key}: ")
                data[key] = value
            params["data"] = data

        elif content_choice == 3:
            files = {}
            while True:
                key = input("Nom du champ (laissez vide pour terminer): ")
                if not key:
                    break
                file_path = input(f"Chemin du fichier pour {key}: ")
                if os.path.exists(file_path):
                    files[key] = open(file_path, 'rb')
                else:
                    print(f"Fichier {file_path} introuvable")
            params["files"] = files

        elif content_choice == 4:
            content = input("Contenu: ")
            content_type = input("Content-Type (par défaut: text/plain): ") or "text/plain"
            if "headers" not in params:
                params["headers"] = {}
            params["headers"]["Content-Type"] = content_type
            params["data"] = content

        elif content_choice == 0:
            return

        self.make_request("PUT", **params)

    def delete_request(self):
        params = self.get_request_params()
        self.make_request("DELETE", **params)

    def head_request(self):
        params = self.get_request_params()
        self.make_request("HEAD", **params)

    def options_request(self):
        params = self.get_request_params()
        self.make_request("OPTIONS", **params)

    def patch_request(self):
        params = self.get_request_params()

        content_menu_options = ["JSON", "Form Data", "Fichiers", "Texte brut"]
        content_choice = self.display_menu("Type de contenu", content_menu_options)

        if content_choice == 1:
            try:
                json_input = input("Entrez le JSON (laissez vide pour annuler): ")
                if json_input:
                    params["json"] = json.loads(json_input)
            except json.JSONDecodeError:
                print("JSON invalide")
                time.sleep(1)
                return

        elif content_choice == 2:
            data = {}
            while True:
                key = input("Nom du champ (laissez vide pour terminer): ")
                if not key:
                    break
                value = input(f"Valeur pour {key}: ")
                data[key] = value
            params["data"] = data

        elif content_choice == 3:
            files = {}
            while True:
                key = input("Nom du champ (laissez vide pour terminer): ")
                if not key:
                    break
                file_path = input(f"Chemin du fichier pour {key}: ")
                if os.path.exists(file_path):
                    files[key] = open(file_path, 'rb')
                else:
                    print(f"Fichier {file_path} introuvable")
            params["files"] = files

        elif content_choice == 4:
            content = input("Contenu: ")
            content_type = input("Content-Type (par défaut: text/plain): ") or "text/plain"
            if "headers" not in params:
                params["headers"] = {}
            params["headers"]["Content-Type"] = content_type
            params["data"] = content

        elif content_choice == 0:
            return

        self.make_request("PATCH", **params)

    def configure_headers(self):
        while True:
            self.clear_screen()
            print("\n===== En-têtes actuels =====")
            for key, value in self.headers.items():
                print(f"{key}: {value}")

            print("\n===== Options =====")
            print("1. Ajouter/Modifier un en-tête")
            print("2. Supprimer un en-tête")
            print("3. Effacer tous les en-têtes")
            print("4. Retour")

            try:
                choice = int(input("\nChoisissez une option: "))
                if choice == 1:
                    key = input("Nom de l'en-tête: ")
                    value = input(f"Valeur pour {key}: ")
                    self.headers[key] = value
                elif choice == 2:
                    key = input("Nom de l'en-tête à supprimer: ")
                    if key in self.headers:
                        del self.headers[key]
                    else:
                        print(f"En-tête {key} introuvable")
                        time.sleep(1)
                elif choice == 3:
                    self.headers = {}
                elif choice == 4:
                    break
                else:
                    print("Option invalide")
                    time.sleep(1)
            except ValueError:
                print("Entrée invalide, veuillez entrer un nombre")
                time.sleep(1)

    def configure_auth(self):
        auth_menu_options = ["Basic Auth", "Bearer Token", "API Key", "Supprimer l'authentification"]
        auth_choice = self.display_menu("Type d'authentification", auth_menu_options)

        if auth_choice == 1:
            username = input("Nom d'utilisateur: ")
            password = input("Mot de passe: ")
            self.auth = (username, password)
            print("Authentification Basic configurée")
            time.sleep(1)

        elif auth_choice == 2:
            token = input("Token: ")
            if "headers" not in self.headers:
                self.headers = {}
            self.headers["Authorization"] = f"Bearer {token}"
            print("Token Bearer configuré")
            time.sleep(1)

        elif auth_choice == 3:
            key_name = input("Nom de la clé API: ")
            key_value = input("Valeur de la clé API: ")
            location = self.display_menu("Emplacement de la clé API", ["En-tête", "Paramètre de requête"])

            if location == 1:
                self.headers[key_name] = key_value
            elif location == 2:
                self.params[key_name] = key_value
            print("Clé API configurée")
            time.sleep(1)

        elif auth_choice == 4:
            self.auth = None
            if "Authorization" in self.headers:
                del self.headers["Authorization"]
            print("Authentification supprimée")
            time.sleep(1)

    def configure_timeout(self):
        try:
            timeout = float(input("Timeout (en secondes): "))
            self.timeout = timeout
            print(f"Timeout configuré à {timeout} secondes")
            time.sleep(1)
        except ValueError:
            print("Valeur invalide, veuillez entrer un nombre")
            time.sleep(1)

    def configure_redirects(self):
        redirects_menu_options = ["Autoriser les redirections", "Ne pas autoriser les redirections"]
        redirects_choice = self.display_menu("Configuration des redirections", redirects_menu_options)

        if redirects_choice == 1:
            self.allow_redirects = True
            print("Redirections autorisées")
            time.sleep(1)
        elif redirects_choice == 2:
            self.allow_redirects = False
            print("Redirections non autorisées")
            time.sleep(1)

    def configure_proxies(self):
        while True:
            self.clear_screen()
            print("\n===== Proxies actuels =====")
            for protocol, url in self.proxies.items():
                print(f"{protocol}: {url}")

            print("\n===== Options =====")
            print("1. Ajouter/Modifier un proxy")
            print("2. Supprimer un proxy")
            print("3. Effacer tous les proxies")
            print("4. Retour")

            try:
                choice = int(input("\nChoisissez une option: "))
                if choice == 1:
                    protocol = input("Protocole (http, https): ")
                    url = input(f"URL du proxy pour {protocol}: ")
                    self.proxies[protocol] = url
                elif choice == 2:
                    protocol = input("Protocole du proxy à supprimer: ")
                    if protocol in self.proxies:
                        del self.proxies[protocol]
                    else:
                        print(f"Proxy pour {protocol} introuvable")
                        time.sleep(1)
                elif choice == 3:
                    self.proxies = {}
                elif choice == 4:
                    break
                else:
                    print("Option invalide")
                    time.sleep(1)
            except ValueError:
                print("Entrée invalide, veuillez entrer un nombre")
                time.sleep(1)

    def configure_ssl(self):
        ssl_menu_options = ["Vérifier SSL", "Ne pas vérifier SSL", "Utiliser un certificat personnalisé"]
        ssl_choice = self.display_menu("Configuration SSL", ssl_menu_options)

        if ssl_choice == 1:
            self.verify = True
            print("Vérification SSL activée")
            time.sleep(1)
        elif ssl_choice == 2:
            self.verify = False
            print("Vérification SSL désactivée")
            time.sleep(1)
        elif ssl_choice == 3:
            cert_path = input("Chemin du certificat: ")
            if os.path.exists(cert_path):
                self.cert = cert_path
                print(f"Certificat configuré: {cert_path}")
            else:
                print(f"Fichier {cert_path} introuvable")
            time.sleep(1)

    def configure_cookies(self):
        while True:
            self.clear_screen()
            print("\n===== Cookies actuels =====")
            for key, value in self.cookies.items():
                print(f"{key}: {value}")

            print("\n===== Options =====")
            print("1. Ajouter/Modifier un cookie")
            print("2. Supprimer un cookie")
            print("3. Effacer tous les cookies")
            print("4. Retour")

            try:
                choice = int(input("\nChoisissez une option: "))
                if choice == 1:
                    key = input("Nom du cookie: ")
                    value = input(f"Valeur pour {key}: ")
                    self.cookies[key] = value
                elif choice == 2:
                    key = input("Nom du cookie à supprimer: ")
                    if key in self.cookies:
                        del self.cookies[key]
                    else:
                        print(f"Cookie {key} introuvable")
                        time.sleep(1)
                elif choice == 3:
                    self.cookies = {}
                elif choice == 4:
                    break
                else:
                    print("Option invalide")
                    time.sleep(1)
            except ValueError:
                print("Entrée invalide, veuillez entrer un nombre")
                time.sleep(1)

    def configure_params(self):
        while True:
            self.clear_screen()
            print("\n===== Paramètres actuels =====")
            for key, value in self.params.items():
                print(f"{key}: {value}")

            print("\n===== Options =====")
            print("1. Ajouter/Modifier un paramètre")
            print("2. Supprimer un paramètre")
            print("3. Effacer tous les paramètres")
            print("4. Retour")

            try:
                choice = int(input("\nChoisissez une option: "))
                if choice == 1:
                    key = input("Nom du paramètre: ")
                    value = input(f"Valeur pour {key}: ")
                    self.params[key] = value
                elif choice == 2:
                    key = input("Nom du paramètre à supprimer: ")
                    if key in self.params:
                        del self.params[key]
                    else:
                        print(f"Paramètre {key} introuvable")
                        time.sleep(1)
                elif choice == 3:
                    self.params = {}
                elif choice == 4:
                    break
                else:
                    print("Option invalide")
                    time.sleep(1)
            except ValueError:
                print("Entrée invalide, veuillez entrer un nombre")
                time.sleep(1)

    def view_history(self):
        if not self.history:
            print("\nPas d'historique disponible")
            time.sleep(1)
            return

        self.clear_screen()
        print("\n===== Historique des requêtes =====")
        for idx, entry in enumerate(self.history, 1):
            print(f"{idx}. {entry['method']} {entry['url']} - {entry['status_code']} ({entry['elapsed']}s)")

        print("\n1. Retour")
        try:
            choice = int(input("\nChoisissez une option: "))
            if choice == 1:
                return
        except ValueError:
            pass

    def request_methods_menu(self):
        while True:
            options = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
            choice = self.display_menu("Méthodes de requête", options)

            if choice == 1:
                self.get_request()
            elif choice == 2:
                self.post_request()
            elif choice == 3:
                self.put_request()
            elif choice == 4:
                self.delete_request()
            elif choice == 5:
                self.head_request()
            elif choice == 6:
                self.options_request()
            elif choice == 7:
                self.patch_request()
            elif choice == 0:
                break

    def configuration_menu(self):
        while True:
            options = [
                "En-têtes",
                "Authentification",
                "Timeout",
                "Redirections",
                "Proxies",
                "Configuration SSL",
                "Cookies",
                "Paramètres de requête"
            ]
            choice = self.display_menu("Configuration", options)

            if choice == 1:
                self.configure_headers()
            elif choice == 2:
                self.configure_auth()
            elif choice == 3:
                self.configure_timeout()
            elif choice == 4:
                self.configure_redirects()
            elif choice == 5:
                self.configure_proxies()
            elif choice == 6:
                self.configure_ssl()
            elif choice == 7:
                self.configure_cookies()
            elif choice == 8:
                self.configure_params()
            elif choice == 0:
                break

    def main_menu(self):
        while True:
            options = ["Méthodes de requête", "Configuration", "Historique", "À propos", "Quitter"]
            choice = self.display_menu("Menu Principal", options)

            if choice == 1:
                self.request_methods_menu()
            elif choice == 2:
                self.configuration_menu()
            elif choice == 3:
                self.view_history()
            elif choice == 4:
                self.clear_screen()
                print("\n===== À propos =====")
                print("Outil Python pour les requêtes HTTP")
                print("Basé sur la bibliothèque requests")
                print("\nFonctionnalités principales:")
                print("- Support de toutes les méthodes HTTP (GET, POST, PUT, DELETE, etc.)")
                print("- Configuration des en-têtes, cookies, authentification")
                print("- Support des proxies et configurations SSL")
                print("- Historique des requêtes")
                input("\nAppuyez sur Entrée pour continuer...")
            elif choice == 5:
                menu_princi()
            else:
               print("[!] Choix invalide. Essayez encore.")