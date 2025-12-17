#!/usr/bin/env python3
"""
MIBurnout Satellite - Point d'Entree Principal
Client distant pour la Station MIBurnout

Usage:
    python satellite.py                    # Mode GUI
    python satellite.py --host 192.168.1.1 # Connexion directe
"""

import os
import sys
import argparse

# Configuration des chemins
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

APP_VERSION = "1.0.0"


def check_dependencies():
    """Vérifie les dépendances requises."""
    missing = []
    
    try:
        import requests
    except ImportError:
        missing.append("requests")
    
    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")
    
    if missing:
        print(f"[!] Dependances manquantes: {', '.join(missing)}")
        print(f"    pip install {' '.join(missing)}")
        return False
    return True


def run_gui():
    """Lance l'interface graphique."""
    from gui.satellite_gui import main as gui_main
    gui_main()


def run_cli(args):
    """Mode ligne de commande pour tester la connexion."""
    from core.api_client import StationClient
    
    print("=" * 50)
    print(f"  MIBurnout Satellite v{APP_VERSION} - Mode CLI")
    print("=" * 50)
    print(f"  Station: {args.host}:{args.port}")
    print("=" * 50)
    
    client = StationClient(args.host, args.port)
    
    # Test ping
    print("\n[*] Test de connexion...", end=" ")
    if client.ping():
        print("OK")
    else:
        print("ECHEC")
        print("[!] Station inaccessible")
        return
    
    # Status
    status = client.get_status()
    if status:
        print(f"[*] Version API: {status.get('version', '?')}")
        print(f"[*] Capture: {'En cours' if status.get('capturing') else 'Arretee'}")
    
    # Login
    if args.user and args.password:
        print(f"\n[*] Connexion en tant que {args.user}...")
        success, msg, user = client.login(args.user, args.password)
        if success:
            print(f"[OK] Connecte - Role: {user.get('role', '?')}")
            
            # Stats
            stats = client.get_stats()
            if stats:
                print(f"\n[*] Statistiques:")
                print(f"    - Paquets: {stats.get('total', 0)}")
                print(f"    - Autorises: {stats.get('authorized', 0)}")
                print(f"    - Suspects: {stats.get('suspect', 0)}")
            
            # Déconnexion
            client.logout()
            print("\n[*] Deconnecte")
        else:
            print(f"[!] Echec: {msg}")
    else:
        print("\n[i] Utilisez --user et --password pour vous connecter")


def main():
    parser = argparse.ArgumentParser(
        description=f"MIBurnout Satellite v{APP_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python satellite.py                              # Interface graphique
  python satellite.py --host 192.168.1.10          # GUI avec IP pre-remplie
  python satellite.py --cli --host 192.168.1.10    # Mode CLI
  python satellite.py --cli --host 192.168.1.10 --user admin --password admin
        """
    )
    
    parser.add_argument("--cli", action="store_true", help="Mode ligne de commande")
    parser.add_argument("--host", default="127.0.0.1", help="Adresse de la Station")
    parser.add_argument("--port", type=int, default=5000, help="Port de l'API")
    parser.add_argument("--user", help="Nom d'utilisateur")
    parser.add_argument("--password", help="Mot de passe")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {APP_VERSION}")
    
    args = parser.parse_args()
    
    if not check_dependencies():
        sys.exit(1)
    
    if args.cli:
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
