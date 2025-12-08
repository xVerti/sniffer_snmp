#!/usr/bin/env python3
"""
MIBurnout Suite V1 - Point d'Entrée Principal
==============================================
Suite complète pour le monitoring, la capture et l'analyse SNMP.

Usage:
    python main.py              # Lance l'interface graphique
    python main.py --cli        # Lance en mode CLI (capture directe)
    python main.py --help       # Affiche l'aide

Projet SAE 501-502 - MIBurnout Corporation
"""

import argparse
import sys
import os

# Ajouter le répertoire racine au path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)


def run_gui():
    """Lance l'interface graphique"""
    try:
        from gui.main_gui import MIBurnoutApp
        print("[*] Démarrage de MIBurnout Suite (GUI)...")
        app = MIBurnoutApp()
        app.mainloop()
    except ImportError as e:
        print(f"[!] Erreur d'import: {e}")
        print("[!] Assurez-vous que customtkinter est installé:")
        print("    pip install customtkinter")
        sys.exit(1)


def run_cli(args):
    """Lance en mode CLI (capture directe sans GUI)"""
    from threading import Thread
    from queue import Queue
    import time
    
    try:
        from core.sniffer import Sniffer
        from core.analyser import Analyser
        from core.SQLiteDB import DataBase
        from core.confAPP import ConfAPP
    except ImportError as e:
        print(f"[!] Erreur d'import des modules core: {e}")
        sys.exit(1)
    
    print("=" * 60)
    print("     MIBurnout Suite V1 - Mode CLI")
    print("=" * 60)
    print(f"[*] Interface: {args.interface}")
    print(f"[*] Filtre: {args.filter}")
    print(f"[*] Base de données: {args.database}")
    print(f"[*] Configuration: {args.config}")
    print("=" * 60)
    
    # Initialisation
    q = Queue(maxsize=args.queue_size)
    
    db = DataBase(dbFile=args.database)
    db.initDB()
    print("[+] Base de données initialisée")
    
    config = ConfAPP(confFile=args.config)
    if config.config is None:
        config.creatConf()
    print("[+] Configuration chargée")
    
    sniffer = Sniffer(iface=args.interface, sfilter=args.filter, queue=q)
    analyser = Analyser(queue=q, baseDB=db, config=config.config, 
                       pcap_dir=args.pcap_dir, lenPcap=args.pcap_size)
    
    # Démarrage des threads
    thread_sniff = Thread(target=sniffer.start_sniffer, daemon=True)
    thread_sniff.start()
    print(f"[+] Sniffer démarré sur {args.interface}")
    
    thread_analyse = Thread(target=analyser.start_analyse, daemon=True)
    thread_analyse.start()
    print("[+] Analyseur démarré")
    
    print("\n[*] Capture en cours... (Ctrl+C pour arrêter)\n")
    
    # Boucle principale
    packet_count = 0
    try:
        while True:
            time.sleep(1)
            new_count = len(analyser.captured_packets) if hasattr(analyser, 'captured_packets') else 0
            if new_count > packet_count:
                packet_count = new_count
                print(f"\r[*] Paquets capturés: {packet_count}", end="", flush=True)
    except KeyboardInterrupt:
        print(f"\n\n[!] Arrêt demandé par l'utilisateur")
        print(f"[*] Total paquets capturés: {packet_count}")


def main():
    parser = argparse.ArgumentParser(
        description="MIBurnout Suite V1 - Outil de capture et analyse SNMP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python main.py                    # Interface graphique
  python main.py --cli              # Mode CLI
  python main.py --cli -i eth0      # CLI sur interface eth0
  python main.py --cli -d snmp.db   # CLI avec DB personnalisée

Projet SAE 501-502 - MIBurnout Corporation
        """
    )
    
    parser.add_argument('--cli', action='store_true', 
                       help='Mode ligne de commande (sans GUI)')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Interface réseau (défaut: eth0)')
    parser.add_argument('-f', '--filter', default='udp port 161 or udp port 162',
                       help='Filtre BPF (défaut: udp port 161 or udp port 162)')
    parser.add_argument('-d', '--database', default='miburnout.db',
                       help='Fichier base de données (défaut: miburnout.db)')
    parser.add_argument('-c', '--config', default='config/conf.json',
                       help='Fichier de configuration (défaut: config/conf.json)')
    parser.add_argument('-p', '--pcap-dir', default='captures',
                       help='Répertoire des captures PCAP (défaut: captures)')
    parser.add_argument('-s', '--pcap-size', type=int, default=100,
                       help='Nombre de paquets par fichier PCAP (défaut: 100)')
    parser.add_argument('-q', '--queue-size', type=int, default=10000,
                       help='Taille de la file d\'attente (défaut: 10000)')
    parser.add_argument('-v', '--version', action='version', 
                       version='MIBurnout Suite V1.0.0')
    
    args = parser.parse_args()
    
    if args.cli:
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
