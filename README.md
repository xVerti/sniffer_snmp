# MIBurnout SNMP Suite v2.0

**Interface complète pour le monitoring, la capture et l'analyse de trafic SNMP**

![Version](https://img.shields.io/badge/version-2.0.0-orange)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Fonctionnalités

### Application Principale (MIBurnout_Suite.py)

#### Monitoring
- Liste des équipements avec statut en temps réel
- Graphiques CPU, mémoire, trafic réseau (matplotlib)
- Auto-refresh configurable
- Connexion API avec indicateur de statut

#### Capture SNMP (style Wireshark)
- **Capture réelle** avec Scapy (nécessite droits admin)
- **Mode simulation** pour les tests
- 3 panneaux : Liste / Détails / Hex Dump
- Filtrage avancé : `type==GetRequest and ip.src==192.168.1.1`
- Sauvegarde/chargement de filtres favoris
- Marquage de paquets (double-clic ou bouton)
- Recherche dans les paquets (Ctrl+F)
- Follow conversation (matching Request/Response par Request-ID)
- Export JSON et PCAP
- Couleurs par type de PDU

#### Analyse
- **Top Talkers** : IPs les plus actives
- **Distribution PDU** : graphique camembert
- **Timeline** : visualisation temporelle du trafic
- **Détection d'anomalies** :
  - Pics de trafic
  - Taux d'erreur élevé
  - Scan réseau
  - Tempête de traps

#### Alertes
- Centre d'alertes avec niveaux (info/warning/critical)
- Seuils configurables par métrique
- Acquittement individuel ou global
- Notifications système (optionnel)

#### Historique
- Sauvegarde automatique des sessions en SQLite
- Chargement de sessions précédentes
- Suppression de sessions

#### Paramètres
- Configuration API
- Profils de configuration (save/load)
- Statistiques base de données
- Nettoyage automatique des anciennes données

### Générateur Externe (MIBurnout_Generator.py)

**8 modes de génération :**

| Mode | Description |
|------|-------------|
| `normal` | Monitoring standard (GetRequest périodiques) |
| `discovery` | SNMP Walk (GetNextRequest séquentiels) |
| `stress` | Test de charge (rafales de requêtes) |
| `trap_storm` | Génération massive de traps |
| `mixed` | Mélange de tous les types de PDU |
| `burst` | Rafales aléatoires |
| `walk` | Parcours de l'arbre MIB |
| `error_sim` | Simulation d'erreurs |

**Interfaces :**
- **GUI** : Interface graphique complète
- **CLI** : Ligne de commande avec options

## Installation

### Dépendances requises
```bash
pip install customtkinter requests
```

### Dépendances optionnelles
```bash
# Pour les graphiques
pip install matplotlib

# Pour la capture réelle (nécessite droits admin/root)
pip install scapy
```

### Structure des fichiers
```
miburnout/
├── __init__.py           # Package init
├── MIBurnout_Suite.py    # Application principale
├── MIBurnout_Generator.py # Générateur externe
├── snmp_decoder.py       # Décodeur ASN.1/BER
├── database.py           # Gestion SQLite
├── capture_engine.py     # Moteur de capture
└── README.md             # Documentation
```

## Utilisation

### Application principale
```bash
# Lancer l'interface
python MIBurnout_Suite.py
```

### Générateur (GUI)
```bash
python MIBurnout_Generator.py --gui
```

### Générateur (CLI)
```bash
# Mode normal
python MIBurnout_Generator.py --target 192.168.1.1 --mode normal --rate 10

# Test de stress
python MIBurnout_Generator.py -t 192.168.1.1 -m stress -r 100 -d 60

# Tempête de traps
python MIBurnout_Generator.py -t 192.168.1.1 -m trap_storm -r 50

# Options complètes
python MIBurnout_Generator.py --help
```

### Options CLI du générateur
```
--target, -t    IP cible (défaut: 127.0.0.1)
--port, -p      Port cible (défaut: 161)
--community, -c Community string (défaut: public)
--version, -V   Version SNMP: 1 ou 2c (défaut: 2c)
--mode, -m      Mode de génération
--rate, -r      Paquets par seconde (défaut: 10)
--duration, -d  Durée en secondes (0=infini)
--count, -n     Nombre de paquets (0=infini)
--interface, -i Interface réseau
--verbose, -v   Mode verbeux
--gui           Lancer l'interface graphique
```

## Raccourcis clavier

| Raccourci | Action |
|-----------|--------|
| `Ctrl+F` | Rechercher dans les paquets |
| `Ctrl+S` | Sauvegarder la capture |
| `Ctrl+O` | Ouvrir une capture |
| `F5` | Rafraîchir tout |
| `Space` | Démarrer/Arrêter la capture |
| `Escape` | Arrêter la capture |
| `Double-clic` | Marquer un paquet |

## Syntaxe des filtres

```
# Par type de PDU
type==GetRequest
type==Trap

# Par IP
ip.src==192.168.1.1
ip.dst==192.168.1.0

# Par version
version==v2c

# Par community
community==public

# Par port
port==161

# Par erreur
error!=0

# Combinaisons (AND implicite)
type==GetRequest ip.src==192.168.1.1
```

## API Requirements

L'application s'attend à une API REST sur `http://127.0.0.1:8000` avec :

```
GET /devices -> Liste des équipements
[
  {
    "name": "Router1",
    "host": "192.168.1.1",
    "port": 161,
    "status": "up"
  }
]
```

## Base de données

SQLite stocke :
- Sessions de capture
- Paquets capturés
- Métriques historiques
- Alertes
- Filtres sauvegardés
- Configuration des équipements
- Profils utilisateur

Fichier : `miburnout.db` (créé automatiquement)

## Droits requis

Pour la capture réelle avec Scapy :
- **Linux** : `sudo python MIBurnout_Suite.py` ou capabilities
- **Windows** : Exécuter en administrateur + Npcap installé

## Projet SAE 501-502

Développé dans le cadre du projet de monitoring SNMP pour MIBurnout Corporation.

## Changelog

### v2.0.0
- Capture réelle avec Scapy
- Décodeur ASN.1/BER complet
- Base de données SQLite pour historique
- Graphiques temps réel (matplotlib)
- Détection d'anomalies
- Générateur externe (CLI + GUI)
- Système d'alertes avec seuils
- Profils de configuration
- Export PCAP
- Recherche et filtres avancés
