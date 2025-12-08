# MIBurnout Suite V1

**Suite complète pour le monitoring, la capture et l'analyse de trafic SNMP**

![Version](https://img.shields.io/badge/version-1.0.0-orange)
![Python](https://img.shields.io/badge/python-3.8+-blue)

## 📋 Description

MIBurnout Suite est un outil professionnel de surveillance réseau SNMP développé dans le cadre du projet SAE 501-502. Il permet de :

- **Capturer** le trafic SNMP en temps réel (v1 et v2c)
- **Analyser** les paquets avec détection d'anomalies
- **Filtrer** selon des règles whitelist/blacklist
- **Stocker** les données dans une base SQLite
- **Visualiser** les statistiques avec une interface moderne

## 🏗️ Architecture

```
MIBurnout_Suite_V1/
├── main.py                 # Point d'entrée principal
├── core/                   # Modules backend
│   ├── __init__.py
│   ├── sniffer.py         # Capture des paquets (Scapy)
│   ├── analyser.py        # Analyse et filtrage
│   ├── SQLiteDB.py        # Gestion base de données
│   ├── confAPP.py         # Gestion configuration
│   ├── snmp_decoder.py    # Décodeur ASN.1/BER
│   └── anomaly_detector.py # Détection d'anomalies
├── gui/                    # Interface graphique
│   ├── __init__.py
│   └── main_gui.py        # Interface CustomTkinter
├── utils/                  # Utilitaires
│   ├── pkts.py            # Génération de paquets test
│   └── afficheDB.py       # Affichage base de données
├── config/                 # Configuration
│   └── conf.json          # Règles de filtrage
├── captures/              # Fichiers PCAP générés
└── README.md
```

## 🚀 Installation

### Prérequis

- Python 3.8+
- Droits administrateur (pour la capture)

### Dépendances

```bash
# Installation des dépendances requises
pip install scapy customtkinter

# Optionnel (graphiques)
pip install matplotlib
```

### Installation rapide

```bash
# Cloner ou extraire le projet
cd MIBurnout_Suite_V1

# Créer le dossier de captures
mkdir -p captures config

# Lancer l'application
sudo python main.py
```

## 📖 Utilisation

### Mode GUI (Interface graphique)

```bash
sudo python main.py
```

**Fonctionnalités GUI :**
- Onglet **Capture** : Liste des paquets en temps réel, détails, filtrage
- Onglet **Analyse** : Graphiques, statistiques, top talkers
- Onglet **Alertes** : Alertes de sécurité (flood, scan, etc.)
- Onglet **Base de Données** : Consultation des tables SQLite

### Mode CLI (Ligne de commande)

```bash
# Capture basique
sudo python main.py --cli

# Options personnalisées
sudo python main.py --cli -i enp4s0 -d capture.db

# Aide
python main.py --help
```

**Options CLI :**
| Option | Description | Défaut |
|--------|-------------|--------|
| `-i`, `--interface` | Interface réseau | eth0 |
| `-f`, `--filter` | Filtre BPF | udp port 161 or 162 |
| `-d`, `--database` | Fichier SQLite | miburnout.db |
| `-c`, `--config` | Fichier configuration | config/conf.json |
| `-p`, `--pcap-dir` | Dossier PCAP | captures |
| `-s`, `--pcap-size` | Paquets par PCAP | 100 |

## ⚙️ Configuration

### Fichier `config/conf.json`

```json
{
    "filtres": {
        "rule_monitoring": {
            "ip_src": "192.168.1.100",
            "port_dst": "161"
        }
    },
    "whiteList": {
        "MACs": ["00:11:22:33:44:55"],
        "IPs": ["192.168.1.1", "10.0.0.1"],
        "PORTs": ["161", "162"],
        "OIDs": ["1.3.6.1.2.1.1"]
    }
}
```

### Logique de filtrage

1. **Whitelist** : Si source ET destination sont dans la whitelist → AUTORISÉ
2. **Filtres** : Si une règle correspond → AUTORISÉ
3. **Sinon** → SUSPECT (tag=1)

## 🔍 Détection d'Anomalies

Le module de détection identifie automatiquement :

| Type | Description | Seuil |
|------|-------------|-------|
| `FLOOD_DETECTED` | Trop de paquets/IP | 100/min |
| `NETWORK_SCAN` | Beaucoup de GetNext | 20 consécutifs |
| `TRAP_STORM` | Tempête de traps | 50/min |
| `AUTH_FAILURE` | Échec authentification | Erreur 16 |
| `COMMUNITY_ENUM` | Test de communautés | 3+ différentes |

## 🗄️ Base de Données

### Tables SQLite

**snmp_v1** (SNMPv1)
- Champs standards + `snmp_enterprise`, `snmp_agent_addr`, `snmp_generic_trap`, `snmp_specific_trap`

**snmp_v2** (SNMPv2c)
- Champs standards + `snmp_non_repeaters`, `snmp_max_repetitions`

### Champs communs
- `id`, `time_stamp`, `mac_src`, `mac_dst`, `ip_src`, `ip_dst`
- `port_src`, `port_dst`, `snmp_community`, `snmp_pdu_type`
- `snmp_request_id`, `snmp_error_status`, `snmp_error_index`
- `snmp_oidsValues` (JSON), `tag`

## 🎨 Interface Graphique

L'interface utilise CustomTkinter avec un thème sombre professionnel :

- **Header** : Logo, contrôles de capture, indicateurs d'état
- **Onglets** : Capture, Analyse, Alertes, Base de Données
- **Liste des paquets** : Style Wireshark avec couleurs par type PDU
- **Panneau détails** : Informations complètes du paquet sélectionné
- **Graphiques** : Distribution des PDU, top talkers (matplotlib)

## 🔧 Modules Core

### sniffer.py
Capture des paquets avec Scapy, gestion de la file d'attente.

### analyser.py
Analyse des paquets, extraction des champs SNMP, comparaison avec les règles.

### SQLiteDB.py
Gestion complète de la base de données SQLite (création tables, lecture/écriture).

### confAPP.py
Chargement et sauvegarde de la configuration JSON.

### anomaly_detector.py
Détection temps réel des comportements anormaux.

### snmp_decoder.py
Décodeur ASN.1/BER pour analyse approfondie des paquets SNMP bruts.

## 🧪 Tests

```bash
# Test du module analyser
python -m core.analyser

# Test de la base de données
python -m core.SQLiteDB

# Test de la configuration
python -m core.confAPP

# Test du détecteur d'anomalies
python -m core.anomaly_detector
```

## 📝 Raccourcis Clavier (GUI)

| Raccourci | Action |
|-----------|--------|
| `Space` | Démarrer/Arrêter la capture |
| `Escape` | Arrêter la capture |
| `F5` | Rafraîchir toutes les vues |
| `Ctrl+S` | Exporter les données |

## ⚠️ Prérequis Système

### Linux
```bash
# Droits de capture
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
# OU utiliser sudo
sudo python main.py
```

### Windows
- Exécuter en tant qu'administrateur
- Installer Npcap (https://npcap.org/)

## 📊 Formats d'Export

- **JSON** : Export complet des paquets capturés
- **PCAP** : Fichiers compatibles Wireshark (automatique)
- **SQLite** : Base de données persistante

## 🤝 Contributeurs

- Développement Core (Sniffer/Analyser/DB) : Binôme
- Interface GUI / Détection Anomalies : Binôme

## 📄 Licence

Projet académique SAE 501-502 - MIBurnout Corporation

---

**MIBurnout Suite V1.0.0** - *Monitoring SNMP Professionnel*
