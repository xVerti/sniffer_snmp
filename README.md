# MIBurnout Suite V1

**Suite professionnelle pour le monitoring, la capture et l'analyse de trafic SNMP**

## ✨ Fonctionnalités

- **Capture temps réel** : Sniffing SNMP v1/v2c avec Scapy
- **Détection d'anomalies** : Flood, scan, trap storm, brute force
- **Interface graphique moderne** : CustomTkinter avec thème sombre
- **Vue détaillée des paquets** : Affichage structuré par couches réseau
- **Client API REST intégré** : Test des endpoints directement depuis l'interface
- **Base de données SQLite** : Stockage persistant des captures
- **Export JSON/PCAP** : Formats compatibles Wireshark

## 🚀 Installation

```bash
# Dépendances requises
pip install scapy customtkinter

# Optionnel (API REST)
pip install flask flask-cors requests

# Optionnel (Graphiques)
pip install matplotlib
```

## 📖 Utilisation

### Mode GUI (Interface graphique)
```bash
cd MIBurnout_V1
sudo python main.py
```

### Mode CLI (Ligne de commande)
```bash
sudo python main.py --cli -i eth0
```

### Mode API (Serveur REST)
```bash
sudo python main.py --api --api-port 5000
```

## 🖥️ Interface Graphique

### Onglets disponibles :

1. **📡 Capture** : Liste des paquets en temps réel
   - Bouton "👁" pour ouvrir la vue détaillée de chaque paquet
   - Affichage coloré par type PDU
   - Indicateur de statut (OK/Suspect)

2. **📊 Analyse** : Statistiques de capture
   - Distribution par type PDU
   - Top 10 des sources IP
   - Métriques de détection d'anomalies

3. **🚨 Alertes** : Alertes de sécurité
   - Détection de flood, scan, trap storm
   - Niveaux de sévérité colorés

4. **🗄️ DB** : Consultation de la base SQLite
   - Tables snmp_v1 et snmp_v2
   - Rechargement dynamique

5. **🔌 API** : Client REST intégré
   - Sélection de méthode (GET/POST/PUT/DELETE)
   - Raccourcis vers les endpoints courants
   - Visualisation des réponses JSON

## 🔍 Vue Détaillée des Paquets

Cliquez sur "👁" pour ouvrir une fenêtre avec :

- **📋 Général** : Résumé des informations principales
- **📦 Couches** : Décomposition Ethernet/IP/UDP/SNMP
- **📡 SNMP** : Header, PDU, Variable Bindings (OIDs)
- **🔢 Raw** : Données JSON brutes

## 🌐 API REST

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/status` | GET | État du système |
| `/api/capture/start` | POST | Démarrer capture |
| `/api/capture/stop` | POST | Arrêter capture |
| `/api/packets` | GET | Liste des paquets |
| `/api/stats` | GET | Statistiques |
| `/api/alerts` | GET | Alertes |

## 🛡️ Détection d'Anomalies

| Type | Description |
|------|-------------|
| FLOOD | Trop de paquets/seconde |
| NETWORK_SCAN | GetNext consécutifs |
| TRAP_STORM | Tempête de traps |
| AUTH_FAILURE | Échecs authentification |
| COMMUNITY_ENUM | Test de communautés |
| BRUTE_FORCE | Attaque par force brute |

## 📁 Structure

```
MIBurnout_V1/
├── main.py           # Point d'entrée
├── api.py            # Serveur API REST
├── core/
│   ├── sniffer.py    # Capture Scapy
│   ├── analyser.py   # Analyse/filtrage
│   ├── SQLiteDB.py   # Base de données
│   ├── confAPP.py    # Configuration
│   └── anomaly_detector.py
├── gui/
│   └── main_gui.py   # Interface graphique
├── config/
│   └── conf.json     # Whitelist/filtres
└── captures/         # Fichiers PCAP
```

## 📜 Licence

Projet SAE 501-502 - MIBurnout Corporation
