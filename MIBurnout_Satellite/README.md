# MIBurnout Satellite

Client distant pour la Station MIBurnout.

## Description

Le Satellite permet de se connecter à distance à une Station MIBurnout pour :
- Visualiser les paquets SNMP capturés en temps réel
- Démarrer/arrêter la capture
- Voir les alertes et anomalies
- Gérer les appareils détectés
- Administrer les utilisateurs (admin)

## Installation

```bash
# Dépendances
pip install requests customtkinter

# Optionnel pour WebSocket temps réel
pip install python-socketio
```

## Utilisation

### Mode Graphique (recommandé)

```bash
python satellite.py
```

Une fenêtre de connexion apparaît pour entrer :
- L'adresse IP de la Station
- Le port (par défaut: 5000)
- Identifiant et mot de passe

### Mode CLI

```bash
# Test de connexion
python satellite.py --cli --host 192.168.1.10

# Avec authentification
python satellite.py --cli --host 192.168.1.10 --user admin --password admin
```

## Architecture

```
Station (Serveur)              Satellite (Client)
┌──────────────────┐           ┌──────────────────┐
│  MIBurnout Main  │           │ MIBurnout Sat.   │
│                  │           │                  │
│  - Capture SNMP  │◄─────────►│  - Visualisation │
│  - Base données  │   API     │  - Contrôle      │
│  - Analyse       │   REST    │  - Alertes       │
│  - Auth          │           │                  │
└──────────────────┘           └──────────────────┘
     Port 5000
```

## Configuration Station

Sur la Station, démarrer l'API avec accès réseau :

```bash
# Écouter sur toutes les interfaces
python api.py --host 0.0.0.0 --port 5000
```

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| Dashboard | Vue d'ensemble des stats et alertes |
| Capture | Démarrer/arrêter la capture à distance |
| Appareils | Liste des appareils SNMP détectés |
| Analyse | Alertes comportementales |
| Profil | Informations utilisateur, déconnexion |

## Sécurité

- Authentification requise pour toutes les actions
- Token de session avec expiration (1h)
- Permissions basées sur les rôles
- Communication chiffrée possible (HTTPS)

## Prérequis

- Python 3.8+
- Station MIBurnout accessible sur le réseau
- Compte utilisateur sur la Station
