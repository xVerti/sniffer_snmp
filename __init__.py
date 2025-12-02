"""
MIBurnout SNMP Suite
====================

Package complet pour le monitoring, la capture et l'analyse de trafic SNMP.

Modules:
    - snmp_decoder: Décodage ASN.1/BER des paquets SNMP
    - database: Gestion SQLite pour l'historique
    - capture_engine: Moteur de capture avec Scapy
    - MIBurnout_Suite: Application principale
    - MIBurnout_Generator: Générateur de trafic externe

Installation:
    pip install customtkinter requests matplotlib
    pip install scapy  # Optionnel, pour capture réelle

Usage:
    # Application principale
    python MIBurnout_Suite.py
    
    # Générateur (GUI)
    python MIBurnout_Generator.py --gui
    
    # Générateur (CLI)
    python MIBurnout_Generator.py --target 192.168.1.1 --mode stress --rate 50
"""

__version__ = "2.0.0"
__author__ = "MIBurnout Team"
__description__ = "SNMP Monitoring, Capture and Analysis Suite"

from .snmp_decoder import SNMPDecoder, SNMPPacket, VarBind
from .database import MIBurnoutDB, get_db
from .capture_engine import CaptureEngine, CaptureMode, get_capture_engine

__all__ = [
    'SNMPDecoder',
    'SNMPPacket', 
    'VarBind',
    'MIBurnoutDB',
    'get_db',
    'CaptureEngine',
    'CaptureMode',
    'get_capture_engine',
]
