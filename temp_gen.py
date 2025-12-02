#!/usr/bin/env python3
"""
MIBurnout SNMP Traffic Generator
Générateur de trafic SNMP externe - CLI et GUI
Génère du vrai trafic SNMP sur le réseau

Requiert: pip install scapy customtkinter
Usage CLI: python MIBurnout_Generator.py --target 192.168.1.1 --mode normal
Usage GUI: python MIBurnout_Generator.py --gui
"""

import argparse
import threading
import time
import random
import sys
import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

# Import conditionnel de Scapy
try:
    from scapy.all import (
        IP, UDP, Raw, send, sendp, Ether,
        get_if_list, get_if_hwaddr, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed. Install with: pip install scapy")

# Import conditionnel de CustomTkinter pour GUI
try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    CTK_AVAILABLE = False


class GeneratorMode(Enum):
    """Modes de génération"""
    NORMAL = "normal"
    DISCOVERY = "discovery"
    STRESS = "stress"
    TRAP_STORM = "trap_storm"
    MIXED = "mixed"
    ERROR_SIM = "error_sim"
    BURST = "burst"
    WALK = "walk"


@dataclass
class GeneratorConfig:
    """Configuration du générateur"""
    target: str = "127.0.0.1"
    port: int = 161
    community: str = "public"
    version: str = "2c"
    mode: GeneratorMode = GeneratorMode.NORMAL
    rate: int = 10  # packets per second
    duration: int = 0  # 0 = infinite
    interface: str = ""
    count: int = 0  # 0 = infinite
    verbose: bool = False


@dataclass
class GeneratorStats:
    """Statistiques du générateur"""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: float = 0.0
    
    @property
    def duration(self) -> float:
        return time.time() - self.start_time if self.start_time else 0
    
    @property
    def rate(self) -> float:
        return self.packets_sent / self.duration if self.duration > 0 else 0


# OIDs SNMP courants
SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10.1",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16.1",
    "ssCpuUser": "1.3.6.1.4.1.2021.11.9.0",
    "ssCpuSystem": "1.3.6.1.4.1.2021.11.10.0",
    "ssCpuIdle": "1.3.6.1.4.1.2021.11.11.0",
    "memTotalReal": "1.3.6.1.4.1.2021.4.5.0",
    "memAvailReal": "1.3.6.1.4.1.2021.4.6.0",
}


class SNMPPacketBuilder:
    """Constructeur de paquets SNMP"""
    
    @staticmethod
    def encode_length(length: int) -> bytes:
        """Encode la longueur en BER"""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    
    @staticmethod
    def encode_integer(value: int) -> bytes:
        """Encode un INTEGER"""
        if value == 0:
            return bytes([0x02, 0x01, 0x00])
        
        result = []
        negative = value < 0
        
        if negative:
            value = ~value
        
        while value > 0:
            result.insert(0, value & 0xFF)
            value >>= 8
        
        if negative:
            result = [~b & 0xFF for b in result]
            if result[0] < 0x80:
                result.insert(0, 0xFF)
        elif result[0] >= 0x80:
            result.insert(0, 0x00)
        
        return bytes([0x02]) + SNMPPacketBuilder.encode_length(len(result)) + bytes(result)
    
    @staticmethod
    def encode_string(value: str) -> bytes:
        """Encode une OCTET STRING"""
        data = value.encode('utf-8')
        return bytes([0x04]) + SNMPPacketBuilder.encode_length(len(data)) + data
    
    @staticmethod
    def encode_oid(oid: str) -> bytes:
        """Encode un Object Identifier"""
        parts = [int(p) for p in oid.split('.')]
        
        if len(parts) < 2:
            parts = [1, 3] + parts
        
        # Premier octet = 40*parts[0] + parts[1]
        result = [40 * parts[0] + parts[1]]
        
        for part in parts[2:]:
            if part == 0:
                result.append(0)
            else:
                encoded = []
                while part > 0:
                    encoded.insert(0, (part & 0x7F) | (0x80 if encoded else 0))
                    part >>= 7
                result.extend(encoded)
        
        return bytes([0x06]) + SNMPPacketBuilder.encode_length(len(result)) + bytes(result)
    
    @staticmethod
    def encode_null() -> bytes:
        """Encode NULL"""
        return bytes([0x05, 0x00])
    
    @staticmethod
    def encode_sequence(data: bytes) -> bytes:
        """Encode une SEQUENCE"""
        return bytes([0x30]) + SNMPPacketBuilder.encode_length(len(data)) + data
    
    @staticmethod
    def encode_varbind(oid: str, value_type: str = "null", value: any = None) -> bytes:
        """Encode un Variable Binding"""
        oid_encoded = SNMPPacketBuilder.encode_oid(oid)
        
        if value_type == "null":
            value_encoded = SNMPPacketBuilder.encode_null()
        elif value_type == "integer":
            value_encoded = SNMPPacketBuilder.encode_integer(int(value))
        elif value_type == "string":
            value_encoded = SNMPPacketBuilder.encode_string(str(value))
        else:
            value_encoded = SNMPPacketBuilder.encode_null()
        
        return SNMPPacketBuilder.encode_sequence(oid_encoded + value_encoded)
    
    @staticmethod
    def build_get_request(community: str, request_id: int, oids: List[str], version: str = "2c") -> bytes:
        """Construit un GetRequest"""
        version_num = 0 if version == "1" else 1
        
        # Varbinds
        varbinds = b''.join([SNMPPacketBuilder.encode_varbind(oid) for oid in oids])
        varbind_list = SNMPPacketBuilder.encode_sequence(varbinds)
        
        # PDU
        pdu_content = (
            SNMPPacketBuilder.encode_integer(request_id) +
            SNMPPacketBuilder.encode_integer(0) +  # error-status
            SNMPPacketBuilder.encode_integer(0) +  # error-index
            varbind_list
        )
        pdu = bytes([0xA0]) + SNMPPacketBuilder.encode_length(len(pdu_content)) + pdu_content
        
        # Message
        message_content = (
            SNMPPacketBuilder.encode_integer(version_num) +
            SNMPPacketBuilder.encode_string(community) +
            pdu
        )
        
        return SNMPPacketBuilder.encode_sequence(message_content)
    
    @staticmethod
    def build_get_next_request(community: str, request_id: int, oids: List[str], version: str = "2c") -> bytes:
        """Construit un GetNextRequest"""
        version_num = 0 if version == "1" else 1
        
        varbinds = b''.join([SNMPPacketBuilder.encode_varbind(oid) for oid in oids])
        varbind_list = SNMPPacketBuilder.encode_sequence(varbinds)
        
        pdu_content = (
            SNMPPacketBuilder.encode_integer(request_id) +
            SNMPPacketBuilder.encode_integer(0) +
            SNMPPacketBuilder.encode_integer(0) +
            varbind_list
        )
        pdu = bytes([0xA1]) + SNMPPacketBuilder.encode_length(len(pdu_content)) + pdu_content
        
        message_content = (
            SNMPPacketBuilder.encode_integer(version_num) +
            SNMPPacketBuilder.encode_string(community) +
            pdu
        )
        
        return SNMPPacketBuilder.encode_sequence(message_content)
    
    @staticmethod
    def build_set_request(community: str, request_id: int, oid: str, value_type: str, value: any, version: str = "2c") -> bytes:
        """Construit un SetRequest"""
        version_num = 0 if version == "1" else 1
        
        varbind = SNMPPacketBuilder.encode_varbind(oid, value_type, value)
        varbind_list = SNMPPacketBuilder.encode_sequence(varbind)
        
        pdu_content = (
            SNMPPacketBuilder.encode_integer(request_id) +
            SNMPPacketBuilder.encode_integer(0) +
            SNMPPacketBuilder.encode_integer(0) +
            varbind_list
        )
        pdu = bytes([0xA3]) + SNMPPacketBuilder.encode_length(len(pdu_content)) + pdu_content
        
        message_content = (
            SNMPPacketBuilder.encode_integer(version_num) +
            SNMPPacketBuilder.encode_string(community) +
            pdu
        )
        
        return SNMPPacketBuilder.encode_sequence(message_content)
    
    @staticmethod
    def build_trap_v2(community: str, request_id: int, uptime: int, trap_oid: str, varbinds: List[tuple], version: str = "2c") -> bytes:
        """Construit un SNMPv2-Trap"""
        # Varbinds système
        sys_varbinds = (
            SNMPPacketBuilder.encode_varbind("1.3.6.1.2.1.1.3.0", "integer", uptime) +  # sysUpTime
            SNMPPacketBuilder.encode_varbind("1.3.6.1.6.3.1.1.4.1.0", "string", trap_oid)  # snmpTrapOID
        )
        
        # Varbinds additionnels
        for oid, vtype, val in varbinds:
            sys_varbinds += SNMPPacketBuilder.encode_varbind(oid, vtype, val)
        
        varbind_list = SNMPPacketBuilder.encode_sequence(sys_varbinds)
        
        pdu_content = (
            SNMPPacketBuilder.encode_integer(request_id) +
            SNMPPacketBuilder.encode_integer(0) +
            SNMPPacketBuilder.encode_integer(0) +
            varbind_list
        )
        pdu = bytes([0xA7]) + SNMPPacketBuilder.encode_length(len(pdu_content)) + pdu_content
        
        message_content = (
            SNMPPacketBuilder.encode_integer(1) +  # v2c
            SNMPPacketBuilder.encode_string(community) +
            pdu
        )
        
        return SNMPPacketBuilder.encode_sequence(message_content)


class SNMPTrafficGenerator:
    """Générateur de trafic SNMP"""
    
    def __init__(self, config: GeneratorConfig):
        self.config = config
        self.stats = GeneratorStats()
        self.running = False
        self.paused = False
        self.builder = SNMPPacketBuilder()
        self.request_id = random.randint(1, 2147483647)
        
        self.callbacks: List[callable] = []
    
    def add_callback(self, callback: callable):
        """Ajoute un callback pour les événements"""
        self.callbacks.append(callback)
    
    def _notify(self, event: str, data: Dict = None):
        """Notifie les callbacks"""
        for cb in self.callbacks:
            try:
                cb(event, data or {})
            except:
                pass
    
    def _get_next_request_id(self) -> int:
        """Génère un nouveau request ID"""
        self.request_id = (self.request_id + 1) % 2147483647
        return self.request_id
    
    def _send_packet(self, snmp_data: bytes, dst_port: int = None) -> bool:
        """Envoie un paquet SNMP"""
        if not SCAPY_AVAILABLE:
            self._notify("error", {"message": "Scapy not available"})
            return False
        
        try:
            dst_port = dst_port or self.config.port
            
            packet = IP(dst=self.config.target) / UDP(sport=random.randint(49152, 65535), dport=dst_port) / Raw(load=snmp_data)
            
            send(packet, verbose=False, iface=self.config.interface if self.config.interface else None)
            
            self.stats.packets_sent += 1
            self.stats.bytes_sent += len(snmp_data)
            
            self._notify("packet_sent", {
                "type": "SNMP",
                "size": len(snmp_data),
                "target": self.config.target,
                "port": dst_port
            })
            
            return True
        
        except Exception as e:
            self.stats.errors += 1
            self._notify("error", {"message": str(e)})
            return False
    
    def _generate_normal(self):
        """Mode normal: monitoring standard"""
        oids = list(SNMP_OIDS.values())
        
        while self.running and not self._check_limits():
            if self.paused:
                time.sleep(0.1)
                continue
            
            # GetRequest avec quelques OIDs
            selected_oids = random.sample(oids, min(3, len(oids)))
            snmp_data = self.builder.build_get_request(
                self.config.community,
                self._get_next_request_id(),
                selected_oids,
                self.config.version
            )
            
            self._send_packet(snmp_data)
            time.sleep(1 / self.config.rate)
    
    def _generate_discovery(self):
        """Mode discovery: SNMP walk"""
        base_oid = "1.3.6.1.2.1"
        current_oid = base_oid
        
        while self.running and not self._check_limits():
            if self.paused:
                time.sleep(0.1)
                continue
            
            snmp_data = self.builder.build_get_next_request(
                self.config.community,
                self._get_next_request_id(),
                [current_oid],
                self.config.version
            )
            
            self._send_packet(snmp_data)
            
            # Simuler la progression dans l'arbre MIB
            parts = current_oid.split('.')
            parts[-1] = str(int(parts[-1]) + 1)
            current_oid = '.'.join(parts)
            
            if not current_oid.startswith(base_oid):
                current_oid = base_oid
            
            time.sleep(1 / self.config.rate)
    
    def _generate_stress(self):
        """Mode stress: test de charge"""
        oids = list(SNMP_OIDS.values())
        
        while self.running and not self._check_limits():
            if self.paused:
                time.sleep(0.1)
                continue
            
            # Rafale de requêtes
            for _ in range(10):
                snmp_data = self.builder.build_get_request(
                    self.config.community,
                    self._get_next_request_id(),
                    oids,  # Tous les OIDs
                    self.config.version
                )
                self._send_packet(snmp_data)
            
            time.sleep(1 / self.config.rate)
    
    def _generate_trap_storm(self):
        """Mode trap storm: génération massive de traps"""
        trap_oids = [
            "1.3.6.1.6.3.1.1.5.1",  # coldStart
            "1.3.6.1.6.3.1.1.5.2",  # warmStart
            "1.3.6.1.6.3.1.1.5.3",  # linkDown
            "1.3.6.1.6.3.1.1.5.4",  # linkUp
            "1.3.6.1.6.3.1.1.5.5",  # authenticationFailure
        ]
        
        uptime = 0
        
        while self.running and not self._check_limits():
            if self.paused:
                time.sleep(0.1)
                continue
            
            trap_oid = random.choice(trap_oids)
            
            snmp_data = self.builder.build_trap_v2(
                self.config.community,
                self._get_next_request_id(),
                uptime,
                trap_oid,
                [("1.3.6.1.2.1.1.5.0", "string", f"Device-{random.randint(1, 100)}")],
                self.config.version
            )
            
            self._send_packet(snmp_data, dst_port=162)
            
            uptime += 100
            time.sleep(1 / self.config.rate)
    
    def _generate_mixed(self):
        """Mode mixed: mélange de tous les types"""
        oids = list(SNMP_OIDS.values())
        
        while self.running and not self._check_limits():
            if self.paused:
                time.sleep(0.1)
                continue
            
            pdu_type = random.choice(["get", "getnext", "set", "trap"])
            
            if pdu_type == "get":
                snmp_data = self.builder.build_get_request(
                    self.config.community,
                    self._get_next_request_id(),
                    random.sample(oids, min(2, len(oids))),
                    self.config.version
                )
                self._send_packet(snmp_data)
            
            elif pdu_type == "getnext":
                snmp_data = self.builder.build_get_next_request(
                    self.config.community,
                    self._get_next_request_id(),
                    [random.choice(oids)],
                    self.config.version
                )
                self._send_packet(snmp_data)
            
            elif pdu_type == "set":
                oid = random.choice(list(SNMP_OIDS.values()))
                snmp_data = self.builder.build_set_request(
                    self.config.community,
                    self._get_next_request_id(),
                    oid,
                    "integer",
                    random.randint(0, 100),
                    self.config.version
                )
                self._send_packet(snmp_data)
            
            elif pdu_type == "trap":
                snmp_data = self.builder.build_trap_v2(
                    self.config.community,
                    self._get_next_request_id(),
                    random.randint(0, 1000000),
                    "1.3.6.1.6.3.1.1.5.3",
                    [],
                    self.config.version
                )
                self._send_packet(snmp_data, dst_port=162)
            
            time.sleep(1 / self.config.rate)
    
    def _generate_burst(self):
        """Mode burst: rafales de paquets"""
        oids = list(SNMP_OIDS.values())
        
        while self.running and not self._check_limits():
            if self.paused:
                time.sleep(0.1)
                continue
            
            # Rafale
            burst_size = random.randint(10, 50)
            for _ in range(burst_size):
                snmp_data = self.builder.build_get_request(
                    self.config.community,
                    self._get_next_request_id(),
                    random.sample(oids, 1),
                    self.config.version
                )
                self._send_packet(snmp_data)
            
            # Pause entre les rafales
            time.sleep(random.uniform(1, 3))
    
    def _check_limits(self) -> bool:
        """Vérifie si les limites sont atteintes"""
        if self.config.count > 0 and self.stats.packets_sent >= self.config.count:
            return True
        
        if self.config.duration > 0 and self.stats.duration >= self.config.duration:
            return True
        
        return False
    
    def start(self):
        """Démarre la génération"""
        if not SCAPY_AVAILABLE:
            print("Error: Scapy is required for packet generation")
            return False
        
        self.running = True
        self.paused = False
        self.stats = GeneratorStats()
        self.stats.start_time = time.time()
        
        self._notify("started", {"mode": self.config.mode.value})
        
        generators = {
            GeneratorMode.NORMAL: self._generate_normal,
            GeneratorMode.DISCOVERY: self._generate_discovery,
            GeneratorMode.STRESS: self._generate_stress,
            GeneratorMode.TRAP_STORM: self._generate_trap_storm,
            GeneratorMode.MIXED: self._generate_mixed,
            GeneratorMode.BURST: self._generate_burst,
            GeneratorMode.WALK: self._generate_discovery,
            GeneratorMode.ERROR_SIM: self._generate_mixed,
        }
        
        generator = generators.get(self.config.mode, self._generate_normal)
        
        thread = threading.Thread(target=generator, daemon=True)
        thread.start()
        
        return True
    
    def stop(self):
        """Arrête la génération"""
        self.running = False
        self._notify("stopped", {
            "packets_sent": self.stats.packets_sent,
            "duration": self.stats.duration
        })
    
    def pause(self):
        """Met en pause"""
        self.paused = True
        self._notify("paused", {})
    
    def resume(self):
        """Reprend"""
        self.paused = False
        self._notify("resumed", {})


# ==================== GUI ====================

COLORS = {
    "primary": "#FF5722",
    "secondary": "#D84315",
    "accent": "#FF8A65",
    "bg_dark": "#1A1A1A",
    "bg_medium": "#252525",
    "bg_light": "#333333",
    "text_light": "#FFFFFF",
    "text_muted": "#A0A0A0",
    "success": "#4CAF50",
    "warning": "#FFC107",
    "critical": "#F44336",
}


