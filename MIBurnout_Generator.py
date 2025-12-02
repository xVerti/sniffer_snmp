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
    rate: int = 10
    duration: int = 0
    interface: str = ""
    count: int = 0
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

# Couleurs GUI
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
    def encode_varbind(oid: str, value_type: str = "null", value=None) -> bytes:
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
        
        varbinds = b''.join([SNMPPacketBuilder.encode_varbind(oid) for oid in oids])
        varbind_list = SNMPPacketBuilder.encode_sequence(varbinds)
        
        pdu_content = (
            SNMPPacketBuilder.encode_integer(request_id) +
            SNMPPacketBuilder.encode_integer(0) +
            SNMPPacketBuilder.encode_integer(0) +
            varbind_list
        )
        pdu = bytes([0xA0]) + SNMPPacketBuilder.encode_length(len(pdu_content)) + pdu_content
        
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
    def build_set_request(community: str, request_id: int, oid: str, value_type: str, value, version: str = "2c") -> bytes:
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
        sys_varbinds = (
            SNMPPacketBuilder.encode_varbind("1.3.6.1.2.1.1.3.0", "integer", uptime) +
            SNMPPacketBuilder.encode_varbind("1.3.6.1.6.3.1.1.4.1.0", "string", trap_oid)
        )
        
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
            SNMPPacketBuilder.encode_integer(1) +
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
            
            for _ in range(10):
                snmp_data = self.builder.build_get_request(
                    self.config.community,
                    self._get_next_request_id(),
                    oids,
                    self.config.version
                )
                self._send_packet(snmp_data)
            
            time.sleep(1 / self.config.rate)
    
    def _generate_trap_storm(self):
        """Mode trap storm: génération massive de traps"""
        trap_oids = [
            "1.3.6.1.6.3.1.1.5.1",
            "1.3.6.1.6.3.1.1.5.2",
            "1.3.6.1.6.3.1.1.5.3",
            "1.3.6.1.6.3.1.1.5.4",
            "1.3.6.1.6.3.1.1.5.5",
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
            
            burst_size = random.randint(10, 50)
            for _ in range(burst_size):
                snmp_data = self.builder.build_get_request(
                    self.config.community,
                    self._get_next_request_id(),
                    random.sample(oids, 1),
                    self.config.version
                )
                self._send_packet(snmp_data)
            
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

class GeneratorGUI:
    """Interface graphique du générateur"""
    
    def __init__(self):
        if not CTK_AVAILABLE:
            raise RuntimeError("CustomTkinter not available")
        
        self.root = ctk.CTk()
        self.root.title("MIBurnout SNMP Generator")
        self.root.geometry("800x650")
        self.root.configure(fg_color=COLORS["bg_dark"])
        
        self.config = GeneratorConfig()
        self.generator: Optional[SNMPTrafficGenerator] = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface"""
        ctk.set_appearance_mode("dark")
        
        # Header
        header = ctk.CTkFrame(self.root, fg_color=COLORS["bg_medium"], height=60)
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text="MIBurnout Generator", font=ctk.CTkFont(size=20, weight="bold"), text_color=COLORS["primary"]).pack(side="left", padx=20, pady=15)
        
        self.status_label = ctk.CTkLabel(header, text="Arrete", text_color=COLORS["critical"])
        self.status_label.pack(side="right", padx=20)
        
        # Main content
        main = ctk.CTkFrame(self.root, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=20, pady=20)
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)
        
        # Configuration panel
        config_frame = ctk.CTkFrame(main, fg_color=COLORS["bg_light"], corner_radius=10)
        config_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
        
        ctk.CTkLabel(config_frame, text="Configuration", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["accent"]).pack(pady=15)
        
        # Target
        target_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        target_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(target_frame, text="Target IP:", width=100).pack(side="left")
        self.target_entry = ctk.CTkEntry(target_frame, width=200)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side="left", padx=10)
        
        # Port
        port_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        port_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(port_frame, text="Port:", width=100).pack(side="left")
        self.port_entry = ctk.CTkEntry(port_frame, width=100)
        self.port_entry.insert(0, "161")
        self.port_entry.pack(side="left", padx=10)
        
        # Community
        comm_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        comm_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(comm_frame, text="Community:", width=100).pack(side="left")
        self.community_entry = ctk.CTkEntry(comm_frame, width=150)
        self.community_entry.insert(0, "public")
        self.community_entry.pack(side="left", padx=10)
        
        # Mode
        ctk.CTkLabel(config_frame, text="Mode:", text_color=COLORS["text_light"]).pack(anchor="w", padx=20, pady=(10, 5))
        
        self.mode_var = ctk.StringVar(value="normal")
        modes = [("Normal", "normal"), ("Discovery", "discovery"), ("Stress", "stress"), 
                 ("Trap Storm", "trap_storm"), ("Mixed", "mixed"), ("Burst", "burst")]
        
        for text, value in modes:
            ctk.CTkRadioButton(config_frame, text=text, variable=self.mode_var, value=value, 
                              fg_color=COLORS["primary"]).pack(anchor="w", padx=30, pady=2)
        
        # Rate
        rate_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        rate_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(rate_frame, text="Rate (pps):", width=100).pack(side="left")
        self.rate_slider = ctk.CTkSlider(rate_frame, from_=1, to=100, number_of_steps=99, 
                                         fg_color=COLORS["bg_medium"], progress_color=COLORS["primary"])
        self.rate_slider.set(10)
        self.rate_slider.pack(side="left", fill="x", expand=True, padx=10)
        self.rate_label = ctk.CTkLabel(rate_frame, text="10", width=40)
        self.rate_label.pack(side="right")
        self.rate_slider.configure(command=lambda v: self.rate_label.configure(text=str(int(v))))
        
        # Interface
        if SCAPY_AVAILABLE:
            iface_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
            iface_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(iface_frame, text="Interface:", width=100).pack(side="left")
            interfaces = get_if_list()
            self.iface_var = ctk.StringVar(value=interfaces[0] if interfaces else "")
            ctk.CTkOptionMenu(iface_frame, values=interfaces if interfaces else [""], variable=self.iface_var, width=150).pack(side="left", padx=10)
        else:
            self.iface_var = ctk.StringVar(value="")
        
        # Stats panel
        stats_frame = ctk.CTkFrame(main, fg_color=COLORS["bg_light"], corner_radius=10)
        stats_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
        
        ctk.CTkLabel(stats_frame, text="Statistiques", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["accent"]).pack(pady=15)
        
        self.stats_labels = {}
        for stat in ["Paquets envoyes", "Octets envoyes", "Erreurs", "Duree", "Debit"]:
            frame = ctk.CTkFrame(stats_frame, fg_color=COLORS["bg_medium"])
            frame.pack(fill="x", padx=20, pady=3)
            ctk.CTkLabel(frame, text=stat, text_color=COLORS["text_muted"]).pack(side="left", padx=10, pady=8)
            label = ctk.CTkLabel(frame, text="0", text_color=COLORS["text_light"], font=ctk.CTkFont(weight="bold"))
            label.pack(side="right", padx=10, pady=8)
            self.stats_labels[stat] = label
        
        # Logs
        ctk.CTkLabel(stats_frame, text="Logs", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["accent"]).pack(pady=(20, 5))
        
        self.logs_text = ctk.CTkTextbox(stats_frame, fg_color=COLORS["bg_dark"], height=150, font=ctk.CTkFont(family="Courier", size=10))
        self.logs_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Buttons
        btn_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=20)
        
        self.start_btn = ctk.CTkButton(btn_frame, text="Demarrer", command=self.start_generator, 
                                       fg_color=COLORS["success"], width=150, height=40)
        self.start_btn.pack(side="left", padx=10)
        
        self.stop_btn = ctk.CTkButton(btn_frame, text="Arreter", command=self.stop_generator,
                                      fg_color=COLORS["critical"], width=150, height=40, state="disabled")
        self.stop_btn.pack(side="left", padx=10)
        
        ctk.CTkButton(btn_frame, text="Clear Logs", command=self.clear_logs,
                     fg_color=COLORS["bg_light"], width=100, height=40).pack(side="right", padx=10)
    
    def log(self, message: str):
        """Ajoute un message aux logs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs_text.insert("end", f"[{timestamp}] {message}\n")
        self.logs_text.see("end")
    
    def clear_logs(self):
        """Efface les logs"""
        self.logs_text.delete("1.0", "end")
    
    def update_stats(self):
        """Met à jour les statistiques"""
        if self.generator:
            stats = self.generator.stats
            self.stats_labels["Paquets envoyes"].configure(text=str(stats.packets_sent))
            self.stats_labels["Octets envoyes"].configure(text=f"{stats.bytes_sent:,}")
            self.stats_labels["Erreurs"].configure(text=str(stats.errors))
            self.stats_labels["Duree"].configure(text=f"{stats.duration:.1f}s")
            self.stats_labels["Debit"].configure(text=f"{stats.rate:.1f} pps")
        
        if self.generator and self.generator.running:
            self.root.after(500, self.update_stats)
    
    def on_generator_event(self, event: str, data: Dict):
        """Callback pour les événements du générateur"""
        self.root.after(0, lambda: self.log(f"{event}: {data}"))
    
    def start_generator(self):
        """Démarre le générateur"""
        if not SCAPY_AVAILABLE:
            self.log("ERREUR: Scapy n'est pas installe!")
            return
        
        # Configuration
        self.config.target = self.target_entry.get()
        self.config.port = int(self.port_entry.get())
        self.config.community = self.community_entry.get()
        self.config.mode = GeneratorMode(self.mode_var.get())
        self.config.rate = int(self.rate_slider.get())
        self.config.interface = self.iface_var.get()
        
        # Créer et démarrer
        self.generator = SNMPTrafficGenerator(self.config)
        self.generator.add_callback(self.on_generator_event)
        
        if self.generator.start():
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.status_label.configure(text="En cours", text_color=COLORS["success"])
            self.log(f"Demarre - Mode: {self.config.mode.value}, Target: {self.config.target}")
            self.update_stats()
        else:
            self.log("ERREUR: Impossible de demarrer le generateur")
    
    def stop_generator(self):
        """Arrête le générateur"""
        if self.generator:
            self.generator.stop()
            self.log(f"Arrete - {self.generator.stats.packets_sent} paquets envoyes")
        
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="Arrete", text_color=COLORS["critical"])
    
    def run(self):
        """Lance l'application"""
        self.root.mainloop()


# ==================== CLI ====================

def run_cli(args):
    """Exécute en mode CLI"""
    config = GeneratorConfig(
        target=args.target,
        port=args.port,
        community=args.community,
        version=args.version,
        mode=GeneratorMode(args.mode),
        rate=args.rate,
        duration=args.duration,
        count=args.count,
        interface=args.interface,
        verbose=args.verbose
    )
    
    def on_event(event, data):
        if config.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {event}: {data}")
    
    generator = SNMPTrafficGenerator(config)
    generator.add_callback(on_event)
    
    print(f"MIBurnout SNMP Generator")
    print(f"Target: {config.target}:{config.port}")
    print(f"Mode: {config.mode.value}")
    print(f"Rate: {config.rate} pps")
    print("-" * 40)
    
    if not generator.start():
        print("Failed to start generator")
        return 1
    
    try:
        while generator.running:
            time.sleep(1)
            stats = generator.stats
            print(f"\rPackets: {stats.packets_sent} | Rate: {stats.rate:.1f} pps | Duration: {stats.duration:.1f}s", end="")
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    
    generator.stop()
    
    print(f"\n\nFinal stats:")
    print(f"  Packets sent: {generator.stats.packets_sent}")
    print(f"  Bytes sent: {generator.stats.bytes_sent}")
    print(f"  Errors: {generator.stats.errors}")
    print(f"  Duration: {generator.stats.duration:.2f}s")
    print(f"  Average rate: {generator.stats.rate:.2f} pps")
    
    return 0


def main():
    parser = argparse.ArgumentParser(description="MIBurnout SNMP Traffic Generator")
    
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=161, help="Target port")
    parser.add_argument("--community", "-c", default="public", help="SNMP community string")
    parser.add_argument("--version", "-V", default="2c", choices=["1", "2c"], help="SNMP version")
    parser.add_argument("--mode", "-m", default="normal", 
                       choices=["normal", "discovery", "stress", "trap_storm", "mixed", "burst"],
                       help="Generation mode")
    parser.add_argument("--rate", "-r", type=int, default=10, help="Packets per second")
    parser.add_argument("--duration", "-d", type=int, default=0, help="Duration in seconds (0=infinite)")
    parser.add_argument("--count", "-n", type=int, default=0, help="Number of packets (0=infinite)")
    parser.add_argument("--interface", "-i", default="", help="Network interface")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.gui:
        if not CTK_AVAILABLE:
            print("Error: CustomTkinter not installed. Install with: pip install customtkinter")
            return 1
        
        app = GeneratorGUI()
        app.run()
        return 0
    else:
        return run_cli(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
