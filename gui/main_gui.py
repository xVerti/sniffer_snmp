#!/usr/bin/env python3
"""
MIBurnout Suite V1 - Interface Graphique
=========================================
Version 5 - Tailles agrandies et lisibilite amelioree
"""

import customtkinter as ctk
from tkinter import filedialog
from threading import Thread, Event, Lock
from queue import Queue, Empty
import json, os, sys, time, traceback
from datetime import datetime
from typing import Dict, List
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

# Import des modules core
CORE_AVAILABLE = False
Sniffer = None
Analyser = None
DataBase = None
ConfAPP = None
get_detector = None

try:
    from core.sniffer import Sniffer as _Sniffer
    from core.analyser import Analyser as _Analyser
    from core.SQLiteDB import DataBase as _DataBase
    from core.confAPP import ConfAPP as _ConfAPP
    from core.anomaly_detector import get_detector as _get_detector
    
    Sniffer = _Sniffer
    Analyser = _Analyser
    DataBase = _DataBase
    ConfAPP = _ConfAPP
    get_detector = _get_detector
    CORE_AVAILABLE = True
    print("[+] Core modules loaded successfully")
except ImportError as e:
    print(f"[!] Core import error: {e}")
    traceback.print_exc()

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# === COULEURS ===
COLORS = {
    "bg_dark": "#0a0a0a",
    "bg_panel": "#111111", 
    "bg_card": "#1a1a1a",
    "bg_widget": "#222222",
    "bg_input": "#2a2a2a",
    "border": "#333333",
    "text": "#ffffff",
    "text_secondary": "#b0b0b0",
    "text_muted": "#707070",
    "primary": "#ff5722",
    "primary_light": "#ff8a65",
    "success": "#4ade80",
    "warning": "#fbbf24",
    "error": "#f87171",
    "info": "#60a5fa",
    "purple": "#c084fc",
    "cyan": "#22d3ee",
}

PDU_COLORS = {
    "SNMPget": "#60a5fa",
    "SNMPgetnext": "#c084fc", 
    "SNMPbulk": "#22d3ee",
    "SNMPset": "#fb923c",
    "SNMPresponse": "#4ade80",
    "SNMPtrap": "#f87171",
    "SNMPv2trap": "#f472b6",
    "SNMPinform": "#a78bfa",
}

ctk.set_appearance_mode("dark")


# =============================================================================
# WIDGETS DASHBOARD - TAILLES AGRANDIES
# =============================================================================

class BigGaugeWidget(ctk.CTkFrame):
    """Grande jauge circulaire lisible"""
    def __init__(self, parent, title="", max_val=100, color="#4ade80", **kwargs):
        self._title = title
        self._max_val = max_val
        self._color = color
        self._value = 0
        self._canvas = None
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=12, **kwargs)
        
        # Titre en haut
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=14, weight="bold"), 
                    text_color=COLORS["text_secondary"]).pack(pady=(15, 5))
        
        # Canvas pour la jauge
        self._canvas = ctk.CTkCanvas(self, bg=COLORS["bg_card"], highlightthickness=0,
                                    width=160, height=130)
        self._canvas.pack(pady=(0, 15))
        self._draw_gauge()
    
    def _draw(self, **kwargs):
        super()._draw(**kwargs)
    
    def _draw_gauge(self):
        if self._canvas is None:
            return
        self._canvas.delete("all")
        w, h = 160, 130
        cx, cy, r = w//2, h//2 + 10, 50
        
        # Arc de fond
        self._canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=135, extent=270,
                              style="arc", outline=COLORS["border"], width=12)
        
        # Arc de valeur
        pct = min(self._value / self._max_val, 1.0) if self._max_val > 0 else 0
        if pct > 0:
            self._canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=135, extent=270*pct,
                                  style="arc", outline=self._color, width=12)
        
        # Valeur centrale - GRANDE
        self._canvas.create_text(cx, cy-5, text=str(int(self._value)),
                               fill=self._color, font=("Helvetica", 32, "bold"))
        
        # Unite en dessous
        self._canvas.create_text(cx, cy+30, text=self._title,
                               fill=COLORS["text_muted"], font=("Helvetica", 11))
    
    def set_value(self, val):
        self._value = val
        self._draw_gauge()


class BigStatWidget(ctk.CTkFrame):
    """Grande carte statistique"""
    def __init__(self, parent, title="", color="#60a5fa", **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=12, **kwargs)
        self._color = color
        
        # Titre
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=13),
                    text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        
        # Valeur - TRES GRANDE
        self._value_label = ctk.CTkLabel(self, text="0", 
                                        font=ctk.CTkFont(size=42, weight="bold"),
                                        text_color=color)
        self._value_label.pack(anchor="w", padx=20, pady=(0, 15))
    
    def set_value(self, val):
        self._value_label.configure(text=str(int(val)))


class HorizontalBarChart(ctk.CTkFrame):
    """Graphique en barres horizontales - Grande taille"""
    def __init__(self, parent, title="", **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=12, **kwargs)
        self._title = title
        self._data = {}
        self._colors = ["#60a5fa", "#4ade80", "#c084fc", "#22d3ee", "#fb923c", "#fbbf24"]
        
        # Titre
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=15, weight="bold"),
                    text_color=COLORS["text"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        # Container des barres
        self._bars_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._bars_frame.pack(fill="both", expand=True, padx=20, pady=(0, 15))
    
    def set_data(self, data: Dict):
        self._data = data
        
        for widget in self._bars_frame.winfo_children():
            widget.destroy()
        
        if not data:
            ctk.CTkLabel(self._bars_frame, text="Aucune donnée", 
                        text_color=COLORS["text_muted"],
                        font=ctk.CTkFont(size=12)).pack(pady=20)
            return
        
        max_val = max(data.values()) if data else 1
        
        for i, (label, val) in enumerate(list(data.items())[:6]):
            row = ctk.CTkFrame(self._bars_frame, fg_color="transparent", height=35)
            row.pack(fill="x", pady=4)
            row.pack_propagate(False)
            
            # Label - PLUS GRAND
            ctk.CTkLabel(row, text=label[:15], width=120, 
                        font=ctk.CTkFont(size=12),
                        text_color=COLORS["text"], anchor="w").pack(side="left")
            
            # Container de la barre
            bar_container = ctk.CTkFrame(row, fg_color=COLORS["bg_widget"], 
                                        corner_radius=4, height=24)
            bar_container.pack(side="left", fill="x", expand=True, padx=10)
            
            # Barre de valeur
            pct = (val / max_val) if max_val > 0 else 0
            color = self._colors[i % len(self._colors)]
            
            if pct > 0:
                inner_bar = ctk.CTkFrame(bar_container, fg_color=color, 
                                        corner_radius=4, height=24)
                inner_bar.place(relx=0, rely=0, relwidth=max(pct, 0.02), relheight=1)
            
            # Valeur - PLUS GRANDE
            ctk.CTkLabel(row, text=str(int(val)), width=50,
                        font=ctk.CTkFont(size=13, weight="bold"),
                        text_color=color, anchor="e").pack(side="right")


class AlertsPanel(ctk.CTkFrame):
    """Panneau d'alertes avec dropdown"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=12, **kwargs)
        self._alerts = []
        self._expanded = False
        
        # Header cliquable
        self._header = ctk.CTkFrame(self, fg_color="transparent", cursor="hand2")
        self._header.pack(fill="x", padx=15, pady=12)
        self._header.bind("<Button-1>", self._toggle)
        
        self._title_label = ctk.CTkLabel(self._header, text="🚨 ALERTES", 
                                        font=ctk.CTkFont(size=15, weight="bold"),
                                        text_color=COLORS["error"])
        self._title_label.pack(side="left")
        self._title_label.bind("<Button-1>", self._toggle)
        
        self._count_label = ctk.CTkLabel(self._header, text="0", 
                                        font=ctk.CTkFont(size=14, weight="bold"),
                                        text_color=COLORS["warning"])
        self._count_label.pack(side="left", padx=(10, 0))
        self._count_label.bind("<Button-1>", self._toggle)
        
        self._arrow = ctk.CTkLabel(self._header, text="▼", 
                                  font=ctk.CTkFont(size=14),
                                  text_color=COLORS["text_muted"])
        self._arrow.pack(side="right")
        self._arrow.bind("<Button-1>", self._toggle)
        
        # Container des alertes
        self._container = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_widget"],
                                                height=250, corner_radius=8)
        
        # Bouton clear
        self._clear_btn = ctk.CTkButton(self, text="Effacer tout", height=32,
                                       fg_color=COLORS["bg_widget"], 
                                       hover_color=COLORS["error"],
                                       font=ctk.CTkFont(size=12),
                                       command=self.clear_alerts)
    
    def _toggle(self, event=None):
        self._expanded = not self._expanded
        if self._expanded:
            self._arrow.configure(text="▲")
            self._container.pack(fill="both", expand=True, padx=15, pady=(0, 10))
            self._clear_btn.pack(pady=(5, 15))
        else:
            self._arrow.configure(text="▼")
            self._container.pack_forget()
            self._clear_btn.pack_forget()
    
    def add_alert(self, alert):
        self._alerts.append(alert)
        self._count_label.configure(text=str(len(self._alerts)))
        
        colors = {"critical": COLORS["error"], "warning": COLORS["warning"], "info": COLORS["info"]}
        color = colors.get(alert.severity, COLORS["warning"])
        
        # Carte d'alerte - PLUS GRANDE
        card = ctk.CTkFrame(self._container, fg_color=COLORS["bg_card"], 
                           corner_radius=8, cursor="hand2")
        card.pack(fill="x", pady=5, padx=5)
        
        # Header
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(10, 5))
        
        severity_icons = {"critical": "🔴", "warning": "🟠", "info": "🔵"}
        icon = severity_icons.get(alert.severity, "⚪")
        
        ctk.CTkLabel(hdr, text=f"{icon} {alert.severity.upper()}",
                    font=ctk.CTkFont(size=12, weight="bold"), 
                    text_color=color).pack(side="left")
        
        ctk.CTkLabel(hdr, text=alert.timestamp[-8:],
                    font=ctk.CTkFont(size=11), 
                    text_color=COLORS["text_muted"]).pack(side="right")
        
        # Type d'anomalie
        ctk.CTkLabel(card, text=alert.anomaly_type, 
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=COLORS["text"]).pack(anchor="w", padx=12)
        
        # Source
        ctk.CTkLabel(card, text=f"Source: {alert.source_ip}", 
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_secondary"]).pack(anchor="w", padx=12, pady=(2, 10))
        
        # Clic pour détails
        card.bind("<Button-1>", lambda e, a=alert: self._show_detail(a))
        for child in card.winfo_children():
            child.bind("<Button-1>", lambda e, a=alert: self._show_detail(a))
    
    def _show_detail(self, alert):
        win = ctk.CTkToplevel(self)
        win.title("Détail de l'alerte")
        win.geometry("550x450")
        win.configure(fg_color=COLORS["bg_dark"])
        win.transient(self.winfo_toplevel())
        win.grab_set()
        
        colors = {"critical": COLORS["error"], "warning": COLORS["warning"], "info": COLORS["info"]}
        color = colors.get(alert.severity, COLORS["warning"])
        
        # Header
        hdr = ctk.CTkFrame(win, fg_color=COLORS["bg_panel"], height=60, corner_radius=0)
        hdr.pack(fill="x")
        
        ctk.CTkLabel(hdr, text=f"🚨 {alert.anomaly_type}", 
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=color).pack(side="left", padx=20, pady=15)
        
        # Contenu
        content = ctk.CTkFrame(win, fg_color=COLORS["bg_card"], corner_radius=12)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        infos = [
            ("Sévérité", alert.severity.upper()),
            ("Timestamp", alert.timestamp),
            ("Source IP", alert.source_ip),
            ("Type", alert.anomaly_type),
        ]
        
        for label, value in infos:
            row = ctk.CTkFrame(content, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=8)
            ctk.CTkLabel(row, text=f"{label}:", width=120, 
                        font=ctk.CTkFont(size=13),
                        text_color=COLORS["text_secondary"], anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(value), 
                        font=ctk.CTkFont(size=13, weight="bold"),
                        text_color=COLORS["text"]).pack(side="left", padx=10)
        
        # Message
        ctk.CTkLabel(content, text="Message:", 
                    font=ctk.CTkFont(size=13),
                    text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        
        msg_box = ctk.CTkTextbox(content, height=100, fg_color=COLORS["bg_widget"],
                                font=ctk.CTkFont(size=12))
        msg_box.pack(fill="x", padx=20, pady=(0, 20))
        msg_box.insert("1.0", alert.message)
        msg_box.configure(state="disabled")
        
        ctk.CTkButton(win, text="Fermer", command=win.destroy,
                     fg_color=COLORS["bg_widget"], height=35,
                     font=ctk.CTkFont(size=13)).pack(pady=15)
    
    def clear_alerts(self):
        self._alerts.clear()
        self._count_label.configure(text="0")
        for widget in self._container.winfo_children():
            widget.destroy()


# =============================================================================
# DASHBOARD TELEMETRIE
# =============================================================================

class TelemetryDashboard(ctk.CTkScrollableFrame):
    """Dashboard de telemetrie - Grande taille"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self._build()
    
    def _build(self):
        # === ROW 1: Jauges et Stats ===
        row1 = ctk.CTkFrame(self, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(15, 10))
        row1.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Jauge PPS
        self._gauge_pps = BigGaugeWidget(row1, title="PPS", max_val=50, 
                                        color=COLORS["success"])
        self._gauge_pps.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        
        # Jauge Threat
        self._gauge_threat = BigGaugeWidget(row1, title="Threat %", max_val=100,
                                           color=COLORS["warning"])
        self._gauge_threat.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        
        # Stat Total
        self._stat_total = BigStatWidget(row1, title="Total Packets", color=COLORS["info"])
        self._stat_total.grid(row=0, column=2, sticky="nsew", padx=8, pady=8)
        
        # Stat Suspects
        self._stat_suspects = BigStatWidget(row1, title="Suspects", color=COLORS["error"])
        self._stat_suspects.grid(row=0, column=3, sticky="nsew", padx=8, pady=8)
        
        # === ROW 2: Stats secondaires ===
        row2 = ctk.CTkFrame(self, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=5)
        row2.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        self._stat_get = BigStatWidget(row2, title="GET Requests", color=COLORS["info"])
        self._stat_get.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        
        self._stat_response = BigStatWidget(row2, title="Responses", color=COLORS["success"])
        self._stat_response.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        
        self._stat_set = BigStatWidget(row2, title="SET Operations", color=COLORS["warning"])
        self._stat_set.grid(row=0, column=2, sticky="nsew", padx=8, pady=8)
        
        self._stat_discovery = BigStatWidget(row2, title="Discovery", color=COLORS["purple"])
        self._stat_discovery.grid(row=0, column=3, sticky="nsew", padx=8, pady=8)
        
        # === ROW 3: Graphiques et Alertes ===
        row3 = ctk.CTkFrame(self, fg_color="transparent")
        row3.pack(fill="both", expand=True, padx=15, pady=10)
        row3.grid_columnconfigure((0, 1, 2), weight=1)
        row3.grid_rowconfigure(0, weight=1)
        
        # Graphique PDU
        self._chart_pdu = HorizontalBarChart(row3, title="📊 Distribution PDU")
        self._chart_pdu.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        
        # Graphique IPs
        self._chart_ips = HorizontalBarChart(row3, title="🌐 Top Sources IP")
        self._chart_ips.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        
        # Alertes
        self._alerts_panel = AlertsPanel(row3)
        self._alerts_panel.grid(row=0, column=2, sticky="nsew", padx=8, pady=8)
    
    def update_stats(self, packets, pps=0):
        total = len(packets)
        suspects = sum(1 for p in packets if p.get('tag') == 1)
        
        # Jauges
        self._gauge_pps.set_value(min(pps, 50))
        threat = (suspects / total * 100) if total > 0 else 0
        self._gauge_threat.set_value(threat)
        
        # Stats principales
        self._stat_total.set_value(total)
        self._stat_suspects.set_value(suspects)
        
        # Compteurs
        pdu_cnt = {}
        ip_cnt = {}
        get_cnt, resp_cnt, set_cnt, disc_cnt = 0, 0, 0, 0
        
        for p in packets[-1000:]:
            pdu = p.get('snmp_pdu_type', 'Unknown')
            pdu_cnt[pdu] = pdu_cnt.get(pdu, 0) + 1
            
            ip = p.get('ip_src', 'Unknown')
            ip_cnt[ip] = ip_cnt.get(ip, 0) + 1
            
            pdu_lower = pdu.lower()
            if 'get' in pdu_lower and 'response' not in pdu_lower and 'next' not in pdu_lower and 'bulk' not in pdu_lower:
                get_cnt += 1
            if 'response' in pdu_lower:
                resp_cnt += 1
            if 'set' in pdu_lower:
                set_cnt += 1
            if 'next' in pdu_lower or 'bulk' in pdu_lower:
                disc_cnt += 1
        
        # Stats secondaires
        self._stat_get.set_value(get_cnt)
        self._stat_response.set_value(resp_cnt)
        self._stat_set.set_value(set_cnt)
        self._stat_discovery.set_value(disc_cnt)
        
        # Graphiques
        top_pdu = dict(sorted(pdu_cnt.items(), key=lambda x: x[1], reverse=True)[:6])
        self._chart_pdu.set_data(top_pdu)
        
        top_ips = dict(sorted(ip_cnt.items(), key=lambda x: x[1], reverse=True)[:6])
        self._chart_ips.set_data(top_ips)
    
    def add_alert(self, alert):
        self._alerts_panel.add_alert(alert)
    
    def clear_alerts(self):
        self._alerts_panel.clear_alerts()


# =============================================================================
# FENETRE DETAIL PAQUET
# =============================================================================

class PacketDetailWindow(ctk.CTkToplevel):
    """Fenetre de detail - Grande et lisible"""
    def __init__(self, parent, pkt: Dict):
        super().__init__(parent)
        self._pkt = pkt
        self.title("Détail du paquet")
        self.geometry("800x650")
        self.configure(fg_color=COLORS["bg_dark"])
        self.transient(parent)
        self.grab_set()
        self._build()
    
    def _build(self):
        pdu = self._pkt.get('snmp_pdu_type', 'N/A')
        tag = self._pkt.get('tag', 0)
        
        # Header
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"], height=70, corner_radius=0)
        hdr.pack(fill="x")
        
        ctk.CTkLabel(hdr, text=f"📦 {pdu}", 
                    font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=PDU_COLORS.get(pdu, COLORS["text"])).pack(side="left", padx=25, pady=20)
        
        tag_txt = "⚠️ SUSPECT" if tag == 1 else "✓ AUTORISÉ"
        tag_col = COLORS["error"] if tag == 1 else COLORS["success"]
        ctk.CTkLabel(hdr, text=tag_txt, 
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=tag_col).pack(side="right", padx=25)
        
        # Contenu scrollable
        content = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_dark"])
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Sections
        self._add_section(content, "⏱️ TIMESTAMP", [
            ("Date/Heure", self._pkt.get('time_stamp'))
        ])
        
        self._add_section(content, "🌐 RÉSEAU", [
            ("MAC Source", self._pkt.get('mac_src')),
            ("MAC Destination", self._pkt.get('mac_dst')),
            ("IP Source", self._pkt.get('ip_src')),
            ("IP Destination", self._pkt.get('ip_dst')),
            ("Port Source", self._pkt.get('port_src')),
            ("Port Destination", self._pkt.get('port_dst')),
        ])
        
        version = "SNMPv1" if str(self._pkt.get('snmp_version')) == '0' else "SNMPv2c"
        self._add_section(content, "📡 SNMP", [
            ("Version", version),
            ("Community", self._pkt.get('snmp_community')),
            ("Type PDU", self._pkt.get('snmp_pdu_type')),
            ("Request ID", self._pkt.get('snmp_request_id')),
            ("Error Status", self._pkt.get('snmp_error_status', 0)),
            ("Error Index", self._pkt.get('snmp_error_index', 0)),
        ])
        
        # OIDs
        oids = self._parse_oids()
        if oids:
            oid_card = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=12)
            oid_card.pack(fill="x", pady=10)
            
            ctk.CTkLabel(oid_card, text=f"📊 VARIABLE BINDINGS ({len(oids)} OIDs)",
                        font=ctk.CTkFont(size=14, weight="bold"),
                        text_color=COLORS["cyan"]).pack(anchor="w", padx=20, pady=(15, 10))
            
            for i, oid in enumerate(oids[:12], 1):
                oid_frame = ctk.CTkFrame(oid_card, fg_color=COLORS["bg_widget"], corner_radius=6)
                oid_frame.pack(fill="x", padx=20, pady=4)
                
                ctk.CTkLabel(oid_frame, text=f"[{i}] {oid.get('oid', 'N/A')}",
                            font=ctk.CTkFont(size=11), 
                            text_color=COLORS["info"]).pack(anchor="w", padx=12, pady=(8, 2))
                
                val = str(oid.get('value', 'N/A'))[:80]
                ctk.CTkLabel(oid_frame, text=f"= {val}",
                            font=ctk.CTkFont(size=11), 
                            text_color=COLORS["success"]).pack(anchor="w", padx=20, pady=(0, 8))
            
            if len(oids) > 12:
                ctk.CTkLabel(oid_card, text=f"... et {len(oids) - 12} autres OIDs",
                            font=ctk.CTkFont(size=11), 
                            text_color=COLORS["text_muted"]).pack(pady=(5, 15))
        
        # Bouton fermer
        ctk.CTkButton(self, text="Fermer", command=self.destroy,
                     fg_color=COLORS["bg_widget"], height=40,
                     font=ctk.CTkFont(size=14)).pack(pady=15)
    
    def _add_section(self, parent, title, items):
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"], corner_radius=12)
        card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(card, text=title, 
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["primary_light"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        for k, v in items:
            if v is None:
                continue
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=4)
            
            ctk.CTkLabel(row, text=f"{k}:", width=150,
                        font=ctk.CTkFont(size=12),
                        text_color=COLORS["text_secondary"], anchor="w").pack(side="left")
            
            ctk.CTkLabel(row, text=str(v),
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=COLORS["text"]).pack(side="left", padx=10)
        
        # Padding en bas
        ctk.CTkFrame(card, fg_color="transparent", height=10).pack()
    
    def _parse_oids(self):
        oids = self._pkt.get('snmp_oidsValues', [])
        if isinstance(oids, str):
            try:
                return json.loads(oids).get('oidsValues', [])
            except:
                return []
        return oids if isinstance(oids, list) else []


# =============================================================================
# CLIENT API
# =============================================================================

class APIClientWidget(ctk.CTkFrame):
    """Client API REST - Taille agrandie"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self._base_url = "http://127.0.0.1:5000"
        self._build()
    
    def _build(self):
        if not REQUESTS_AVAILABLE:
            ctk.CTkLabel(self, text="Module 'requests' non disponible\npip install requests",
                        font=ctk.CTkFont(size=16),
                        text_color=COLORS["error"]).pack(pady=50)
            return
        
        # Header
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"], corner_radius=12)
        hdr.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(hdr, text="🔌 Client API REST", 
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["primary"]).pack(side="left", padx=20, pady=15)
        
        url_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        url_frame.pack(side="right", padx=20, pady=15)
        
        ctk.CTkLabel(url_frame, text="Base URL:", 
                    font=ctk.CTkFont(size=12)).pack(side="left", padx=5)
        self._url_entry = ctk.CTkEntry(url_frame, width=200, height=35,
                                      font=ctk.CTkFont(size=12))
        self._url_entry.insert(0, self._base_url)
        self._url_entry.pack(side="left", padx=5)
        
        # Requete
        req_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12)
        req_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        row1 = ctk.CTkFrame(req_frame, fg_color="transparent")
        row1.pack(fill="x", padx=20, pady=15)
        
        self._method_var = ctk.StringVar(value="GET")
        ctk.CTkOptionMenu(row1, values=["GET", "POST", "PUT", "DELETE"],
                         variable=self._method_var, width=100, height=35,
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=5)
        
        self._endpoint_entry = ctk.CTkEntry(row1, width=350, height=35,
                                           placeholder_text="/api/status",
                                           font=ctk.CTkFont(size=12))
        self._endpoint_entry.insert(0, "/api/status")
        self._endpoint_entry.pack(side="left", padx=15)
        
        ctk.CTkButton(row1, text="▶ Envoyer", command=self._send_request,
                     fg_color=COLORS["success"], width=120, height=35,
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=10)
        
        # Raccourcis
        shortcuts = ctk.CTkFrame(req_frame, fg_color="transparent")
        shortcuts.pack(fill="x", padx=20, pady=(0, 15))
        
        ctk.CTkLabel(shortcuts, text="Raccourcis:", 
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_muted"]).pack(side="left", padx=5)
        
        for ep, label in [("/api/status", "Status"), ("/api/stats", "Stats"),
                          ("/api/packets", "Packets"), ("/api/alerts", "Alerts"),
                          ("/api/capture/start", "Start"), ("/api/capture/stop", "Stop")]:
            ctk.CTkButton(shortcuts, text=label, width=70, height=28,
                         fg_color=COLORS["bg_widget"],
                         font=ctk.CTkFont(size=11),
                         command=lambda e=ep: self._set_endpoint(e)).pack(side="left", padx=3)
        
        # Body
        body_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12)
        body_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        ctk.CTkLabel(body_frame, text="Corps de la requête (JSON):",
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        
        self._body_text = ctk.CTkTextbox(body_frame, height=80, 
                                        fg_color=COLORS["bg_input"],
                                        font=ctk.CTkFont(family="Courier", size=12))
        self._body_text.pack(fill="x", padx=20, pady=(0, 15))
        self._body_text.insert("1.0", '{"interface": "eth0"}')
        
        # Response
        resp_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12)
        resp_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        resp_hdr = ctk.CTkFrame(resp_frame, fg_color="transparent")
        resp_hdr.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(resp_hdr, text="Réponse",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["info"]).pack(side="left")
        
        self._status_label = ctk.CTkLabel(resp_hdr, text="",
                                         font=ctk.CTkFont(size=12),
                                         text_color=COLORS["text_muted"])
        self._status_label.pack(side="right")
        
        self._response_text = ctk.CTkTextbox(resp_frame, fg_color=COLORS["bg_input"],
                                            font=ctk.CTkFont(family="Courier", size=12))
        self._response_text.pack(fill="both", expand=True, padx=20, pady=(0, 15))
    
    def _set_endpoint(self, ep):
        self._endpoint_entry.delete(0, "end")
        self._endpoint_entry.insert(0, ep)
        self._method_var.set("POST" if "start" in ep or "stop" in ep else "GET")
    
    def _send_request(self):
        base = self._url_entry.get().strip().rstrip("/")
        endpoint = self._endpoint_entry.get().strip()
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = base + endpoint
        method = self._method_var.get()
        
        self._response_text.delete("1.0", "end")
        self._status_label.configure(text="Envoi en cours...", text_color=COLORS["warning"])
        
        def do_request():
            try:
                headers = {"Content-Type": "application/json"}
                body = None
                if method in ["POST", "PUT"]:
                    try:
                        body = json.loads(self._body_text.get("1.0", "end").strip())
                    except:
                        body = {}
                
                start = time.time()
                if method == "GET":
                    r = requests.get(url, headers=headers, timeout=10)
                elif method == "POST":
                    r = requests.post(url, json=body, headers=headers, timeout=10)
                elif method == "PUT":
                    r = requests.put(url, json=body, headers=headers, timeout=10)
                else:
                    r = requests.delete(url, headers=headers, timeout=10)
                elapsed = (time.time() - start) * 1000
                
                self.after(0, lambda: self._show_response(r, elapsed))
            except requests.exceptions.ConnectionError:
                self.after(0, lambda: self._show_error("Connexion refusée - L'API est-elle lancée?"))
            except Exception as e:
                self.after(0, lambda: self._show_error(str(e)))
        
        Thread(target=do_request, daemon=True).start()
    
    def _show_response(self, r, elapsed):
        color = COLORS["success"] if r.status_code < 400 else COLORS["error"]
        self._status_label.configure(text=f"Status: {r.status_code} | {elapsed:.0f}ms", text_color=color)
        try:
            formatted = json.dumps(r.json(), indent=2, ensure_ascii=False)
        except:
            formatted = r.text
        self._response_text.delete("1.0", "end")
        self._response_text.insert("1.0", formatted)
    
    def _show_error(self, msg):
        self._status_label.configure(text="Erreur", text_color=COLORS["error"])
        self._response_text.delete("1.0", "end")
        self._response_text.insert("1.0", f"Erreur: {msg}")


# =============================================================================
# LISTE DES PAQUETS - AGRANDIE
# =============================================================================

class PacketListWidget(ctk.CTkFrame):
    """Liste des paquets - Taille agrandie et lisible"""
    def __init__(self, parent, on_select=None, on_detail=None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_panel"], corner_radius=12, **kwargs)
        self._on_select = on_select
        self._on_detail = on_detail
        self.packets = []
        self._rows = []
        self._lock = Lock()
        self._build()
    
    def _build(self):
        # Header avec colonnes - PLUS GRAND
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=8)
        hdr.pack(fill="x", padx=8, pady=8)
        
        columns = [
            ("", 35),           # Bouton detail
            ("#", 50),          # Index
            ("Timestamp", 110), # Heure
            ("IP Source", 140), # IP source
            ("IP Dest", 140),   # IP dest
            ("Type PDU", 120),  # Type
            ("Community", 100), # Community
            ("Status", 60),     # Tag
        ]
        
        for txt, w in columns:
            ctk.CTkLabel(hdr, text=txt, width=w, 
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=COLORS["primary_light"], anchor="w").pack(side="left", padx=4, pady=10)
        
        # Liste scrollable
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_dark"])
        self._list_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
    
    def add_packet(self, pkt: Dict):
        with self._lock:
            self.packets.append(pkt)
            idx = len(self.packets) - 1
            
            if len(self._rows) >= 300:
                old_row = self._rows.pop(0)
                try:
                    old_row.destroy()
                except:
                    pass
            
            self._create_row(pkt, idx)
        
        try:
            self._list_frame._parent_canvas.yview_moveto(1.0)
        except:
            pass
    
    def _create_row(self, pkt: Dict, idx: int):
        pdu_type = str(pkt.get('snmp_pdu_type', 'N/A'))
        tag = pkt.get('tag', 0)
        
        # Couleur de fond
        if tag == 1:
            bg = "#2d1818"
        else:
            bg = COLORS["bg_card"] if idx % 2 == 0 else COLORS["bg_widget"]
        
        row = ctk.CTkFrame(self._list_frame, fg_color=bg, corner_radius=6, height=38)
        row.pack(fill="x", pady=2, padx=4)
        row.pack_propagate(False)
        
        # Bouton detail
        btn = ctk.CTkButton(row, text="👁", width=30, height=28,
                           fg_color=COLORS["bg_dark"], hover_color=COLORS["info"],
                           font=ctk.CTkFont(size=11),
                           command=lambda p=pkt: self._show_detail(p))
        btn.pack(side="left", padx=(6, 4), pady=5)
        
        row.bind("<Button-1>", lambda e, i=idx: self._on_row_click(i))
        
        # Timestamp
        ts = str(pkt.get('time_stamp', ''))
        if len(ts) > 12:
            ts = ts[-12:]
        
        pdu_color = PDU_COLORS.get(pdu_type, COLORS["text"])
        tag_text = "⚠️" if tag == 1 else "✓"
        tag_color = COLORS["error"] if tag == 1 else COLORS["success"]
        
        data = [
            (str(idx + 1), 50, COLORS["text_muted"]),
            (ts, 110, COLORS["text"]),
            (str(pkt.get('ip_src', ''))[:18], 140, COLORS["text"]),
            (str(pkt.get('ip_dst', ''))[:18], 140, COLORS["text_secondary"]),
            (pdu_type[:15], 120, pdu_color),
            (str(pkt.get('snmp_community', ''))[:12], 100, COLORS["text_muted"]),
            (tag_text, 60, tag_color),
        ]
        
        for text, width, color in data:
            lbl = ctk.CTkLabel(row, text=text, width=width,
                              font=ctk.CTkFont(size=11),
                              text_color=color, anchor="w")
            lbl.pack(side="left", padx=4)
            lbl.bind("<Button-1>", lambda e, i=idx: self._on_row_click(i))
        
        self._rows.append(row)
    
    def _show_detail(self, pkt):
        if self._on_detail:
            self._on_detail(pkt)
    
    def _on_row_click(self, idx):
        if self._on_select and idx < len(self.packets):
            self._on_select(self.packets[idx])
    
    def clear(self):
        with self._lock:
            self.packets.clear()
            for row in self._rows:
                try:
                    row.destroy()
                except:
                    pass
            self._rows.clear()
    
    def get_stats(self):
        with self._lock:
            total = len(self.packets)
            suspects = sum(1 for p in self.packets if p.get('tag') == 1)
        return {"total": total, "ok": total - suspects, "suspect": suspects}


# =============================================================================
# APPLICATION PRINCIPALE
# =============================================================================

class MIBurnoutApp(ctk.CTk):
    """Application principale MIBurnout Suite"""
    
    def __init__(self):
        super().__init__()
        self.title("MIBurnout Suite v1.0")
        self.geometry("1500x900")
        self.configure(fg_color=COLORS["bg_dark"])
        
        # Variables
        self._queue = Queue(maxsize=10000)
        self._db = None
        self._config_mgr = None
        self._sniffer = None
        self._analyser = None
        self._detector = None
        
        self._is_capturing = False
        self._stop_event = Event()
        self._capture_thread = None
        
        self._interface = "eth0"
        self._snmp_filter = "udp port 161 or udp port 162"
        self._db_file = "miburnout.db"
        self._config_file = os.path.join(ROOT_DIR, "config", "conf.json")
        self._pcap_dir = os.path.join(ROOT_DIR, "captures")
        
        self._last_pkt_count = 0
        self._pps = 0.0
        
        self._setup_ui()
        self._init_core()
        self.after(1000, self._update_loop)
    
    def _init_core(self):
        if not CORE_AVAILABLE:
            self._status_label.configure(text="⚠ Core modules non disponibles", text_color=COLORS["error"])
            return
        
        try:
            os.makedirs(self._pcap_dir, exist_ok=True)
            os.makedirs(os.path.dirname(self._config_file), exist_ok=True)
            
            self._db = DataBase(dbFile=self._db_file)
            self._db.initDB()
            
            self._config_mgr = ConfAPP(confFile=self._config_file)
            if self._config_mgr.config is None:
                self._config_mgr.creatConf()
            
            self._detector = get_detector()
            
            self._status_label.configure(text="✓ Prêt", text_color=COLORS["success"])
        except Exception as e:
            print(f"[!] Init error: {e}")
            traceback.print_exc()
            self._status_label.configure(text=f"⚠ Erreur: {e}", text_color=COLORS["error"])
    
    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # ===== HEADER =====
        header = ctk.CTkFrame(self, height=70, fg_color=COLORS["bg_panel"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        
        # Logo
        logo_frame = ctk.CTkFrame(header, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=12, sticky="w")
        
        ctk.CTkLabel(logo_frame, text="🔥 MIBurnout", 
                    font=ctk.CTkFont(size=24, weight="bold"),
                    text_color=COLORS["primary"]).pack(side="left")
        ctk.CTkLabel(logo_frame, text=" Suite v1", 
                    font=ctk.CTkFont(size=14),
                    text_color=COLORS["text_secondary"]).pack(side="left", anchor="s", pady=5)
        
        # Controls
        ctrl_frame = ctk.CTkFrame(header, fg_color="transparent")
        ctrl_frame.grid(row=0, column=1, pady=12)
        
        ctk.CTkLabel(ctrl_frame, text="Interface:", 
                    font=ctk.CTkFont(size=13),
                    text_color=COLORS["text_secondary"]).pack(side="left", padx=8)
        
        self._if_entry = ctk.CTkEntry(ctrl_frame, width=100, height=35,
                                     font=ctk.CTkFont(size=13))
        self._if_entry.insert(0, self._interface)
        self._if_entry.pack(side="left", padx=5)
        
        self._start_btn = ctk.CTkButton(ctrl_frame, text="▶ Start", 
                                       command=self.start_capture,
                                       fg_color=COLORS["success"], width=90, height=35,
                                       font=ctk.CTkFont(size=13, weight="bold"))
        self._start_btn.pack(side="left", padx=10)
        
        self._stop_btn = ctk.CTkButton(ctrl_frame, text="⏹ Stop", 
                                      command=self.stop_capture,
                                      fg_color=COLORS["error"], width=90, height=35,
                                      font=ctk.CTkFont(size=13, weight="bold"), 
                                      state="disabled")
        self._stop_btn.pack(side="left", padx=5)
        
        ctk.CTkButton(ctrl_frame, text="🗑", command=self.clear_all,
                     fg_color=COLORS["bg_widget"], width=40, height=35,
                     font=ctk.CTkFont(size=14)).pack(side="left", padx=10)
        
        # Status
        status_frame = ctk.CTkFrame(header, fg_color="transparent")
        status_frame.grid(row=0, column=2, padx=20, pady=12, sticky="e")
        
        self._capture_indicator = ctk.CTkLabel(status_frame, text="● STOPPED",
                                              font=ctk.CTkFont(size=13, weight="bold"),
                                              text_color=COLORS["error"])
        self._capture_indicator.pack(side="left", padx=15)
        
        self._time_label = ctk.CTkLabel(status_frame, text="",
                                       font=ctk.CTkFont(size=13),
                                       text_color=COLORS["text_muted"])
        self._time_label.pack(side="left", padx=10)
        
        # ===== TABS =====
        self._tabview = ctk.CTkTabview(self, fg_color=COLORS["bg_panel"],
                                      segmented_button_fg_color=COLORS["bg_card"],
                                      segmented_button_selected_color=COLORS["primary"],
                                      segmented_button_selected_hover_color=COLORS["primary_light"])
        self._tabview.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="nsew")
        
        # Configurer la taille des onglets
        self._tabview._segmented_button.configure(font=ctk.CTkFont(size=14))
        
        tab_dashboard = self._tabview.add("📊 Dashboard")
        tab_capture = self._tabview.add("📡 Capture")
        tab_db = self._tabview.add("🗄️ Database")
        tab_api = self._tabview.add("🔌 API")
        
        self._build_dashboard_tab(tab_dashboard)
        self._build_capture_tab(tab_capture)
        self._build_db_tab(tab_db)
        self._build_api_tab(tab_api)
        
        # ===== STATUS BAR =====
        statusbar = ctk.CTkFrame(self, height=30, fg_color=COLORS["bg_panel"], corner_radius=0)
        statusbar.grid(row=2, column=0, sticky="ew")
        
        self._status_label = ctk.CTkLabel(statusbar, text="Initialisation...",
                                         font=ctk.CTkFont(size=11),
                                         text_color=COLORS["text_muted"])
        self._status_label.pack(side="left", padx=15, pady=5)
        
        core_status = "✓ Core OK" if CORE_AVAILABLE else "✗ Core manquant"
        core_color = COLORS["success"] if CORE_AVAILABLE else COLORS["error"]
        ctk.CTkLabel(statusbar, text=core_status,
                    font=ctk.CTkFont(size=11),
                    text_color=core_color).pack(side="right", padx=15)
    
    def _build_dashboard_tab(self, tab):
        self._dashboard = TelemetryDashboard(tab)
        self._dashboard.pack(fill="both", expand=True)
    
    def _build_capture_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=3)
        tab.grid_rowconfigure(2, weight=2)
        
        # Toolbar
        toolbar = ctk.CTkFrame(tab, fg_color=COLORS["bg_card"], corner_radius=10)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="Filtre BPF:",
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_secondary"]).pack(side="left", padx=(15, 8), pady=12)
        
        self._filter_entry = ctk.CTkEntry(toolbar, width=300, height=32,
                                         font=ctk.CTkFont(size=12))
        self._filter_entry.insert(0, self._snmp_filter)
        self._filter_entry.pack(side="left", padx=5)
        
        ctk.CTkButton(toolbar, text="💾 Export JSON", command=self.export_data,
                     fg_color=COLORS["info"], width=120, height=32,
                     font=ctk.CTkFont(size=12)).pack(side="right", padx=15, pady=12)
        
        self._stats_label = ctk.CTkLabel(toolbar, text="Packets: 0 | Suspects: 0",
                                        font=ctk.CTkFont(size=13, weight="bold"),
                                        text_color=COLORS["primary_light"])
        self._stats_label.pack(side="right", padx=20)
        
        # Packet list
        self._packet_list = PacketListWidget(tab, on_select=self._on_packet_select,
                                            on_detail=self._on_packet_detail)
        self._packet_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
        
        # Detail panel
        detail_frame = ctk.CTkFrame(tab, fg_color=COLORS["bg_panel"], corner_radius=10)
        detail_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(detail_frame, text="📝 Détails du paquet sélectionné",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["primary"]).pack(anchor="w", padx=15, pady=10)
        
        self._detail_text = ctk.CTkTextbox(detail_frame, fg_color=COLORS["bg_dark"],
                                          font=ctk.CTkFont(family="Courier", size=12))
        self._detail_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_db_tab(self, tab):
        toolbar = ctk.CTkFrame(tab, fg_color=COLORS["bg_card"], corner_radius=10)
        toolbar.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="🗄️ Base de données SQLite",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=COLORS["primary"]).pack(side="left", padx=20, pady=12)
        
        ctk.CTkLabel(toolbar, text="Table:",
                    font=ctk.CTkFont(size=12)).pack(side="left", padx=(20, 8))
        
        self._table_var = ctk.StringVar(value="snmp_v2")
        ctk.CTkOptionMenu(toolbar, values=["snmp_v1", "snmp_v2"],
                         variable=self._table_var, command=self.load_database,
                         width=120, height=32,
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=5)
        
        ctk.CTkButton(toolbar, text="🔄 Recharger",
                     command=lambda: self.load_database(self._table_var.get()),
                     fg_color=COLORS["info"], width=100, height=32,
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=15)
        
        self._db_count_label = ctk.CTkLabel(toolbar, text="0 entrées",
                                           font=ctk.CTkFont(size=13),
                                           text_color=COLORS["primary_light"])
        self._db_count_label.pack(side="right", padx=20)
        
        self._db_text = ctk.CTkTextbox(tab, fg_color=COLORS["bg_dark"],
                                      font=ctk.CTkFont(family="Courier", size=11))
        self._db_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_api_tab(self, tab):
        self._api_client = APIClientWidget(tab)
        self._api_client.pack(fill="both", expand=True)
    
    # =========================================================================
    # CAPTURE
    # =========================================================================
    
    def start_capture(self):
        if not CORE_AVAILABLE:
            self._status_label.configure(text="⚠ Core modules non disponibles!", text_color=COLORS["error"])
            return
        
        if self._is_capturing:
            return
        
        self._interface = self._if_entry.get().strip() or "eth0"
        self._snmp_filter = self._filter_entry.get().strip() or "udp port 161 or udp port 162"
        
        try:
            self._queue = Queue(maxsize=10000)
            self._stop_event.clear()
            
            self._sniffer = Sniffer(iface=self._interface, sfilter=self._snmp_filter, queue=self._queue)
            
            cfg = self._config_mgr.config if self._config_mgr else {}
            self._analyser = Analyser(queue=self._queue, baseDB=self._db, config=cfg,
                                     pcap_dir=self._pcap_dir, lenPcap=100)
            
            self._is_capturing = True
            
            Thread(target=self._sniffer.start_sniffer, daemon=True).start()
            self._capture_thread = Thread(target=self._capture_loop, daemon=True)
            self._capture_thread.start()
            
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            self._capture_indicator.configure(text="● CAPTURING", text_color=COLORS["success"])
            self._status_label.configure(text=f"Capture sur {self._interface}...", text_color=COLORS["success"])
            
        except Exception as e:
            print(f"[!] Start error: {e}")
            traceback.print_exc()
            self._status_label.configure(text=f"⚠ Erreur: {e}", text_color=COLORS["error"])
    
    def _capture_loop(self):
        while self._is_capturing and not self._stop_event.is_set():
            try:
                pkt = self._queue.get(timeout=0.5)
            except Empty:
                continue
            except:
                continue
            
            try:
                data = self._analyser.packet_info(pkt)
            except:
                data = {"time_stamp": str(datetime.now()), "ip_src": "?", "ip_dst": "?",
                        "snmp_pdu_type": "Unknown", "tag": 0}
            
            try:
                data["tag"] = 0 if self._analyser.compare(data) else 1
            except:
                data["tag"] = 0
            
            try:
                if self._detector:
                    alerts = self._detector.analyze_packet(data)
                    if alerts:
                        for alert in alerts:
                            self.after(0, lambda a=alert: self._dashboard.add_alert(a))
            except:
                pass
            
            try:
                db_data = self._prepare_db_data(data)
                version = str(data.get("snmp_version", "1"))
                table = "snmp_v1" if version == "0" else "snmp_v2"
                self._db.wrData(table, db_data)
            except:
                pass
            
            try:
                if self._analyser and hasattr(self._analyser, 'pcap_writer') and self._analyser.pcap_writer:
                    self._analyser.pcap_writer.write(pkt)
                    self._analyser.nb_pkt += 1
                    if self._analyser.nb_pkt >= self._analyser.lenPcap:
                        self._analyser.open_new_pcap()
            except:
                pass
            
            try:
                pkt_copy = data.copy()
                self.after(0, lambda d=pkt_copy: self._packet_list.add_packet(d))
            except:
                pass
            
            try:
                self._queue.task_done()
            except:
                pass
    
    def _prepare_db_data(self, data):
        result = {
            "time_stamp": data.get("time_stamp"),
            "mac_src": data.get("mac_src"),
            "mac_dst": data.get("mac_dst"),
            "ip_src": data.get("ip_src"),
            "ip_dst": data.get("ip_dst"),
            "port_src": data.get("port_src"),
            "port_dst": data.get("port_dst"),
            "snmp_community": data.get("snmp_community"),
            "snmp_pdu_type": data.get("snmp_pdu_type"),
            "snmp_oidsValues": json.dumps({"oidsValues": data.get("snmp_oidsValues", [])}),
            "tag": data.get("tag", 0)
        }
        
        version = str(data.get("snmp_version", "1"))
        if version == "0":
            result.update({
                "snmp_enterprise": data.get("snmp_enterprise"),
                "snmp_agent_addr": data.get("snmp_agent_addr"),
                "snmp_generic_trap": data.get("snmp_generic_trap"),
                "snmp_specific_trap": data.get("snmp_specific_trap"),
                "snmp_request_id": data.get("snmp_request_id"),
                "snmp_error_status": data.get("snmp_error_status"),
                "snmp_error_index": data.get("snmp_error_index")
            })
        else:
            result.update({
                "snmp_request_id": data.get("snmp_request_id"),
                "snmp_error_status": data.get("snmp_error_status"),
                "snmp_error_index": data.get("snmp_error_index"),
                "snmp_non_repeaters": data.get("snmp_non_repeaters"),
                "snmp_max_repetitions": data.get("snmp_max_repetitions")
            })
        
        return {k: v for k, v in result.items() if v is not None}
    
    def stop_capture(self):
        self._is_capturing = False
        self._stop_event.set()
        
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._capture_indicator.configure(text="● STOPPED", text_color=COLORS["warning"])
        self._status_label.configure(text="Capture arrêtée", text_color=COLORS["text_muted"])
        
        if self._analyser and hasattr(self._analyser, 'pcap_writer') and self._analyser.pcap_writer:
            try:
                self._analyser.pcap_writer.close()
            except:
                pass
    
    def clear_all(self):
        self._packet_list.clear()
        self._detail_text.delete("1.0", "end")
        self._update_stats_label()
        if self._detector:
            self._detector.clear_alerts()
        self._dashboard.clear_alerts()
    
    def _update_loop(self):
        self._time_label.configure(text=datetime.now().strftime("%H:%M:%S"))
        self._update_stats_label()
        
        current_count = len(self._packet_list.packets)
        self._pps = current_count - self._last_pkt_count
        self._last_pkt_count = current_count
        
        self._dashboard.update_stats(self._packet_list.packets, self._pps)
        
        self.after(1000, self._update_loop)
    
    def _update_stats_label(self):
        stats = self._packet_list.get_stats()
        self._stats_label.configure(
            text=f"Packets: {stats['total']} | OK: {stats['ok']} | Suspects: {stats['suspect']}"
        )
    
    def _on_packet_select(self, pkt):
        self._detail_text.delete("1.0", "end")
        
        oids = pkt.get('snmp_oidsValues', [])
        if isinstance(oids, str):
            try:
                oids = json.loads(oids).get('oidsValues', [])
            except:
                oids = []
        
        version = "SNMPv1" if str(pkt.get('snmp_version')) == '0' else "SNMPv2c"
        tag_str = "⚠️ SUSPECT" if pkt.get('tag') == 1 else "✓ AUTORISÉ"
        
        text = f"""
{'='*60}
                    DÉTAILS DU PAQUET
{'='*60}

  TIMESTAMP     {pkt.get('time_stamp', 'N/A')}

  RÉSEAU
  ─────────────────────────────────────────
  MAC Source    {pkt.get('mac_src', 'N/A')}
  MAC Dest      {pkt.get('mac_dst', 'N/A')}
  IP Source     {pkt.get('ip_src', 'N/A')}
  IP Dest       {pkt.get('ip_dst', 'N/A')}
  Ports         {pkt.get('port_src', 'N/A')} → {pkt.get('port_dst', 'N/A')}

  SNMP
  ─────────────────────────────────────────
  Version       {version}
  Community     {pkt.get('snmp_community', 'N/A')}
  Type PDU      {pkt.get('snmp_pdu_type', 'N/A')}
  Request ID    {pkt.get('snmp_request_id', 'N/A')}
  Error Status  {pkt.get('snmp_error_status', 0)}
  Error Index   {pkt.get('snmp_error_index', 0)}

  STATUS        {tag_str}

  OIDs ({len(oids)} variables)
  ─────────────────────────────────────────
"""
        for i, oid in enumerate(oids[:8], 1):
            oid_str = oid.get('oid', 'N/A')
            val_str = str(oid.get('value', 'N/A'))[:45]
            text += f"  [{i}] {oid_str}\n       = {val_str}\n\n"
        
        if len(oids) > 8:
            text += f"  ... et {len(oids) - 8} autres OIDs\n"
        
        self._detail_text.insert("1.0", text)
    
    def _on_packet_detail(self, pkt):
        PacketDetailWindow(self, pkt)
    
    def load_database(self, table=None):
        if not self._db:
            return
        
        table = table or self._table_var.get()
        
        try:
            if not self._db.table_exists(table):
                self._db_text.delete("1.0", "end")
                self._db_text.insert("1.0", f"Table '{table}' n'existe pas")
                return
            
            columns = [c[1] for c in self._db.getChamps(table)]
            rows = self._db.getData(table=table, columns=["*"])
            
            self._db_count_label.configure(text=f"{len(rows)} entrées")
            
            self._db_text.delete("1.0", "end")
            self._db_text.insert("1.0", f"Table: {table}\nColonnes: {', '.join(columns)}\n{'='*100}\n\n")
            
            for row in rows[-80:]:
                row_str = " | ".join(str(v)[:25] for v in row)
                self._db_text.insert("end", row_str + "\n")
            
            if len(rows) > 80:
                self._db_text.insert("end", f"\n... et {len(rows) - 80} autres entrées")
                
        except Exception as e:
            self._status_label.configure(text=f"DB Error: {e}", text_color=COLORS["error"])
    
    def export_data(self):
        if not self._packet_list.packets:
            self._status_label.configure(text="Aucune donnée à exporter", text_color=COLORS["warning"])
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self._packet_list.packets, f, indent=2, default=str, ensure_ascii=False)
                self._status_label.configure(text=f"Exporté: {os.path.basename(filename)}",
                                            text_color=COLORS["success"])
            except Exception as e:
                self._status_label.configure(text=f"Erreur export: {e}", text_color=COLORS["error"])


def main():
    app = MIBurnoutApp()
    app.mainloop()


if __name__ == "__main__":
    main()
