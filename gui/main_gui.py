#!/usr/bin/env python3
"""
MIBurnout Suite V1 - Interface Graphique Principale
====================================================
Interface complète pour le monitoring, la capture et l'analyse SNMP.
Intègre le backend de capture avec une interface utilisateur moderne.

Requiert: pip install customtkinter scapy
Optionnel: pip install matplotlib (pour graphiques)
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from threading import Thread
from queue import Queue
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import deque

# Ajout du chemin pour les imports locaux
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import des modules core
try:
    from core.sniffer import Sniffer
    from core.analyser import Analyser
    from core.SQLiteDB import DataBase
    from core.confAPP import ConfAPP
    from core.anomaly_detector import AnomalyDetector, get_detector
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core modules not fully available: {e}")
    CORE_AVAILABLE = False

# Import matplotlib optionnel
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Configuration
APP_VERSION = "1.0.0"
APP_NAME = "MIBurnout Suite"

# Charte graphique
COLORS = {
    "primary": "#FF5722",
    "secondary": "#D84315",
    "accent": "#FF8A65",
    "bg_dark": "#1A1A1A",
    "bg_medium": "#252525",
    "bg_light": "#333333",
    "bg_lighter": "#404040",
    "text_light": "#FFFFFF",
    "text_muted": "#A0A0A0",
    "text_dark": "#000000",
    "success": "#4CAF50",
    "warning": "#FFC107",
    "critical": "#F44336",
    "info": "#2196F3",
    "blue": "#4A90E2",
    "purple": "#9B59B6",
    "cyan": "#00BCD4",
}

PDU_COLORS = {
    "SNMPget": COLORS["blue"],
    "SNMPgetnext": COLORS["purple"],
    "SNMPbulk": COLORS["cyan"],
    "SNMPset": COLORS["warning"],
    "SNMPresponse": COLORS["success"],
    "SNMPtrap": COLORS["critical"],
    "GetRequest": COLORS["blue"],
    "GetNextRequest": COLORS["purple"],
    "SetRequest": COLORS["warning"],
    "GetResponse": COLORS["success"],
    "Trap": COLORS["critical"],
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NotificationManager:
    def __init__(self, parent):
        self.parent = parent
        self.notifications = deque(maxlen=50)
    
    def show(self, message: str, type: str = "info", duration: int = 3000):
        colors = {"info": COLORS["info"], "success": COLORS["success"], 
                  "warning": COLORS["warning"], "error": COLORS["critical"]}
        
        notif = ctk.CTkToplevel(self.parent)
        notif.overrideredirect(True)
        notif.attributes("-topmost", True)
        
        screen_width = self.parent.winfo_screenwidth()
        notif.geometry(f"350x60+{screen_width - 370}+50")
        
        frame = ctk.CTkFrame(notif, fg_color=colors.get(type, COLORS["info"]), corner_radius=10)
        frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        ctk.CTkLabel(frame, text=message, font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_light"], wraplength=320).pack(pady=15, padx=15)
        
        self.parent.after(duration, notif.destroy)


class GraphWidget(ctk.CTkFrame):
    def __init__(self, parent, title: str = "", **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_medium"], corner_radius=8, **kwargs)
        self.title = title
        
        if not MATPLOTLIB_AVAILABLE:
            ctk.CTkLabel(self, text="Graphiques non disponibles\n(pip install matplotlib)", 
                        text_color=COLORS["text_muted"]).pack(pady=50)
            return
        
        self.figure = Figure(figsize=(5, 3), dpi=100, facecolor=COLORS["bg_medium"])
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor(COLORS["bg_dark"])
        self.ax.tick_params(colors=COLORS["text_muted"])
        
        if title:
            self.ax.set_title(title, color=COLORS["text_light"], fontsize=10)
        
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
    
    def plot_bar(self, labels: List[str], values: List[float], colors: List[str] = None):
        if not MATPLOTLIB_AVAILABLE:
            return
        self.ax.clear()
        self.ax.set_facecolor(COLORS["bg_dark"])
        bar_colors = colors or [COLORS["primary"]] * len(labels)
        self.ax.bar(labels, values, color=bar_colors)
        self.ax.tick_params(colors=COLORS["text_muted"], labelrotation=45)
        self.figure.tight_layout()
        self.canvas.draw()


class PacketListWidget(ctk.CTkFrame):
    def __init__(self, parent, on_select: Callable = None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_light"], corner_radius=8, **kwargs)
        
        self.on_select = on_select
        self.packets: List[Dict] = []
        self.selected_index = -1
        self.marked_indices: set = set()
        
        # Headers
        headers_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_medium"])
        headers_frame.pack(fill="x", padx=5, pady=(5, 0))
        
        headers = [("", 25), ("No.", 50), ("Time", 85), ("Source", 120), ("Destination", 120),
                   ("Type", 100), ("Community", 80), ("Tag", 50), ("Info", 300)]
        
        for text, width in headers:
            ctk.CTkLabel(headers_frame, text=text, font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=COLORS["accent"], width=width, anchor="w").pack(side="left", padx=2, pady=5)
        
        self.list_frame = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_dark"])
        self.list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.visible_rows: List[ctk.CTkFrame] = []
        self.max_visible = 500
    
    def add_packet(self, packet: Dict):
        self.packets.append(packet)
        
        if len(self.visible_rows) >= self.max_visible:
            old_row = self.visible_rows.pop(0)
            old_row.destroy()
        
        self._create_row(packet, len(self.packets) - 1)
        self.list_frame._parent_canvas.yview_moveto(1.0)
    
    def _create_row(self, packet: Dict, index: int):
        pdu_type = str(packet.get('snmp_pdu_type', ''))
        color = PDU_COLORS.get(pdu_type, COLORS["text_light"])
        tag = packet.get('tag', 0)
        
        bg_color = "#3D2020" if tag == 1 else COLORS["bg_medium"]
        
        row = ctk.CTkFrame(self.list_frame, fg_color=bg_color, corner_radius=3, height=24)
        row.pack(fill="x", pady=1)
        row.bind("<Button-1>", lambda e, idx=index: self._on_click(idx))
        
        # Marqueur
        mark_text = "★" if index in self.marked_indices else ""
        ctk.CTkLabel(row, text=mark_text, width=25, text_color=COLORS["warning"]).pack(side="left", padx=2)
        
        # Info OIDs
        oids_values = packet.get('snmp_oidsValues', '{}')
        if isinstance(oids_values, str):
            try:
                oids_data = json.loads(oids_values)
                oids_list = oids_data.get('oidsValues', [])
            except:
                oids_list = []
        else:
            oids_list = oids_values if isinstance(oids_values, list) else []
        
        info = ""
        if oids_list:
            first_oid = oids_list[0] if oids_list else {}
            info = f"{first_oid.get('oid', '')} = {first_oid.get('value', '')}"[:50]
        
        data = [
            (str(index + 1), 50, COLORS["text_muted"]),
            (str(packet.get('time_stamp', ''))[-15:], 85, COLORS["text_light"]),
            (str(packet.get('ip_src', '')), 120, COLORS["text_light"]),
            (str(packet.get('ip_dst', '')), 120, COLORS["text_light"]),
            (pdu_type, 100, color),
            (str(packet.get('snmp_community', '')), 80, COLORS["text_muted"]),
            ("⚠" if tag == 1 else "✓", 50, COLORS["critical"] if tag == 1 else COLORS["success"]),
            (info, 300, COLORS["text_light"]),
        ]
        
        for text, width, col in data:
            lbl = ctk.CTkLabel(row, text=text, font=ctk.CTkFont(size=10), text_color=col, width=width, anchor="w")
            lbl.pack(side="left", padx=2)
            lbl.bind("<Button-1>", lambda e, idx=index: self._on_click(idx))
        
        self.visible_rows.append(row)
    
    def _on_click(self, index: int):
        self.selected_index = index
        if self.on_select and index < len(self.packets):
            self.on_select(self.packets[index])
    
    def clear(self):
        self.packets.clear()
        self.marked_indices.clear()
        self.selected_index = -1
        for row in self.visible_rows:
            row.destroy()
        self.visible_rows.clear()
    
    def get_stats(self) -> Dict:
        total = len(self.packets)
        suspects = sum(1 for p in self.packets if p.get('tag') == 1)
        return {"total": total, "authorized": total - suspects, "suspects": suspects, "marked": len(self.marked_indices)}


class MIBurnoutApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1600x900")
        self.configure(fg_color=COLORS["bg_dark"])
        
        self.notification = NotificationManager(self)
        self.queue = Queue(maxsize=10000)
        self.db: Optional[DataBase] = None
        self.config_manager: Optional[ConfAPP] = None
        self.sniffer: Optional[Sniffer] = None
        self.analyser: Optional[Analyser] = None
        self.anomaly_detector: Optional[AnomalyDetector] = None
        
        self.is_capturing = False
        self.packets_captured = 0
        self.packets_suspect = 0
        
        self.interface = "eth0"
        self.snmp_filter = "udp port 161 or udp port 162"
        self.db_file = "miburnout.db"
        self.config_file = "config/conf.json"
        self.pcap_dir = "captures"
        
        self._setup_ui()
        self._init_components()
        self.after(100, self._update_ui)
    
    def _init_components(self):
        if not CORE_AVAILABLE:
            self.notification.show("Modules core non disponibles", "warning")
            return
        
        try:
            self.db = DataBase(dbFile=self.db_file)
            self.db.initDB()
            
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base_dir, self.config_file)
            self.config_manager = ConfAPP(confFile=config_path)
            if self.config_manager.config is None:
                self.config_manager.creatConf()
            
            self.anomaly_detector = get_detector()
            self.notification.show("Composants initialisés", "success")
        except Exception as e:
            self.notification.show(f"Erreur init: {str(e)[:50]}", "error")
    
    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        self._create_header()
        self._create_main_content()
        self._create_status_bar()
    
    def _create_header(self):
        header = ctk.CTkFrame(self, height=60, fg_color=COLORS["bg_medium"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        
        logo_frame = ctk.CTkFrame(header, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        
        ctk.CTkLabel(logo_frame, text="🔥 MIBurnout", font=ctk.CTkFont(size=24, weight="bold"), 
                    text_color=COLORS["primary"]).pack(side="left")
        ctk.CTkLabel(logo_frame, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=10), 
                    text_color=COLORS["text_muted"]).pack(side="left", padx=(10, 0), anchor="s")
        
        control_frame = ctk.CTkFrame(header, fg_color="transparent")
        control_frame.grid(row=0, column=1, padx=20, pady=10)
        
        ctk.CTkLabel(control_frame, text="Interface:").pack(side="left", padx=5)
        self.interface_entry = ctk.CTkEntry(control_frame, width=100)
        self.interface_entry.insert(0, self.interface)
        self.interface_entry.pack(side="left", padx=5)
        
        self.start_btn = ctk.CTkButton(control_frame, text="▶ Démarrer", command=self.start_capture,
                                       fg_color=COLORS["success"], width=120)
        self.start_btn.pack(side="left", padx=10)
        
        self.stop_btn = ctk.CTkButton(control_frame, text="⏹ Arrêter", command=self.stop_capture,
                                      fg_color=COLORS["critical"], width=100, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        ctk.CTkButton(control_frame, text="🗑 Clear", command=self.clear_all,
                     fg_color=COLORS["bg_light"], width=80).pack(side="left", padx=5)
        
        status_frame = ctk.CTkFrame(header, fg_color="transparent")
        status_frame.grid(row=0, column=2, padx=20, pady=10, sticky="e")
        
        self.capture_indicator = ctk.CTkLabel(status_frame, text="● Arrêté", font=ctk.CTkFont(size=11), 
                                              text_color=COLORS["critical"])
        self.capture_indicator.pack(side="left", padx=10)
        
        self.time_label = ctk.CTkLabel(status_frame, text="", font=ctk.CTkFont(size=11), 
                                       text_color=COLORS["text_muted"])
        self.time_label.pack(side="left", padx=10)
    
    def _create_main_content(self):
        self.tabview = ctk.CTkTabview(self, fg_color=COLORS["bg_medium"],
                                      segmented_button_fg_color=COLORS["bg_light"],
                                      segmented_button_selected_color=COLORS["primary"])
        self.tabview.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="nsew")
        
        self.tab_capture = self.tabview.add("📡 Capture")
        self.tab_analysis = self.tabview.add("📊 Analyse")
        self.tab_alerts = self.tabview.add("🚨 Alertes")
        self.tab_db = self.tabview.add("🗄️ Base de Données")
        
        self._setup_capture_tab()
        self._setup_analysis_tab()
        self._setup_alerts_tab()
        self._setup_db_tab()
    
    def _setup_capture_tab(self):
        self.tab_capture.grid_columnconfigure(0, weight=1)
        self.tab_capture.grid_rowconfigure(1, weight=3)
        self.tab_capture.grid_rowconfigure(2, weight=2)
        
        toolbar = ctk.CTkFrame(self.tab_capture, fg_color=COLORS["bg_light"], corner_radius=8)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="Filtre BPF:").pack(side="left", padx=(10, 5), pady=8)
        self.filter_entry = ctk.CTkEntry(toolbar, width=300)
        self.filter_entry.insert(0, self.snmp_filter)
        self.filter_entry.pack(side="left", padx=5)
        
        ctk.CTkButton(toolbar, text="💾 Export JSON", command=lambda: self.export_data("json"),
                     fg_color=COLORS["blue"], width=100).pack(side="right", padx=5, pady=8)
        
        self.stats_label = ctk.CTkLabel(toolbar, text="Paquets: 0 | Suspects: 0", text_color=COLORS["accent"])
        self.stats_label.pack(side="right", padx=20)
        
        self.packet_list = PacketListWidget(self.tab_capture, on_select=self._on_packet_select)
        self.packet_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 5))
        
        details_frame = ctk.CTkFrame(self.tab_capture, fg_color=COLORS["bg_light"], corner_radius=8)
        details_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(5, 10))
        
        ctk.CTkLabel(details_frame, text="📝 Détails du Paquet", font=ctk.CTkFont(size=12, weight="bold"), 
                    text_color=COLORS["primary"]).pack(anchor="w", padx=10, pady=5)
        
        self.details_text = ctk.CTkTextbox(details_frame, fg_color=COLORS["bg_dark"], 
                                           font=ctk.CTkFont(family="Courier", size=11))
        self.details_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))
    
    def _setup_analysis_tab(self):
        self.tab_analysis.grid_columnconfigure(0, weight=1)
        self.tab_analysis.grid_columnconfigure(1, weight=1)
        self.tab_analysis.grid_rowconfigure(1, weight=1)
        
        toolbar = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"])
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="📊 Analyse du Trafic", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["primary"]).pack(side="left", padx=20, pady=10)
        
        ctk.CTkButton(toolbar, text="🔄 Actualiser", command=self.refresh_analysis,
                     fg_color=COLORS["accent"], text_color=COLORS["text_dark"]).pack(side="right", padx=20, pady=10)
        
        self.pdu_graph = GraphWidget(self.tab_analysis, title="Distribution des PDU")
        self.pdu_graph.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=(0, 10))
        
        stats_frame = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"])
        stats_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))
        
        ctk.CTkLabel(stats_frame, text="Statistiques", font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["accent"]).pack(pady=10)
        
        self.stats_text = ctk.CTkTextbox(stats_frame, fg_color=COLORS["bg_dark"])
        self.stats_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _setup_alerts_tab(self):
        self.tab_alerts.grid_columnconfigure(0, weight=1)
        self.tab_alerts.grid_rowconfigure(1, weight=1)
        
        toolbar = ctk.CTkFrame(self.tab_alerts, fg_color=COLORS["bg_light"])
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="🚨 Alertes de Sécurité", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["critical"]).pack(side="left", padx=20, pady=10)
        
        self.alert_count_label = ctk.CTkLabel(toolbar, text="0 alertes", text_color=COLORS["accent"])
        self.alert_count_label.pack(side="right", padx=20)
        
        ctk.CTkButton(toolbar, text="🗑 Effacer", command=self.clear_alerts,
                     fg_color=COLORS["bg_medium"]).pack(side="right", padx=5)
        
        self.alerts_list = ctk.CTkScrollableFrame(self.tab_alerts, fg_color=COLORS["bg_light"])
        self.alerts_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
    
    def _setup_db_tab(self):
        self.tab_db.grid_columnconfigure(0, weight=1)
        self.tab_db.grid_rowconfigure(1, weight=1)
        
        toolbar = ctk.CTkFrame(self.tab_db, fg_color=COLORS["bg_light"])
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="🗄️ Base de Données SQLite", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["primary"]).pack(side="left", padx=20, pady=10)
        
        ctk.CTkLabel(toolbar, text="Table:").pack(side="left", padx=(20, 5))
        self.table_var = ctk.StringVar(value="snmp_v2")
        ctk.CTkOptionMenu(toolbar, values=["snmp_v1", "snmp_v2"], variable=self.table_var,
                         command=self.load_db_data).pack(side="left", padx=5)
        
        ctk.CTkButton(toolbar, text="🔄 Recharger", 
                     command=lambda: self.load_db_data(self.table_var.get())).pack(side="left", padx=10)
        
        self.db_count_label = ctk.CTkLabel(toolbar, text="0 entrées", text_color=COLORS["accent"])
        self.db_count_label.pack(side="right", padx=20)
        
        self.db_text = ctk.CTkTextbox(self.tab_db, fg_color=COLORS["bg_dark"],
                                      font=ctk.CTkFont(family="Courier", size=10))
        self.db_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
    
    def _create_status_bar(self):
        status_bar = ctk.CTkFrame(self, height=25, fg_color=COLORS["bg_medium"], corner_radius=0)
        status_bar.grid(row=2, column=0, sticky="ew")
        
        self.status_text = ctk.CTkLabel(status_bar, text="Prêt", font=ctk.CTkFont(size=10),
                                        text_color=COLORS["text_muted"])
        self.status_text.pack(side="left", padx=10, pady=3)
        
        ctk.CTkLabel(status_bar, text=f"DB: {self.db_file}", font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_muted"]).pack(side="right", padx=10, pady=3)
    
    def start_capture(self):
        if not CORE_AVAILABLE:
            self.notification.show("Modules core non disponibles", "error")
            return
        
        if self.is_capturing:
            return
        
        self.interface = self.interface_entry.get() or self.interface
        self.snmp_filter = self.filter_entry.get() or self.snmp_filter
        
        try:
            self.sniffer = Sniffer(iface=self.interface, sfilter=self.snmp_filter, queue=self.queue)
            
            config = self.config_manager.config if self.config_manager else {}
            self.analyser = Analyser(queue=self.queue, baseDB=self.db, config=config,
                                     pcap_dir=self.pcap_dir, lenPcap=100)
            
            self.sniffer_thread = Thread(target=self.sniffer.start_sniffer, daemon=True)
            self.sniffer_thread.start()
            
            self.analyser_thread = Thread(target=self._analyser_loop, daemon=True)
            self.analyser_thread.start()
            
            self.is_capturing = True
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.capture_indicator.configure(text="● Capture en cours", text_color=COLORS["success"])
            self.status_text.configure(text=f"Capture sur {self.interface}...")
            
            self.notification.show(f"Capture démarrée sur {self.interface}", "success")
        except Exception as e:
            self.notification.show(f"Erreur: {str(e)[:50]}", "error")
    
    def _analyser_loop(self):
        while self.is_capturing:
            try:
                if not self.queue.empty():
                    pkt = self.queue.get(timeout=0.1)
                    
                    full_data = self.analyser.packet_info(pkt)
                    
                    if self.analyser.compare(full_data):
                        full_data["tag"] = 0
                    else:
                        full_data["tag"] = 1
                        self.packets_suspect += 1
                    
                    if self.anomaly_detector:
                        alerts = self.anomaly_detector.analyze_packet(full_data)
                        if alerts:
                            self.after(0, lambda a=alerts: self._add_alerts(a))
                    
                    db_data = self._prepare_db_data(full_data)
                    version = str(full_data.get("snmp_version", "1"))
                    table = "snmp_v1" if version == "0" else "snmp_v2"
                    
                    self.db.wrData(table, db_data)
                    
                    self.analyser.pcap_writer.write(pkt)
                    self.analyser.nb_pkt += 1
                    if self.analyser.nb_pkt >= self.analyser.lenPcap:
                        self.analyser.open_new_pcap()
                    
                    self.packets_captured += 1
                    self.after(0, lambda d=full_data: self.packet_list.add_packet(d))
                    self.queue.task_done()
            except:
                pass
    
    def _prepare_db_data(self, full_data: dict) -> dict:
        db_data = {
            "time_stamp": full_data.get("time_stamp"),
            "mac_src": full_data.get("mac_src"),
            "mac_dst": full_data.get("mac_dst"),
            "ip_src": full_data.get("ip_src"),
            "ip_dst": full_data.get("ip_dst"),
            "port_src": full_data.get("port_src"),
            "port_dst": full_data.get("port_dst"),
            "snmp_community": full_data.get("snmp_community"),
            "snmp_pdu_type": full_data.get("snmp_pdu_type"),
            "snmp_oidsValues": json.dumps({"oidsValues": full_data.get("snmp_oidsValues", [])}),
            "tag": full_data.get("tag", 0)
        }
        
        version = str(full_data.get("snmp_version", "1"))
        
        if version == "0":
            db_data.update({
                "snmp_enterprise": full_data.get("snmp_enterprise"),
                "snmp_agent_addr": full_data.get("snmp_agent_addr"),
                "snmp_generic_trap": full_data.get("snmp_generic_trap"),
                "snmp_specific_trap": full_data.get("snmp_specific_trap"),
                "snmp_request_id": full_data.get("snmp_request_id"),
                "snmp_error_status": full_data.get("snmp_error_status"),
                "snmp_error_index": full_data.get("snmp_error_index"),
            })
        else:
            db_data.update({
                "snmp_request_id": full_data.get("snmp_request_id"),
                "snmp_error_status": full_data.get("snmp_error_status"),
                "snmp_error_index": full_data.get("snmp_error_index"),
                "snmp_non_repeaters": full_data.get("snmp_non_repeaters"),
                "snmp_max_repetitions": full_data.get("snmp_max_repetitions"),
            })
        
        return {k: v for k, v in db_data.items() if v is not None}
    
    def stop_capture(self):
        self.is_capturing = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.capture_indicator.configure(text="● Arrêté", text_color=COLORS["warning"])
        self.status_text.configure(text="Capture arrêtée")
        
        if self.analyser and self.analyser.pcap_writer:
            self.analyser.pcap_writer.close()
        
        self.notification.show(f"Capture arrêtée - {self.packets_captured} paquets", "info")
    
    def clear_all(self):
        self.packet_list.clear()
        self.packets_captured = 0
        self.packets_suspect = 0
        self._update_stats_display()
        self.details_text.delete("1.0", "end")
        self.notification.show("Données effacées", "info")
    
    def _update_ui(self):
        self.time_label.configure(text=datetime.now().strftime("%H:%M:%S"))
        self._update_stats_display()
        self.after(500, self._update_ui)
    
    def _update_stats_display(self):
        stats = self.packet_list.get_stats()
        self.stats_label.configure(
            text=f"Paquets: {stats['total']} | Autorisés: {stats['authorized']} | Suspects: {stats['suspects']}"
        )
    
    def _on_packet_select(self, packet: dict):
        self.details_text.delete("1.0", "end")
        
        oids_values = packet.get('snmp_oidsValues', [])
        if isinstance(oids_values, str):
            try:
                oids_data = json.loads(oids_values)
                oids_values = oids_data.get('oidsValues', [])
            except:
                oids_values = []
        
        details = f"""════════════════════════════════════════════════════════════
                 DÉTAILS DU PAQUET
════════════════════════════════════════════════════════════

▼ Timestamp: {packet.get('time_stamp', 'N/A')}

▼ Couche 2 - Ethernet
  ├─ MAC Source: {packet.get('mac_src', 'N/A')}
  └─ MAC Destination: {packet.get('mac_dst', 'N/A')}

▼ Couche 3 - IP
  ├─ IP Source: {packet.get('ip_src', 'N/A')}
  └─ IP Destination: {packet.get('ip_dst', 'N/A')}

▼ Couche 4 - UDP
  ├─ Port Source: {packet.get('port_src', 'N/A')}
  └─ Port Destination: {packet.get('port_dst', 'N/A')}

▼ SNMP
  ├─ Version: {'v1' if packet.get('snmp_version') == '0' else 'v2c'}
  ├─ Community: {packet.get('snmp_community', 'N/A')}
  ├─ PDU Type: {packet.get('snmp_pdu_type', 'N/A')}
  ├─ Request ID: {packet.get('snmp_request_id', 'N/A')}
  ├─ Error Status: {packet.get('snmp_error_status', 0)}
  └─ Error Index: {packet.get('snmp_error_index', 0)}

▼ Classification: {'⚠️ SUSPECT' if packet.get('tag') == 1 else '✅ AUTORISÉ'}

▼ Variable Bindings ({len(oids_values)} OIDs)
"""
        for i, vb in enumerate(oids_values, 1):
            details += f"  [{i}] {vb.get('oid', 'N/A')} = {vb.get('value', 'N/A')}\n"
        
        self.details_text.insert("1.0", details)
    
    def _add_alerts(self, alerts: list):
        for alert in alerts:
            severity_colors = {"critical": COLORS["critical"], "warning": COLORS["warning"], "info": COLORS["info"]}
            color = severity_colors.get(alert.severity, COLORS["warning"])
            
            card = ctk.CTkFrame(self.alerts_list, fg_color=COLORS["bg_medium"])
            card.pack(fill="x", pady=3, padx=5)
            
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=5)
            
            ctk.CTkLabel(header, text=f"● {alert.severity.upper()}", text_color=color, 
                        font=ctk.CTkFont(weight="bold")).pack(side="left")
            ctk.CTkLabel(header, text=alert.timestamp, text_color=COLORS["text_muted"]).pack(side="right")
            
            ctk.CTkLabel(card, text=f"[{alert.anomaly_type}] {alert.source_ip}",
                        text_color=COLORS["text_light"]).pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.message, text_color=COLORS["text_muted"], 
                        wraplength=500).pack(anchor="w", padx=10, pady=(0, 5))
        
        if self.anomaly_detector:
            self.alert_count_label.configure(text=f"{len(self.anomaly_detector.alerts)} alertes")
    
    def clear_alerts(self):
        for widget in self.alerts_list.winfo_children():
            widget.destroy()
        if self.anomaly_detector:
            self.anomaly_detector.clear_alerts()
        self.alert_count_label.configure(text="0 alertes")
    
    def refresh_analysis(self):
        pdu_counts = {}
        for pkt in self.packet_list.packets:
            pdu = pkt.get('snmp_pdu_type', 'Unknown')
            pdu_counts[pdu] = pdu_counts.get(pdu, 0) + 1
        
        if pdu_counts and MATPLOTLIB_AVAILABLE:
            labels = list(pdu_counts.keys())
            values = list(pdu_counts.values())
            colors = [PDU_COLORS.get(l, COLORS["primary"]) for l in labels]
            self.pdu_graph.plot_bar(labels, values, colors)
        
        self.stats_text.delete("1.0", "end")
        stats = self.packet_list.get_stats()
        
        ip_counts = {}
        for pkt in self.packet_list.packets:
            ip = pkt.get('ip_src', 'Unknown')
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        stats_str = f"""════════════════════════════════════════
       STATISTIQUES DE CAPTURE
════════════════════════════════════════

Total paquets: {stats['total']}
Autorisés: {stats['authorized']}
Suspects: {stats['suspects']}

────────────────────────────────────────
       DISTRIBUTION PAR TYPE
────────────────────────────────────────
"""
        for pdu, count in sorted(pdu_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / stats['total'] * 100) if stats['total'] > 0 else 0
            stats_str += f"{pdu}: {count} ({pct:.1f}%)\n"
        
        stats_str += f"""
────────────────────────────────────────
       TOP 10 SOURCES
────────────────────────────────────────
"""
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_str += f"{ip}: {count}\n"
        
        self.stats_text.insert("1.0", stats_str)
    
    def load_db_data(self, table: str = None):
        if not self.db:
            return
        
        table = table or self.table_var.get()
        
        try:
            if not self.db.table_exists(table):
                self.db_text.delete("1.0", "end")
                self.db_text.insert("1.0", f"Table '{table}' n'existe pas")
                return
            
            columns_info = self.db.getChamps(table)
            columns = [col[1] for col in columns_info]
            rows = self.db.getData(table=table, columns=["*"])
            
            self.db_count_label.configure(text=f"{len(rows)} entrées")
            
            self.db_text.delete("1.0", "end")
            header = f"Table: {table}\nColonnes: {', '.join(columns)}\n{'=' * 80}\n\n"
            self.db_text.insert("1.0", header)
            
            for row in rows[-100:]:
                row_str = " | ".join(str(v)[:30] for v in row) + "\n"
                self.db_text.insert("end", row_str)
            
            if len(rows) > 100:
                self.db_text.insert("end", f"\n... et {len(rows) - 100} autres entrées")
        except Exception as e:
            self.notification.show(f"Erreur DB: {str(e)[:50]}", "error")
    
    def export_data(self, format: str = "json"):
        if not self.packet_list.packets:
            self.notification.show("Aucune donnée à exporter", "warning")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format}",
            filetypes=[(f"{format.upper()} files", f"*.{format}")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.packet_list.packets, f, indent=2, default=str, ensure_ascii=False)
                self.notification.show(f"Exporté: {os.path.basename(filename)}", "success")
            except Exception as e:
                self.notification.show(f"Erreur export: {str(e)[:50]}", "error")


def main():
    app = MIBurnoutApp()
    app.mainloop()


if __name__ == "__main__":
    main()
