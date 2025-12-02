#!/usr/bin/env python3
"""
MIBurnout SNMP Suite - Application Principale
Interface complète pour le monitoring, la capture et l'analyse SNMP
Version 2.0 - Avec capture réelle, historique, et analyse comportementale

Requiert: pip install customtkinter requests matplotlib pillow
Optionnel: pip install scapy (pour capture réelle)
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import requests
from datetime import datetime, timedelta
import threading
import time
import json
import os
import sys
from typing import Dict, List, Any, Optional, Callable
from collections import deque
import queue

# Import des modules MIBurnout
try:
    from snmp_decoder import SNMPDecoder, SNMPPacket, VarBind, OID_DATABASE
    from database import MIBurnoutDB, get_db, AlertRecord, SavedFilter
    from capture_engine import CaptureEngine, CaptureMode, CaptureStats, get_capture_engine
except ImportError:
    # Fallback si les modules ne sont pas trouvés
    print("Warning: Some modules not found, running in limited mode")
    SNMPPacket = None
    MIBurnoutDB = None
    CaptureEngine = None

# Import optionnel de matplotlib
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available, graphs disabled")

# Configuration
API_URL = "http://127.0.0.1:8000"
REFRESH_INTERVAL = 5000
APP_VERSION = "2.0.0"

# Charte graphique MIBurnout
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
    "green": "#50C878",
    "purple": "#9B59B6",
    "cyan": "#00BCD4",
    "orange": "#FF9800",
    "pink": "#E91E63",
}

# Couleurs par type de PDU
PDU_COLORS = {
    "GetRequest": COLORS["blue"],
    "GetNextRequest": COLORS["purple"],
    "GetBulkRequest": COLORS["cyan"],
    "SetRequest": COLORS["warning"],
    "GetResponse": COLORS["success"],
    "Trap": COLORS["critical"],
    "Trap-v1": COLORS["critical"],
    "Trap-v2": COLORS["critical"],
    "InformRequest": COLORS["orange"],
    "Report": COLORS["pink"],
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NotificationManager:
    """Gestionnaire de notifications"""
    
    def __init__(self, parent):
        self.parent = parent
        self.notifications = deque(maxlen=50)
        self.sound_enabled = True
    
    def show(self, message: str, type: str = "info", duration: int = 3000):
        """Affiche une notification"""
        colors = {
            "info": COLORS["info"],
            "success": COLORS["success"],
            "warning": COLORS["warning"],
            "error": COLORS["critical"],
        }
        
        notif = ctk.CTkToplevel(self.parent)
        notif.overrideredirect(True)
        notif.attributes("-topmost", True)
        
        # Position en bas à droite
        screen_width = self.parent.winfo_screenwidth()
        notif.geometry(f"350x60+{screen_width - 370}+50")
        
        frame = ctk.CTkFrame(notif, fg_color=colors.get(type, COLORS["info"]), corner_radius=10)
        frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        ctk.CTkLabel(
            frame, text=message,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_light"],
            wraplength=320
        ).pack(pady=15, padx=15)
        
        self.notifications.append({
            "message": message,
            "type": type,
            "time": datetime.now()
        })
        
        self.parent.after(duration, notif.destroy)
    
    def play_sound(self, sound_type: str = "alert"):
        """Joue un son de notification (si disponible)"""
        if not self.sound_enabled:
            return
        try:
            if sys.platform == "win32":
                import winsound
                if sound_type == "alert":
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                else:
                    winsound.MessageBeep()
        except:
            pass


class SearchDialog(ctk.CTkToplevel):
    """Dialog de recherche dans les paquets"""
    
    def __init__(self, parent, search_callback: Callable):
        super().__init__(parent)
        
        self.title("Rechercher")
        self.geometry("400x150")
        self.transient(parent)
        self.grab_set()
        
        self.search_callback = search_callback
        
        ctk.CTkLabel(self, text="Rechercher:", font=ctk.CTkFont(size=12)).pack(pady=(20, 5))
        
        self.search_entry = ctk.CTkEntry(self, width=300, placeholder_text="Terme de recherche...")
        self.search_entry.pack(pady=5)
        self.search_entry.bind("<Return>", lambda e: self.do_search())
        self.search_entry.focus()
        
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        ctk.CTkButton(btn_frame, text="Rechercher", command=self.do_search, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Fermer", command=self.destroy, width=100, fg_color=COLORS["bg_light"]).pack(side="left", padx=5)
    
    def do_search(self):
        query = self.search_entry.get().strip()
        if query:
            self.search_callback(query)


class FilterDialog(ctk.CTkToplevel):
    """Dialog pour gérer les filtres sauvegardés"""
    
    def __init__(self, parent, db: Optional['MIBurnoutDB'], apply_callback: Callable):
        super().__init__(parent)
        
        self.title("Filtres sauvegardés")
        self.geometry("500x400")
        self.transient(parent)
        
        self.db = db
        self.apply_callback = apply_callback
        
        # Header
        header = ctk.CTkFrame(self, fg_color=COLORS["bg_medium"])
        header.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(header, text="Gérer les filtres", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10, pady=10)
        
        # Liste des filtres
        self.filters_frame = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_light"])
        self.filters_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Nouveau filtre
        new_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_medium"])
        new_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(new_frame, text="Nouveau filtre:").pack(anchor="w", padx=10, pady=5)
        
        input_frame = ctk.CTkFrame(new_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=10, pady=5)
        
        self.name_entry = ctk.CTkEntry(input_frame, placeholder_text="Nom", width=100)
        self.name_entry.pack(side="left", padx=5)
        
        self.expr_entry = ctk.CTkEntry(input_frame, placeholder_text="Expression (ex: type==GetRequest)", width=250)
        self.expr_entry.pack(side="left", padx=5)
        
        ctk.CTkButton(input_frame, text="+", width=40, command=self.add_filter).pack(side="left", padx=5)
        
        self.load_filters()
    
    def load_filters(self):
        """Charge les filtres depuis la base"""
        for widget in self.filters_frame.winfo_children():
            widget.destroy()
        
        if not self.db:
            ctk.CTkLabel(self.filters_frame, text="Base de données non disponible").pack(pady=20)
            return
        
        filters = self.db.get_filters()
        
        if not filters:
            ctk.CTkLabel(self.filters_frame, text="Aucun filtre sauvegardé", text_color=COLORS["text_muted"]).pack(pady=20)
            return
        
        for f in filters:
            row = ctk.CTkFrame(self.filters_frame, fg_color=COLORS["bg_medium"])
            row.pack(fill="x", pady=2)
            
            ctk.CTkLabel(row, text=f.name, font=ctk.CTkFont(weight="bold"), width=100).pack(side="left", padx=10, pady=8)
            ctk.CTkLabel(row, text=f.expression, text_color=COLORS["text_muted"]).pack(side="left", padx=5)
            
            ctk.CTkButton(
                row, text="Appliquer", width=70, height=25,
                command=lambda expr=f.expression: self.apply_filter(expr)
            ).pack(side="right", padx=5, pady=5)
            
            ctk.CTkButton(
                row, text="🗑", width=30, height=25,
                fg_color=COLORS["critical"],
                command=lambda name=f.name: self.delete_filter(name)
            ).pack(side="right", padx=2, pady=5)
    
    def add_filter(self):
        name = self.name_entry.get().strip()
        expr = self.expr_entry.get().strip()
        
        if name and expr and self.db:
            self.db.save_filter(name, expr)
            self.name_entry.delete(0, "end")
            self.expr_entry.delete(0, "end")
            self.load_filters()
    
    def delete_filter(self, name: str):
        if self.db:
            self.db.delete_filter(name)
            self.load_filters()
    
    def apply_filter(self, expression: str):
        self.apply_callback(expression)
        self.destroy()


class ThresholdDialog(ctk.CTkToplevel):
    """Dialog pour configurer les seuils d'alertes"""
    
    def __init__(self, parent, db: Optional['MIBurnoutDB']):
        super().__init__(parent)
        
        self.title("Seuils d'alertes")
        self.geometry("500x500")
        self.transient(parent)
        
        self.db = db
        
        # Header
        ctk.CTkLabel(self, text="Configuration des seuils", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
        
        # Seuils par défaut
        default_thresholds = {
            "ssCpuUser": {"warning": 70, "critical": 90, "unit": "%"},
            "ssCpuSystem": {"warning": 50, "critical": 80, "unit": "%"},
            "memAvailReal": {"warning": 1000000, "critical": 500000, "unit": "KB"},
            "ifInOctets": {"warning": 100000000, "critical": 500000000, "unit": "bytes"},
            "ifOutOctets": {"warning": 100000000, "critical": 500000000, "unit": "bytes"},
            "ifInErrors": {"warning": 100, "critical": 1000, "unit": "count"},
        }
        
        # Charger les seuils sauvegardés
        if self.db:
            saved = self.db.get_config("thresholds")
            if saved:
                default_thresholds.update(saved)
        
        self.threshold_entries = {}
        
        scroll = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_light"])
        scroll.pack(fill="both", expand=True, padx=20, pady=10)
        
        for metric, values in default_thresholds.items():
            frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_medium"])
            frame.pack(fill="x", pady=5)
            
            ctk.CTkLabel(frame, text=metric, font=ctk.CTkFont(weight="bold"), width=120).pack(side="left", padx=10, pady=10)
            
            warn_entry = ctk.CTkEntry(frame, width=80, placeholder_text="Warning")
            warn_entry.insert(0, str(values.get("warning", "")))
            warn_entry.pack(side="left", padx=5)
            
            ctk.CTkLabel(frame, text="⚠️", width=20).pack(side="left")
            
            crit_entry = ctk.CTkEntry(frame, width=80, placeholder_text="Critical")
            crit_entry.insert(0, str(values.get("critical", "")))
            crit_entry.pack(side="left", padx=5)
            
            ctk.CTkLabel(frame, text="🔴", width=20).pack(side="left")
            
            ctk.CTkLabel(frame, text=values.get("unit", ""), text_color=COLORS["text_muted"]).pack(side="right", padx=10)
            
            self.threshold_entries[metric] = {"warning": warn_entry, "critical": crit_entry, "unit": values.get("unit", "")}
        
        # Boutons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Sauvegarder", command=self.save_thresholds).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Annuler", command=self.destroy, fg_color=COLORS["bg_light"]).pack(side="left", padx=10)
    
    def save_thresholds(self):
        thresholds = {}
        
        for metric, entries in self.threshold_entries.items():
            try:
                warning = float(entries["warning"].get())
                critical = float(entries["critical"].get())
                thresholds[metric] = {
                    "warning": warning,
                    "critical": critical,
                    "unit": entries["unit"]
                }
            except ValueError:
                pass
        
        if self.db:
            self.db.set_config("thresholds", thresholds)
        
        self.destroy()


class GraphWidget(ctk.CTkFrame):
    """Widget pour afficher des graphiques matplotlib"""
    
    def __init__(self, parent, title: str = "", **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_medium"], corner_radius=8, **kwargs)
        
        self.title = title
        
        if not MATPLOTLIB_AVAILABLE:
            ctk.CTkLabel(self, text="Graphiques non disponibles\n(installez matplotlib)", text_color=COLORS["text_muted"]).pack(pady=50)
            return
        
        # Créer la figure
        self.figure = Figure(figsize=(5, 3), dpi=100, facecolor=COLORS["bg_medium"])
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor(COLORS["bg_dark"])
        
        # Style
        self.ax.tick_params(colors=COLORS["text_muted"])
        self.ax.spines['bottom'].set_color(COLORS["text_muted"])
        self.ax.spines['top'].set_color(COLORS["bg_medium"])
        self.ax.spines['left'].set_color(COLORS["text_muted"])
        self.ax.spines['right'].set_color(COLORS["bg_medium"])
        
        if title:
            self.ax.set_title(title, color=COLORS["text_light"], fontsize=10)
        
        # Canvas
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
    
    def plot_line(self, x_data: List, y_data: List, label: str = "", color: str = None):
        """Affiche un graphique en ligne"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        self.ax.clear()
        self.ax.set_facecolor(COLORS["bg_dark"])
        self.ax.plot(x_data, y_data, color=color or COLORS["primary"], linewidth=2, label=label)
        
        if label:
            self.ax.legend(facecolor=COLORS["bg_medium"], edgecolor=COLORS["bg_light"], labelcolor=COLORS["text_light"])
        
        self.ax.tick_params(colors=COLORS["text_muted"])
        self.figure.tight_layout()
        self.canvas.draw()
    
    def plot_bar(self, labels: List[str], values: List[float], colors: List[str] = None):
        """Affiche un graphique en barres"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        self.ax.clear()
        self.ax.set_facecolor(COLORS["bg_dark"])
        
        bar_colors = colors or [COLORS["primary"]] * len(labels)
        bars = self.ax.bar(labels, values, color=bar_colors)
        
        self.ax.tick_params(colors=COLORS["text_muted"], rotation=45)
        
        # Valeurs sur les barres
        for bar, val in zip(bars, values):
            self.ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                        str(int(val)), ha='center', va='bottom', color=COLORS["text_light"], fontsize=8)
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def plot_pie(self, labels: List[str], values: List[float], colors: List[str] = None):
        """Affiche un graphique camembert"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        self.ax.clear()
        self.ax.set_facecolor(COLORS["bg_medium"])
        
        pie_colors = colors or [COLORS["blue"], COLORS["success"], COLORS["warning"], COLORS["critical"], COLORS["purple"]]
        
        # Filtrer les valeurs nulles
        filtered = [(l, v, c) for l, v, c in zip(labels, values, pie_colors) if v > 0]
        if not filtered:
            return
        
        labels, values, colors = zip(*filtered)
        
        self.ax.pie(values, labels=labels, colors=colors, autopct='%1.1f%%',
                   textprops={'color': COLORS["text_light"], 'fontsize': 8})
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def clear(self):
        """Efface le graphique"""
        if MATPLOTLIB_AVAILABLE:
            self.ax.clear()
            self.ax.set_facecolor(COLORS["bg_dark"])
            self.canvas.draw()


class PacketListWidget(ctk.CTkFrame):
    """Widget optimisé pour afficher la liste des paquets"""
    
    def __init__(self, parent, on_select: Callable = None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_light"], corner_radius=8, **kwargs)
        
        self.on_select = on_select
        self.packets: List[Dict] = []
        self.filtered_packets: List[Dict] = []
        self.selected_index = -1
        self.marked_packets: set = set()
        
        # Headers
        self.headers_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_medium"])
        self.headers_frame.pack(fill="x", padx=5, pady=(5, 0))
        
        headers = [
            ("", 25), ("No.", 50), ("Time", 90), ("Source", 130), ("Destination", 130),
            ("Ver", 40), ("Type", 100), ("Info", 350)
        ]
        
        for text, width in headers:
            ctk.CTkLabel(
                self.headers_frame, text=text,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=COLORS["accent"],
                width=width, anchor="w"
            ).pack(side="left", padx=2, pady=5)
        
        # Liste scrollable
        self.list_frame = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg_dark"])
        self.list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Virtual scrolling - on garde que les widgets visibles
        self.visible_rows: List[ctk.CTkFrame] = []
        self.row_height = 24
        self.max_visible_rows = 100
    
    def add_packet(self, packet: Dict):
        """Ajoute un paquet à la liste"""
        self.packets.append(packet)
        self.filtered_packets.append(packet)
        
        # Limiter les widgets affichés
        if len(self.visible_rows) >= self.max_visible_rows:
            # Supprimer le plus ancien
            old_row = self.visible_rows.pop(0)
            old_row.destroy()
        
        self._create_row(packet, len(self.packets) - 1)
        
        # Auto-scroll
        self.list_frame._parent_canvas.yview_moveto(1.0)
    
    def _create_row(self, packet: Dict, index: int):
        """Crée une ligne pour un paquet"""
        pdu_type = packet.get('pdu_type', '')
        color = PDU_COLORS.get(pdu_type, COLORS["text_light"])
        
        is_marked = index in self.marked_packets
        bg_color = COLORS["bg_lighter"] if is_marked else COLORS["bg_medium"]
        
        row = ctk.CTkFrame(self.list_frame, fg_color=bg_color, corner_radius=3, height=self.row_height)
        row.pack(fill="x", pady=1)
        row.bind("<Button-1>", lambda e, idx=index: self._on_click(idx))
        row.bind("<Double-Button-1>", lambda e, idx=index: self._on_double_click(idx))
        
        # Marqueur
        mark_label = ctk.CTkLabel(row, text="★" if is_marked else "", width=25, text_color=COLORS["warning"])
        mark_label.pack(side="left", padx=2)
        mark_label.bind("<Button-1>", lambda e, idx=index: self._toggle_mark(idx))
        
        # Données
        data = [
            (str(packet.get('frame_number', '')), 50, COLORS["text_muted"]),
            (str(packet.get('timestamp', ''))[:8], 90, COLORS["text_light"]),
            (packet.get('ip_src', ''), 130, COLORS["text_light"]),
            (packet.get('ip_dst', ''), 130, COLORS["text_light"]),
            (packet.get('version', packet.get('snmp_version', '')), 40, COLORS["text_muted"]),
            (pdu_type, 100, color),
            (packet.get('info', packet.get('info_summary', ''))[:50], 350, COLORS["text_light"]),
        ]
        
        for text, width, col in data:
            lbl = ctk.CTkLabel(row, text=str(text), font=ctk.CTkFont(size=10), text_color=col, width=width, anchor="w")
            lbl.pack(side="left", padx=2)
            lbl.bind("<Button-1>", lambda e, idx=index: self._on_click(idx))
        
        self.visible_rows.append(row)
    
    def _on_click(self, index: int):
        """Gère le clic sur une ligne"""
        self.selected_index = index
        
        # Highlight
        for i, row in enumerate(self.visible_rows):
            start_idx = max(0, len(self.packets) - len(self.visible_rows))
            actual_idx = start_idx + i
            if actual_idx == index:
                row.configure(fg_color=COLORS["primary"])
            else:
                is_marked = actual_idx in self.marked_packets
                row.configure(fg_color=COLORS["bg_lighter"] if is_marked else COLORS["bg_medium"])
        
        if self.on_select and index < len(self.packets):
            self.on_select(self.packets[index])
    
    def _on_double_click(self, index: int):
        """Gère le double-clic (marquer/démarquer)"""
        self._toggle_mark(index)
    
    def _toggle_mark(self, index: int):
        """Marque/démarque un paquet"""
        if index in self.marked_packets:
            self.marked_packets.remove(index)
        else:
            self.marked_packets.add(index)
        
        # Rafraîchir l'affichage
        self.refresh()
    
    def clear(self):
        """Efface tous les paquets"""
        self.packets.clear()
        self.filtered_packets.clear()
        self.marked_packets.clear()
        self.selected_index = -1
        
        for row in self.visible_rows:
            row.destroy()
        self.visible_rows.clear()
    
    def refresh(self):
        """Rafraîchit l'affichage"""
        for row in self.visible_rows:
            row.destroy()
        self.visible_rows.clear()
        
        # Afficher les derniers paquets
        start_idx = max(0, len(self.filtered_packets) - self.max_visible_rows)
        for i, packet in enumerate(self.filtered_packets[start_idx:]):
            self._create_row(packet, start_idx + i)
    
    def apply_filter(self, filter_func: Callable) -> int:
        """Applique un filtre sur les paquets"""
        self.filtered_packets = [p for p in self.packets if filter_func(p)]
        self.refresh()
        return len(self.filtered_packets)
    
    def search(self, query: str) -> List[int]:
        """Recherche dans les paquets"""
        results = []
        query_lower = query.lower()
        
        for i, packet in enumerate(self.packets):
            # Recherche dans tous les champs
            searchable = " ".join(str(v) for v in packet.values()).lower()
            if query_lower in searchable:
                results.append(i)
        
        return results
    
    def get_marked_packets(self) -> List[Dict]:
        """Retourne les paquets marqués"""
        return [self.packets[i] for i in sorted(self.marked_packets) if i < len(self.packets)]


class MIBurnoutSuite(ctk.CTk):
    """Application principale MIBurnout Suite"""
    
    def __init__(self):
        super().__init__()
        
        self.title(f"MIBurnout SNMP Suite v{APP_VERSION}")
        self.geometry("1700x1000")
        self.configure(fg_color=COLORS["bg_dark"])
        
        # Initialisation des modules
        self.db = get_db() if MIBurnoutDB else None
        self.capture_engine = get_capture_engine() if CaptureEngine else None
        self.notification = NotificationManager(self)
        
        # État
        self.devices: List[Dict] = []
        self.alerts: List[Dict] = []
        self.auto_refresh = True
        self.api_connected = False
        self.current_session_id: Optional[int] = None
        
        # Métriques historiques
        self.metrics_history: Dict[str, deque] = {}
        
        # Thresholds
        self.thresholds = self._load_thresholds()
        
        # Setup UI
        self.setup_ui()
        self.setup_keybindings()
        self.start_background_tasks()
        
        # Callback pour la capture
        if self.capture_engine:
            self.capture_engine.add_callback(self._on_packet_captured)
    
    def _load_thresholds(self) -> Dict:
        """Charge les seuils depuis la base"""
        defaults = {
            "ssCpuUser": {"warning": 70, "critical": 90},
            "memAvailReal": {"warning": 1000000, "critical": 500000},
        }
        
        if self.db:
            saved = self.db.get_config("thresholds")
            if saved:
                defaults.update(saved)
        
        return defaults
    
    def setup_keybindings(self):
        """Configure les raccourcis clavier"""
        self.bind("<Control-f>", lambda e: self.show_search_dialog())
        self.bind("<Control-s>", lambda e: self.save_capture())
        self.bind("<Control-o>", lambda e: self.load_capture())
        self.bind("<F5>", lambda e: self.refresh_all())
        self.bind("<space>", lambda e: self.toggle_capture())
        self.bind("<Escape>", lambda e: self.stop_capture())
    
    def setup_ui(self):
        """Configure l'interface utilisateur"""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header
        self._create_header()
        
        # Tabview principal
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=COLORS["bg_medium"],
            segmented_button_fg_color=COLORS["bg_light"],
            segmented_button_selected_color=COLORS["primary"],
            segmented_button_selected_hover_color=COLORS["secondary"],
        )
        self.tabview.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        # Onglets
        self.tab_monitor = self.tabview.add("📊 Monitoring")
        self.tab_capture = self.tabview.add("🔍 Capture SNMP")
        self.tab_analysis = self.tabview.add("📈 Analyse")
        self.tab_alerts = self.tabview.add("🚨 Alertes")
        self.tab_history = self.tabview.add("📁 Historique")
        self.tab_settings = self.tabview.add("⚙️ Paramètres")
        
        # Setup des onglets
        self._setup_monitor_tab()
        self._setup_capture_tab()
        self._setup_analysis_tab()
        self._setup_alerts_tab()
        self._setup_history_tab()
        self._setup_settings_tab()
    
    def _create_header(self):
        """Crée le header"""
        header = ctk.CTkFrame(self, height=60, fg_color=COLORS["bg_medium"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        
        # Logo
        logo_frame = ctk.CTkFrame(header, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        
        ctk.CTkLabel(logo_frame, text="🔥 MIBurnout", font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["primary"]).pack(side="left")
        ctk.CTkLabel(logo_frame, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=10), text_color=COLORS["text_muted"]).pack(side="left", padx=(10, 0), anchor="s")
        
        # Status
        status_frame = ctk.CTkFrame(header, fg_color="transparent")
        status_frame.grid(row=0, column=1, padx=20, pady=10, sticky="e")
        
        self.api_indicator = ctk.CTkLabel(status_frame, text="● API", font=ctk.CTkFont(size=11), text_color=COLORS["critical"])
        self.api_indicator.pack(side="left", padx=10)
        
        self.capture_indicator = ctk.CTkLabel(status_frame, text="● Capture", font=ctk.CTkFont(size=11), text_color=COLORS["text_muted"])
        self.capture_indicator.pack(side="left", padx=10)
        
        self.scapy_indicator = ctk.CTkLabel(
            status_frame, 
            text=f"● Scapy {'OK' if CaptureEngine and CaptureEngine.is_scapy_available() else 'N/A'}", 
            font=ctk.CTkFont(size=11), 
            text_color=COLORS["success"] if CaptureEngine and CaptureEngine.is_scapy_available() else COLORS["warning"]
        )
        self.scapy_indicator.pack(side="left", padx=10)
        
        self.time_label = ctk.CTkLabel(status_frame, text="", font=ctk.CTkFont(size=11), text_color=COLORS["text_muted"])
        self.time_label.pack(side="left", padx=10)
    
    # Suite dans la partie 2...
    # ==================== ONGLET MONITORING ====================
    
    def _setup_monitor_tab(self):
        """Configure l'onglet Monitoring"""
        self.tab_monitor.grid_columnconfigure(0, weight=1)
        self.tab_monitor.grid_columnconfigure(1, weight=2)
        self.tab_monitor.grid_rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ctk.CTkFrame(self.tab_monitor, fg_color=COLORS["bg_light"], corner_radius=8)
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        
        ctk.CTkButton(toolbar, text="🔄 Rafraîchir", command=self.refresh_devices, fg_color=COLORS["primary"], width=120).pack(side="left", padx=10, pady=8)
        
        self.auto_refresh_switch = ctk.CTkSwitch(toolbar, text="Auto-refresh", command=self.toggle_auto_refresh, fg_color=COLORS["bg_medium"], progress_color=COLORS["primary"])
        self.auto_refresh_switch.pack(side="left", padx=20)
        self.auto_refresh_switch.select()
        
        self.device_count_label = ctk.CTkLabel(toolbar, text="0 équipements", text_color=COLORS["accent"])
        self.device_count_label.pack(side="right", padx=20)
        
        # Panel gauche - Liste équipements
        left_panel = ctk.CTkFrame(self.tab_monitor, fg_color=COLORS["bg_light"], corner_radius=8)
        left_panel.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=(0, 10))
        
        ctk.CTkLabel(left_panel, text="Équipements", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(pady=10)
        
        self.devices_list = ctk.CTkScrollableFrame(left_panel, fg_color="transparent")
        self.devices_list.pack(fill="both", expand=True, padx=5, pady=(0, 10))
        
        # Panel droit - Graphiques
        right_panel = ctk.CTkFrame(self.tab_monitor, fg_color="transparent")
        right_panel.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_columnconfigure(1, weight=1)
        right_panel.grid_rowconfigure(0, weight=1)
        right_panel.grid_rowconfigure(1, weight=1)
        
        # Graphiques
        self.cpu_graph = GraphWidget(right_panel, title="CPU Usage (%)")
        self.cpu_graph.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.memory_graph = GraphWidget(right_panel, title="Memory Usage")
        self.memory_graph.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        self.traffic_graph = GraphWidget(right_panel, title="Network Traffic")
        self.traffic_graph.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        self.pdu_graph = GraphWidget(right_panel, title="PDU Distribution")
        self.pdu_graph.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
    
    def refresh_devices(self):
        """Rafraîchit la liste des équipements"""
        def fetch():
            try:
                r = requests.get(f"{API_URL}/devices", timeout=3)
                if r.status_code == 200:
                    self.devices = r.json()
                    self.api_connected = True
                    self.after(0, lambda: self.api_indicator.configure(text="● API", text_color=COLORS["success"]))
                    self.after(0, self._update_devices_display)
            except:
                self.api_connected = False
                self.after(0, lambda: self.api_indicator.configure(text="● API", text_color=COLORS["critical"]))
        
        threading.Thread(target=fetch, daemon=True).start()
    
    def _update_devices_display(self):
        """Met à jour l'affichage des équipements"""
        for widget in self.devices_list.winfo_children():
            widget.destroy()
        
        self.device_count_label.configure(text=f"{len(self.devices)} équipements")
        
        if not self.devices:
            ctk.CTkLabel(self.devices_list, text="Aucun équipement\n\nVérifiez l'API", text_color=COLORS["text_muted"]).pack(pady=50)
            return
        
        for device in self.devices:
            card = ctk.CTkFrame(self.devices_list, fg_color=COLORS["bg_medium"], corner_radius=8)
            card.pack(fill="x", pady=3, padx=5)
            
            status = device.get("status", "up")
            status_color = COLORS["success"] if status == "up" else COLORS["critical"]
            
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=8)
            
            ctk.CTkLabel(header, text="●", text_color=status_color).pack(side="left")
            ctk.CTkLabel(header, text=device.get('name', 'Unknown'), font=ctk.CTkFont(weight="bold"), text_color=COLORS["text_light"]).pack(side="left", padx=5)
            ctk.CTkLabel(header, text=f"{device.get('host', '')}:{device.get('port', 161)}", text_color=COLORS["text_muted"]).pack(side="right")
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh"""
        self.auto_refresh = self.auto_refresh_switch.get()
    
    # ==================== ONGLET CAPTURE ====================
    
    def _setup_capture_tab(self):
        """Configure l'onglet Capture SNMP"""
        self.tab_capture.grid_columnconfigure(0, weight=1)
        self.tab_capture.grid_rowconfigure(1, weight=3)
        self.tab_capture.grid_rowconfigure(2, weight=2)
        self.tab_capture.grid_rowconfigure(3, weight=1)
        
        # Toolbar
        toolbar = ctk.CTkFrame(self.tab_capture, fg_color=COLORS["bg_light"], corner_radius=8)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        # Interface selector
        ctk.CTkLabel(toolbar, text="Interface:").pack(side="left", padx=(10, 5), pady=8)
        
        interfaces = ["Simulation"]
        if self.capture_engine and CaptureEngine.is_scapy_available():
            interfaces = CaptureEngine.get_interfaces() + interfaces
        
        self.interface_var = ctk.StringVar(value=interfaces[0] if interfaces else "Simulation")
        self.interface_menu = ctk.CTkOptionMenu(toolbar, values=interfaces, variable=self.interface_var, width=150)
        self.interface_menu.pack(side="left", padx=5, pady=8)
        
        # Buttons
        self.start_btn = ctk.CTkButton(toolbar, text="▶ Start", command=self.start_capture, fg_color=COLORS["success"], width=100)
        self.start_btn.pack(side="left", padx=10, pady=8)
        
        self.stop_btn = ctk.CTkButton(toolbar, text="⏹ Stop", command=self.stop_capture, fg_color=COLORS["critical"], width=100, state="disabled")
        self.stop_btn.pack(side="left", padx=5, pady=8)
        
        self.pause_btn = ctk.CTkButton(toolbar, text="⏸ Pause", command=self.pause_capture, fg_color=COLORS["warning"], width=100, state="disabled")
        self.pause_btn.pack(side="left", padx=5, pady=8)
        
        ctk.CTkButton(toolbar, text="🗑 Clear", command=self.clear_capture, fg_color=COLORS["accent"], text_color=COLORS["text_dark"], width=80).pack(side="left", padx=5, pady=8)
        
        # Separator
        ctk.CTkFrame(toolbar, width=2, height=25, fg_color=COLORS["bg_medium"]).pack(side="left", padx=10)
        
        # Export buttons
        ctk.CTkButton(toolbar, text="💾 JSON", command=self.export_json, fg_color=COLORS["blue"], width=80).pack(side="left", padx=5, pady=8)
        ctk.CTkButton(toolbar, text="📄 PCAP", command=self.export_pcap, fg_color=COLORS["cyan"], width=80).pack(side="left", padx=5, pady=8)
        ctk.CTkButton(toolbar, text="📊 PDF", command=self.export_pdf_report, fg_color=COLORS["purple"], width=80).pack(side="left", padx=5, pady=8)
        
        # Separator
        ctk.CTkFrame(toolbar, width=2, height=25, fg_color=COLORS["bg_medium"]).pack(side="left", padx=10)
        
        # Filter
        ctk.CTkLabel(toolbar, text="Filtre:").pack(side="left", padx=5)
        self.filter_entry = ctk.CTkEntry(toolbar, placeholder_text="type==GetRequest and ip.src==192.168.1.1", width=300)
        self.filter_entry.pack(side="left", padx=5)
        self.filter_entry.bind("<Return>", lambda e: self.apply_capture_filter())
        
        ctk.CTkButton(toolbar, text="Appliquer", command=self.apply_capture_filter, width=80).pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="📁", command=self.show_filter_dialog, width=30).pack(side="left", padx=2)
        
        # Stats
        self.capture_stats_label = ctk.CTkLabel(toolbar, text="Packets: 0", text_color=COLORS["accent"])
        self.capture_stats_label.pack(side="right", padx=10)
        
        # Packet List
        self.packet_list = PacketListWidget(self.tab_capture, on_select=self._on_packet_select)
        self.packet_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 5))
        
        # Details Panel
        details_frame = ctk.CTkFrame(self.tab_capture, fg_color=COLORS["bg_light"], corner_radius=8)
        details_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        
        details_header = ctk.CTkFrame(details_frame, fg_color="transparent")
        details_header.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(details_header, text="📝 Packet Details", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["primary"]).pack(side="left")
        
        self.details_text = ctk.CTkTextbox(details_frame, fg_color=COLORS["bg_dark"], font=ctk.CTkFont(family="Courier", size=11), wrap="none")
        self.details_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # Hex Panel
        hex_frame = ctk.CTkFrame(self.tab_capture, fg_color=COLORS["bg_light"], corner_radius=8)
        hex_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(5, 10))
        
        ctk.CTkLabel(hex_frame, text="🔢 Hex Dump", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["primary"]).pack(anchor="w", padx=10, pady=5)
        
        self.hex_text = ctk.CTkTextbox(hex_frame, fg_color=COLORS["bg_dark"], font=ctk.CTkFont(family="Courier", size=10), height=100)
        self.hex_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))
    
    def start_capture(self):
        """Démarre la capture"""
        if not self.capture_engine:
            self.notification.show("Moteur de capture non disponible", "error")
            return
        
        interface = self.interface_var.get()
        mode = CaptureMode.SIMULATION if interface == "Simulation" else CaptureMode.LIVE
        
        # Créer une session
        if self.db:
            self.current_session_id = self.db.create_session(
                f"Capture {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                interface=interface,
                filter_expr=self.filter_entry.get()
            )
        
        # Appliquer le filtre
        filter_expr = self.filter_entry.get().strip()
        if filter_expr:
            self.capture_engine.set_filter(filter_expr)
        
        try:
            self.capture_engine.start(mode=mode, interface=interface if mode == CaptureMode.LIVE else "")
            
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.pause_btn.configure(state="normal")
            self.capture_indicator.configure(text="● Capture", text_color=COLORS["success"])
            
            self.notification.show("Capture démarrée", "success")
        except Exception as e:
            self.notification.show(f"Erreur: {str(e)}", "error")
    
    def stop_capture(self):
        """Arrête la capture"""
        if self.capture_engine:
            self.capture_engine.stop()
            
            # Fermer la session
            if self.db and self.current_session_id:
                self.db.end_session(self.current_session_id, len(self.packet_list.packets))
        
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.pause_btn.configure(state="disabled")
        self.capture_indicator.configure(text="● Capture", text_color=COLORS["warning"])
        
        self.notification.show(f"Capture arrêtée - {len(self.packet_list.packets)} paquets", "info")
    
    def pause_capture(self):
        """Met en pause/reprend la capture"""
        if not self.capture_engine:
            return
        
        if self.capture_engine.paused:
            self.capture_engine.resume()
            self.pause_btn.configure(text="⏸ Pause")
            self.capture_indicator.configure(text="● Capture", text_color=COLORS["success"])
        else:
            self.capture_engine.pause()
            self.pause_btn.configure(text="▶ Resume")
            self.capture_indicator.configure(text="● Paused", text_color=COLORS["warning"])
    
    def toggle_capture(self):
        """Toggle capture start/stop"""
        if self.capture_engine and self.capture_engine.running:
            self.stop_capture()
        else:
            self.start_capture()
    
    def clear_capture(self):
        """Efface la capture"""
        self.packet_list.clear()
        self.details_text.delete("1.0", "end")
        self.hex_text.delete("1.0", "end")
        
        if self.capture_engine:
            self.capture_engine.clear()
        
        self._update_capture_stats()
    
    def _on_packet_captured(self, packet):
        """Callback pour chaque paquet capturé"""
        packet_dict = packet.to_dict() if hasattr(packet, 'to_dict') else packet
        self.after(0, lambda p=packet_dict: self.packet_list.add_packet(p))
        self.after(0, self._update_capture_stats)
        
        # Sauvegarder en base
        if self.db and self.current_session_id:
            try:
                self.db.save_packet(self.current_session_id, packet_dict)
            except:
                pass
    
    def _on_packet_select(self, packet: Dict):
        """Callback quand un paquet est sélectionné"""
        self.details_text.delete("1.0", "end")
        self.hex_text.delete("1.0", "end")
        
        # Construire les détails
        details = f"""Frame {packet.get('frame_number', 'N/A')}: {packet.get('frame_length', 0)} bytes
═══════════════════════════════════════════════════════════════════════════════

▼ Internet Protocol Version 4
  ├─ Source: {packet.get('ip_src', 'N/A')}
  ├─ Destination: {packet.get('ip_dst', 'N/A')}
  └─ TTL: {packet.get('ip_ttl', 64)}

▼ User Datagram Protocol
  ├─ Source Port: {packet.get('udp_src_port', 'N/A')}
  └─ Destination Port: {packet.get('udp_dst_port', 'N/A')}

▼ Simple Network Management Protocol
  ├─ Version: {packet.get('version', packet.get('snmp_version', 'N/A'))}
  ├─ Community: {packet.get('community', 'N/A')}
  ├─ PDU Type: {packet.get('pdu_type', 'N/A')}
  ├─ Request ID: {packet.get('request_id', 'N/A')}
  ├─ Error Status: {packet.get('error_status', 0)} ({packet.get('error_status_name', 'noError')})
  └─ Variable Bindings: {len(packet.get('varbinds', []))} items
"""
        
        for i, vb in enumerate(packet.get('varbinds', []), 1):
            if isinstance(vb, dict):
                details += f"""
     └─ [{i}] {vb.get('name', vb.get('oid', 'N/A'))}
        ├─ OID: {vb.get('oid', 'N/A')}
        ├─ Type: {vb.get('type', 'N/A')}
        └─ Value: {vb.get('value', 'N/A')}
"""
        
        self.details_text.insert("1.0", details)
        
        # Hex dump
        hex_dump = packet.get('raw_hex', '')
        if not hex_dump and packet.get('raw_bytes'):
            raw = packet['raw_bytes']
            if isinstance(raw, bytes):
                hex_dump = self._generate_hex_dump(raw)
        
        self.hex_text.insert("1.0", hex_dump or "No hex data available")
    
    def _generate_hex_dump(self, data: bytes) -> str:
        """Génère un hex dump"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
            if len(chunk) > 8:
                hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<48}  |{ascii_part}|")
        return "\n".join(lines)
    
    def _update_capture_stats(self):
        """Met à jour les statistiques de capture"""
        if self.capture_engine:
            stats = self.capture_engine.stats
            text = f"Packets: {stats.packets_snmp} | GET: {stats.get_requests} | RESP: {stats.get_responses} | TRAP: {stats.traps}"
            self.capture_stats_label.configure(text=text)
    
    def apply_capture_filter(self):
        """Applique un filtre sur la capture"""
        filter_expr = self.filter_entry.get().strip()
        
        if self.capture_engine:
            if self.capture_engine.set_filter(filter_expr):
                # Filtrer les paquets existants
                def filter_func(p):
                    # Implémentation simplifiée
                    if not filter_expr:
                        return True
                    
                    if "type==" in filter_expr:
                        type_val = filter_expr.split("type==")[1].split()[0]
                        if type_val.lower() not in p.get('pdu_type', '').lower():
                            return False
                    
                    if "ip.src==" in filter_expr:
                        ip_val = filter_expr.split("ip.src==")[1].split()[0]
                        if ip_val not in p.get('ip_src', ''):
                            return False
                    
                    return True
                
                count = self.packet_list.apply_filter(filter_func)
                self.notification.show(f"Filtre appliqué: {count} paquets", "info")
            else:
                self.notification.show("Expression de filtre invalide", "warning")
    
    def show_filter_dialog(self):
        """Affiche le dialog des filtres"""
        FilterDialog(self, self.db, self._apply_saved_filter)
    
    def _apply_saved_filter(self, expression: str):
        """Applique un filtre sauvegardé"""
        self.filter_entry.delete(0, "end")
        self.filter_entry.insert(0, expression)
        self.apply_capture_filter()
    
    def show_search_dialog(self):
        """Affiche le dialog de recherche"""
        SearchDialog(self, self._do_search)
    
    def _do_search(self, query: str):
        """Effectue une recherche"""
        results = self.packet_list.search(query)
        if results:
            self.notification.show(f"{len(results)} résultats trouvés", "info")
        else:
            self.notification.show("Aucun résultat", "warning")
    
    def export_json(self):
        """Exporte en JSON"""
        if not self.packet_list.packets:
            self.notification.show("Aucun paquet à exporter", "warning")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.packet_list.packets, f, indent=2, default=str)
                self.notification.show(f"Exporté: {os.path.basename(filename)}", "success")
            except Exception as e:
                self.notification.show(f"Erreur: {str(e)}", "error")
    
    def export_pcap(self):
        """Exporte en PCAP"""
        if not self.capture_engine or not CaptureEngine.is_scapy_available():
            self.notification.show("Export PCAP nécessite Scapy", "warning")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        )
        
        if filename:
            if self.capture_engine.export_pcap(filename):
                self.notification.show(f"Exporté: {os.path.basename(filename)}", "success")
            else:
                self.notification.show("Erreur lors de l'export", "error")
    
    def export_pdf_report(self):
        """Génère un rapport PDF"""
        self.notification.show("Export PDF en cours de développement", "info")
    
    def save_capture(self):
        """Sauvegarde la capture"""
        self.export_json()
    
    def load_capture(self):
        """Charge une capture"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            if filename.endswith('.json'):
                try:
                    with open(filename, 'r') as f:
                        packets = json.load(f)
                    
                    self.clear_capture()
                    for p in packets:
                        self.packet_list.add_packet(p)
                    
                    self.notification.show(f"Chargé: {len(packets)} paquets", "success")
                except Exception as e:
                    self.notification.show(f"Erreur: {str(e)}", "error")
            
            elif filename.endswith('.pcap') and self.capture_engine:
                try:
                    count = self.capture_engine.import_pcap(filename)
                    self.notification.show(f"Importé: {count} paquets SNMP", "success")
                except Exception as e:
                    self.notification.show(f"Erreur: {str(e)}", "error")
    
    # ==================== ONGLET ANALYSE ====================
    
    def _setup_analysis_tab(self):
        """Configure l'onglet Analyse"""
        self.tab_analysis.grid_columnconfigure(0, weight=1)
        self.tab_analysis.grid_columnconfigure(1, weight=1)
        self.tab_analysis.grid_rowconfigure(1, weight=1)
        self.tab_analysis.grid_rowconfigure(2, weight=1)
        
        # Toolbar
        toolbar = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"], corner_radius=8)
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="📈 Analyse du Trafic", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(side="left", padx=20, pady=10)
        
        ctk.CTkButton(toolbar, text="🔄 Actualiser", command=self.refresh_analysis, fg_color=COLORS["accent"], text_color=COLORS["text_dark"]).pack(side="right", padx=20, pady=10)
        
        # Top Talkers
        talkers_frame = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"], corner_radius=8)
        talkers_frame.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=5)
        
        ctk.CTkLabel(talkers_frame, text="🔝 Top Talkers", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["accent"]).pack(pady=10)
        
        self.talkers_list = ctk.CTkScrollableFrame(talkers_frame, fg_color="transparent")
        self.talkers_list.pack(fill="both", expand=True, padx=5, pady=(0, 10))
        
        # Distribution
        dist_frame = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"], corner_radius=8)
        dist_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=5)
        
        ctk.CTkLabel(dist_frame, text="📊 Distribution PDU", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["accent"]).pack(pady=10)
        
        self.dist_graph = GraphWidget(dist_frame)
        self.dist_graph.pack(fill="both", expand=True, padx=5, pady=(0, 10))
        
        # Timeline
        timeline_frame = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"], corner_radius=8)
        timeline_frame.grid(row=2, column=0, sticky="nsew", padx=(10, 5), pady=(5, 10))
        
        ctk.CTkLabel(timeline_frame, text="📈 Timeline", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["accent"]).pack(pady=10)
        
        self.timeline_graph = GraphWidget(timeline_frame)
        self.timeline_graph.pack(fill="both", expand=True, padx=5, pady=(0, 10))
        
        # Anomalies
        anomalies_frame = ctk.CTkFrame(self.tab_analysis, fg_color=COLORS["bg_light"], corner_radius=8)
        anomalies_frame.grid(row=2, column=1, sticky="nsew", padx=(5, 10), pady=(5, 10))
        
        ctk.CTkLabel(anomalies_frame, text="⚠️ Anomalies Détectées", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["warning"]).pack(pady=10)
        
        self.anomalies_list = ctk.CTkScrollableFrame(anomalies_frame, fg_color="transparent")
        self.anomalies_list.pack(fill="both", expand=True, padx=5, pady=(0, 10))
    
    def refresh_analysis(self):
        """Rafraîchit l'analyse"""
        if not self.capture_engine:
            return
        
        # Top Talkers
        for widget in self.talkers_list.winfo_children():
            widget.destroy()
        
        talkers = self.capture_engine.get_top_talkers(10)
        for ip, count in talkers:
            row = ctk.CTkFrame(self.talkers_list, fg_color=COLORS["bg_medium"])
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=ip, text_color=COLORS["text_light"]).pack(side="left", padx=10, pady=5)
            ctk.CTkLabel(row, text=str(count), text_color=COLORS["accent"]).pack(side="right", padx=10, pady=5)
        
        # Distribution
        dist = self.capture_engine.get_pdu_distribution()
        if dist:
            labels = list(dist.keys())
            values = list(dist.values())
            colors = [PDU_COLORS.get(l, COLORS["primary"]) for l in labels]
            self.dist_graph.plot_bar(labels, values, colors)
        
        # Timeline
        timeline = self.capture_engine.get_timeline(bucket_size=1.0)
        if timeline:
            times = [t[0] for t in timeline]
            counts = [t[1] for t in timeline]
            self.timeline_graph.plot_line(times, counts, "Packets/s", COLORS["primary"])
        
        # Anomalies
        for widget in self.anomalies_list.winfo_children():
            widget.destroy()
        
        anomalies = self.capture_engine.find_anomalies()
        if not anomalies:
            ctk.CTkLabel(self.anomalies_list, text="✅ Aucune anomalie détectée", text_color=COLORS["success"]).pack(pady=20)
        else:
            for anomaly in anomalies:
                card = ctk.CTkFrame(self.anomalies_list, fg_color=COLORS["bg_medium"])
                card.pack(fill="x", pady=3)
                
                color = COLORS["critical"] if "storm" in anomaly['type'] or "ddos" in anomaly['type'].lower() else COLORS["warning"]
                
                ctk.CTkLabel(card, text=f"⚠️ {anomaly['type']}", font=ctk.CTkFont(weight="bold"), text_color=color).pack(anchor="w", padx=10, pady=(5, 0))
                ctk.CTkLabel(card, text=anomaly['message'], text_color=COLORS["text_muted"], wraplength=300).pack(anchor="w", padx=10, pady=(0, 5))
    
    # ==================== ONGLET ALERTES ====================
    
    def _setup_alerts_tab(self):
        """Configure l'onglet Alertes"""
        self.tab_alerts.grid_columnconfigure(0, weight=1)
        self.tab_alerts.grid_rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ctk.CTkFrame(self.tab_alerts, fg_color=COLORS["bg_light"], corner_radius=8)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="🚨 Centre d'Alertes", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["critical"]).pack(side="left", padx=20, pady=10)
        
        ctk.CTkButton(toolbar, text="⚙️ Seuils", command=self.show_threshold_dialog, fg_color=COLORS["accent"], text_color=COLORS["text_dark"]).pack(side="right", padx=10, pady=10)
        ctk.CTkButton(toolbar, text="✓ Tout acquitter", command=self.acknowledge_all_alerts, fg_color=COLORS["success"]).pack(side="right", padx=10, pady=10)
        
        self.alert_count_badge = ctk.CTkLabel(toolbar, text="0", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["critical"])
        self.alert_count_badge.pack(side="right", padx=10)
        
        # Liste des alertes
        self.alerts_list = ctk.CTkScrollableFrame(self.tab_alerts, fg_color=COLORS["bg_light"])
        self.alerts_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        self._refresh_alerts()
    
    def _refresh_alerts(self):
        """Rafraîchit la liste des alertes"""
        for widget in self.alerts_list.winfo_children():
            widget.destroy()
        
        if not self.db:
            ctk.CTkLabel(self.alerts_list, text="Base de données non disponible", text_color=COLORS["text_muted"]).pack(pady=50)
            return
        
        alerts = self.db.get_alerts(acknowledged=False, limit=50)
        self.alert_count_badge.configure(text=str(len(alerts)))
        
        if not alerts:
            ctk.CTkLabel(self.alerts_list, text="✅ Aucune alerte active", text_color=COLORS["success"]).pack(pady=50)
            return
        
        for alert in alerts:
            card = ctk.CTkFrame(self.alerts_list, fg_color=COLORS["bg_medium"], corner_radius=8)
            card.pack(fill="x", pady=3, padx=5)
            
            severity_colors = {"critical": COLORS["critical"], "warning": COLORS["warning"], "info": COLORS["info"]}
            color = severity_colors.get(alert.severity, COLORS["warning"])
            
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=5)
            
            ctk.CTkLabel(header, text=f"● {alert.severity.upper()}", text_color=color, font=ctk.CTkFont(weight="bold")).pack(side="left")
            ctk.CTkLabel(header, text=alert.timestamp[:19], text_color=COLORS["text_muted"]).pack(side="right")
            
            ctk.CTkLabel(card, text=f"{alert.device_name} - {alert.metric_name}", text_color=COLORS["text_light"]).pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.message, text_color=COLORS["text_muted"], wraplength=600).pack(anchor="w", padx=10, pady=(0, 5))
            
            ctk.CTkButton(card, text="Acquitter", width=80, height=25, command=lambda a=alert: self._acknowledge_alert(a.id)).pack(anchor="e", padx=10, pady=5)
    
    def _acknowledge_alert(self, alert_id: int):
        """Acquitte une alerte"""
        if self.db:
            self.db.acknowledge_alert(alert_id)
            self._refresh_alerts()
    
    def acknowledge_all_alerts(self):
        """Acquitte toutes les alertes"""
        if self.db:
            alerts = self.db.get_alerts(acknowledged=False)
            for alert in alerts:
                self.db.acknowledge_alert(alert.id)
            self._refresh_alerts()
            self.notification.show("Toutes les alertes acquittées", "success")
    
    def show_threshold_dialog(self):
        """Affiche le dialog des seuils"""
        ThresholdDialog(self, self.db)
    
    # ==================== ONGLET HISTORIQUE ====================
    
    def _setup_history_tab(self):
        """Configure l'onglet Historique"""
        self.tab_history.grid_columnconfigure(0, weight=1)
        self.tab_history.grid_rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ctk.CTkFrame(self.tab_history, fg_color=COLORS["bg_light"], corner_radius=8)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(toolbar, text="📁 Historique des Sessions", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(side="left", padx=20, pady=10)
        
        ctk.CTkButton(toolbar, text="🔄 Actualiser", command=self._refresh_history, fg_color=COLORS["accent"], text_color=COLORS["text_dark"]).pack(side="right", padx=10, pady=10)
        
        # Liste des sessions
        self.history_list = ctk.CTkScrollableFrame(self.tab_history, fg_color=COLORS["bg_light"])
        self.history_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        self._refresh_history()
    
    def _refresh_history(self):
        """Rafraîchit l'historique"""
        for widget in self.history_list.winfo_children():
            widget.destroy()
        
        if not self.db:
            ctk.CTkLabel(self.history_list, text="Base de données non disponible", text_color=COLORS["text_muted"]).pack(pady=50)
            return
        
        sessions = self.db.get_sessions(limit=50)
        
        if not sessions:
            ctk.CTkLabel(self.history_list, text="Aucune session enregistrée", text_color=COLORS["text_muted"]).pack(pady=50)
            return
        
        for session in sessions:
            card = ctk.CTkFrame(self.history_list, fg_color=COLORS["bg_medium"], corner_radius=8)
            card.pack(fill="x", pady=3, padx=5)
            
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=8)
            
            ctk.CTkLabel(header, text=session.name, font=ctk.CTkFont(weight="bold"), text_color=COLORS["text_light"]).pack(side="left")
            ctk.CTkLabel(header, text=f"{session.packet_count} paquets", text_color=COLORS["accent"]).pack(side="right")
            
            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(fill="x", padx=10, pady=(0, 8))
            
            ctk.CTkLabel(info, text=f"🕐 {session.start_time[:19]}", text_color=COLORS["text_muted"]).pack(side="left")
            ctk.CTkLabel(info, text=f"📡 {session.interface or 'N/A'}", text_color=COLORS["text_muted"]).pack(side="left", padx=20)
            
            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(fill="x", padx=10, pady=(0, 8))
            
            ctk.CTkButton(btn_frame, text="Charger", width=70, height=25, command=lambda s=session: self._load_session(s.id)).pack(side="left", padx=2)
            ctk.CTkButton(btn_frame, text="🗑", width=30, height=25, fg_color=COLORS["critical"], command=lambda s=session: self._delete_session(s.id)).pack(side="left", padx=2)
    
    def _load_session(self, session_id: int):
        """Charge une session"""
        if not self.db:
            return
        
        packets = self.db.get_session_packets(session_id)
        self.clear_capture()
        
        for p in packets:
            self.packet_list.add_packet(p)
        
        self.notification.show(f"Session chargée: {len(packets)} paquets", "success")
        self.tabview.set("🔍 Capture SNMP")
    
    def _delete_session(self, session_id: int):
        """Supprime une session"""
        if messagebox.askyesno("Confirmer", "Supprimer cette session ?"):
            if self.db:
                self.db.delete_session(session_id)
                self._refresh_history()
                self.notification.show("Session supprimée", "info")
    
    # ==================== ONGLET PARAMÈTRES ====================
    
    def _setup_settings_tab(self):
        """Configure l'onglet Paramètres"""
        scroll = ctk.CTkScrollableFrame(self.tab_settings, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        # API
        api_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_light"], corner_radius=8)
        api_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(api_frame, text="🔌 Configuration API", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(anchor="w", padx=20, pady=15)
        
        api_row = ctk.CTkFrame(api_frame, fg_color="transparent")
        api_row.pack(fill="x", padx=20, pady=(0, 15))
        
        ctk.CTkLabel(api_row, text="URL:").pack(side="left")
        self.api_entry = ctk.CTkEntry(api_row, width=300)
        self.api_entry.insert(0, API_URL)
        self.api_entry.pack(side="left", padx=10)
        ctk.CTkButton(api_row, text="Tester", command=self._test_api, width=80).pack(side="left")
        
        # Capture
        capture_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_light"], corner_radius=8)
        capture_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(capture_frame, text="📡 Capture", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(anchor="w", padx=20, pady=15)
        
        capture_info = ctk.CTkFrame(capture_frame, fg_color="transparent")
        capture_info.pack(fill="x", padx=20, pady=(0, 15))
        
        scapy_status = "✅ Installé" if CaptureEngine and CaptureEngine.is_scapy_available() else "❌ Non installé"
        ctk.CTkLabel(capture_info, text=f"Scapy: {scapy_status}").pack(anchor="w")
        ctk.CTkLabel(capture_info, text="Pour la capture réelle: pip install scapy", text_color=COLORS["text_muted"]).pack(anchor="w")
        
        # Profils
        profiles_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_light"], corner_radius=8)
        profiles_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(profiles_frame, text="👤 Profils", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(anchor="w", padx=20, pady=15)
        
        profiles_row = ctk.CTkFrame(profiles_frame, fg_color="transparent")
        profiles_row.pack(fill="x", padx=20, pady=(0, 15))
        
        profiles = self.db.get_profiles() if self.db else []
        self.profile_var = ctk.StringVar(value=profiles[0] if profiles else "default")
        ctk.CTkOptionMenu(profiles_row, values=profiles or ["default"], variable=self.profile_var, width=200).pack(side="left")
        ctk.CTkButton(profiles_row, text="Charger", command=self._load_profile, width=80).pack(side="left", padx=10)
        ctk.CTkButton(profiles_row, text="Sauvegarder", command=self._save_profile, width=100).pack(side="left")
        
        # Base de données
        db_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_light"], corner_radius=8)
        db_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(db_frame, text="🗄️ Base de Données", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(anchor="w", padx=20, pady=15)
        
        if self.db:
            stats = self.db.get_database_stats()
            db_info = ctk.CTkFrame(db_frame, fg_color="transparent")
            db_info.pack(fill="x", padx=20, pady=(0, 15))
            
            ctk.CTkLabel(db_info, text=f"Sessions: {stats.get('capture_sessions', 0)}").pack(anchor="w")
            ctk.CTkLabel(db_info, text=f"Paquets: {stats.get('captured_packets', 0)}").pack(anchor="w")
            ctk.CTkLabel(db_info, text=f"Métriques: {stats.get('metrics', 0)}").pack(anchor="w")
            ctk.CTkLabel(db_info, text=f"Taille: {stats.get('db_size_bytes', 0) / 1024:.1f} KB").pack(anchor="w")
            
            ctk.CTkButton(db_frame, text="🗑 Nettoyer", command=self._cleanup_db, fg_color=COLORS["warning"], text_color=COLORS["text_dark"]).pack(anchor="w", padx=20, pady=(0, 15))
        
        # À propos
        about_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_light"], corner_radius=8)
        about_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(about_frame, text="ℹ️ À propos", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["primary"]).pack(anchor="w", padx=20, pady=15)
        ctk.CTkLabel(about_frame, text=f"MIBurnout SNMP Suite v{APP_VERSION}\nInterface complète pour le monitoring et l'analyse SNMP\n\nProjet SAE 501-502", text_color=COLORS["text_muted"], justify="left").pack(anchor="w", padx=20, pady=(0, 15))
    
    def _test_api(self):
        """Teste la connexion API"""
        url = self.api_entry.get()
        try:
            r = requests.get(f"{url}/devices", timeout=3)
            if r.status_code == 200:
                self.notification.show("✅ API connectée", "success")
            else:
                self.notification.show(f"⚠️ API retourne {r.status_code}", "warning")
        except Exception as e:
            self.notification.show(f"❌ Erreur: {str(e)[:50]}", "error")
    
    def _load_profile(self):
        """Charge un profil"""
        if self.db:
            config = self.db.get_profile(self.profile_var.get())
            if config:
                self.notification.show("Profil chargé", "success")
    
    def _save_profile(self):
        """Sauvegarde le profil actuel"""
        if self.db:
            config = {
                "api_url": self.api_entry.get(),
                "auto_refresh": self.auto_refresh,
            }
            self.db.save_profile(self.profile_var.get(), config)
            self.notification.show("Profil sauvegardé", "success")
    
    def _cleanup_db(self):
        """Nettoie la base de données"""
        if self.db and messagebox.askyesno("Confirmer", "Supprimer les anciennes données (>30 jours) ?"):
            count = self.db.cleanup_old_metrics(days=30)
            self.db.vacuum()
            self.notification.show(f"Nettoyé: {count} enregistrements", "info")
    
    # ==================== BACKGROUND TASKS ====================
    
    def start_background_tasks(self):
        """Démarre les tâches en arrière-plan"""
        def update_loop():
            while True:
                if self.auto_refresh:
                    self.refresh_devices()
                
                self.after(0, lambda: self.time_label.configure(text=datetime.now().strftime("%H:%M:%S")))
                
                time.sleep(REFRESH_INTERVAL / 1000)
        
        threading.Thread(target=update_loop, daemon=True).start()
    
    def refresh_all(self):
        """Rafraîchit tout"""
        self.refresh_devices()
        self._refresh_alerts()
        self.refresh_analysis()
        self._refresh_history()


def main():
    app = MIBurnoutSuite()
    app.mainloop()


if __name__ == "__main__":
    main()
