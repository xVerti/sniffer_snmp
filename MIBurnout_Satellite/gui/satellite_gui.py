#!/usr/bin/env python3
"""
MIBurnout Satellite - Interface Graphique
Client distant pour la Station MIBurnout
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional

# CustomTkinter
try:
    import customtkinter as ctk
    from tkinter import messagebox
    CTK_AVAILABLE = True
except ImportError:
    CTK_AVAILABLE = False
    print("[!] customtkinter requis: pip install customtkinter")
    sys.exit(1)

# Import du client API
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.api_client import StationClient

# =============================================================================
# THEME
# =============================================================================

THEME = {
    "bg_main": "#0d1117",
    "bg_panel": "#161b22",
    "bg_card": "#21262d",
    "bg_input": "#0d1117",
    "bg_hover": "#30363d",
    "border": "#30363d",
    "accent": "#58a6ff",
    "success": "#3fb950",
    "warning": "#d29922",
    "error": "#f85149",
    "info": "#58a6ff",
    "text_primary": "#f0f6fc",
    "text_secondary": "#8b949e",
    "text_muted": "#6e7681"
}

APP_VERSION = "1.0.0"


# =============================================================================
# APPLICATION SATELLITE
# =============================================================================

class SatelliteApp(ctk.CTk):
    """Application Satellite MIBurnout."""
    
    def __init__(self, client: StationClient):
        super().__init__()
        
        self.client = client
        self._is_connected = True
        self._current_user = client.user
        
        self.title(f"MIBurnout Satellite - {client.host}:{client.port}")
        self.geometry("1400x800")
        self.minsize(1100, 650)
        self.configure(fg_color=THEME["bg_main"])
        
        self._packets: List[Dict] = []
        self._alerts: List[Dict] = []
        self._devices: List[Dict] = []
        self._stats: Dict = {}
        
        self._running = True
        self._update_thread: Optional[threading.Thread] = None
        
        self._setup_ui()
        self._start_updates()
        
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _on_close(self):
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=2)
        self.client.logout()
        self.destroy()
    
    def _setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # === SIDEBAR ===
        sidebar = ctk.CTkFrame(self, width=200, fg_color=THEME["bg_panel"], corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        
        # Logo
        ctk.CTkLabel(sidebar, text="MIBurnout",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(20, 0))
        ctk.CTkLabel(sidebar, text="Satellite",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15)
        
        # Connexion
        conn_frame = ctk.CTkFrame(sidebar, fg_color=THEME["bg_card"], corner_radius=6)
        conn_frame.pack(fill="x", padx=10, pady=10)
        
        self._conn_status = ctk.CTkLabel(conn_frame, text="Connecte",
                                        font=ctk.CTkFont(size=10, weight="bold"),
                                        text_color=THEME["success"])
        self._conn_status.pack(pady=5)
        
        ctk.CTkLabel(conn_frame, text=f"{self.client.host}:{self.client.port}",
                    font=ctk.CTkFont(size=9),
                    text_color=THEME["text_muted"]).pack(pady=(0, 5))
        
        # Navigation
        ctk.CTkFrame(sidebar, height=1, fg_color=THEME["border"]).pack(fill="x", padx=15, pady=10)
        
        self._nav_btns = {}
        for tab_id, tab_name in [("dashboard", "Dashboard"), ("capture", "Capture"),
                                  ("devices", "Appareils"), ("behavior", "Analyse"),
                                  ("profile", "Profil")]:
            btn = ctk.CTkButton(sidebar, text=tab_name, font=ctk.CTkFont(size=12),
                               fg_color="transparent", text_color=THEME["text_secondary"],
                               hover_color=THEME["bg_hover"], anchor="w", height=36,
                               command=lambda t=tab_id: self._switch_tab(t))
            btn.pack(fill="x", padx=10, pady=2)
            self._nav_btns[tab_id] = btn
        
        self._nav_btns["dashboard"].configure(fg_color=THEME["accent"], text_color=THEME["text_primary"])
        self._current_tab = "dashboard"
        
        # Capture controls
        ctk.CTkFrame(sidebar, height=1, fg_color=THEME["border"]).pack(fill="x", padx=15, pady=10)
        
        ctrl = ctk.CTkFrame(sidebar, fg_color="transparent")
        ctrl.pack(fill="x", padx=15)
        
        ctk.CTkLabel(ctrl, text="CAPTURE",
                    font=ctk.CTkFont(size=9, weight="bold"),
                    text_color=THEME["text_muted"]).pack(anchor="w", pady=(0, 8))
        
        btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_row.pack(fill="x")
        
        self._start_btn = ctk.CTkButton(btn_row, text="Start", fg_color=THEME["success"],
                                       height=30, command=self._start_capture)
        self._start_btn.pack(side="left", fill="x", expand=True, padx=(0, 3))
        
        self._stop_btn = ctk.CTkButton(btn_row, text="Stop", fg_color=THEME["error"],
                                      height=30, state="disabled", command=self._stop_capture)
        self._stop_btn.pack(side="right", fill="x", expand=True, padx=(3, 0))
        
        self._capture_label = ctk.CTkLabel(ctrl, text="ARRETE",
                                          font=ctk.CTkFont(size=9, weight="bold"),
                                          text_color=THEME["text_muted"])
        self._capture_label.pack(pady=8)
        
        # Spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(fill="both", expand=True)
        
        # User info
        user_frame = ctk.CTkFrame(sidebar, fg_color=THEME["bg_card"], corner_radius=6)
        user_frame.pack(fill="x", padx=10, pady=15)
        
        username = self._current_user.get("username", "?") if self._current_user else "?"
        role = self._current_user.get("role", "?").upper() if self._current_user else "?"
        
        ctk.CTkLabel(user_frame, text=username,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(user_frame, text=role,
                    font=ctk.CTkFont(size=9),
                    text_color=THEME["text_muted"]).pack(anchor="w", padx=10, pady=(0, 8))
        
        # === MAIN CONTENT ===
        main = ctk.CTkFrame(self, fg_color=THEME["bg_main"], corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        
        # Header
        header = ctk.CTkFrame(main, height=50, fg_color=THEME["bg_panel"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        
        self._page_title = ctk.CTkLabel(header, text="Dashboard",
                                       font=ctk.CTkFont(size=16, weight="bold"),
                                       text_color=THEME["text_primary"])
        self._page_title.pack(side="left", padx=20, pady=10)
        
        self._update_label = ctk.CTkLabel(header, text="",
                                         font=ctk.CTkFont(size=9),
                                         text_color=THEME["text_muted"])
        self._update_label.pack(side="right", padx=20)
        
        ctk.CTkButton(header, text="Actualiser", width=80, height=28,
                     fg_color=THEME["bg_input"],
                     command=self._force_refresh).pack(side="right", padx=5)
        
        # Pages container
        self._pages_frame = ctk.CTkFrame(main, fg_color=THEME["bg_main"])
        self._pages_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self._pages_frame.grid_columnconfigure(0, weight=1)
        self._pages_frame.grid_rowconfigure(0, weight=1)
        
        self._pages = {}
        for p in ["dashboard", "capture", "devices", "behavior", "profile"]:
            self._pages[p] = ctk.CTkFrame(self._pages_frame, fg_color="transparent")
            self._pages[p].grid(row=0, column=0, sticky="nsew")
        
        self._build_dashboard()
        self._build_capture()
        self._build_devices()
        self._build_behavior()
        self._build_profile()
        
        self._pages["dashboard"].tkraise()
        
        # Status bar
        status = ctk.CTkFrame(main, height=25, fg_color=THEME["bg_panel"], corner_radius=0)
        status.grid(row=2, column=0, sticky="ew")
        
        self._status_text = ctk.CTkLabel(status, text="Pret",
                                        font=ctk.CTkFont(size=9),
                                        text_color=THEME["text_muted"])
        self._status_text.pack(side="left", padx=15, pady=3)
        
        self._pkt_count = ctk.CTkLabel(status, text="Paquets: 0",
                                      font=ctk.CTkFont(size=9),
                                      text_color=THEME["text_muted"])
        self._pkt_count.pack(side="right", padx=15)
    
    def _switch_tab(self, tab_id: str):
        for btn in self._nav_btns.values():
            btn.configure(fg_color="transparent", text_color=THEME["text_secondary"])
        self._nav_btns[tab_id].configure(fg_color=THEME["accent"], text_color=THEME["text_primary"])
        
        titles = {"dashboard": "Dashboard", "capture": "Capture", "devices": "Appareils",
                  "behavior": "Analyse Comportementale", "profile": "Profil"}
        self._page_title.configure(text=titles.get(tab_id, ""))
        
        self._pages[tab_id].tkraise()
        self._current_tab = tab_id
    
    # =========================================================================
    # PAGES
    # =========================================================================
    
    def _build_dashboard(self):
        page = self._pages["dashboard"]
        page.grid_columnconfigure((0, 1), weight=1)
        page.grid_rowconfigure(1, weight=1)
        
        # Stats
        stats_row = ctk.CTkFrame(page, fg_color="transparent")
        stats_row.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        self._stat_labels = {}
        for key, label, color in [("total", "Total", THEME["info"]),
                                   ("authorized", "Autorises", THEME["success"]),
                                   ("suspect", "Suspects", THEME["warning"]),
                                   ("alerts", "Alertes", THEME["error"])]:
            card = ctk.CTkFrame(stats_row, fg_color=THEME["bg_card"], corner_radius=8)
            card.pack(side="left", fill="x", expand=True, padx=5)
            
            val = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=26, weight="bold"),
                              text_color=color)
            val.pack(pady=(12, 3))
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10),
                        text_color=THEME["text_muted"]).pack(pady=(0, 12))
            self._stat_labels[key] = val
        
        # Packets list
        pkt_frame = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        pkt_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        
        ctk.CTkLabel(pkt_frame, text="Derniers Paquets",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=10)
        
        self._pkt_list = ctk.CTkScrollableFrame(pkt_frame, fg_color="transparent")
        self._pkt_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Alerts list
        alert_frame = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        alert_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        
        ctk.CTkLabel(alert_frame, text="Alertes",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["error"]).pack(anchor="w", padx=15, pady=10)
        
        self._alert_list = ctk.CTkScrollableFrame(alert_frame, fg_color="transparent")
        self._alert_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_capture(self):
        page = self._pages["capture"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        
        # Controls
        ctrl = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ctk.CTkLabel(ctrl, text="Controle de Capture",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        row = ctk.CTkFrame(ctrl, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 15))
        
        ctk.CTkLabel(row, text="Interface:", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(side="left")
        
        self._iface_entry = ctk.CTkEntry(row, width=120, height=32, fg_color=THEME["bg_input"])
        self._iface_entry.pack(side="left", padx=10)
        self._iface_entry.insert(0, "eth0")
        
        self._start_btn2 = ctk.CTkButton(row, text="Demarrer", width=100, height=32,
                                        fg_color=THEME["success"], command=self._start_capture)
        self._start_btn2.pack(side="left", padx=5)
        
        self._stop_btn2 = ctk.CTkButton(row, text="Arreter", width=100, height=32,
                                       fg_color=THEME["error"], state="disabled",
                                       command=self._stop_capture)
        self._stop_btn2.pack(side="left", padx=5)
        
        self._capture_status = ctk.CTkLabel(row, text="Capture arretee",
                                           font=ctk.CTkFont(size=11),
                                           text_color=THEME["text_muted"])
        self._capture_status.pack(side="right", padx=10)
        
        # Packets table
        table = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        table.grid(row=1, column=0, sticky="nsew")
        
        ctk.CTkLabel(table, text="Paquets Captures",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        self._capture_list = ctk.CTkScrollableFrame(table, fg_color="transparent")
        self._capture_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_devices(self):
        page = self._pages["devices"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(0, weight=1)
        
        frame = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        frame.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(frame, text="Appareils Detectes",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        self._devices_list = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        self._devices_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_behavior(self):
        page = self._pages["behavior"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(0, weight=1)
        
        frame = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        frame.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(frame, text="Analyse Comportementale",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        self._behavior_text = ctk.CTkTextbox(frame, fg_color=THEME["bg_input"],
                                            font=ctk.CTkFont(size=11))
        self._behavior_text.pack(fill="both", expand=True, padx=20, pady=(0, 15))
    
    def _build_profile(self):
        page = self._pages["profile"]
        
        frame = ctk.CTkFrame(page, fg_color=THEME["bg_card"], corner_radius=8)
        frame.pack(fill="x", padx=0, pady=0)
        
        ctk.CTkLabel(frame, text="Mon Profil",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(20, 15))
        
        if self._current_user:
            for key, label in [("username", "Identifiant"), ("role", "Role")]:
                row = ctk.CTkFrame(frame, fg_color="transparent")
                row.pack(fill="x", padx=20, pady=5)
                
                ctk.CTkLabel(row, text=f"{label}:", width=120,
                            font=ctk.CTkFont(size=12),
                            text_color=THEME["text_secondary"]).pack(side="left")
                
                val = self._current_user.get(key, "-")
                if key == "role":
                    val = val.upper()
                ctk.CTkLabel(row, text=val,
                            font=ctk.CTkFont(size=12),
                            text_color=THEME["text_primary"]).pack(side="left")
        
        ctk.CTkFrame(frame, fg_color="transparent", height=15).pack()
        
        ctk.CTkButton(frame, text="Deconnexion", fg_color=THEME["error"],
                     height=36, command=self._logout).pack(padx=20, pady=(10, 20))
    
    # =========================================================================
    # ACTIONS
    # =========================================================================
    
    def _start_capture(self):
        iface = self._iface_entry.get().strip() if hasattr(self, '_iface_entry') else "eth0"
        result = self.client.start_capture(interface=iface)
        
        if result.get("success"):
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            if hasattr(self, '_start_btn2'):
                self._start_btn2.configure(state="disabled")
                self._stop_btn2.configure(state="normal")
            self._capture_label.configure(text="EN COURS", text_color=THEME["success"])
            if hasattr(self, '_capture_status'):
                self._capture_status.configure(text="Capture en cours", text_color=THEME["success"])
            self._status_text.configure(text="Capture demarree")
        else:
            messagebox.showerror("Erreur", result.get("error", "Impossible de demarrer"))
    
    def _stop_capture(self):
        result = self.client.stop_capture()
        
        if result.get("success"):
            self._start_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            if hasattr(self, '_start_btn2'):
                self._start_btn2.configure(state="normal")
                self._stop_btn2.configure(state="disabled")
            self._capture_label.configure(text="ARRETE", text_color=THEME["text_muted"])
            if hasattr(self, '_capture_status'):
                self._capture_status.configure(text="Capture arretee", text_color=THEME["text_muted"])
            self._status_text.configure(text="Capture arretee")
        else:
            messagebox.showerror("Erreur", result.get("error", "Impossible d'arreter"))
    
    def _force_refresh(self):
        self._update_data()
        self._update_label.configure(text=f"Actualise: {datetime.now().strftime('%H:%M:%S')}")
    
    def _logout(self):
        self._running = False
        self.client.logout()
        self._is_connected = False
        self.destroy()
    
    # =========================================================================
    # DATA UPDATES
    # =========================================================================
    
    def _start_updates(self):
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
    
    def _update_loop(self):
        while self._running:
            try:
                self._update_data()
            except:
                pass
            time.sleep(2)
    
    def _update_data(self):
        if not self._running or not self.client.is_connected:
            return
        
        try:
            # Stats
            stats = self.client.get_stats()
            if stats and "error" not in stats:
                self._stats = stats
                self.after(0, self._refresh_stats)
            
            # Packets
            pkts = self.client.get_packets(limit=50)
            if pkts and "error" not in pkts:
                self._packets = pkts.get("packets", [])
                self.after(0, self._refresh_packets)
            
            # Alerts
            alerts = self.client.get_alerts(limit=20)
            if alerts and "error" not in alerts:
                self._alerts = alerts.get("alerts", [])
                self.after(0, self._refresh_alerts)
            
            # Devices
            devices = self.client.get_devices()
            if devices and "error" not in devices:
                self._devices = devices.get("devices", [])
                self.after(0, self._refresh_devices)
            
            # Status
            status = self.client.get_status()
            if status:
                capturing = status.get("capturing", False)
                self.after(0, lambda: self._update_capture_status(capturing))
            
            self.after(0, lambda: self._update_label.configure(
                text=f"Maj: {datetime.now().strftime('%H:%M:%S')}"
            ))
            
        except Exception as e:
            self.after(0, lambda: self._conn_status.configure(
                text="Deconnecte", text_color=THEME["error"]
            ))
    
    def _update_capture_status(self, capturing: bool):
        if capturing:
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            self._capture_label.configure(text="EN COURS", text_color=THEME["success"])
        else:
            self._start_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            self._capture_label.configure(text="ARRETE", text_color=THEME["text_muted"])
    
    def _refresh_stats(self):
        self._stat_labels["total"].configure(text=str(self._stats.get("total", 0)))
        self._stat_labels["authorized"].configure(text=str(self._stats.get("authorized", 0)))
        self._stat_labels["suspect"].configure(text=str(self._stats.get("suspect", 0)))
        
        anomalies = self._stats.get("anomalies", {})
        alert_count = anomalies.get("total_alerts_generated", len(self._alerts))
        self._stat_labels["alerts"].configure(text=str(alert_count))
        
        self._pkt_count.configure(text=f"Paquets: {self._stats.get('total', 0)}")
    
    def _refresh_packets(self):
        for w in self._pkt_list.winfo_children():
            w.destroy()
        
        for pkt in self._packets[-30:]:
            row = ctk.CTkFrame(self._pkt_list, fg_color=THEME["bg_input"], corner_radius=4)
            row.pack(fill="x", pady=2)
            
            tag = pkt.get("tag", 0)
            color = THEME["success"] if tag == 0 else THEME["warning"]
            
            ts = pkt.get("time_stamp", "")[:19] if pkt.get("time_stamp") else ""
            ctk.CTkLabel(row, text=ts, font=ctk.CTkFont(size=9),
                        text_color=THEME["text_muted"], width=130).pack(side="left", padx=5)
            
            src = pkt.get("ip_src", "?")
            dst = pkt.get("ip_dst", "?")
            ctk.CTkLabel(row, text=f"{src} -> {dst}",
                        font=ctk.CTkFont(size=10),
                        text_color=color).pack(side="left", padx=5)
            
            comm = pkt.get("snmp_community", "")
            if comm:
                ctk.CTkLabel(row, text=comm, font=ctk.CTkFont(size=9),
                            text_color=THEME["text_secondary"]).pack(side="right", padx=10)
    
    def _refresh_alerts(self):
        for w in self._alert_list.winfo_children():
            w.destroy()
        
        for alert in self._alerts[-20:]:
            row = ctk.CTkFrame(self._alert_list, fg_color=THEME["bg_input"], corner_radius=4)
            row.pack(fill="x", pady=2)
            
            severity = alert.get("severity", "medium")
            colors = {"low": THEME["info"], "medium": THEME["warning"], "high": THEME["error"]}
            color = colors.get(severity, THEME["warning"])
            
            alert_type = alert.get("type", "unknown")
            ctk.CTkLabel(row, text=alert_type, font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=color).pack(side="left", padx=10, pady=5)
            
            msg = alert.get("message", "")[:50]
            ctk.CTkLabel(row, text=msg, font=ctk.CTkFont(size=9),
                        text_color=THEME["text_secondary"]).pack(side="left", padx=5)
    
    def _refresh_devices(self):
        for w in self._devices_list.winfo_children():
            w.destroy()
        
        for dev in self._devices:
            row = ctk.CTkFrame(self._devices_list, fg_color=THEME["bg_input"], corner_radius=4)
            row.pack(fill="x", pady=2)
            
            ip = dev.get("ip", "?")
            ctk.CTkLabel(row, text=ip, font=ctk.CTkFont(size=11, weight="bold"),
                        text_color=THEME["text_primary"], width=120).pack(side="left", padx=10, pady=8)
            
            dtype = dev.get("device_type", "unknown")
            ctk.CTkLabel(row, text=dtype, font=ctk.CTkFont(size=10),
                        text_color=THEME["info"]).pack(side="left", padx=5)
            
            vendor = dev.get("vendor", "")
            if vendor:
                ctk.CTkLabel(row, text=vendor, font=ctk.CTkFont(size=9),
                            text_color=THEME["text_muted"]).pack(side="left", padx=10)
            
            pkts = dev.get("packet_count", 0)
            ctk.CTkLabel(row, text=f"{pkts} pkts", font=ctk.CTkFont(size=9),
                        text_color=THEME["text_secondary"]).pack(side="right", padx=10)


# =============================================================================
# FENETRE DE CONNEXION
# =============================================================================

def show_connection_window():
    """Affiche la fenêtre de connexion à la Station."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    
    result = {"client": None}
    
    root = ctk.CTk()
    root.title("MIBurnout Satellite - Connexion")
    root.geometry("450x500")
    root.minsize(450, 500)
    root.configure(fg_color=THEME["bg_main"])
    
    # Centrer
    root.update_idletasks()
    x = (root.winfo_screenwidth() - 450) // 2
    y = (root.winfo_screenheight() - 500) // 2
    root.geometry(f"450x500+{x}+{y}")
    
    # Logo
    ctk.CTkLabel(root, text="MIBurnout",
                font=ctk.CTkFont(size=28, weight="bold"),
                text_color=THEME["accent"]).pack(pady=(40, 5))
    ctk.CTkLabel(root, text="Satellite",
                font=ctk.CTkFont(size=14),
                text_color=THEME["text_secondary"]).pack()
    ctk.CTkLabel(root, text="Connexion a la Station",
                font=ctk.CTkFont(size=11),
                text_color=THEME["text_muted"]).pack(pady=(5, 25))
    
    # Form
    form = ctk.CTkFrame(root, fg_color=THEME["bg_card"], corner_radius=10)
    form.pack(fill="x", padx=30)
    
    # Station
    ctk.CTkLabel(form, text="Adresse Station",
                font=ctk.CTkFont(size=11),
                text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
    
    addr_frame = ctk.CTkFrame(form, fg_color="transparent")
    addr_frame.pack(fill="x", padx=20)
    
    host_entry = ctk.CTkEntry(addr_frame, height=36, placeholder_text="IP ou hostname",
                             fg_color=THEME["bg_input"])
    host_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
    host_entry.insert(0, "127.0.0.1")
    
    port_entry = ctk.CTkEntry(addr_frame, width=80, height=36, placeholder_text="Port",
                             fg_color=THEME["bg_input"])
    port_entry.pack(side="right")
    port_entry.insert(0, "5000")
    
    # Username
    ctk.CTkLabel(form, text="Identifiant",
                font=ctk.CTkFont(size=11),
                text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
    
    user_entry = ctk.CTkEntry(form, height=36, fg_color=THEME["bg_input"])
    user_entry.pack(fill="x", padx=20)
    
    # Password
    ctk.CTkLabel(form, text="Mot de passe",
                font=ctk.CTkFont(size=11),
                text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
    
    pwd_entry = ctk.CTkEntry(form, height=36, show="*", fg_color=THEME["bg_input"])
    pwd_entry.pack(fill="x", padx=20)
    
    # Error
    error_label = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=11),
                              text_color=THEME["error"])
    error_label.pack(pady=10)
    
    def do_connect():
        host = host_entry.get().strip()
        port_str = port_entry.get().strip()
        username = user_entry.get().strip()
        password = pwd_entry.get()
        
        if not host or not port_str or not username or not password:
            error_label.configure(text="Remplissez tous les champs")
            return
        
        try:
            port = int(port_str)
        except:
            error_label.configure(text="Port invalide")
            return
        
        error_label.configure(text="Connexion...", text_color=THEME["info"])
        root.update()
        
        client = StationClient(host, port)
        
        if not client.ping():
            error_label.configure(text="Station inaccessible", text_color=THEME["error"])
            return
        
        success, msg, user = client.login(username, password)
        
        if success:
            result["client"] = client
            root.quit()
            root.destroy()
        else:
            error_label.configure(text=msg, text_color=THEME["error"])
    
    ctk.CTkButton(form, text="Se connecter", height=40,
                 fg_color=THEME["accent"],
                 font=ctk.CTkFont(size=13, weight="bold"),
                 command=do_connect).pack(fill="x", padx=20, pady=(5, 20))
    
    root.bind("<Return>", lambda e: do_connect())
    
    def on_close():
        root.quit()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    
    user_entry.focus()
    root.mainloop()
    
    return result["client"]


def main():
    """Point d'entrée principal."""
    client = show_connection_window()
    
    if client and client.is_connected:
        app = SatelliteApp(client)
        app.mainloop()


if __name__ == "__main__":
    main()
