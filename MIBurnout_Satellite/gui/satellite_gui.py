#!/usr/bin/env python3
"""
MIBurnout Satellite - Interface Graphique Identique a la Station
"""

import customtkinter as ctk
from tkinter import messagebox
from threading import Thread, Lock
import os, sys, time
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque

import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

from core.api_client import StationClient

THEME = {
    "bg_main": "#0b0c0e", "bg_panel": "#141619", "bg_card": "#1e2228",
    "bg_input": "#2a2f38", "bg_hover": "#353b47", "border": "#2a2f38",
    "text_primary": "#e6e9ef", "text_secondary": "#8b949e", "text_muted": "#5c6370",
    "accent": "#3b82f6", "success": "#22c55e", "warning": "#f59e0b",
    "error": "#ef4444", "info": "#06b6d4", "graph_bg": "#0b0c0e",
    "graph_grid": "#1e2228", "graph_line1": "#3b82f6",
}


class SatelliteApp(ctk.CTk):
    def __init__(self, client: StationClient):
        super().__init__()
        self.client = client
        self._current_user = client.user
        self.title(f"MIBurnout Satellite - {client.host}:{client.port}")
        self.geometry("1600x900")
        self.minsize(1200, 700)
        self.configure(fg_color=THEME["bg_main"])
        
        self._is_capturing = False
        self._running = True
        self._packets, self._alerts, self._devices = [], [], []
        self._stats = {}
        self._packet_history = deque(maxlen=60)
        self._data_lock = Lock()
        
        self._setup_ui()
        self._start_updates()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _on_close(self):
        self._running = False
        self.client.logout()
        self.destroy()
    
    def _setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        sidebar = ctk.CTkFrame(self, width=220, fg_color=THEME["bg_panel"], corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        
        ctk.CTkLabel(sidebar, text="MIBurnout", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(20, 0))
        ctk.CTkLabel(sidebar, text="Satellite", font=ctk.CTkFont(size=11),
                    text_color=THEME["warning"]).pack(anchor="w", padx=15)
        
        # Station indicator
        sf = ctk.CTkFrame(sidebar, fg_color=THEME["bg_card"], corner_radius=6)
        sf.pack(fill="x", padx=10, pady=10)
        self._station_indicator = ctk.CTkLabel(sf, text="Station connectee",
                                              font=ctk.CTkFont(size=9, weight="bold"),
                                              text_color=THEME["success"])
        self._station_indicator.pack(pady=(8, 2))
        ctk.CTkLabel(sf, text=f"{self.client.host}:{self.client.port}",
                    font=ctk.CTkFont(size=9), text_color=THEME["text_muted"]).pack(pady=(0, 8))
        
        ctk.CTkFrame(sidebar, height=1, fg_color=THEME["border"]).pack(fill="x", padx=15, pady=10)
        
        # Navigation
        self._nav_buttons = {}
        for tid, tname in [("dashboard", "Dashboard"), ("capture", "Capture"),
                          ("devices", "Appareils"), ("behavior", "Analyse"), ("profile", "Profil")]:
            btn = ctk.CTkButton(sidebar, text=tname, font=ctk.CTkFont(size=12),
                               fg_color="transparent", text_color=THEME["text_secondary"],
                               hover_color=THEME["bg_hover"], anchor="w", height=38,
                               command=lambda t=tid: self._switch_tab(t))
            btn.pack(fill="x", padx=10, pady=2)
            self._nav_buttons[tid] = btn
        self._nav_buttons["dashboard"].configure(fg_color=THEME["accent"], text_color=THEME["text_primary"])
        self._current_tab = "dashboard"
        
        ctk.CTkFrame(sidebar, height=1, fg_color=THEME["border"]).pack(fill="x", padx=15, pady=15)
        
        # Capture controls
        cf = ctk.CTkFrame(sidebar, fg_color="transparent")
        cf.pack(fill="x", padx=15)
        ctk.CTkLabel(cf, text="CAPTURE DISTANTE", font=ctk.CTkFont(size=9, weight="bold"),
                    text_color=THEME["text_muted"]).pack(anchor="w", pady=(0, 8))
        
        ctk.CTkLabel(cf, text="Interface:", font=ctk.CTkFont(size=10),
                    text_color=THEME["text_secondary"]).pack(anchor="w")
        self._interface_entry = ctk.CTkEntry(cf, height=28, fg_color=THEME["bg_input"])
        self._interface_entry.pack(fill="x", pady=(2, 8))
        self._interface_entry.insert(0, "eth0")
        
        bf = ctk.CTkFrame(cf, fg_color="transparent")
        bf.pack(fill="x")
        self._start_btn = ctk.CTkButton(bf, text="Demarrer", fg_color=THEME["success"],
                                       height=32, command=self._start_capture)
        self._start_btn.pack(side="left", fill="x", expand=True, padx=(0, 3))
        self._stop_btn = ctk.CTkButton(bf, text="Stop", fg_color=THEME["error"],
                                      height=32, state="disabled", command=self._stop_capture)
        self._stop_btn.pack(side="right", fill="x", expand=True, padx=(3, 0))
        
        self._capture_indicator = ctk.CTkLabel(cf, text="ARRETE",
                                              font=ctk.CTkFont(size=10, weight="bold"),
                                              text_color=THEME["text_muted"])
        self._capture_indicator.pack(pady=10)
        
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(fill="both", expand=True)
        
        # User info
        uf = ctk.CTkFrame(sidebar, fg_color=THEME["bg_card"], corner_radius=6)
        uf.pack(fill="x", padx=10, pady=15)
        uname = self._current_user.get("username", "?") if self._current_user else "?"
        role = self._current_user.get("role", "?").upper() if self._current_user else "?"
        ctk.CTkLabel(uf, text=uname, font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(uf, text=role, font=ctk.CTkFont(size=9),
                    text_color=THEME["text_muted"]).pack(anchor="w", padx=12, pady=(0, 10))
        
        # Main content
        main = ctk.CTkFrame(self, fg_color=THEME["bg_main"], corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        
        # Header
        header = ctk.CTkFrame(main, height=55, fg_color=THEME["bg_panel"], corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        self._page_title = ctk.CTkLabel(header, text="Dashboard",
                                       font=ctk.CTkFont(size=18, weight="bold"),
                                       text_color=THEME["text_primary"])
        self._page_title.pack(side="left", padx=20, pady=12)
        self._update_label = ctk.CTkLabel(header, text="", font=ctk.CTkFont(size=9),
                                         text_color=THEME["text_muted"])
        self._update_label.pack(side="right", padx=10)
        ctk.CTkButton(header, text="Actualiser", width=80, height=30,
                     fg_color=THEME["bg_input"], command=self._force_refresh).pack(side="right", padx=5)
        ctk.CTkButton(header, text="Effacer", width=80, height=30,
                     fg_color=THEME["bg_input"], command=self._clear_data).pack(side="right", padx=5)
        
        # Pages
        self._pages_frame = ctk.CTkFrame(main, fg_color=THEME["bg_main"])
        self._pages_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=10)
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
        sb = ctk.CTkFrame(main, height=28, fg_color=THEME["bg_panel"], corner_radius=0)
        sb.grid(row=2, column=0, sticky="ew")
        self._status_label = ctk.CTkLabel(sb, text="Connecte", font=ctk.CTkFont(size=9),
                                         text_color=THEME["text_muted"])
        self._status_label.pack(side="left", padx=15, pady=5)
        self._packets_status = ctk.CTkLabel(sb, text="Paquets: 0", font=ctk.CTkFont(size=9),
                                           text_color=THEME["text_muted"])
        self._packets_status.pack(side="right", padx=15)
    
    def _switch_tab(self, tid):
        for b in self._nav_buttons.values():
            b.configure(fg_color="transparent", text_color=THEME["text_secondary"])
        self._nav_buttons[tid].configure(fg_color=THEME["accent"], text_color=THEME["text_primary"])
        titles = {"dashboard": "Dashboard", "capture": "Capture", "devices": "Appareils",
                  "behavior": "Analyse", "profile": "Profil"}
        self._page_title.configure(text=titles.get(tid, ""))
        self._pages[tid].tkraise()
        self._current_tab = tid
    
    def _build_dashboard(self):
        p = self._pages["dashboard"]
        p.grid_columnconfigure((0, 1), weight=1)
        p.grid_rowconfigure(1, weight=1)
        
        sf = ctk.CTkFrame(p, fg_color="transparent")
        sf.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        self._stat_cards = {}
        for k, l, c in [("total", "Total", THEME["info"]), ("authorized", "Autorises", THEME["success"]),
                        ("suspect", "Suspects", THEME["warning"]), ("alerts", "Alertes", THEME["error"])]:
            card = ctk.CTkFrame(sf, fg_color=THEME["bg_card"], corner_radius=10)
            card.pack(side="left", fill="x", expand=True, padx=5)
            v = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=32, weight="bold"), text_color=c)
            v.pack(pady=(20, 5))
            ctk.CTkLabel(card, text=l, font=ctk.CTkFont(size=11), text_color=THEME["text_muted"]).pack(pady=(0, 20))
            self._stat_cards[k] = v
        
        gf = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        gf.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(gf, text="Trafic Temps Reel", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(15, 10))
        self._fig = Figure(figsize=(8, 4), dpi=100, facecolor=THEME["graph_bg"])
        self._ax = self._fig.add_subplot(111)
        self._ax.set_facecolor(THEME["graph_bg"])
        self._ax.tick_params(colors=THEME["text_muted"])
        for s in ['top', 'right']: self._ax.spines[s].set_visible(False)
        for s in ['bottom', 'left']: self._ax.spines[s].set_color(THEME["border"])
        self._line, = self._ax.plot([], [], color=THEME["graph_line1"], linewidth=2)
        self._ax.set_xlim(0, 60)
        self._ax.set_ylim(0, 10)
        self._ax.grid(True, color=THEME["graph_grid"], alpha=0.3)
        self._canvas = FigureCanvasTkAgg(self._fig, master=gf)
        self._canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        pf = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        pf.grid(row=1, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(pf, text="Derniers Paquets", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(15, 10))
        self._packets_list = ctk.CTkScrollableFrame(pf, fg_color="transparent")
        self._packets_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_capture(self):
        p = self._pages["capture"]
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(1, weight=1)
        
        cf = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        cf.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        ctk.CTkLabel(cf, text="Controle Capture Distant", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=15)
        cr = ctk.CTkFrame(cf, fg_color="transparent")
        cr.pack(fill="x", padx=20, pady=(0, 15))
        ctk.CTkLabel(cr, text="Interface:", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(side="left")
        self._iface2 = ctk.CTkEntry(cr, width=120, height=32, fg_color=THEME["bg_input"])
        self._iface2.pack(side="left", padx=10)
        self._iface2.insert(0, "eth0")
        ctk.CTkButton(cr, text="Demarrer", width=100, height=32, fg_color=THEME["success"],
                     command=self._start_capture).pack(side="left", padx=5)
        ctk.CTkButton(cr, text="Arreter", width=100, height=32, fg_color=THEME["error"],
                     command=self._stop_capture).pack(side="left", padx=5)
        self._cap_status = ctk.CTkLabel(cr, text="Arrete", font=ctk.CTkFont(size=11),
                                       text_color=THEME["text_muted"])
        self._cap_status.pack(side="right", padx=20)
        
        tf = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        tf.grid(row=1, column=0, sticky="nsew")
        ctk.CTkLabel(tf, text="Paquets Captures", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=15)
        self._capture_list = ctk.CTkScrollableFrame(tf, fg_color="transparent")
        self._capture_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_devices(self):
        p = self._pages["devices"]
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(0, weight=1)
        f = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        f.grid(row=0, column=0, sticky="nsew")
        h = ctk.CTkFrame(f, fg_color="transparent")
        h.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(h, text="Appareils Detectes", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        self._dev_count = ctk.CTkLabel(h, text="0", font=ctk.CTkFont(size=11),
                                      text_color=THEME["text_muted"])
        self._dev_count.pack(side="right")
        self._devices_list = ctk.CTkScrollableFrame(f, fg_color="transparent")
        self._devices_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_behavior(self):
        p = self._pages["behavior"]
        p.grid_columnconfigure((0, 1), weight=1)
        p.grid_rowconfigure(0, weight=1)
        af = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        af.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(af, text="Alertes", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["error"]).pack(anchor="w", padx=20, pady=15)
        self._alerts_list = ctk.CTkScrollableFrame(af, fg_color="transparent")
        self._alerts_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        sf = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        sf.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(sf, text="Statistiques", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["warning"]).pack(anchor="w", padx=20, pady=15)
        self._anom_stats = ctk.CTkTextbox(sf, fg_color=THEME["bg_input"], font=ctk.CTkFont(size=11))
        self._anom_stats.pack(fill="both", expand=True, padx=20, pady=(0, 15))
    
    def _build_profile(self):
        p = self._pages["profile"]
        f = ctk.CTkFrame(p, fg_color=THEME["bg_card"], corner_radius=10)
        f.pack(fill="x")
        ctk.CTkLabel(f, text="Mon Profil", font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(20, 15))
        if self._current_user:
            for k, l in [("username", "Identifiant"), ("role", "Role")]:
                r = ctk.CTkFrame(f, fg_color="transparent")
                r.pack(fill="x", padx=20, pady=8)
                ctk.CTkLabel(r, text=f"{l}:", width=150, font=ctk.CTkFont(size=12),
                            text_color=THEME["text_secondary"]).pack(side="left")
                v = self._current_user.get(k, "-")
                if k == "role": v = v.upper()
                ctk.CTkLabel(r, text=v, font=ctk.CTkFont(size=12, weight="bold"),
                            text_color=THEME["text_primary"]).pack(side="left")
        ctk.CTkButton(f, text="Deconnexion", fg_color=THEME["error"], height=40,
                     command=self._logout).pack(padx=20, pady=20)
    
    def _start_capture(self):
        iface = self._interface_entry.get().strip()
        result = self.client.start_capture(interface=iface)
        if result.get("success"):
            self._is_capturing = True
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            self._capture_indicator.configure(text="EN COURS", text_color=THEME["success"])
            if hasattr(self, '_cap_status'):
                self._cap_status.configure(text="En cours", text_color=THEME["success"])
        else:
            messagebox.showerror("Erreur", result.get("error", "Echec"))
    
    def _stop_capture(self):
        result = self.client.stop_capture()
        if result.get("success"):
            self._is_capturing = False
            self._start_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            self._capture_indicator.configure(text="ARRETE", text_color=THEME["text_muted"])
            if hasattr(self, '_cap_status'):
                self._cap_status.configure(text="Arrete", text_color=THEME["text_muted"])
        else:
            messagebox.showerror("Erreur", result.get("error", "Echec"))
    
    def _clear_data(self):
        self.client.clear_data()
        self._force_refresh()
    
    def _force_refresh(self):
        Thread(target=self._fetch_data, daemon=True).start()
    
    def _logout(self):
        self._running = False
        self.client.logout()
        self.destroy()
    
    def _start_updates(self):
        self._schedule_update()
    
    def _schedule_update(self):
        if self._running:
            Thread(target=self._fetch_data, daemon=True).start()
            self.after(2000, self._schedule_update)
    
    def _fetch_data(self):
        if not self._running: return
        try:
            status = self.client.get_status()
            if status:
                cap = status.get("capturing", False)
                self.after(0, lambda: self._update_cap_ui(cap))
            
            stats = self.client.get_stats()
            if stats and "error" not in stats:
                with self._data_lock: self._stats = stats
                self.after(0, self._refresh_stats)
            
            pkts = self.client.get_packets(limit=100)
            if pkts and "error" not in pkts:
                with self._data_lock: self._packets = pkts.get("packets", [])
                self.after(0, self._refresh_packets)
            
            alerts = self.client.get_alerts(limit=50)
            if alerts and "error" not in alerts:
                with self._data_lock: self._alerts = alerts.get("alerts", [])
                self.after(0, self._refresh_alerts)
            
            devs = self.client.get_devices()
            if devs and "error" not in devs:
                with self._data_lock: self._devices = devs.get("devices", [])
                self.after(0, self._refresh_devices)
            
            self.after(0, lambda: self._update_label.configure(
                text=f"Maj: {datetime.now().strftime('%H:%M:%S')}"))
            
            if stats:
                self._packet_history.append(stats.get("total", 0))
                self.after(0, self._update_graph)
        except:
            self.after(0, lambda: self._station_indicator.configure(
                text="Connexion perdue", text_color=THEME["error"]))
    
    def _update_cap_ui(self, cap):
        if cap:
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            self._capture_indicator.configure(text="EN COURS", text_color=THEME["success"])
        else:
            self._start_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            self._capture_indicator.configure(text="ARRETE", text_color=THEME["text_muted"])
    
    def _refresh_stats(self):
        self._stat_cards["total"].configure(text=str(self._stats.get("total", 0)))
        self._stat_cards["authorized"].configure(text=str(self._stats.get("authorized", 0)))
        self._stat_cards["suspect"].configure(text=str(self._stats.get("suspect", 0)))
        anom = self._stats.get("anomalies", {})
        self._stat_cards["alerts"].configure(text=str(anom.get("total_alerts_generated", len(self._alerts))))
        self._packets_status.configure(text=f"Paquets: {self._stats.get('total', 0)}")
        if hasattr(self, '_anom_stats'):
            self._anom_stats.configure(state="normal")
            self._anom_stats.delete("1.0", "end")
            self._anom_stats.insert("1.0", f"Paquets: {anom.get('total_packets_analyzed', 0)}\nAlertes: {anom.get('total_alerts_generated', 0)}")
            self._anom_stats.configure(state="disabled")
    
    def _refresh_packets(self):
        for w in self._packets_list.winfo_children(): w.destroy()
        for pkt in self._packets[-30:]: self._add_pkt_row(self._packets_list, pkt)
        if hasattr(self, '_capture_list'):
            for w in self._capture_list.winfo_children(): w.destroy()
            for pkt in self._packets[-50:]: self._add_pkt_row(self._capture_list, pkt, True)
    
    def _add_pkt_row(self, parent, pkt, detail=False):
        tag = pkt.get("tag", 0)
        color = THEME["success"] if tag == 0 else THEME["warning"]
        row = ctk.CTkFrame(parent, fg_color=THEME["bg_input"], corner_radius=4)
        row.pack(fill="x", pady=2)
        ts = pkt.get("time_stamp", "")[11:19] if pkt.get("time_stamp") else ""
        ctk.CTkLabel(row, text=ts, font=ctk.CTkFont(size=9), text_color=THEME["text_muted"],
                    width=70).pack(side="left", padx=5, pady=4)
        ctk.CTkLabel(row, text=f"{pkt.get('ip_src', '?')} -> {pkt.get('ip_dst', '?')}",
                    font=ctk.CTkFont(size=10), text_color=color).pack(side="left", padx=5)
        if detail and pkt.get("snmp_community"):
            ctk.CTkLabel(row, text=pkt["snmp_community"], font=ctk.CTkFont(size=9),
                        text_color=THEME["text_secondary"]).pack(side="right", padx=10)
    
    def _refresh_alerts(self):
        if not hasattr(self, '_alerts_list'): return
        for w in self._alerts_list.winfo_children(): w.destroy()
        for a in self._alerts[-30:]:
            sev = a.get("severity", "medium")
            colors = {"low": THEME["info"], "medium": THEME["warning"], "high": THEME["error"]}
            row = ctk.CTkFrame(self._alerts_list, fg_color=THEME["bg_input"], corner_radius=4)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=a.get("type", "?"), font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=colors.get(sev, THEME["warning"])).pack(side="left", padx=10, pady=6)
            ctk.CTkLabel(row, text=a.get("message", "")[:50], font=ctk.CTkFont(size=9),
                        text_color=THEME["text_secondary"]).pack(side="left", padx=5)
    
    def _refresh_devices(self):
        if not hasattr(self, '_devices_list'): return
        for w in self._devices_list.winfo_children(): w.destroy()
        self._dev_count.configure(text=f"{len(self._devices)} appareils")
        for d in self._devices:
            row = ctk.CTkFrame(self._devices_list, fg_color=THEME["bg_input"], corner_radius=4)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=d.get("ip", "?"), font=ctk.CTkFont(size=11, weight="bold"),
                        text_color=THEME["text_primary"], width=130).pack(side="left", padx=10, pady=8)
            ctk.CTkLabel(row, text=d.get("device_type", "?"), font=ctk.CTkFont(size=10),
                        text_color=THEME["info"]).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=f"{d.get('packet_count', 0)} pkts", font=ctk.CTkFont(size=9),
                        text_color=THEME["text_secondary"]).pack(side="right", padx=10)
    
    def _update_graph(self):
        if len(self._packet_history) < 2: return
        vals = list(self._packet_history)
        diffs = [max(0, vals[i] - vals[i-1]) for i in range(1, len(vals))]
        if diffs:
            self._line.set_data(range(len(diffs)), diffs)
            self._ax.set_xlim(0, max(60, len(diffs)))
            self._ax.set_ylim(0, max(10, max(diffs) * 1.2))
            self._canvas.draw_idle()


def show_connection_window():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    result = {"client": None}
    root = ctk.CTk()
    root.title("MIBurnout Satellite - Connexion")
    root.geometry("450x500")
    root.minsize(450, 500)
    root.configure(fg_color=THEME["bg_main"])
    root.update_idletasks()
    x, y = (root.winfo_screenwidth() - 450) // 2, (root.winfo_screenheight() - 500) // 2
    root.geometry(f"450x500+{x}+{y}")
    
    ctk.CTkLabel(root, text="MIBurnout", font=ctk.CTkFont(size=28, weight="bold"),
                text_color=THEME["accent"]).pack(pady=(40, 5))
    ctk.CTkLabel(root, text="Satellite", font=ctk.CTkFont(size=14),
                text_color=THEME["warning"]).pack()
    ctk.CTkLabel(root, text="Connexion a la Station", font=ctk.CTkFont(size=11),
                text_color=THEME["text_muted"]).pack(pady=(5, 25))
    
    form = ctk.CTkFrame(root, fg_color=THEME["bg_card"], corner_radius=10)
    form.pack(fill="x", padx=30)
    
    ctk.CTkLabel(form, text="Adresse Station", font=ctk.CTkFont(size=11),
                text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
    af = ctk.CTkFrame(form, fg_color="transparent")
    af.pack(fill="x", padx=20)
    host = ctk.CTkEntry(af, height=38, fg_color=THEME["bg_input"])
    host.pack(side="left", fill="x", expand=True, padx=(0, 8))
    host.insert(0, "127.0.0.1")
    port = ctk.CTkEntry(af, width=80, height=38, fg_color=THEME["bg_input"])
    port.pack(side="right")
    port.insert(0, "5000")
    
    ctk.CTkLabel(form, text="Identifiant", font=ctk.CTkFont(size=11),
                text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
    user = ctk.CTkEntry(form, height=38, fg_color=THEME["bg_input"])
    user.pack(fill="x", padx=20)
    
    ctk.CTkLabel(form, text="Mot de passe", font=ctk.CTkFont(size=11),
                text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
    pwd = ctk.CTkEntry(form, height=38, show="*", fg_color=THEME["bg_input"])
    pwd.pack(fill="x", padx=20)
    
    err = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=11), text_color=THEME["error"])
    err.pack(pady=10)
    
    def connect():
        h, p, u, pw = host.get().strip(), port.get().strip(), user.get().strip(), pwd.get()
        if not all([h, p, u, pw]):
            err.configure(text="Remplissez tous les champs")
            return
        try:
            pt = int(p)
        except:
            err.configure(text="Port invalide")
            return
        err.configure(text="Connexion...", text_color=THEME["info"])
        root.update()
        client = StationClient(h, pt)
        if not client.ping():
            err.configure(text="Station inaccessible", text_color=THEME["error"])
            return
        ok, msg, _ = client.login(u, pw)
        if ok:
            result["client"] = client
            root.quit()
            root.destroy()
        else:
            err.configure(text=msg, text_color=THEME["error"])
    
    ctk.CTkButton(form, text="Se connecter", height=42, fg_color=THEME["accent"],
                 font=ctk.CTkFont(size=13, weight="bold"), command=connect).pack(fill="x", padx=20, pady=(5, 20))
    root.bind("<Return>", lambda e: connect())
    root.protocol("WM_DELETE_WINDOW", lambda: (root.quit(), root.destroy()))
    user.focus()
    root.mainloop()
    return result["client"]


def main():
    client = show_connection_window()
    if client and client.is_connected:
        app = SatelliteApp(client)
        app.mainloop()


if __name__ == "__main__":
    main()
