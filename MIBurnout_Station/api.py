#!/usr/bin/env python3
"""
MIBurnout Suite V1 - API REST + WebSocket
API complète pour la communication Station <-> Satellites
"""

import os
import sys
import json
import time
import argparse
import threading
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from typing import Dict, List, Optional
from functools import wraps

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

# Flask
FLASK_AVAILABLE = False
try:
    from flask import Flask, jsonify, request, Response
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    print("[!] Flask requis: pip install flask flask-cors")

# Flask-SocketIO pour WebSocket
SOCKETIO_AVAILABLE = False
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    pass

# Core modules
CORE_AVAILABLE = False
try:
    from core.sniffer import Sniffer
    from core.analyser import Analyser
    from core.SQLiteDB import DataBase
    from core.confAPP import ConfAPP
    from core.anomaly_detector import get_detector
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"[!] Core: {e}")

# Auth module
AUTH_AVAILABLE = False
try:
    from core.auth import AuthManager, get_auth_manager, ROLES, PERMISSIONS
    AUTH_AVAILABLE = True
except ImportError as e:
    print(f"[!] Auth: {e}")

API_VERSION = "2.0.0"
DEFAULT_CONFIG = {
    "interface": "eth0",
    "filter": "udp port 161 or udp port 162",
    "database": "miburnout.db",
    "config_file": "config/conf.json",
    "pcap_dir": "captures"
}


# =============================================================================
# CAPTURE MANAGER
# =============================================================================

class CaptureManager:
    """Gestionnaire de capture SNMP singleton."""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init = False
        return cls._instance
    
    def __init__(self):
        if self._init:
            return
        self._init = True
        self.config = DEFAULT_CONFIG.copy()
        self.db = None
        self.cfg_mgr = None
        self.sniffer = None
        self.analyser = None
        self.detector = None
        self.queue = None
        self.is_capturing = False
        self.is_initialized = False
        self.start_time = None
        self.packets = []
        self.lock = Lock()
        self.stats = {"total": 0, "authorized": 0, "suspect": 0}
        self._packet_callbacks = []
        self._alert_callbacks = []
    
    def add_packet_callback(self, callback):
        """Ajoute un callback appelé à chaque nouveau paquet."""
        self._packet_callbacks.append(callback)
    
    def add_alert_callback(self, callback):
        """Ajoute un callback appelé à chaque nouvelle alerte."""
        self._alert_callbacks.append(callback)
    
    def initialize(self):
        if not CORE_AVAILABLE:
            return {"success": False, "error": "Core not available"}
        try:
            os.makedirs(self.config["pcap_dir"], exist_ok=True)
            os.makedirs(os.path.dirname(self.config["config_file"]) or "config", exist_ok=True)
            self.db = DataBase(dbFile=self.config["database"])
            self.db.initDB()
            self.cfg_mgr = ConfAPP(confFile=self.config["config_file"])
            if self.cfg_mgr.config is None:
                self.cfg_mgr.creatConf()
            self.detector = get_detector()
            self.queue = Queue(maxsize=10000)
            self.is_initialized = True
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def start(self, iface=None, filt=None):
        if not self.is_initialized:
            r = self.initialize()
            if not r["success"]:
                return r
        if self.is_capturing:
            return {"success": False, "error": "Already running"}
        if iface:
            self.config["interface"] = iface
        if filt:
            self.config["filter"] = filt
        try:
            self.sniffer = Sniffer(
                iface=self.config["interface"],
                sfilter=self.config["filter"],
                queue=self.queue
            )
            cfg = self.cfg_mgr.config if self.cfg_mgr else {}
            self.analyser = Analyser(
                queue=self.queue,
                baseDB=self.db,
                config=cfg,
                pcap_dir=self.config["pcap_dir"],
                lenPcap=100
            )
            Thread(target=self.sniffer.start_sniffer, daemon=True).start()
            Thread(target=self._capture_loop, daemon=True).start()
            self.is_capturing = True
            self.start_time = time.time()
            return {"success": True, "interface": self.config["interface"]}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _capture_loop(self):
        while self.is_capturing:
            try:
                if self.queue.empty():
                    time.sleep(0.01)
                    continue
                pkt = self.queue.get(timeout=0.5)
                data = self.analyser.packet_info(pkt)
                
                if self.analyser.compare(data):
                    data["tag"] = 0
                    self.stats["authorized"] += 1
                else:
                    data["tag"] = 1
                    self.stats["suspect"] += 1
                
                # Analyse comportementale
                if self.detector:
                    alerts = self.detector.analyze_packet(data)
                    if alerts:
                        for callback in self._alert_callbacks:
                            try:
                                callback(alerts)
                            except:
                                pass
                
                # Écriture DB
                db_data = self._prepare_db_data(data)
                ver = str(data.get("snmp_version", "1"))
                self.db.wrData("snmp_v1" if ver == "0" else "snmp_v2", db_data)
                
                # PCAP
                try:
                    self.analyser.pcap_writer.write(pkt)
                    self.analyser.nb_pkt += 1
                    if self.analyser.nb_pkt >= self.analyser.lenPcap:
                        self.analyser.open_new_pcap()
                except:
                    pass
                
                # Stockage mémoire
                with self.lock:
                    self.packets.append(data)
                    if len(self.packets) > 10000:
                        self.packets = self.packets[-5000:]
                
                self.stats["total"] += 1
                
                # Notifier les callbacks de paquets
                for callback in self._packet_callbacks:
                    try:
                        callback(data)
                    except:
                        pass
                
                self.queue.task_done()
            except:
                pass
    
    def _prepare_db_data(self, d):
        r = {
            "time_stamp": d.get("time_stamp"),
            "mac_src": d.get("mac_src"),
            "mac_dst": d.get("mac_dst"),
            "ip_src": d.get("ip_src"),
            "ip_dst": d.get("ip_dst"),
            "port_src": d.get("port_src"),
            "port_dst": d.get("port_dst"),
            "snmp_community": d.get("snmp_community"),
            "snmp_pdu_type": d.get("snmp_pdu_type"),
            "snmp_oidsValues": json.dumps({"oidsValues": d.get("snmp_oidsValues", [])}),
            "tag": d.get("tag", 0)
        }
        ver = str(d.get("snmp_version", "1"))
        if ver == "0":
            r.update({
                "snmp_enterprise": d.get("snmp_enterprise"),
                "snmp_agent_addr": d.get("snmp_agent_addr"),
                "snmp_generic_trap": d.get("snmp_generic_trap"),
                "snmp_specific_trap": d.get("snmp_specific_trap"),
                "snmp_request_id": d.get("snmp_request_id"),
                "snmp_error_status": d.get("snmp_error_status"),
                "snmp_error_index": d.get("snmp_error_index")
            })
        else:
            r.update({
                "snmp_request_id": d.get("snmp_request_id"),
                "snmp_error_status": d.get("snmp_error_status"),
                "snmp_error_index": d.get("snmp_error_index"),
                "snmp_non_repeaters": d.get("snmp_non_repeaters"),
                "snmp_max_repetitions": d.get("snmp_max_repetitions")
            })
        return {k: v for k, v in r.items() if v is not None}
    
    def stop(self):
        if not self.is_capturing:
            return {"success": False, "error": "Not running"}
        self.is_capturing = False
        if self.analyser and hasattr(self.analyser, 'pcap_writer'):
            try:
                self.analyser.pcap_writer.close()
            except:
                pass
        dur = time.time() - self.start_time if self.start_time else 0
        return {"success": True, "duration": round(dur, 2), "packets": self.stats["total"]}
    
    def get_status(self):
        return {
            "version": API_VERSION,
            "core": CORE_AVAILABLE,
            "auth": AUTH_AVAILABLE,
            "capturing": self.is_capturing,
            "interface": self.config.get("interface"),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_stats(self):
        dur = time.time() - self.start_time if self.start_time and self.is_capturing else 0
        r = {
            **self.stats,
            "duration": round(dur, 2),
            "in_memory": len(self.packets)
        }
        if self.detector:
            r["anomalies"] = self.detector.get_statistics()
        return r
    
    def get_packets(self, limit=100, offset=0, tag=None):
        with self.lock:
            f = self.packets.copy()
        if tag is not None:
            f = [p for p in f if p.get("tag") == tag]
        return {"total": len(f), "packets": f[offset:offset+limit]}
    
    def get_alerts(self, limit=100):
        if not self.detector:
            return {"alerts": []}
        return {
            "alerts": self.detector.get_alerts(limit=limit),
            "stats": self.detector.get_statistics()
        }
    
    def get_devices(self):
        """Récupère la liste des appareils découverts."""
        if not self.detector:
            return {"devices": []}
        try:
            from core.anomaly_detector import get_device_manager
            dm = get_device_manager()
            if dm:
                devices = []
                for ip, device in dm.devices.items():
                    devices.append({
                        "ip": ip,
                        "mac": device.mac_address,
                        "hostname": device.hostname,
                        "device_type": device.device_type,
                        "vendor": device.vendor,
                        "role": device.role,
                        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
                        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                        "packet_count": device.packet_count,
                        "is_whitelisted": device.is_whitelisted,
                        "is_blacklisted": device.is_blacklisted
                    })
                return {"devices": devices, "total": len(devices)}
        except:
            pass
        return {"devices": [], "total": 0}
    
    def get_baseline(self):
        """Récupère les données de baseline."""
        if not self.detector:
            return {"baseline": {}}
        try:
            stats = self.detector.get_statistics()
            return {
                "baseline": {
                    "packets_analyzed": stats.get("total_packets_analyzed", 0),
                    "alerts_generated": stats.get("total_alerts_generated", 0),
                    "unique_sources": stats.get("unique_sources", 0),
                    "unique_destinations": stats.get("unique_destinations", 0)
                }
            }
        except:
            return {"baseline": {}}
    
    def clear_data(self):
        """Efface les données en mémoire."""
        with self.lock:
            self.packets.clear()
        self.stats = {"total": 0, "authorized": 0, "suspect": 0}
        if self.detector:
            self.detector.reset()
        return {"success": True}


# =============================================================================
# FLASK APP
# =============================================================================

def create_app(enable_auth=True):
    """Crée l'application Flask avec tous les endpoints."""
    if not FLASK_AVAILABLE:
        print("Flask requis!")
        sys.exit(1)
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'miburnout-secret-key-change-in-production'
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # WebSocket
    socketio = None
    if SOCKETIO_AVAILABLE:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    mgr = CaptureManager()
    auth = get_auth_manager() if AUTH_AVAILABLE else None
    
    # Sessions actives (token -> user_data)
    active_sessions = {}
    sessions_lock = Lock()
    
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not enable_auth or not AUTH_AVAILABLE:
                return f(*args, **kwargs)
            
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                token = request.args.get('token', '')
            
            if not token:
                return jsonify({"error": "Token requis"}), 401
            
            with sessions_lock:
                if token not in active_sessions:
                    if auth:
                        user = auth.validate_session(token)
                        if user:
                            active_sessions[token] = user
                        else:
                            return jsonify({"error": "Token invalide"}), 401
                    else:
                        return jsonify({"error": "Auth non disponible"}), 500
                
                request.current_user = active_sessions.get(token)
            
            return f(*args, **kwargs)
        return decorated
    
    def require_permission(permission):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not enable_auth:
                    return f(*args, **kwargs)
                
                user = getattr(request, 'current_user', None)
                if not user:
                    return jsonify({"error": "Non authentifié"}), 401
                
                perms = user.get("permissions", [])
                if "all" in perms or permission in perms:
                    return f(*args, **kwargs)
                
                return jsonify({"error": "Permission insuffisante"}), 403
            return decorated
        return decorator
    
    # WebSocket callbacks
    if socketio:
        def on_new_packet(packet):
            socketio.emit('new_packet', packet, namespace='/live')
        
        def on_new_alert(alerts):
            for alert in alerts if isinstance(alerts, list) else [alerts]:
                socketio.emit('new_alert', alert, namespace='/live')
        
        mgr.add_packet_callback(on_new_packet)
        mgr.add_alert_callback(on_new_alert)
        
        @socketio.on('connect', namespace='/live')
        def handle_connect():
            print(f"[WS] Client connecté")
        
        @socketio.on('disconnect', namespace='/live')
        def handle_disconnect():
            print(f"[WS] Client déconnecté")
    
    # === ENDPOINTS ===
    
    @app.route("/")
    def index():
        return jsonify({
            "name": "MIBurnout Station API",
            "version": API_VERSION,
            "auth_enabled": enable_auth and AUTH_AVAILABLE,
            "websocket": SOCKETIO_AVAILABLE
        })
    
    @app.route("/api/status")
    def status():
        return jsonify(mgr.get_status())
    
    @app.route("/api/ping")
    def ping():
        return jsonify({"pong": True, "timestamp": datetime.now().isoformat()})
    
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        if not AUTH_AVAILABLE:
            return jsonify({"error": "Auth non disponible"}), 500
        
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")
        
        if not username or not password:
            return jsonify({"success": False, "error": "Identifiants requis"}), 400
        
        success, msg, user = auth.login(username, password)
        
        if success:
            token = user.get("session_token")
            with sessions_lock:
                active_sessions[token] = user
            return jsonify({
                "success": True,
                "token": token,
                "user": {
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "role": user.get("role"),
                    "permissions": user.get("permissions", [])
                }
            })
        else:
            return jsonify({"success": False, "error": msg}), 401
    
    @app.route("/api/auth/logout", methods=["POST"])
    @require_auth
    def logout():
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        with sessions_lock:
            if token in active_sessions:
                del active_sessions[token]
        if auth:
            auth.logout()
        return jsonify({"success": True})
    
    @app.route("/api/auth/verify", methods=["GET"])
    @require_auth
    def verify():
        user = getattr(request, 'current_user', None)
        if user:
            return jsonify({
                "valid": True,
                "user": {
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "role": user.get("role"),
                    "permissions": user.get("permissions", [])
                }
            })
        return jsonify({"valid": False}), 401
    
    @app.route("/api/auth/users", methods=["GET"])
    @require_auth
    @require_permission("manage_users")
    def get_users():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        users = auth.get_all_users()
        return jsonify({"users": users})
    
    @app.route("/api/auth/users", methods=["POST"])
    @require_auth
    @require_permission("manage_users")
    def create_user():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        data = request.get_json() or {}
        success, msg = auth.create_user(
            username=data.get("username"),
            password=data.get("password"),
            role=data.get("role", "viewer"),
            email=data.get("email"),
            full_name=data.get("full_name")
        )
        if success:
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "error": msg}), 400
    
    @app.route("/api/auth/tickets", methods=["GET"])
    @require_auth
    @require_permission("manage_users")
    def get_tickets():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        tickets = auth.get_tickets()
        return jsonify({"tickets": tickets})
    
    @app.route("/api/auth/tickets", methods=["POST"])
    def create_ticket():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        data = request.get_json() or {}
        success, msg, ticket_id = auth.create_ticket(
            username=data.get("username"),
            ticket_type=data.get("ticket_type", "other"),
            subject=data.get("subject", ""),
            message=data.get("message", "")
        )
        if success:
            return jsonify({"success": True, "ticket_id": ticket_id})
        return jsonify({"success": False, "error": msg}), 400
    
    @app.route("/api/capture/start", methods=["POST"])
    @require_auth
    @require_permission("start_capture")
    def start_capture():
        data = request.get_json() or {}
        return jsonify(mgr.start(
            iface=data.get("interface"),
            filt=data.get("filter")
        ))
    
    @app.route("/api/capture/stop", methods=["POST"])
    @require_auth
    @require_permission("stop_capture")
    def stop_capture():
        return jsonify(mgr.stop())
    
    @app.route("/api/capture/clear", methods=["POST"])
    @require_auth
    def clear_capture():
        return jsonify(mgr.clear_data())
    
    @app.route("/api/packets")
    @require_auth
    @require_permission("view_packets")
    def get_packets():
        return jsonify(mgr.get_packets(
            limit=request.args.get("limit", 100, type=int),
            offset=request.args.get("offset", 0, type=int),
            tag=request.args.get("tag", type=int)
        ))
    
    @app.route("/api/stats")
    @require_auth
    @require_permission("view_stats")
    def get_stats():
        return jsonify(mgr.get_stats())
    
    @app.route("/api/alerts")
    @require_auth
    @require_permission("view_behavior")
    def get_alerts():
        return jsonify(mgr.get_alerts(
            limit=request.args.get("limit", 100, type=int)
        ))
    
    @app.route("/api/devices")
    @require_auth
    @require_permission("view_devices")
    def get_devices():
        return jsonify(mgr.get_devices())
    
    @app.route("/api/baseline")
    @require_auth
    @require_permission("view_behavior")
    def get_baseline():
        return jsonify(mgr.get_baseline())
    
    @app.route("/api/config", methods=["GET"])
    @require_auth
    @require_permission("manage_config")
    def get_config():
        if mgr.cfg_mgr and mgr.cfg_mgr.config:
            return jsonify({"config": mgr.cfg_mgr.config})
        return jsonify({"config": {}})
    
    @app.route("/api/docs")
    def docs():
        return jsonify({
            "version": API_VERSION,
            "endpoints": [
                "GET /api/status", "GET /api/ping",
                "POST /api/auth/login", "POST /api/auth/logout", "GET /api/auth/verify",
                "GET /api/packets", "GET /api/stats", "GET /api/alerts", "GET /api/devices",
                "POST /api/capture/start", "POST /api/capture/stop"
            ]
        })
    
    if socketio:
        return app, socketio
    return app, None


def main():
    if not FLASK_AVAILABLE:
        print("pip install flask flask-cors")
        sys.exit(1)
    
    p = argparse.ArgumentParser(description="MIBurnout Station API")
    p.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    p.add_argument("--debug", action="store_true", help="Mode debug")
    p.add_argument("--no-auth", action="store_true", help="Désactiver l'auth")
    args = p.parse_args()
    
    print("=" * 50)
    print(f"  MIBurnout Station API v{API_VERSION}")
    print("=" * 50)
    print(f"  URL: http://{args.host}:{args.port}")
    print(f"  Auth: {'Desactivee' if args.no_auth else 'Activee'}")
    print(f"  WebSocket: {'Disponible' if SOCKETIO_AVAILABLE else 'Non disponible'}")
    print("=" * 50)
    
    app, socketio = create_app(enable_auth=not args.no_auth)
    
    if socketio:
        socketio.run(app, host=args.host, port=args.port, debug=args.debug)
    else:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
