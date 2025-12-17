#!/usr/bin/env python3
"""
MIBurnout Satellite - Client API
Client pour communiquer avec la Station MIBurnout
"""

import json
import time
import threading
from typing import Dict, List, Optional, Callable
from datetime import datetime

# Requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests requis: pip install requests")

# WebSocket
try:
    import socketio
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False


class StationClient:
    """Client pour communiquer avec la Station MIBurnout."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, use_ssl: bool = False):
        """
        Initialise le client.
        
        Args:
            host: Adresse IP de la Station
            port: Port de l'API
            use_ssl: Utiliser HTTPS
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.base_url = f"{'https' if use_ssl else 'http'}://{host}:{port}"
        
        self.token: Optional[str] = None
        self.user: Optional[Dict] = None
        self.connected = False
        
        # WebSocket
        self.sio: Optional[socketio.Client] = None
        self.ws_connected = False
        
        # Callbacks
        self._packet_callbacks: List[Callable] = []
        self._alert_callbacks: List[Callable] = []
        self._connection_callbacks: List[Callable] = []
        
        # Cache
        self._last_stats: Optional[Dict] = None
        self._last_status: Optional[Dict] = None
        
        # Polling thread
        self._polling = False
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_interval = 2.0
    
    # =========================================================================
    # CONNECTION
    # =========================================================================
    
    def ping(self) -> bool:
        """Teste la connexion à la Station."""
        try:
            resp = requests.get(f"{self.base_url}/api/ping", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def get_status(self) -> Optional[Dict]:
        """Récupère le statut de la Station."""
        try:
            resp = requests.get(f"{self.base_url}/api/status", timeout=5)
            if resp.status_code == 200:
                self._last_status = resp.json()
                return self._last_status
        except:
            pass
        return None
    
    # =========================================================================
    # AUTHENTICATION
    # =========================================================================
    
    def login(self, username: str, password: str) -> tuple[bool, str, Optional[Dict]]:
        """
        Authentification auprès de la Station.
        
        Returns:
            Tuple (success, message, user_data)
        """
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/login",
                json={"username": username, "password": password},
                timeout=10
            )
            
            data = resp.json()
            
            if resp.status_code == 200 and data.get("success"):
                self.token = data.get("token")
                self.user = data.get("user")
                self.connected = True
                
                # Notifier les callbacks
                for cb in self._connection_callbacks:
                    try:
                        cb(True, self.user)
                    except:
                        pass
                
                return True, "Connexion réussie", self.user
            else:
                return False, data.get("error", "Échec de connexion"), None
                
        except requests.exceptions.ConnectionError:
            return False, "Impossible de contacter la Station", None
        except requests.exceptions.Timeout:
            return False, "Délai de connexion dépassé", None
        except Exception as e:
            return False, f"Erreur: {str(e)}", None
    
    def logout(self) -> bool:
        """Déconnexion."""
        if not self.connected:
            return True
        
        try:
            self._request("POST", "/api/auth/logout")
        except:
            pass
        
        self.token = None
        self.user = None
        self.connected = False
        
        # Arrêter le polling
        self.stop_polling()
        
        # Déconnecter WebSocket
        self.disconnect_websocket()
        
        # Notifier les callbacks
        for cb in self._connection_callbacks:
            try:
                cb(False, None)
            except:
                pass
        
        return True
    
    def verify_token(self) -> bool:
        """Vérifie si le token est toujours valide."""
        if not self.token:
            return False
        
        try:
            resp = self._request("GET", "/api/auth/verify")
            if resp and resp.get("valid"):
                self.user = resp.get("user")
                return True
        except:
            pass
        
        return False
    
    # =========================================================================
    # API REQUESTS
    # =========================================================================
    
    def _request(self, method: str, endpoint: str, data: Dict = None, 
                 params: Dict = None) -> Optional[Dict]:
        """Effectue une requête authentifiée."""
        if not REQUESTS_AVAILABLE:
            return None
        
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, params=params, timeout=10)
            elif method == "POST":
                resp = requests.post(url, headers=headers, json=data, timeout=10)
            elif method == "PUT":
                resp = requests.put(url, headers=headers, json=data, timeout=10)
            elif method == "DELETE":
                resp = requests.delete(url, headers=headers, timeout=10)
            else:
                return None
            
            if resp.status_code == 401:
                self.connected = False
                return {"error": "Non authentifié"}
            
            if resp.status_code == 403:
                return {"error": "Permission insuffisante"}
            
            return resp.json()
            
        except requests.exceptions.ConnectionError:
            self.connected = False
            return {"error": "Connexion perdue"}
        except Exception as e:
            return {"error": str(e)}
    
    # =========================================================================
    # CAPTURE
    # =========================================================================
    
    def start_capture(self, interface: str = None, filter: str = None) -> Dict:
        """Démarre la capture sur la Station."""
        data = {}
        if interface:
            data["interface"] = interface
        if filter:
            data["filter"] = filter
        
        return self._request("POST", "/api/capture/start", data) or {"success": False}
    
    def stop_capture(self) -> Dict:
        """Arrête la capture sur la Station."""
        return self._request("POST", "/api/capture/stop") or {"success": False}
    
    def clear_data(self) -> Dict:
        """Efface les données sur la Station."""
        return self._request("POST", "/api/capture/clear") or {"success": False}
    
    # =========================================================================
    # DATA RETRIEVAL
    # =========================================================================
    
    def get_packets(self, limit: int = 100, offset: int = 0, tag: int = None) -> Dict:
        """Récupère les paquets."""
        params = {"limit": limit, "offset": offset}
        if tag is not None:
            params["tag"] = tag
        return self._request("GET", "/api/packets", params=params) or {"packets": [], "total": 0}
    
    def get_stats(self) -> Dict:
        """Récupère les statistiques."""
        result = self._request("GET", "/api/stats")
        if result and "error" not in result:
            self._last_stats = result
        return result or {}
    
    def get_alerts(self, limit: int = 100) -> Dict:
        """Récupère les alertes."""
        return self._request("GET", "/api/alerts", params={"limit": limit}) or {"alerts": []}
    
    def get_devices(self) -> Dict:
        """Récupère les appareils."""
        return self._request("GET", "/api/devices") or {"devices": [], "total": 0}
    
    def get_baseline(self) -> Dict:
        """Récupère les données de baseline."""
        return self._request("GET", "/api/baseline") or {"baseline": {}}
    
    def get_config(self) -> Dict:
        """Récupère la configuration."""
        return self._request("GET", "/api/config") or {"config": {}}
    
    # =========================================================================
    # USER MANAGEMENT
    # =========================================================================
    
    def get_users(self) -> List[Dict]:
        """Récupère la liste des utilisateurs (admin)."""
        result = self._request("GET", "/api/auth/users")
        return result.get("users", []) if result else []
    
    def create_user(self, username: str, password: str, role: str = "viewer",
                   email: str = None, full_name: str = None) -> Dict:
        """Crée un utilisateur (admin)."""
        data = {
            "username": username,
            "password": password,
            "role": role
        }
        if email:
            data["email"] = email
        if full_name:
            data["full_name"] = full_name
        
        return self._request("POST", "/api/auth/users", data) or {"success": False}
    
    def get_tickets(self) -> List[Dict]:
        """Récupère les tickets (admin)."""
        result = self._request("GET", "/api/auth/tickets")
        return result.get("tickets", []) if result else []
    
    def create_ticket(self, username: str, ticket_type: str, subject: str, 
                     message: str = "") -> Dict:
        """Crée un ticket (sans auth nécessaire)."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/tickets",
                json={
                    "username": username,
                    "ticket_type": ticket_type,
                    "subject": subject,
                    "message": message
                },
                timeout=10
            )
            return resp.json()
        except:
            return {"success": False, "error": "Erreur de connexion"}
    
    # =========================================================================
    # WEBSOCKET
    # =========================================================================
    
    def connect_websocket(self) -> bool:
        """Connecte le WebSocket pour les données temps réel."""
        if not SOCKETIO_AVAILABLE:
            print("[!] python-socketio requis pour WebSocket")
            return False
        
        if self.ws_connected:
            return True
        
        try:
            self.sio = socketio.Client()
            
            @self.sio.on('connect', namespace='/live')
            def on_connect():
                self.ws_connected = True
                print("[WS] Connecté à la Station")
            
            @self.sio.on('disconnect', namespace='/live')
            def on_disconnect():
                self.ws_connected = False
                print("[WS] Déconnecté de la Station")
            
            @self.sio.on('new_packet', namespace='/live')
            def on_packet(data):
                for cb in self._packet_callbacks:
                    try:
                        cb(data)
                    except:
                        pass
            
            @self.sio.on('new_alert', namespace='/live')
            def on_alert(data):
                for cb in self._alert_callbacks:
                    try:
                        cb(data)
                    except:
                        pass
            
            self.sio.connect(
                self.base_url,
                namespaces=['/live'],
                headers={"Authorization": f"Bearer {self.token}"} if self.token else {}
            )
            
            return True
            
        except Exception as e:
            print(f"[WS] Erreur connexion: {e}")
            return False
    
    def disconnect_websocket(self):
        """Déconnecte le WebSocket."""
        if self.sio:
            try:
                self.sio.disconnect()
            except:
                pass
            self.sio = None
        self.ws_connected = False
    
    # =========================================================================
    # POLLING (Alternative au WebSocket)
    # =========================================================================
    
    def start_polling(self, interval: float = 2.0):
        """Démarre le polling pour récupérer les données périodiquement."""
        if self._polling:
            return
        
        self._polling = True
        self._poll_interval = interval
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
    
    def stop_polling(self):
        """Arrête le polling."""
        self._polling = False
        if self._poll_thread:
            self._poll_thread.join(timeout=2)
            self._poll_thread = None
    
    def _poll_loop(self):
        """Boucle de polling."""
        last_packet_count = 0
        last_alert_count = 0
        
        while self._polling and self.connected:
            try:
                # Stats
                stats = self.get_stats()
                if stats:
                    current_count = stats.get("total", 0)
                    
                    # Nouveaux paquets ?
                    if current_count > last_packet_count:
                        # Récupérer les derniers paquets
                        new_count = current_count - last_packet_count
                        packets_data = self.get_packets(limit=min(new_count, 100))
                        
                        for pkt in packets_data.get("packets", [])[-new_count:]:
                            for cb in self._packet_callbacks:
                                try:
                                    cb(pkt)
                                except:
                                    pass
                        
                        last_packet_count = current_count
                
                # Alertes
                alerts_data = self.get_alerts(limit=10)
                alerts = alerts_data.get("alerts", [])
                if len(alerts) > last_alert_count:
                    for alert in alerts[:len(alerts) - last_alert_count]:
                        for cb in self._alert_callbacks:
                            try:
                                cb(alert)
                            except:
                                pass
                    last_alert_count = len(alerts)
                
            except:
                pass
            
            time.sleep(self._poll_interval)
    
    # =========================================================================
    # CALLBACKS
    # =========================================================================
    
    def on_packet(self, callback: Callable):
        """Enregistre un callback pour les nouveaux paquets."""
        self._packet_callbacks.append(callback)
    
    def on_alert(self, callback: Callable):
        """Enregistre un callback pour les nouvelles alertes."""
        self._alert_callbacks.append(callback)
    
    def on_connection_change(self, callback: Callable):
        """Enregistre un callback pour les changements de connexion."""
        self._connection_callbacks.append(callback)
    
    # =========================================================================
    # PROPERTIES
    # =========================================================================
    
    @property
    def is_connected(self) -> bool:
        return self.connected and self.token is not None
    
    @property
    def is_admin(self) -> bool:
        if not self.user:
            return False
        return self.user.get("role") == "admin" or "all" in self.user.get("permissions", [])
    
    def has_permission(self, permission: str) -> bool:
        if not self.user:
            return False
        perms = self.user.get("permissions", [])
        return "all" in perms or permission in perms


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    print("Test du client Station...")
    
    client = StationClient("127.0.0.1", 5000)
    
    # Test ping
    if client.ping():
        print("[OK] Station accessible")
        
        # Test status
        status = client.get_status()
        if status:
            print(f"[OK] Version: {status.get('version')}")
        
        # Test login
        success, msg, user = client.login("admin", "admin")
        if success:
            print(f"[OK] Connecté en tant que {user.get('username')}")
            
            # Test stats
            stats = client.get_stats()
            print(f"[OK] Stats: {stats}")
            
            # Logout
            client.logout()
            print("[OK] Déconnecté")
        else:
            print(f"[!] Login échoué: {msg}")
    else:
        print("[!] Station inaccessible")
