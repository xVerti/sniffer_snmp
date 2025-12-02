#!/usr/bin/env python3
"""
MIBurnout Database Module
Gestion SQLite pour l'historique des captures, métriques et configuration
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import threading


@dataclass
class CaptureSession:
    """Représente une session de capture"""
    id: Optional[int] = None
    name: str = ""
    start_time: str = ""
    end_time: str = ""
    packet_count: int = 0
    interface: str = ""
    filter_expr: str = ""
    notes: str = ""


@dataclass
class MetricRecord:
    """Représente un enregistrement de métrique"""
    id: Optional[int] = None
    timestamp: str = ""
    device_id: str = ""
    device_name: str = ""
    metric_name: str = ""
    metric_value: float = 0.0
    unit: str = ""


@dataclass
class AlertRecord:
    """Représente une alerte"""
    id: Optional[int] = None
    timestamp: str = ""
    device_id: str = ""
    device_name: str = ""
    severity: str = "warning"  # info, warning, critical
    metric_name: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0
    message: str = ""
    acknowledged: bool = False
    acknowledged_at: str = ""
    acknowledged_by: str = ""


@dataclass
class SavedFilter:
    """Représente un filtre sauvegardé"""
    id: Optional[int] = None
    name: str = ""
    expression: str = ""
    description: str = ""
    color: str = ""
    created_at: str = ""


@dataclass
class DeviceConfig:
    """Configuration d'un équipement"""
    id: Optional[int] = None
    device_id: str = ""
    name: str = ""
    host: str = ""
    port: int = 161
    community: str = "public"
    version: str = "v2c"
    enabled: bool = True
    poll_interval: int = 60
    thresholds: str = "{}"  # JSON
    created_at: str = ""
    updated_at: str = ""


class MIBurnoutDB:
    """Gestionnaire de base de données MIBurnout"""
    
    def __init__(self, db_path: str = "miburnout.db"):
        self.db_path = db_path
        self.local = threading.local()
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        """Obtient une connexion thread-safe"""
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self.local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.local.conn.row_factory = sqlite3.Row
        return self.local.conn
    
    @contextmanager
    def get_cursor(self):
        """Context manager pour les curseurs"""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
    
    def _init_db(self):
        """Initialise le schéma de la base de données"""
        with self.get_cursor() as cursor:
            # Table des sessions de capture
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS capture_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    packet_count INTEGER DEFAULT 0,
                    interface TEXT,
                    filter_expr TEXT,
                    notes TEXT
                )
            """)
            
            # Table des paquets capturés
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS captured_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    frame_number INTEGER,
                    timestamp REAL,
                    frame_length INTEGER,
                    ip_src TEXT,
                    ip_dst TEXT,
                    udp_src_port INTEGER,
                    udp_dst_port INTEGER,
                    snmp_version TEXT,
                    community TEXT,
                    pdu_type TEXT,
                    request_id INTEGER,
                    error_status INTEGER,
                    varbinds_json TEXT,
                    raw_hex TEXT,
                    marked INTEGER DEFAULT 0,
                    color_tag TEXT,
                    notes TEXT,
                    FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
                )
            """)
            
            # Index pour les recherches
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_session 
                ON captured_packets(session_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_ip_src 
                ON captured_packets(ip_src)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_pdu_type 
                ON captured_packets(pdu_type)
            """)
            
            # Table des métriques
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_name TEXT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    unit TEXT
                )
            """)
            
            # Index pour les métriques
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_device 
                ON metrics(device_id, timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_name 
                ON metrics(metric_name, timestamp)
            """)
            
            # Table des alertes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device_id TEXT,
                    device_name TEXT,
                    severity TEXT DEFAULT 'warning',
                    metric_name TEXT,
                    metric_value REAL,
                    threshold REAL,
                    message TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    acknowledged_at TEXT,
                    acknowledged_by TEXT
                )
            """)
            
            # Table des filtres sauvegardés
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS saved_filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    expression TEXT NOT NULL,
                    description TEXT,
                    color TEXT,
                    created_at TEXT
                )
            """)
            
            # Table de configuration des équipements
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT UNIQUE NOT NULL,
                    name TEXT,
                    host TEXT NOT NULL,
                    port INTEGER DEFAULT 161,
                    community TEXT DEFAULT 'public',
                    version TEXT DEFAULT 'v2c',
                    enabled INTEGER DEFAULT 1,
                    poll_interval INTEGER DEFAULT 60,
                    thresholds TEXT DEFAULT '{}',
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Table de configuration générale
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            """)
            
            # Table des profils
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    config_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Table des conversations SNMP (request/response matching)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS snmp_conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    request_id INTEGER,
                    request_packet_id INTEGER,
                    response_packet_id INTEGER,
                    request_time REAL,
                    response_time REAL,
                    latency_ms REAL,
                    FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
                )
            """)
    
    # ==================== SESSIONS ====================
    
    def create_session(self, name: str, interface: str = "", filter_expr: str = "") -> int:
        """Crée une nouvelle session de capture"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO capture_sessions (name, start_time, interface, filter_expr)
                VALUES (?, ?, ?, ?)
            """, (name, datetime.now().isoformat(), interface, filter_expr))
            return cursor.lastrowid
    
    def end_session(self, session_id: int, packet_count: int):
        """Termine une session de capture"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                UPDATE capture_sessions 
                SET end_time = ?, packet_count = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), packet_count, session_id))
    
    def get_sessions(self, limit: int = 50) -> List[CaptureSession]:
        """Récupère les sessions de capture"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM capture_sessions 
                ORDER BY start_time DESC 
                LIMIT ?
            """, (limit,))
            
            return [CaptureSession(**dict(row)) for row in cursor.fetchall()]
    
    def delete_session(self, session_id: int):
        """Supprime une session et ses paquets"""
        with self.get_cursor() as cursor:
            cursor.execute("DELETE FROM captured_packets WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM snmp_conversations WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM capture_sessions WHERE id = ?", (session_id,))
    
    # ==================== PAQUETS ====================
    
    def save_packet(self, session_id: int, packet_data: Dict) -> int:
        """Sauvegarde un paquet capturé"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO captured_packets (
                    session_id, frame_number, timestamp, frame_length,
                    ip_src, ip_dst, udp_src_port, udp_dst_port,
                    snmp_version, community, pdu_type, request_id,
                    error_status, varbinds_json, raw_hex, marked, color_tag, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                packet_data.get('frame_number', 0),
                packet_data.get('timestamp', 0),
                packet_data.get('frame_length', 0),
                packet_data.get('ip_src', ''),
                packet_data.get('ip_dst', ''),
                packet_data.get('udp_src_port', 0),
                packet_data.get('udp_dst_port', 0),
                packet_data.get('version', ''),
                packet_data.get('community', ''),
                packet_data.get('pdu_type', ''),
                packet_data.get('request_id', 0),
                packet_data.get('error_status', 0),
                json.dumps(packet_data.get('varbinds', [])),
                packet_data.get('raw_hex', ''),
                1 if packet_data.get('marked', False) else 0,
                packet_data.get('color_tag', ''),
                packet_data.get('notes', ''),
            ))
            return cursor.lastrowid
    
    def save_packets_bulk(self, session_id: int, packets: List[Dict]):
        """Sauvegarde plusieurs paquets en batch"""
        with self.get_cursor() as cursor:
            cursor.executemany("""
                INSERT INTO captured_packets (
                    session_id, frame_number, timestamp, frame_length,
                    ip_src, ip_dst, udp_src_port, udp_dst_port,
                    snmp_version, community, pdu_type, request_id,
                    error_status, varbinds_json, raw_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    session_id,
                    p.get('frame_number', 0),
                    p.get('timestamp', 0),
                    p.get('frame_length', 0),
                    p.get('ip_src', ''),
                    p.get('ip_dst', ''),
                    p.get('udp_src_port', 0),
                    p.get('udp_dst_port', 0),
                    p.get('version', ''),
                    p.get('community', ''),
                    p.get('pdu_type', ''),
                    p.get('request_id', 0),
                    p.get('error_status', 0),
                    json.dumps(p.get('varbinds', [])),
                    p.get('raw_hex', ''),
                ) for p in packets
            ])
    
    def get_session_packets(self, session_id: int, limit: int = 10000) -> List[Dict]:
        """Récupère les paquets d'une session"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM captured_packets 
                WHERE session_id = ?
                ORDER BY frame_number
                LIMIT ?
            """, (session_id, limit))
            
            packets = []
            for row in cursor.fetchall():
                packet = dict(row)
                packet['varbinds'] = json.loads(packet['varbinds_json'] or '[]')
                del packet['varbinds_json']
                packets.append(packet)
            
            return packets
    
    def mark_packet(self, packet_id: int, marked: bool = True, color: str = "", notes: str = ""):
        """Marque un paquet"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                UPDATE captured_packets 
                SET marked = ?, color_tag = ?, notes = ?
                WHERE id = ?
            """, (1 if marked else 0, color, notes, packet_id))
    
    def search_packets(self, session_id: int, query: str) -> List[Dict]:
        """Recherche dans les paquets"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM captured_packets 
                WHERE session_id = ? AND (
                    ip_src LIKE ? OR ip_dst LIKE ? OR 
                    pdu_type LIKE ? OR community LIKE ? OR
                    varbinds_json LIKE ? OR notes LIKE ?
                )
                ORDER BY frame_number
            """, (session_id, f"%{query}%", f"%{query}%", f"%{query}%", 
                  f"%{query}%", f"%{query}%", f"%{query}%"))
            
            packets = []
            for row in cursor.fetchall():
                packet = dict(row)
                packet['varbinds'] = json.loads(packet['varbinds_json'] or '[]')
                del packet['varbinds_json']
                packets.append(packet)
            
            return packets
    
    # ==================== MÉTRIQUES ====================
    
    def save_metric(self, device_id: str, device_name: str, metric_name: str, 
                    value: float, unit: str = ""):
        """Sauvegarde une métrique"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO metrics (timestamp, device_id, device_name, metric_name, metric_value, unit)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), device_id, device_name, metric_name, value, unit))
    
    def get_metrics(self, device_id: str, metric_name: str, 
                    hours: int = 24, limit: int = 1000) -> List[MetricRecord]:
        """Récupère l'historique des métriques"""
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM metrics 
                WHERE device_id = ? AND metric_name = ? AND timestamp > ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (device_id, metric_name, since, limit))
            
            return [MetricRecord(**dict(row)) for row in cursor.fetchall()]
    
    def get_latest_metrics(self, device_id: str) -> Dict[str, float]:
        """Récupère les dernières valeurs de toutes les métriques d'un équipement"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT metric_name, metric_value 
                FROM metrics 
                WHERE device_id = ? 
                GROUP BY metric_name 
                HAVING timestamp = MAX(timestamp)
            """, (device_id,))
            
            return {row['metric_name']: row['metric_value'] for row in cursor.fetchall()}
    
    def cleanup_old_metrics(self, days: int = 30):
        """Supprime les métriques anciennes"""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        with self.get_cursor() as cursor:
            cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))
            return cursor.rowcount
    
    # ==================== ALERTES ====================
    
    def create_alert(self, device_id: str, device_name: str, severity: str,
                     metric_name: str, metric_value: float, threshold: float, message: str) -> int:
        """Crée une alerte"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp, device_id, device_name, severity,
                    metric_name, metric_value, threshold, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), device_id, device_name, severity,
                  metric_name, metric_value, threshold, message))
            return cursor.lastrowid
    
    def get_alerts(self, acknowledged: Optional[bool] = None, 
                   severity: Optional[str] = None, limit: int = 100) -> List[AlertRecord]:
        """Récupère les alertes"""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(1 if acknowledged else 0)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return [AlertRecord(**dict(row)) for row in cursor.fetchall()]
    
    def acknowledge_alert(self, alert_id: int, by: str = "user"):
        """Acquitte une alerte"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                UPDATE alerts 
                SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), by, alert_id))
    
    def get_alert_count(self, acknowledged: bool = False) -> int:
        """Compte les alertes"""
        with self.get_cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) as count FROM alerts WHERE acknowledged = ?",
                (1 if acknowledged else 0,)
            )
            return cursor.fetchone()['count']
    
    # ==================== FILTRES ====================
    
    def save_filter(self, name: str, expression: str, description: str = "", color: str = ""):
        """Sauvegarde un filtre"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO saved_filters (name, expression, description, color, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (name, expression, description, color, datetime.now().isoformat()))
    
    def get_filters(self) -> List[SavedFilter]:
        """Récupère tous les filtres"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT * FROM saved_filters ORDER BY name")
            return [SavedFilter(**dict(row)) for row in cursor.fetchall()]
    
    def delete_filter(self, name: str):
        """Supprime un filtre"""
        with self.get_cursor() as cursor:
            cursor.execute("DELETE FROM saved_filters WHERE name = ?", (name,))
    
    # ==================== ÉQUIPEMENTS ====================
    
    def save_device(self, device: DeviceConfig):
        """Sauvegarde un équipement"""
        now = datetime.now().isoformat()
        
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO devices (
                    device_id, name, host, port, community, version,
                    enabled, poll_interval, thresholds, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT created_at FROM devices WHERE device_id = ?), ?), ?)
            """, (
                device.device_id, device.name, device.host, device.port,
                device.community, device.version, 1 if device.enabled else 0,
                device.poll_interval, device.thresholds,
                device.device_id, now, now
            ))
    
    def get_devices(self, enabled_only: bool = False) -> List[DeviceConfig]:
        """Récupère les équipements"""
        query = "SELECT * FROM devices"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY name"
        
        with self.get_cursor() as cursor:
            cursor.execute(query)
            return [DeviceConfig(**dict(row)) for row in cursor.fetchall()]
    
    def delete_device(self, device_id: str):
        """Supprime un équipement"""
        with self.get_cursor() as cursor:
            cursor.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
    
    # ==================== CONFIGURATION ====================
    
    def set_config(self, key: str, value: Any):
        """Définit une valeur de configuration"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO config (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, json.dumps(value), datetime.now().isoformat()))
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Récupère une valeur de configuration"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['value'])
            return default
    
    # ==================== PROFILS ====================
    
    def save_profile(self, name: str, config: Dict):
        """Sauvegarde un profil de configuration"""
        now = datetime.now().isoformat()
        
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO profiles (name, config_json, created_at, updated_at)
                VALUES (?, ?, 
                    COALESCE((SELECT created_at FROM profiles WHERE name = ?), ?), ?)
            """, (name, json.dumps(config), name, now, now))
    
    def get_profile(self, name: str) -> Optional[Dict]:
        """Récupère un profil"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT config_json FROM profiles WHERE name = ?", (name,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['config_json'])
            return None
    
    def get_profiles(self) -> List[str]:
        """Liste les profils disponibles"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT name FROM profiles ORDER BY name")
            return [row['name'] for row in cursor.fetchall()]
    
    def delete_profile(self, name: str):
        """Supprime un profil"""
        with self.get_cursor() as cursor:
            cursor.execute("DELETE FROM profiles WHERE name = ?", (name,))
    
    # ==================== CONVERSATIONS SNMP ====================
    
    def save_conversation(self, session_id: int, request_id: int, 
                          request_packet_id: int, request_time: float):
        """Enregistre le début d'une conversation (requête)"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO snmp_conversations (session_id, request_id, request_packet_id, request_time)
                VALUES (?, ?, ?, ?)
            """, (session_id, request_id, request_packet_id, request_time))
            return cursor.lastrowid
    
    def complete_conversation(self, session_id: int, request_id: int,
                              response_packet_id: int, response_time: float):
        """Complète une conversation (réponse)"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                UPDATE snmp_conversations 
                SET response_packet_id = ?, response_time = ?, 
                    latency_ms = (? - request_time) * 1000
                WHERE session_id = ? AND request_id = ? AND response_packet_id IS NULL
            """, (response_packet_id, response_time, response_time, session_id, request_id))
    
    def get_conversations(self, session_id: int) -> List[Dict]:
        """Récupère les conversations d'une session"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM snmp_conversations 
                WHERE session_id = ?
                ORDER BY request_time
            """, (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== STATISTIQUES ====================
    
    def get_top_talkers(self, session_id: int, limit: int = 10) -> List[Tuple[str, int]]:
        """Récupère les IPs les plus actives"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT ip_src as ip, COUNT(*) as count 
                FROM captured_packets 
                WHERE session_id = ?
                GROUP BY ip_src
                ORDER BY count DESC
                LIMIT ?
            """, (session_id, limit))
            return [(row['ip'], row['count']) for row in cursor.fetchall()]
    
    def get_pdu_distribution(self, session_id: int) -> Dict[str, int]:
        """Récupère la distribution des types de PDU"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT pdu_type, COUNT(*) as count 
                FROM captured_packets 
                WHERE session_id = ?
                GROUP BY pdu_type
            """, (session_id,))
            return {row['pdu_type']: row['count'] for row in cursor.fetchall()}
    
    def get_traffic_timeline(self, session_id: int, interval_seconds: int = 60) -> List[Tuple[int, int]]:
        """Récupère la timeline du trafic"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT CAST(timestamp / ? AS INTEGER) * ? as time_bucket, COUNT(*) as count
                FROM captured_packets 
                WHERE session_id = ?
                GROUP BY time_bucket
                ORDER BY time_bucket
            """, (interval_seconds, interval_seconds, session_id))
            return [(row['time_bucket'], row['count']) for row in cursor.fetchall()]
    
    def get_error_stats(self, session_id: int) -> Dict[int, int]:
        """Récupère les statistiques d'erreurs"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT error_status, COUNT(*) as count 
                FROM captured_packets 
                WHERE session_id = ? AND error_status > 0
                GROUP BY error_status
            """, (session_id,))
            return {row['error_status']: row['count'] for row in cursor.fetchall()}
    
    def get_average_latency(self, session_id: int) -> Optional[float]:
        """Récupère la latence moyenne des conversations"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT AVG(latency_ms) as avg_latency 
                FROM snmp_conversations 
                WHERE session_id = ? AND latency_ms IS NOT NULL
            """, (session_id,))
            row = cursor.fetchone()
            return row['avg_latency'] if row else None
    
    def get_database_stats(self) -> Dict[str, int]:
        """Récupère les statistiques de la base de données"""
        with self.get_cursor() as cursor:
            stats = {}
            
            for table in ['capture_sessions', 'captured_packets', 'metrics', 'alerts', 'devices']:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[table] = cursor.fetchone()['count']
            
            # Taille de la base de données
            cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
            row = cursor.fetchone()
            stats['db_size_bytes'] = row['size'] if row else 0
            
            return stats
    
    def vacuum(self):
        """Optimise la base de données"""
        conn = self._get_conn()
        conn.execute("VACUUM")


# Singleton pour accès global
_db_instance: Optional[MIBurnoutDB] = None

def get_db(db_path: str = "miburnout.db") -> MIBurnoutDB:
    """Récupère l'instance de la base de données"""
    global _db_instance
    if _db_instance is None:
        _db_instance = MIBurnoutDB(db_path)
    return _db_instance


if __name__ == "__main__":
    # Test de la base de données
    db = MIBurnoutDB(":memory:")  # Base en mémoire pour les tests
    
    # Test session
    session_id = db.create_session("Test Session", "eth0", "snmp")
    print(f"Created session: {session_id}")
    
    # Test packet
    packet_id = db.save_packet(session_id, {
        'frame_number': 1,
        'timestamp': 0.0,
        'frame_length': 100,
        'ip_src': '192.168.1.1',
        'ip_dst': '192.168.1.2',
        'pdu_type': 'GetRequest',
        'request_id': 12345,
        'varbinds': [{'oid': '1.3.6.1.2.1.1.1.0', 'name': 'sysDescr', 'value': 'Test'}]
    })
    print(f"Saved packet: {packet_id}")
    
    # Test metric
    db.save_metric("device1", "Router1", "ssCpuUser", 45.5, "%")
    metrics = db.get_metrics("device1", "ssCpuUser", hours=1)
    print(f"Metrics: {len(metrics)}")
    
    # Test alert
    alert_id = db.create_alert("device1", "Router1", "warning", "ssCpuUser", 85.0, 80.0, "CPU élevé")
    print(f"Created alert: {alert_id}")
    
    # Test filter
    db.save_filter("GetRequests", "pdu_type==GetRequest", "Filtre GET", "#4A90E2")
    filters = db.get_filters()
    print(f"Filters: {[f.name for f in filters]}")
    
    # Test config
    db.set_config("refresh_interval", 5000)
    interval = db.get_config("refresh_interval")
    print(f"Config refresh_interval: {interval}")
    
    # Test profile
    db.save_profile("default", {"theme": "dark", "auto_refresh": True})
    profile = db.get_profile("default")
    print(f"Profile: {profile}")
    
    # Stats
    stats = db.get_database_stats()
    print(f"DB Stats: {stats}")
    
    print("\n✅ All database tests passed!")
