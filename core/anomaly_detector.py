#!/usr/bin/env python3
"""
MIBurnout - Module de Détection d'Anomalies
============================================
Analyse le trafic SNMP pour détecter les comportements anormaux.
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import time
import threading


@dataclass
class AnomalyAlert:
    """Représente une alerte d'anomalie"""
    timestamp: str
    anomaly_type: str
    severity: str  # info, warning, critical
    source_ip: str
    message: str
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "type": self.anomaly_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "message": self.message,
            "details": self.details
        }


class AnomalyDetector:
    """Détecteur d'anomalies dans le trafic SNMP"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Seuils par défaut (peuvent être personnalisés)
        self.thresholds = {
            "packets_per_second": 100,          # Max paquets/seconde par IP
            "error_rate_percent": 10,           # Max % d'erreurs
            "trap_rate_per_minute": 50,         # Max traps/minute
            "scan_detection_count": 20,         # GetNext consécutifs = scan
            "auth_failure_threshold": 5,        # Échecs auth avant alerte
            "community_strings_threshold": 3,   # Communautés différentes/IP
            "request_response_ratio": 0.1,      # Min réponses/requêtes
        }
        self.thresholds.update(self.config.get("thresholds", {}))
        
        # Compteurs par IP
        self.ip_packet_count: Dict[str, int] = defaultdict(int)
        self.ip_error_count: Dict[str, int] = defaultdict(int)
        self.ip_trap_count: Dict[str, int] = defaultdict(int)
        self.ip_getnext_count: Dict[str, int] = defaultdict(int)
        self.ip_community_strings: Dict[str, set] = defaultdict(set)
        self.ip_requests: Dict[str, int] = defaultdict(int)
        self.ip_responses: Dict[str, int] = defaultdict(int)
        
        # Historique temporel
        self.packet_history: deque = deque(maxlen=10000)
        self.time_buckets: Dict[int, int] = defaultdict(int)
        
        # Alertes
        self.alerts: List[AnomalyAlert] = []
        self.alerts_lock = threading.Lock()
        
        # État
        self.start_time = time.time()
        self.total_packets = 0
        self.last_reset = time.time()
        
    def reset_counters(self):
        """Réinitialise les compteurs périodiquement"""
        current_time = time.time()
        if current_time - self.last_reset > 60:  # Reset toutes les minutes
            self.ip_packet_count.clear()
            self.ip_trap_count.clear()
            self.ip_getnext_count.clear()
            self.last_reset = current_time
    
    def analyze_packet(self, packet_data: Dict) -> List[AnomalyAlert]:
        """Analyse un paquet et retourne les anomalies détectées"""
        new_alerts = []
        
        self.reset_counters()
        self.total_packets += 1
        
        ip_src = packet_data.get("ip_src", "unknown")
        ip_dst = packet_data.get("ip_dst", "unknown")
        pdu_type = packet_data.get("snmp_pdu_type", "")
        community = packet_data.get("snmp_community", "")
        error_status = packet_data.get("snmp_error_status")
        timestamp = packet_data.get("time_stamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Mise à jour des compteurs
        self.ip_packet_count[ip_src] += 1
        
        if community:
            self.ip_community_strings[ip_src].add(community)
        
        # 1. Détection de flood/DDoS
        if self.ip_packet_count[ip_src] > self.thresholds["packets_per_second"]:
            alert = AnomalyAlert(
                timestamp=timestamp,
                anomaly_type="FLOOD_DETECTED",
                severity="critical",
                source_ip=ip_src,
                message=f"Flood détecté: {self.ip_packet_count[ip_src]} paquets/min depuis {ip_src}",
                details={"packet_count": self.ip_packet_count[ip_src]}
            )
            new_alerts.append(alert)
        
        # 2. Détection de scan réseau (beaucoup de GetNext)
        if pdu_type and "GetNext" in pdu_type:
            self.ip_getnext_count[ip_src] += 1
            if self.ip_getnext_count[ip_src] > self.thresholds["scan_detection_count"]:
                alert = AnomalyAlert(
                    timestamp=timestamp,
                    anomaly_type="NETWORK_SCAN",
                    severity="warning",
                    source_ip=ip_src,
                    message=f"Scan réseau potentiel: {self.ip_getnext_count[ip_src]} GetNext depuis {ip_src}",
                    details={"getnext_count": self.ip_getnext_count[ip_src]}
                )
                new_alerts.append(alert)
        
        # 3. Détection de tempête de traps
        if pdu_type and "Trap" in pdu_type:
            self.ip_trap_count[ip_src] += 1
            if self.ip_trap_count[ip_src] > self.thresholds["trap_rate_per_minute"]:
                alert = AnomalyAlert(
                    timestamp=timestamp,
                    anomaly_type="TRAP_STORM",
                    severity="critical",
                    source_ip=ip_src,
                    message=f"Tempête de traps: {self.ip_trap_count[ip_src]} traps/min depuis {ip_src}",
                    details={"trap_count": self.ip_trap_count[ip_src]}
                )
                new_alerts.append(alert)
        
        # 4. Détection d'erreurs SNMP
        if error_status and int(error_status) != 0:
            self.ip_error_count[ip_src] += 1
            
            # Erreur d'authentification
            if int(error_status) == 16:  # authorizationError
                alert = AnomalyAlert(
                    timestamp=timestamp,
                    anomaly_type="AUTH_FAILURE",
                    severity="warning",
                    source_ip=ip_src,
                    message=f"Échec d'authentification SNMP depuis {ip_src}",
                    details={"error_status": error_status}
                )
                new_alerts.append(alert)
        
        # 5. Détection d'énumération de communautés
        if len(self.ip_community_strings[ip_src]) > self.thresholds["community_strings_threshold"]:
            alert = AnomalyAlert(
                timestamp=timestamp,
                anomaly_type="COMMUNITY_ENUM",
                severity="warning",
                source_ip=ip_src,
                message=f"Énumération de communautés: {len(self.ip_community_strings[ip_src])} communautés testées par {ip_src}",
                details={"communities": list(self.ip_community_strings[ip_src])}
            )
            new_alerts.append(alert)
        
        # 6. Tracking requêtes/réponses
        if pdu_type:
            if "Request" in pdu_type:
                self.ip_requests[ip_src] += 1
            elif "Response" in pdu_type:
                self.ip_responses[ip_dst] += 1
        
        # Enregistrement des alertes
        with self.alerts_lock:
            self.alerts.extend(new_alerts)
        
        return new_alerts
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques globales"""
        duration = time.time() - self.start_time
        
        total_errors = sum(self.ip_error_count.values())
        error_rate = (total_errors / self.total_packets * 100) if self.total_packets > 0 else 0
        
        return {
            "total_packets": self.total_packets,
            "duration_seconds": duration,
            "packets_per_second": self.total_packets / duration if duration > 0 else 0,
            "total_errors": total_errors,
            "error_rate_percent": error_rate,
            "unique_sources": len(self.ip_packet_count),
            "total_alerts": len(self.alerts),
            "alerts_by_severity": self._count_alerts_by_severity(),
            "alerts_by_type": self._count_alerts_by_type(),
            "top_talkers": self._get_top_talkers(5),
        }
    
    def _count_alerts_by_severity(self) -> Dict[str, int]:
        """Compte les alertes par niveau de sévérité"""
        counts = {"info": 0, "warning": 0, "critical": 0}
        with self.alerts_lock:
            for alert in self.alerts:
                counts[alert.severity] = counts.get(alert.severity, 0) + 1
        return counts
    
    def _count_alerts_by_type(self) -> Dict[str, int]:
        """Compte les alertes par type"""
        counts = {}
        with self.alerts_lock:
            for alert in self.alerts:
                counts[alert.anomaly_type] = counts.get(alert.anomaly_type, 0) + 1
        return counts
    
    def _get_top_talkers(self, limit: int = 10) -> List[tuple]:
        """Retourne les IPs les plus actives"""
        sorted_ips = sorted(self.ip_packet_count.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:limit]
    
    def get_alerts(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """Retourne les alertes filtrées"""
        with self.alerts_lock:
            alerts = self.alerts[-limit:]
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            return [a.to_dict() for a in alerts]
    
    def clear_alerts(self):
        """Efface toutes les alertes"""
        with self.alerts_lock:
            self.alerts.clear()
    
    def get_ip_profile(self, ip: str) -> Dict:
        """Retourne le profil comportemental d'une IP"""
        return {
            "ip": ip,
            "packet_count": self.ip_packet_count.get(ip, 0),
            "error_count": self.ip_error_count.get(ip, 0),
            "trap_count": self.ip_trap_count.get(ip, 0),
            "getnext_count": self.ip_getnext_count.get(ip, 0),
            "community_strings": list(self.ip_community_strings.get(ip, set())),
            "requests": self.ip_requests.get(ip, 0),
            "responses": self.ip_responses.get(ip, 0),
        }


# Instance globale
_detector: Optional[AnomalyDetector] = None

def get_detector(config: Dict = None) -> AnomalyDetector:
    """Récupère l'instance du détecteur"""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector(config)
    return _detector


if __name__ == "__main__":
    # Test du détecteur
    detector = AnomalyDetector()
    
    # Simulation de paquets
    test_packets = [
        {"ip_src": "192.168.1.100", "snmp_pdu_type": "SNMPget", "snmp_community": "public"},
        {"ip_src": "192.168.1.100", "snmp_pdu_type": "SNMPgetnext", "snmp_community": "public"},
        {"ip_src": "10.0.0.1", "snmp_pdu_type": "SNMPtrap", "snmp_community": "public"},
    ]
    
    # Simulation de flood
    for i in range(150):
        test_packets.append({
            "ip_src": "192.168.1.200",
            "snmp_pdu_type": "SNMPget",
            "snmp_community": "public"
        })
    
    # Simulation de scan
    for i in range(25):
        test_packets.append({
            "ip_src": "10.10.10.10",
            "snmp_pdu_type": "SNMPgetnext",
            "snmp_community": "public"
        })
    
    print("=== Test du détecteur d'anomalies ===\n")
    
    for pkt in test_packets:
        alerts = detector.analyze_packet(pkt)
        for alert in alerts:
            print(f"[{alert.severity.upper()}] {alert.message}")
    
    print("\n=== Statistiques ===")
    stats = detector.get_statistics()
    print(f"Total paquets: {stats['total_packets']}")
    print(f"Sources uniques: {stats['unique_sources']}")
    print(f"Total alertes: {stats['total_alerts']}")
    print(f"Par sévérité: {stats['alerts_by_severity']}")
    print(f"Par type: {stats['alerts_by_type']}")
    print(f"Top talkers: {stats['top_talkers']}")
