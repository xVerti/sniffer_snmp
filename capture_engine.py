#!/usr/bin/env python3
"""
MIBurnout SNMP Capture Engine
Moteur de capture SNMP réelle avec Scapy
Supporte la capture live et l'analyse de fichiers PCAP
"""

import threading
import queue
import time
import os
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json

# Import conditionnel de Scapy
try:
    from scapy.all import (
        sniff, rdpcap, wrpcap, 
        IP, UDP, Raw,
        get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from snmp_decoder import SNMPDecoder, SNMPPacket


class CaptureMode(Enum):
    """Modes de capture"""
    LIVE = "live"
    FILE = "file"
    SIMULATION = "simulation"


@dataclass
class CaptureConfig:
    """Configuration de capture"""
    interface: str = ""
    filter_expr: str = "udp port 161 or udp port 162"
    promiscuous: bool = True
    timeout: int = 0  # 0 = infini
    packet_count: int = 0  # 0 = infini
    buffer_size: int = 65535
    snaplen: int = 65535


@dataclass
class CaptureStats:
    """Statistiques de capture"""
    packets_captured: int = 0
    packets_snmp: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    start_time: float = 0.0
    
    # Par type de PDU
    get_requests: int = 0
    get_next_requests: int = 0
    get_bulk_requests: int = 0
    set_requests: int = 0
    get_responses: int = 0
    traps: int = 0
    informs: int = 0
    
    # Erreurs
    decode_errors: int = 0
    snmp_errors: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'packets_captured': self.packets_captured,
            'packets_snmp': self.packets_snmp,
            'packets_dropped': self.packets_dropped,
            'bytes_captured': self.bytes_captured,
            'duration': time.time() - self.start_time if self.start_time else 0,
            'pps': self.packets_snmp / (time.time() - self.start_time) if self.start_time and time.time() > self.start_time else 0,
            'get_requests': self.get_requests,
            'get_next_requests': self.get_next_requests,
            'get_bulk_requests': self.get_bulk_requests,
            'set_requests': self.set_requests,
            'get_responses': self.get_responses,
            'traps': self.traps,
            'informs': self.informs,
            'decode_errors': self.decode_errors,
            'snmp_errors': self.snmp_errors,
        }


class PacketFilter:
    """Filtre de paquets avancé"""
    
    def __init__(self):
        self.rules: List[Dict] = []
    
    def parse(self, expression: str) -> bool:
        """Parse une expression de filtre"""
        self.rules.clear()
        
        if not expression.strip():
            return True
        
        # Syntaxe supportée:
        # ip.src==192.168.1.1
        # ip.dst==192.168.1.0/24
        # type==GetRequest
        # version==v2c
        # community==public
        # oid contains sysDescr
        # error!=0
        # port==161
        
        try:
            parts = expression.split(" and ")
            for part in parts:
                part = part.strip()
                
                if "==" in part:
                    field, value = part.split("==", 1)
                    self.rules.append({'op': 'eq', 'field': field.strip(), 'value': value.strip()})
                elif "!=" in part:
                    field, value = part.split("!=", 1)
                    self.rules.append({'op': 'ne', 'field': field.strip(), 'value': value.strip()})
                elif " contains " in part:
                    field, value = part.split(" contains ", 1)
                    self.rules.append({'op': 'contains', 'field': field.strip(), 'value': value.strip()})
                elif " in " in part:
                    field, value = part.split(" in ", 1)
                    values = [v.strip() for v in value.strip("[]()").split(",")]
                    self.rules.append({'op': 'in', 'field': field.strip(), 'values': values})
            
            return True
        except Exception:
            return False
    
    def match(self, packet: SNMPPacket) -> bool:
        """Vérifie si un paquet correspond au filtre"""
        if not self.rules:
            return True
        
        for rule in self.rules:
            field = rule['field'].lower()
            op = rule['op']
            
            # Récupérer la valeur du champ
            value = None
            if field in ('ip.src', 'src', 'source'):
                value = packet.ip_src
            elif field in ('ip.dst', 'dst', 'destination'):
                value = packet.ip_dst
            elif field in ('type', 'pdu_type', 'pdu'):
                value = packet.pdu_type
            elif field in ('version', 'snmp_version'):
                value = packet.version
            elif field in ('community'):
                value = packet.community
            elif field in ('port', 'src_port'):
                value = str(packet.udp_src_port)
            elif field in ('dst_port'):
                value = str(packet.udp_dst_port)
            elif field in ('error', 'error_status'):
                value = str(packet.error_status)
            elif field in ('request_id', 'reqid'):
                value = str(packet.request_id)
            elif field in ('oid', 'varbind'):
                # Cherche dans tous les OIDs
                value = " ".join([vb.oid + " " + vb.oid_name for vb in packet.varbinds])
            
            if value is None:
                return False
            
            # Appliquer l'opération
            if op == 'eq':
                if rule['value'].lower() not in value.lower():
                    return False
            elif op == 'ne':
                if rule['value'].lower() in value.lower():
                    return False
            elif op == 'contains':
                if rule['value'].lower() not in value.lower():
                    return False
            elif op == 'in':
                if not any(v.lower() in value.lower() for v in rule['values']):
                    return False
        
        return True


class CaptureEngine:
    """Moteur de capture SNMP"""
    
    def __init__(self):
        self.decoder = SNMPDecoder()
        self.config = CaptureConfig()
        self.stats = CaptureStats()
        
        self.running = False
        self.paused = False
        
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.callbacks: List[Callable[[SNMPPacket], None]] = []
        
        self.capture_thread: Optional[threading.Thread] = None
        self.process_thread: Optional[threading.Thread] = None
        
        self.filter = PacketFilter()
        self.captured_packets: List[SNMPPacket] = []
        
        # Tracking des conversations
        self.pending_requests: Dict[int, SNMPPacket] = {}  # request_id -> packet
    
    @staticmethod
    def get_interfaces() -> List[str]:
        """Liste les interfaces réseau disponibles"""
        if SCAPY_AVAILABLE:
            return get_if_list()
        return []
    
    @staticmethod
    def is_scapy_available() -> bool:
        """Vérifie si Scapy est disponible"""
        return SCAPY_AVAILABLE
    
    def add_callback(self, callback: Callable[[SNMPPacket], None]):
        """Ajoute un callback pour les nouveaux paquets"""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[SNMPPacket], None]):
        """Retire un callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def set_filter(self, expression: str) -> bool:
        """Définit le filtre de paquets"""
        return self.filter.parse(expression)
    
    def _process_packet(self, scapy_packet) -> Optional[SNMPPacket]:
        """Traite un paquet Scapy et le convertit en SNMPPacket"""
        try:
            if not scapy_packet.haslayer(IP) or not scapy_packet.haslayer(UDP):
                return None
            
            ip_layer = scapy_packet[IP]
            udp_layer = scapy_packet[UDP]
            
            # Vérifier le port SNMP
            if udp_layer.dport not in (161, 162) and udp_layer.sport not in (161, 162):
                return None
            
            # Extraire les données SNMP
            if not scapy_packet.haslayer(Raw):
                return None
            
            raw_data = bytes(scapy_packet[Raw].load)
            
            # Décoder le paquet SNMP
            snmp_packet = self.decoder.decode_safe(raw_data)
            if snmp_packet is None:
                self.stats.decode_errors += 1
                return None
            
            # Ajouter les métadonnées réseau
            snmp_packet.timestamp = float(scapy_packet.time)
            snmp_packet.frame_number = self.stats.packets_snmp + 1
            snmp_packet.frame_length = len(scapy_packet)
            snmp_packet.ip_src = ip_layer.src
            snmp_packet.ip_dst = ip_layer.dst
            snmp_packet.ip_ttl = ip_layer.ttl
            snmp_packet.ip_id = ip_layer.id
            snmp_packet.udp_src_port = udp_layer.sport
            snmp_packet.udp_dst_port = udp_layer.dport
            snmp_packet.udp_length = udp_layer.len
            snmp_packet.udp_checksum = udp_layer.chksum
            snmp_packet.raw_bytes = raw_data
            
            return snmp_packet
            
        except Exception as e:
            self.stats.decode_errors += 1
            return None
    
    def _update_stats(self, packet: SNMPPacket):
        """Met à jour les statistiques"""
        self.stats.packets_snmp += 1
        self.stats.bytes_captured += packet.frame_length
        
        pdu_type = packet.pdu_type.lower()
        
        if 'getrequest' in pdu_type and 'next' not in pdu_type and 'bulk' not in pdu_type:
            self.stats.get_requests += 1
        elif 'getnext' in pdu_type:
            self.stats.get_next_requests += 1
        elif 'getbulk' in pdu_type:
            self.stats.get_bulk_requests += 1
        elif 'setrequest' in pdu_type:
            self.stats.set_requests += 1
        elif 'response' in pdu_type:
            self.stats.get_responses += 1
        elif 'trap' in pdu_type:
            self.stats.traps += 1
        elif 'inform' in pdu_type:
            self.stats.informs += 1
        
        if packet.error_status != 0:
            self.stats.snmp_errors += 1
    
    def _match_conversation(self, packet: SNMPPacket):
        """Match les requêtes et réponses"""
        if 'Request' in packet.pdu_type:
            self.pending_requests[packet.request_id] = packet
        elif 'Response' in packet.pdu_type:
            if packet.request_id in self.pending_requests:
                request = self.pending_requests.pop(packet.request_id)
                # Calculer la latence
                latency = packet.timestamp - request.timestamp
                # On pourrait stocker cette info quelque part
    
    def _packet_callback(self, scapy_packet):
        """Callback appelé pour chaque paquet capturé"""
        self.stats.packets_captured += 1
        
        if self.paused:
            return
        
        snmp_packet = self._process_packet(scapy_packet)
        if snmp_packet is None:
            return
        
        # Appliquer le filtre
        if not self.filter.match(snmp_packet):
            return
        
        # Mettre à jour les stats
        self._update_stats(snmp_packet)
        
        # Match des conversations
        self._match_conversation(snmp_packet)
        
        # Stocker le paquet
        self.captured_packets.append(snmp_packet)
        
        # Mettre en queue pour les callbacks
        try:
            self.packet_queue.put_nowait(snmp_packet)
        except queue.Full:
            self.stats.packets_dropped += 1
    
    def _process_loop(self):
        """Boucle de traitement des paquets pour les callbacks"""
        while self.running or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=0.1)
                for callback in self.callbacks:
                    try:
                        callback(packet)
                    except Exception:
                        pass
            except queue.Empty:
                continue
    
    def start(self, mode: CaptureMode = CaptureMode.LIVE, 
              interface: str = "", pcap_file: str = ""):
        """Démarre la capture"""
        if self.running:
            return False
        
        self.running = True
        self.paused = False
        self.stats = CaptureStats()
        self.stats.start_time = time.time()
        self.captured_packets.clear()
        self.pending_requests.clear()
        
        if mode == CaptureMode.LIVE:
            if not SCAPY_AVAILABLE:
                self.running = False
                raise RuntimeError("Scapy n'est pas installé. Installez-le avec: pip install scapy")
            
            if interface:
                self.config.interface = interface
            
            def capture_thread():
                try:
                    sniff(
                        iface=self.config.interface if self.config.interface else None,
                        filter=self.config.filter_expr,
                        prn=self._packet_callback,
                        store=False,
                        promisc=self.config.promiscuous,
                        stop_filter=lambda x: not self.running,
                    )
                except Exception as e:
                    print(f"Capture error: {e}")
                finally:
                    self.running = False
            
            self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
            self.capture_thread.start()
        
        elif mode == CaptureMode.FILE:
            if not SCAPY_AVAILABLE:
                self.running = False
                raise RuntimeError("Scapy n'est pas installé")
            
            def file_thread():
                try:
                    packets = rdpcap(pcap_file)
                    for pkt in packets:
                        if not self.running:
                            break
                        self._packet_callback(pkt)
                except Exception as e:
                    print(f"File read error: {e}")
                finally:
                    self.running = False
            
            self.capture_thread = threading.Thread(target=file_thread, daemon=True)
            self.capture_thread.start()
        
        elif mode == CaptureMode.SIMULATION:
            # Mode simulation pour les tests
            def sim_thread():
                self._run_simulation()
            
            self.capture_thread = threading.Thread(target=sim_thread, daemon=True)
            self.capture_thread.start()
        
        # Thread de traitement des callbacks
        self.process_thread = threading.Thread(target=self._process_loop, daemon=True)
        self.process_thread.start()
        
        return True
    
    def _run_simulation(self):
        """Exécute une simulation de capture"""
        import random
        
        pdu_types = ["GetRequest", "GetResponse", "GetNextRequest", "SetRequest", 
                     "GetBulkRequest", "Trap", "InformRequest"]
        
        oids = [
            ("1.3.6.1.2.1.1.1.0", "sysDescr"),
            ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
            ("1.3.6.1.2.1.1.5.0", "sysName"),
            ("1.3.6.1.4.1.2021.11.9.0", "ssCpuUser"),
            ("1.3.6.1.4.1.2021.4.6.0", "memAvailReal"),
        ]
        
        frame_num = 0
        start_time = time.time()
        
        while self.running:
            if self.paused:
                time.sleep(0.1)
                continue
            
            frame_num += 1
            elapsed = time.time() - start_time
            
            pdu_type = random.choice(pdu_types)
            src_ip = f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
            dst_ip = f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
            
            # Créer des varbinds
            from snmp_decoder import VarBind
            num_varbinds = random.randint(1, 3)
            varbinds = []
            for _ in range(num_varbinds):
                oid, name = random.choice(oids)
                value = random.randint(0, 100000) if 'Cpu' in name or 'mem' in name.lower() else f"Device-{random.randint(1,100)}"
                varbinds.append(VarBind(
                    oid=oid,
                    oid_name=name,
                    value_type="INTEGER" if isinstance(value, int) else "STRING",
                    value=value
                ))
            
            packet = SNMPPacket(
                version=random.choice(["v1", "v2c", "v3"]),
                community=random.choice(["public", "private", "monitor"]),
                pdu_type=pdu_type,
                pdu_type_code=0xA0,
                request_id=random.randint(1, 2147483647),
                error_status=0 if random.random() > 0.05 else random.randint(1, 5),
                error_status_name="noError",
                error_index=0,
                varbinds=varbinds,
                timestamp=elapsed,
                frame_number=frame_num,
                frame_length=random.randint(80, 500),
                ip_src=src_ip,
                ip_dst=dst_ip,
                ip_ttl=64,
                ip_id=random.randint(1000, 65535),
                udp_src_port=161 if "Response" in pdu_type else random.randint(49152, 65535),
                udp_dst_port=161 if "Request" in pdu_type else random.randint(49152, 65535),
                udp_length=random.randint(60, 400),
                udp_checksum=random.randint(0, 65535),
                raw_bytes=os.urandom(random.randint(80, 300))
            )
            
            # Appliquer le filtre
            if not self.filter.match(packet):
                continue
            
            self._update_stats(packet)
            self._match_conversation(packet)
            self.captured_packets.append(packet)
            
            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                self.stats.packets_dropped += 1
            
            time.sleep(random.uniform(0.05, 0.3))
        
        self.running = False
    
    def stop(self):
        """Arrête la capture"""
        self.running = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        if self.process_thread and self.process_thread.is_alive():
            self.process_thread.join(timeout=2)
    
    def pause(self):
        """Met en pause la capture"""
        self.paused = True
    
    def resume(self):
        """Reprend la capture"""
        self.paused = False
    
    def clear(self):
        """Efface les paquets capturés"""
        self.captured_packets.clear()
        self.pending_requests.clear()
        
        # Vider la queue
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break
        
        # Reset les stats (sauf le temps de démarrage)
        start_time = self.stats.start_time
        self.stats = CaptureStats()
        self.stats.start_time = start_time
    
    def get_packets(self, start: int = 0, count: int = 0) -> List[SNMPPacket]:
        """Récupère les paquets capturés"""
        if count <= 0:
            return self.captured_packets[start:]
        return self.captured_packets[start:start + count]
    
    def get_packet(self, frame_number: int) -> Optional[SNMPPacket]:
        """Récupère un paquet par son numéro de frame"""
        for packet in self.captured_packets:
            if packet.frame_number == frame_number:
                return packet
        return None
    
    def export_pcap(self, filename: str) -> bool:
        """Exporte les paquets en PCAP"""
        if not SCAPY_AVAILABLE:
            return False
        
        try:
            # Reconstruire les paquets Scapy depuis les données brutes
            from scapy.all import Ether
            
            scapy_packets = []
            for pkt in self.captured_packets:
                # Créer un paquet IP/UDP/Raw
                ip_pkt = IP(src=pkt.ip_src, dst=pkt.ip_dst, ttl=pkt.ip_ttl)
                udp_pkt = UDP(sport=pkt.udp_src_port, dport=pkt.udp_dst_port)
                raw_pkt = Raw(load=pkt.raw_bytes)
                
                full_pkt = Ether() / ip_pkt / udp_pkt / raw_pkt
                full_pkt.time = pkt.timestamp
                scapy_packets.append(full_pkt)
            
            wrpcap(filename, scapy_packets)
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False
    
    def export_json(self, filename: str) -> bool:
        """Exporte les paquets en JSON"""
        try:
            data = [pkt.to_dict() for pkt in self.captured_packets]
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False
    
    def import_pcap(self, filename: str) -> int:
        """Importe un fichier PCAP"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy n'est pas installé")
        
        count = 0
        try:
            packets = rdpcap(filename)
            for pkt in packets:
                snmp_packet = self._process_packet(pkt)
                if snmp_packet:
                    self.captured_packets.append(snmp_packet)
                    self._update_stats(snmp_packet)
                    count += 1
        except Exception as e:
            print(f"Import error: {e}")
        
        return count
    
    def get_top_talkers(self, limit: int = 10) -> List[tuple]:
        """Récupère les IPs les plus actives"""
        ip_counts: Dict[str, int] = {}
        
        for pkt in self.captured_packets:
            ip_counts[pkt.ip_src] = ip_counts.get(pkt.ip_src, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:limit]
    
    def get_pdu_distribution(self) -> Dict[str, int]:
        """Récupère la distribution des types de PDU"""
        dist: Dict[str, int] = {}
        
        for pkt in self.captured_packets:
            dist[pkt.pdu_type] = dist.get(pkt.pdu_type, 0) + 1
        
        return dist
    
    def get_timeline(self, bucket_size: float = 1.0) -> List[tuple]:
        """Récupère la timeline du trafic"""
        if not self.captured_packets:
            return []
        
        buckets: Dict[int, int] = {}
        
        for pkt in self.captured_packets:
            bucket = int(pkt.timestamp / bucket_size)
            buckets[bucket] = buckets.get(bucket, 0) + 1
        
        return sorted(buckets.items())
    
    def find_anomalies(self) -> List[Dict]:
        """Détecte les anomalies dans le trafic"""
        anomalies = []
        
        # 1. Pics de trafic
        timeline = self.get_timeline(bucket_size=1.0)
        if len(timeline) > 10:
            avg_pps = sum(t[1] for t in timeline) / len(timeline)
            for bucket, count in timeline:
                if count > avg_pps * 3:  # 3x la moyenne
                    anomalies.append({
                        'type': 'traffic_spike',
                        'time': bucket,
                        'value': count,
                        'threshold': avg_pps * 3,
                        'message': f"Pic de trafic: {count} paquets/s (moyenne: {avg_pps:.1f})"
                    })
        
        # 2. Taux d'erreur élevé
        total = len(self.captured_packets)
        if total > 100:
            errors = self.stats.snmp_errors
            error_rate = errors / total * 100
            if error_rate > 5:  # Plus de 5% d'erreurs
                anomalies.append({
                    'type': 'high_error_rate',
                    'value': error_rate,
                    'threshold': 5,
                    'message': f"Taux d'erreur élevé: {error_rate:.1f}%"
                })
        
        # 3. Scan réseau potentiel (beaucoup de GetNextRequest)
        if self.stats.get_next_requests > total * 0.5 and total > 50:
            anomalies.append({
                'type': 'network_scan',
                'value': self.stats.get_next_requests,
                'message': f"Scan réseau potentiel détecté ({self.stats.get_next_requests} GetNextRequest)"
            })
        
        # 4. Tempête de traps
        if self.stats.traps > 100:
            trap_rate = self.stats.traps / (time.time() - self.stats.start_time) if self.stats.start_time else 0
            if trap_rate > 10:  # Plus de 10 traps/seconde
                anomalies.append({
                    'type': 'trap_storm',
                    'value': trap_rate,
                    'threshold': 10,
                    'message': f"Tempête de traps: {trap_rate:.1f} traps/s"
                })
        
        return anomalies


# Singleton
_capture_engine: Optional[CaptureEngine] = None

def get_capture_engine() -> CaptureEngine:
    """Récupère l'instance du moteur de capture"""
    global _capture_engine
    if _capture_engine is None:
        _capture_engine = CaptureEngine()
    return _capture_engine


if __name__ == "__main__":
    # Test du moteur de capture en mode simulation
    engine = CaptureEngine()
    
    def on_packet(packet: SNMPPacket):
        print(f"[{packet.frame_number}] {packet.ip_src} -> {packet.ip_dst}: {packet.pdu_type}")
    
    engine.add_callback(on_packet)
    
    print("Démarrage de la capture en mode simulation...")
    engine.start(mode=CaptureMode.SIMULATION)
    
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        pass
    
    engine.stop()
    
    print(f"\nStatistiques:")
    print(f"  Paquets capturés: {engine.stats.packets_snmp}")
    print(f"  GET Requests: {engine.stats.get_requests}")
    print(f"  GET Responses: {engine.stats.get_responses}")
    print(f"  Traps: {engine.stats.traps}")
    
    print(f"\nTop Talkers:")
    for ip, count in engine.get_top_talkers(5):
        print(f"  {ip}: {count} paquets")
    
    print(f"\nAnomalies:")
    for anomaly in engine.find_anomalies():
        print(f"  [{anomaly['type']}] {anomaly['message']}")
    
    # Test export
    engine.export_json("test_capture.json")
    print("\nExport JSON: test_capture.json")
