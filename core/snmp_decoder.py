#!/usr/bin/env python3
"""
MIBurnout - Décodeur SNMP ASN.1/BER Avancé
==========================================
Décode les paquets SNMP bruts en structures Python exploitables.
Supporte SNMPv1, SNMPv2c et SNMPv3.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import IntEnum
from datetime import datetime


class ASN1Tag(IntEnum):
    """Tags ASN.1 standards et SNMP-specific"""
    # Universal tags
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL = 0x05
    OID = 0x06
    SEQUENCE = 0x30
    
    # SNMP Application tags
    IP_ADDRESS = 0x40
    COUNTER32 = 0x41
    GAUGE32 = 0x42
    TIMETICKS = 0x43
    OPAQUE = 0x44
    COUNTER64 = 0x46
    
    # SNMP PDU types
    GET_REQUEST = 0xA0
    GET_NEXT_REQUEST = 0xA1
    GET_RESPONSE = 0xA2
    SET_REQUEST = 0xA3
    TRAP_V1 = 0xA4
    GET_BULK_REQUEST = 0xA5
    INFORM_REQUEST = 0xA6
    TRAP_V2 = 0xA7
    REPORT = 0xA8


PDU_TYPE_NAMES = {
    0xA0: "GetRequest",
    0xA1: "GetNextRequest",
    0xA2: "GetResponse",
    0xA3: "SetRequest",
    0xA4: "Trap-v1",
    0xA5: "GetBulkRequest",
    0xA6: "InformRequest",
    0xA7: "Trap-v2",
    0xA8: "Report",
}

SNMP_ERROR_STATUS = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}

# Base de données OID commune
OID_DATABASE = {
    "1.3.6.1.2.1.1.1": "sysDescr",
    "1.3.6.1.2.1.1.2": "sysObjectID",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.4": "sysContact",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.1.6": "sysLocation",
    "1.3.6.1.2.1.1.7": "sysServices",
    "1.3.6.1.2.1.2.1": "ifNumber",
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.11": "ifInUcastPkts",
    "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.17": "ifOutUcastPkts",
    "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    "1.3.6.1.4.1.2021.4.5": "memTotalReal",
    "1.3.6.1.4.1.2021.4.6": "memAvailReal",
    "1.3.6.1.4.1.2021.4.11": "memTotalFree",
    "1.3.6.1.4.1.2021.11.9": "ssCpuUser",
    "1.3.6.1.4.1.2021.11.10": "ssCpuSystem",
    "1.3.6.1.4.1.2021.11.11": "ssCpuIdle",
    "1.3.6.1.4.1.2021.10.1.3.1": "laLoad1",
    "1.3.6.1.4.1.2021.10.1.3.2": "laLoad5",
    "1.3.6.1.4.1.2021.10.1.3.3": "laLoad15",
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}


@dataclass
class VarBind:
    """Représente un Variable Binding SNMP"""
    oid: str
    oid_name: str = ""
    value_type: str = ""
    value: Any = None
    raw_bytes: bytes = field(default_factory=bytes, repr=False)
    
    def to_dict(self) -> Dict:
        return {
            "oid": self.oid,
            "name": self.oid_name,
            "type": self.value_type,
            "value": str(self.value) if self.value is not None else None
        }


@dataclass
class SNMPPacket:
    """Représente un paquet SNMP décodé complet"""
    # Champs SNMP de base
    version: str = ""
    community: str = ""
    pdu_type: str = ""
    pdu_type_code: int = 0
    request_id: int = 0
    error_status: int = 0
    error_status_name: str = ""
    error_index: int = 0
    varbinds: List[VarBind] = field(default_factory=list)
    
    # Métadonnées réseau
    timestamp: float = 0.0
    frame_number: int = 0
    frame_length: int = 0
    ip_src: str = ""
    ip_dst: str = ""
    ip_ttl: int = 0
    ip_id: int = 0
    mac_src: str = ""
    mac_dst: str = ""
    udp_src_port: int = 0
    udp_dst_port: int = 0
    udp_length: int = 0
    udp_checksum: int = 0
    
    # Champs SNMPv1 Trap spécifiques
    enterprise: str = ""
    agent_addr: str = ""
    generic_trap: int = 0
    specific_trap: int = 0
    trap_timestamp: int = 0
    
    # Champs SNMPv2 Bulk spécifiques
    non_repeaters: int = 0
    max_repetitions: int = 0
    
    # SNMPv3
    engine_id: str = ""
    engine_boots: int = 0
    engine_time: int = 0
    username: str = ""
    auth_protocol: str = ""
    priv_protocol: str = ""
    
    # Marquage utilisateur
    marked: bool = False
    color_tag: str = ""
    notes: str = ""
    tag: int = 0  # 0 = autorisé, 1 = suspect
    
    # Données brutes
    raw_bytes: bytes = field(default_factory=bytes, repr=False)
    
    @property
    def info_summary(self) -> str:
        """Génère un résumé pour l'affichage"""
        if self.varbinds:
            first_vb = self.varbinds[0]
            oid_display = first_vb.oid_name or first_vb.oid
            if len(self.varbinds) > 1:
                return f"{oid_display} (+{len(self.varbinds)-1} more)"
            return oid_display
        return self.pdu_type
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            "version": self.version,
            "community": self.community,
            "pdu_type": self.pdu_type,
            "request_id": self.request_id,
            "error_status": self.error_status,
            "error_status_name": self.error_status_name,
            "error_index": self.error_index,
            "varbinds": [vb.to_dict() for vb in self.varbinds],
            "timestamp": self.timestamp,
            "frame_number": self.frame_number,
            "frame_length": self.frame_length,
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "mac_src": self.mac_src,
            "mac_dst": self.mac_dst,
            "udp_src_port": self.udp_src_port,
            "udp_dst_port": self.udp_dst_port,
            "info": self.info_summary,
            "tag": self.tag,
            "marked": self.marked,
        }
    
    def get_hex_dump(self, bytes_per_line: int = 16) -> str:
        """Génère un hex dump des données brutes"""
        if not self.raw_bytes:
            return ""
        
        lines = []
        for i in range(0, len(self.raw_bytes), bytes_per_line):
            chunk = self.raw_bytes[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
            if len(chunk) > 8:
                hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<48}  |{ascii_part}|")
        
        return "\n".join(lines)


class BERDecoder:
    """Décodeur ASN.1 BER bas niveau"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
    
    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("Unexpected end of data")
        b = self.data[self.pos]
        self.pos += 1
        return b
    
    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("Unexpected end of data")
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result
    
    def read_length(self) -> int:
        """Lit une longueur BER"""
        first = self.read_byte()
        if first < 0x80:
            return first
        
        num_octets = first & 0x7F
        if num_octets == 0:
            raise ValueError("Indefinite length not supported")
        
        length = 0
        for _ in range(num_octets):
            length = (length << 8) | self.read_byte()
        return length
    
    def read_tlv(self) -> Tuple[int, bytes]:
        """Lit un TLV (Tag-Length-Value)"""
        tag = self.read_byte()
        length = self.read_length()
        value = self.read_bytes(length)
        return tag, value
    
    def decode_integer(self, data: bytes) -> int:
        """Décode un INTEGER"""
        if not data:
            return 0
        
        result = data[0]
        if result & 0x80:
            result -= 256
        
        for b in data[1:]:
            result = (result << 8) | b
        
        return result
    
    def decode_unsigned(self, data: bytes) -> int:
        """Décode un entier non signé"""
        result = 0
        for b in data:
            result = (result << 8) | b
        return result
    
    def decode_oid(self, data: bytes) -> str:
        """Décode un Object Identifier"""
        if not data:
            return ""
        
        components = []
        components.append(data[0] // 40)
        components.append(data[0] % 40)
        
        value = 0
        for b in data[1:]:
            value = (value << 7) | (b & 0x7F)
            if not (b & 0x80):
                components.append(value)
                value = 0
        
        return ".".join(str(c) for c in components)
    
    def decode_string(self, data: bytes) -> str:
        """Décode une OCTET STRING"""
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return data.decode('latin-1')
            except:
                return data.hex()
    
    def decode_ip_address(self, data: bytes) -> str:
        """Décode une adresse IP"""
        if len(data) == 4:
            return ".".join(str(b) for b in data)
        return data.hex()
    
    def decode_timeticks(self, data: bytes) -> int:
        """Décode TimeTicks (centièmes de seconde)"""
        return self.decode_unsigned(data)


class SNMPDecoder:
    """Décodeur SNMP haut niveau"""
    
    def __init__(self):
        self.oid_database = OID_DATABASE.copy()
    
    def add_oid(self, oid: str, name: str):
        """Ajoute un OID à la base"""
        self.oid_database[oid] = name
    
    def resolve_oid_name(self, oid: str) -> str:
        """Résout le nom d'un OID"""
        if oid in self.oid_database:
            return self.oid_database[oid]
        
        # Cherche un préfixe correspondant
        parts = oid.split(".")
        for i in range(len(parts), 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in self.oid_database:
                suffix = ".".join(parts[i:])
                return f"{self.oid_database[prefix]}.{suffix}" if suffix else self.oid_database[prefix]
        
        return oid
    
    def decode_value(self, tag: int, data: bytes) -> Tuple[str, Any]:
        """Décode une valeur selon son tag"""
        decoder = BERDecoder(data)
        
        if tag == ASN1Tag.INTEGER:
            return "INTEGER", decoder.decode_integer(data)
        elif tag == ASN1Tag.OCTET_STRING:
            return "OCTET STRING", decoder.decode_string(data)
        elif tag == ASN1Tag.NULL:
            return "NULL", None
        elif tag == ASN1Tag.OID:
            return "OID", decoder.decode_oid(data)
        elif tag == ASN1Tag.IP_ADDRESS:
            return "IpAddress", decoder.decode_ip_address(data)
        elif tag == ASN1Tag.COUNTER32:
            return "Counter32", decoder.decode_unsigned(data)
        elif tag == ASN1Tag.GAUGE32:
            return "Gauge32", decoder.decode_unsigned(data)
        elif tag == ASN1Tag.TIMETICKS:
            return "TimeTicks", decoder.decode_timeticks(data)
        elif tag == ASN1Tag.COUNTER64:
            return "Counter64", decoder.decode_unsigned(data)
        elif tag == ASN1Tag.OPAQUE:
            return "Opaque", data.hex()
        elif tag == 0x80:
            return "noSuchObject", None
        elif tag == 0x81:
            return "noSuchInstance", None
        elif tag == 0x82:
            return "endOfMibView", None
        else:
            return f"Unknown(0x{tag:02x})", data.hex()
    
    def decode_varbind(self, data: bytes) -> VarBind:
        """Décode un Variable Binding"""
        decoder = BERDecoder(data)
        
        tag, content = decoder.read_tlv()
        if tag != ASN1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE, got 0x{tag:02x}")
        
        inner = BERDecoder(content)
        
        oid_tag, oid_data = inner.read_tlv()
        if oid_tag != ASN1Tag.OID:
            raise ValueError(f"Expected OID, got 0x{oid_tag:02x}")
        
        oid = BERDecoder(b'').decode_oid(oid_data)
        
        value_tag, value_data = inner.read_tlv()
        value_type, value = self.decode_value(value_tag, value_data)
        
        return VarBind(
            oid=oid,
            oid_name=self.resolve_oid_name(oid),
            value_type=value_type,
            value=value,
            raw_bytes=data
        )
    
    def decode_varbind_list(self, data: bytes) -> List[VarBind]:
        """Décode une liste de Variable Bindings"""
        decoder = BERDecoder(data)
        
        tag, content = decoder.read_tlv()
        if tag != ASN1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE, got 0x{tag:02x}")
        
        varbinds = []
        inner = BERDecoder(content)
        
        while inner.pos < len(content):
            start_pos = inner.pos
            vb_tag, vb_data = inner.read_tlv()
            
            if vb_tag == ASN1Tag.SEQUENCE:
                vb_decoder = BERDecoder(vb_data)
                
                oid_tag, oid_data = vb_decoder.read_tlv()
                oid = BERDecoder(b'').decode_oid(oid_data)
                
                value_tag, value_data = vb_decoder.read_tlv()
                value_type, value = self.decode_value(value_tag, value_data)
                
                varbinds.append(VarBind(
                    oid=oid,
                    oid_name=self.resolve_oid_name(oid),
                    value_type=value_type,
                    value=value
                ))
        
        return varbinds
    
    def decode_pdu(self, pdu_type: int, data: bytes) -> Dict:
        """Décode un PDU SNMP"""
        decoder = BERDecoder(data)
        result = {
            "pdu_type": PDU_TYPE_NAMES.get(pdu_type, f"Unknown(0x{pdu_type:02x})"),
            "pdu_type_code": pdu_type
        }
        
        if pdu_type == ASN1Tag.TRAP_V1:
            # SNMPv1 Trap
            tag, enterprise_data = decoder.read_tlv()
            result["enterprise"] = BERDecoder(b'').decode_oid(enterprise_data)
            
            tag, agent_data = decoder.read_tlv()
            result["agent_addr"] = BERDecoder(b'').decode_ip_address(agent_data)
            
            tag, generic_data = decoder.read_tlv()
            result["generic_trap"] = BERDecoder(b'').decode_integer(generic_data)
            
            tag, specific_data = decoder.read_tlv()
            result["specific_trap"] = BERDecoder(b'').decode_integer(specific_data)
            
            tag, timestamp_data = decoder.read_tlv()
            result["trap_timestamp"] = BERDecoder(b'').decode_unsigned(timestamp_data)
            
            remaining = data[decoder.pos:]
            result["varbinds"] = self.decode_varbind_list(remaining) if remaining else []
        
        elif pdu_type == ASN1Tag.GET_BULK_REQUEST:
            # GetBulkRequest
            tag, id_data = decoder.read_tlv()
            result["request_id"] = BERDecoder(b'').decode_integer(id_data)
            
            tag, nr_data = decoder.read_tlv()
            result["non_repeaters"] = BERDecoder(b'').decode_integer(nr_data)
            
            tag, mr_data = decoder.read_tlv()
            result["max_repetitions"] = BERDecoder(b'').decode_integer(mr_data)
            
            remaining = data[decoder.pos:]
            result["varbinds"] = self.decode_varbind_list(remaining) if remaining else []
        
        else:
            # Standard PDU
            tag, id_data = decoder.read_tlv()
            result["request_id"] = BERDecoder(b'').decode_integer(id_data)
            
            tag, error_data = decoder.read_tlv()
            result["error_status"] = BERDecoder(b'').decode_integer(error_data)
            result["error_status_name"] = SNMP_ERROR_STATUS.get(result["error_status"], "unknown")
            
            tag, index_data = decoder.read_tlv()
            result["error_index"] = BERDecoder(b'').decode_integer(index_data)
            
            remaining = data[decoder.pos:]
            result["varbinds"] = self.decode_varbind_list(remaining) if remaining else []
        
        return result
    
    def decode(self, data: bytes) -> SNMPPacket:
        """Décode un paquet SNMP complet"""
        decoder = BERDecoder(data)
        
        tag, content = decoder.read_tlv()
        if tag != ASN1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE, got 0x{tag:02x}")
        
        inner = BERDecoder(content)
        
        # Version
        tag, version_data = inner.read_tlv()
        version_num = BERDecoder(b'').decode_integer(version_data)
        version_map = {0: "v1", 1: "v2c", 3: "v3"}
        version = version_map.get(version_num, f"v{version_num}")
        
        packet = SNMPPacket(version=version, raw_bytes=data)
        
        if version in ("v1", "v2c"):
            # Community string
            tag, community_data = inner.read_tlv()
            packet.community = BERDecoder(b'').decode_string(community_data)
            
            # PDU
            pdu_tag, pdu_data = inner.read_tlv()
            pdu_info = self.decode_pdu(pdu_tag, pdu_data)
            
            packet.pdu_type = pdu_info.get("pdu_type", "")
            packet.pdu_type_code = pdu_info.get("pdu_type_code", 0)
            packet.request_id = pdu_info.get("request_id", 0)
            packet.error_status = pdu_info.get("error_status", 0)
            packet.error_status_name = pdu_info.get("error_status_name", "")
            packet.error_index = pdu_info.get("error_index", 0)
            packet.varbinds = pdu_info.get("varbinds", [])
            
            # Champs spécifiques
            if "enterprise" in pdu_info:
                packet.enterprise = pdu_info["enterprise"]
            if "agent_addr" in pdu_info:
                packet.agent_addr = pdu_info["agent_addr"]
            if "generic_trap" in pdu_info:
                packet.generic_trap = pdu_info["generic_trap"]
            if "specific_trap" in pdu_info:
                packet.specific_trap = pdu_info["specific_trap"]
            if "non_repeaters" in pdu_info:
                packet.non_repeaters = pdu_info["non_repeaters"]
            if "max_repetitions" in pdu_info:
                packet.max_repetitions = pdu_info["max_repetitions"]
        
        return packet
    
    def decode_safe(self, data: bytes) -> Optional[SNMPPacket]:
        """Décode un paquet avec gestion des erreurs"""
        try:
            return self.decode(data)
        except Exception as e:
            return None


if __name__ == "__main__":
    # Test du décodeur
    decoder = SNMPDecoder()
    
    # Exemple de paquet SNMPv2c GetRequest
    test_packet = bytes([
        0x30, 0x29,  # SEQUENCE
        0x02, 0x01, 0x01,  # INTEGER v2c
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # "public"
        0xa0, 0x1c,  # GetRequest
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78,  # request-id
        0x02, 0x01, 0x00,  # error-status
        0x02, 0x01, 0x00,  # error-index
        0x30, 0x0e,  # varbind list
        0x30, 0x0c,  # varbind
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID
        0x05, 0x00   # NULL
    ])
    
    packet = decoder.decode(test_packet)
    print(f"Version: {packet.version}")
    print(f"Community: {packet.community}")
    print(f"PDU Type: {packet.pdu_type}")
    print(f"Request ID: {packet.request_id}")
    print(f"Varbinds: {len(packet.varbinds)}")
    for vb in packet.varbinds:
        print(f"  - {vb.oid_name} ({vb.oid}): {vb.value}")
