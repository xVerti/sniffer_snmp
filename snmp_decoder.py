#!/usr/bin/env python3
"""
MIBurnout SNMP Decoder
Module de décodage ASN.1/BER pour les paquets SNMP
Supporte SNMPv1, SNMPv2c, SNMPv3
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import IntEnum
import struct


class ASN1Tag(IntEnum):
    """Tags ASN.1 standards"""
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30
    
    # SNMP specific
    IP_ADDRESS = 0x40
    COUNTER32 = 0x41
    GAUGE32 = 0x42
    TIMETICKS = 0x43
    OPAQUE = 0x44
    COUNTER64 = 0x46
    
    # PDU Types
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

# MIB OID Database (extensible)
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
    "1.3.6.1.2.1.2.2.1.4": "ifMtu",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.11": "ifInUcastPkts",
    "1.3.6.1.2.1.2.2.1.13": "ifInDiscards",
    "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.17": "ifOutUcastPkts",
    "1.3.6.1.2.1.2.2.1.19": "ifOutDiscards",
    "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    "1.3.6.1.2.1.4.1": "ipForwarding",
    "1.3.6.1.2.1.4.3": "ipInReceives",
    "1.3.6.1.2.1.4.10": "ipInDelivers",
    "1.3.6.1.2.1.4.11": "ipOutRequests",
    "1.3.6.1.4.1.2021.4.3": "memTotalSwap",
    "1.3.6.1.4.1.2021.4.4": "memAvailSwap",
    "1.3.6.1.4.1.2021.4.5": "memTotalReal",
    "1.3.6.1.4.1.2021.4.6": "memAvailReal",
    "1.3.6.1.4.1.2021.4.11": "memTotalFree",
    "1.3.6.1.4.1.2021.4.13": "memShared",
    "1.3.6.1.4.1.2021.4.14": "memBuffer",
    "1.3.6.1.4.1.2021.4.15": "memCached",
    "1.3.6.1.4.1.2021.10.1.3.1": "laLoad1",
    "1.3.6.1.4.1.2021.10.1.3.2": "laLoad5",
    "1.3.6.1.4.1.2021.10.1.3.3": "laLoad15",
    "1.3.6.1.4.1.2021.11.9": "ssCpuUser",
    "1.3.6.1.4.1.2021.11.10": "ssCpuSystem",
    "1.3.6.1.4.1.2021.11.11": "ssCpuIdle",
    "1.3.6.1.4.1.2021.11.50": "ssCpuRawUser",
    "1.3.6.1.4.1.2021.11.51": "ssCpuRawNice",
    "1.3.6.1.4.1.2021.11.52": "ssCpuRawSystem",
    "1.3.6.1.4.1.2021.11.53": "ssCpuRawIdle",
}


@dataclass
class VarBind:
    """Représente un Variable Binding SNMP"""
    oid: str
    oid_name: str
    value_type: str
    value: Any
    raw_bytes: bytes = field(default=b'', repr=False)
    
    def to_dict(self) -> Dict:
        return {
            "oid": self.oid,
            "name": self.oid_name,
            "type": self.value_type,
            "value": self.value,
        }


@dataclass
class SNMPPacket:
    """Représente un paquet SNMP décodé"""
    version: str
    community: str
    pdu_type: str
    pdu_type_code: int
    request_id: int
    error_status: int
    error_status_name: str
    error_index: int
    varbinds: List[VarBind]
    
    # Métadonnées réseau (remplies par le capteur)
    timestamp: float = 0.0
    frame_number: int = 0
    frame_length: int = 0
    ip_src: str = ""
    ip_dst: str = ""
    ip_ttl: int = 0
    ip_id: int = 0
    udp_src_port: int = 0
    udp_dst_port: int = 0
    udp_length: int = 0
    udp_checksum: int = 0
    
    # Données brutes
    raw_bytes: bytes = field(default=b'', repr=False)
    
    # Pour SNMPv3
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
    
    @property
    def info_summary(self) -> str:
        """Génère un résumé pour l'affichage"""
        parts = [self.pdu_type]
        for vb in self.varbinds[:2]:
            parts.append(f"{vb.oid_name}={vb.value}")
        if len(self.varbinds) > 2:
            parts.append(f"(+{len(self.varbinds)-2})")
        if self.error_status != 0:
            parts.append(f"[{self.error_status_name}]")
        return " ".join(parts)
    
    def to_dict(self) -> Dict:
        return {
            "frame_number": self.frame_number,
            "timestamp": self.timestamp,
            "frame_length": self.frame_length,
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "ip_ttl": self.ip_ttl,
            "udp_src_port": self.udp_src_port,
            "udp_dst_port": self.udp_dst_port,
            "version": self.version,
            "community": self.community,
            "pdu_type": self.pdu_type,
            "request_id": self.request_id,
            "error_status": self.error_status,
            "error_status_name": self.error_status_name,
            "error_index": self.error_index,
            "varbinds": [vb.to_dict() for vb in self.varbinds],
            "info": self.info_summary,
            "marked": self.marked,
            "color_tag": self.color_tag,
            "notes": self.notes,
        }
    
    def get_hex_dump(self, bytes_per_line: int = 16) -> str:
        """Génère un dump hexadécimal formaté"""
        lines = []
        data = self.raw_bytes
        
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
            if len(chunk) > 8:
                hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
            
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<48}  |{ascii_part}|")
        
        return "\n".join(lines)


class BERDecoder:
    """Décodeur ASN.1 BER pour SNMP"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
    
    def read_byte(self) -> int:
        """Lit un octet"""
        if self.offset >= len(self.data):
            raise ValueError("End of data reached")
        byte = self.data[self.offset]
        self.offset += 1
        return byte
    
    def read_bytes(self, count: int) -> bytes:
        """Lit plusieurs octets"""
        if self.offset + count > len(self.data):
            raise ValueError("Not enough data")
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result
    
    def peek_byte(self) -> int:
        """Regarde l'octet suivant sans avancer"""
        if self.offset >= len(self.data):
            raise ValueError("End of data reached")
        return self.data[self.offset]
    
    def read_length(self) -> int:
        """Lit la longueur BER"""
        first_byte = self.read_byte()
        
        if first_byte < 0x80:
            return first_byte
        
        num_octets = first_byte & 0x7F
        if num_octets == 0:
            raise ValueError("Indefinite length not supported")
        
        length = 0
        for _ in range(num_octets):
            length = (length << 8) | self.read_byte()
        
        return length
    
    def read_tlv(self) -> Tuple[int, bytes]:
        """Lit un TLV (Tag, Length, Value)"""
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
        
        for byte in data[1:]:
            result = (result << 8) | byte
        
        return result
    
    def decode_unsigned(self, data: bytes) -> int:
        """Décode un entier non signé (Counter, Gauge, etc.)"""
        result = 0
        for byte in data:
            result = (result << 8) | byte
        return result
    
    def decode_oid(self, data: bytes) -> str:
        """Décode un Object Identifier"""
        if not data:
            return ""
        
        # Premier octet = 40*X + Y où X est le premier sous-identifiant et Y le second
        first = data[0]
        oid_parts = [str(first // 40), str(first % 40)]
        
        # Reste des sous-identifiants
        value = 0
        for byte in data[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                oid_parts.append(str(value))
                value = 0
        
        return ".".join(oid_parts)
    
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
        """Décode une IP Address"""
        if len(data) == 4:
            return ".".join(str(b) for b in data)
        return data.hex()
    
    def decode_timeticks(self, data: bytes) -> str:
        """Décode TimeTicks en format lisible"""
        ticks = self.decode_unsigned(data)
        # TimeTicks sont en centièmes de seconde
        total_seconds = ticks // 100
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        centiseconds = ticks % 100
        
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}.{centiseconds:02d} ({ticks})"


class SNMPDecoder:
    """Décodeur de paquets SNMP complet"""
    
    def __init__(self):
        self.oid_database = OID_DATABASE.copy()
    
    def add_oid(self, oid: str, name: str):
        """Ajoute un OID à la base"""
        self.oid_database[oid] = name
    
    def resolve_oid_name(self, oid: str) -> str:
        """Résout le nom d'un OID"""
        # Cherche une correspondance exacte
        if oid in self.oid_database:
            return self.oid_database[oid]
        
        # Cherche le préfixe le plus long
        best_match = ""
        best_name = ""
        
        for db_oid, name in self.oid_database.items():
            if oid.startswith(db_oid) and len(db_oid) > len(best_match):
                best_match = db_oid
                best_name = name
        
        if best_name:
            suffix = oid[len(best_match):]
            return f"{best_name}{suffix}"
        
        return oid
    
    def decode_value(self, decoder: BERDecoder, tag: int, data: bytes) -> Tuple[str, Any]:
        """Décode une valeur selon son tag"""
        if tag == ASN1Tag.INTEGER:
            return "INTEGER", decoder.decode_integer(data)
        
        elif tag == ASN1Tag.OCTET_STRING:
            return "OCTET STRING", decoder.decode_string(data)
        
        elif tag == ASN1Tag.NULL:
            return "NULL", None
        
        elif tag == ASN1Tag.OBJECT_IDENTIFIER:
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
        
        elif tag == 0x80:  # noSuchObject
            return "noSuchObject", None
        
        elif tag == 0x81:  # noSuchInstance
            return "noSuchInstance", None
        
        elif tag == 0x82:  # endOfMibView
            return "endOfMibView", None
        
        else:
            return f"Unknown({tag:#x})", data.hex()
    
    def decode_varbind(self, decoder: BERDecoder) -> VarBind:
        """Décode un Variable Binding"""
        start_offset = decoder.offset
        
        # Sequence englobante
        tag = decoder.read_byte()
        if tag != ASN1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE for varbind, got {tag:#x}")
        
        length = decoder.read_length()
        end_offset = decoder.offset + length
        
        # OID
        oid_tag, oid_data = decoder.read_tlv()
        if oid_tag != ASN1Tag.OBJECT_IDENTIFIER:
            raise ValueError(f"Expected OID, got {oid_tag:#x}")
        
        oid_decoder = BERDecoder(oid_data)
        oid = oid_decoder.decode_oid(oid_data)
        oid_name = self.resolve_oid_name(oid)
        
        # Value
        value_tag, value_data = decoder.read_tlv()
        value_decoder = BERDecoder(value_data)
        value_type, value = self.decode_value(value_decoder, value_tag, value_data)
        
        raw_bytes = decoder.data[start_offset:end_offset]
        
        return VarBind(
            oid=oid,
            oid_name=oid_name,
            value_type=value_type,
            value=value,
            raw_bytes=raw_bytes
        )
    
    def decode_varbind_list(self, decoder: BERDecoder) -> List[VarBind]:
        """Décode la liste des Variable Bindings"""
        tag = decoder.read_byte()
        if tag != ASN1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE for varbind list, got {tag:#x}")
        
        length = decoder.read_length()
        end_offset = decoder.offset + length
        
        varbinds = []
        while decoder.offset < end_offset:
            varbinds.append(self.decode_varbind(decoder))
        
        return varbinds
    
    def decode_pdu(self, decoder: BERDecoder) -> Tuple[int, int, int, int, List[VarBind]]:
        """Décode un PDU SNMP"""
        pdu_type = decoder.read_byte()
        pdu_length = decoder.read_length()
        
        # Request ID
        tag, data = decoder.read_tlv()
        request_id = BERDecoder(data).decode_integer(data)
        
        # Error Status (ou non-repeaters pour GetBulk)
        tag, data = decoder.read_tlv()
        error_status = BERDecoder(data).decode_integer(data)
        
        # Error Index (ou max-repetitions pour GetBulk)
        tag, data = decoder.read_tlv()
        error_index = BERDecoder(data).decode_integer(data)
        
        # Variable Bindings
        varbinds = self.decode_varbind_list(decoder)
        
        return pdu_type, request_id, error_status, error_index, varbinds
    
    def decode(self, data: bytes) -> SNMPPacket:
        """Décode un paquet SNMP complet"""
        decoder = BERDecoder(data)
        
        # Message SEQUENCE
        tag = decoder.read_byte()
        if tag != ASN1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE, got {tag:#x}")
        
        msg_length = decoder.read_length()
        
        # Version
        tag, version_data = decoder.read_tlv()
        version_num = BERDecoder(version_data).decode_integer(version_data)
        version_map = {0: "v1", 1: "v2c", 3: "v3"}
        version = version_map.get(version_num, f"v{version_num}")
        
        community = ""
        engine_id = ""
        username = ""
        
        if version in ["v1", "v2c"]:
            # Community string
            tag, community_data = decoder.read_tlv()
            community = BERDecoder(community_data).decode_string(community_data)
            
            # PDU
            pdu_type, request_id, error_status, error_index, varbinds = self.decode_pdu(decoder)
        
        else:  # SNMPv3
            # msgGlobalData
            tag = decoder.read_byte()
            if tag != ASN1Tag.SEQUENCE:
                raise ValueError("Expected SEQUENCE for msgGlobalData")
            decoder.read_length()
            
            # msgID
            tag, data = decoder.read_tlv()
            # msg_id = BERDecoder(data).decode_integer(data)
            
            # msgMaxSize
            tag, data = decoder.read_tlv()
            
            # msgFlags
            tag, data = decoder.read_tlv()
            
            # msgSecurityModel
            tag, data = decoder.read_tlv()
            
            # msgSecurityParameters (OCTET STRING contenant USM)
            tag, security_data = decoder.read_tlv()
            
            # Décodage USM simplifié
            usm_decoder = BERDecoder(security_data)
            usm_tag = usm_decoder.read_byte()
            if usm_tag == ASN1Tag.SEQUENCE:
                usm_decoder.read_length()
                
                # Engine ID
                tag, data = usm_decoder.read_tlv()
                engine_id = data.hex()
                
                # Engine Boots
                tag, data = usm_decoder.read_tlv()
                
                # Engine Time
                tag, data = usm_decoder.read_tlv()
                
                # User Name
                tag, data = usm_decoder.read_tlv()
                username = BERDecoder(data).decode_string(data)
            
            # ScopedPDU (peut être chiffré)
            # Pour simplifier, on essaie de décoder
            try:
                tag = decoder.read_byte()
                if tag == ASN1Tag.SEQUENCE:
                    decoder.read_length()
                    
                    # Context Engine ID
                    tag, data = decoder.read_tlv()
                    
                    # Context Name
                    tag, data = decoder.read_tlv()
                    
                    # PDU
                    pdu_type, request_id, error_status, error_index, varbinds = self.decode_pdu(decoder)
                else:
                    # PDU chiffré ou format inattendu
                    pdu_type = 0
                    request_id = 0
                    error_status = 0
                    error_index = 0
                    varbinds = []
            except:
                pdu_type = 0
                request_id = 0
                error_status = 0
                error_index = 0
                varbinds = []
        
        pdu_type_name = PDU_TYPE_NAMES.get(pdu_type, f"Unknown({pdu_type:#x})")
        error_status_name = SNMP_ERROR_STATUS.get(error_status, f"Unknown({error_status})")
        
        return SNMPPacket(
            version=version,
            community=community,
            pdu_type=pdu_type_name,
            pdu_type_code=pdu_type,
            request_id=request_id,
            error_status=error_status,
            error_status_name=error_status_name,
            error_index=error_index,
            varbinds=varbinds,
            raw_bytes=data,
            engine_id=engine_id,
            username=username,
        )
    
    def decode_safe(self, data: bytes) -> Optional[SNMPPacket]:
        """Décode un paquet SNMP avec gestion d'erreurs"""
        try:
            return self.decode(data)
        except Exception as e:
            return None


# Fonction utilitaire pour test
def decode_snmp_packet(data: bytes) -> Optional[SNMPPacket]:
    """Fonction helper pour décoder un paquet SNMP"""
    decoder = SNMPDecoder()
    return decoder.decode_safe(data)


if __name__ == "__main__":
    # Test avec un paquet SNMP GetRequest simple
    # Ceci est un exemple de paquet SNMP v2c GetRequest
    test_packet = bytes([
        0x30, 0x29,  # SEQUENCE, length 41
        0x02, 0x01, 0x01,  # INTEGER, version = 1 (v2c)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING "public"
        0xa0, 0x1c,  # GetRequest PDU
        0x02, 0x04, 0x01, 0x02, 0x03, 0x04,  # Request ID
        0x02, 0x01, 0x00,  # Error Status = 0
        0x02, 0x01, 0x00,  # Error Index = 0
        0x30, 0x0e,  # Varbind list
        0x30, 0x0c,  # Varbind
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID 1.3.6.1.2.1.1.1.0
        0x05, 0x00,  # NULL value
    ])
    
    decoder = SNMPDecoder()
    packet = decoder.decode(test_packet)
    
    print(f"Version: {packet.version}")
    print(f"Community: {packet.community}")
    print(f"PDU Type: {packet.pdu_type}")
    print(f"Request ID: {packet.request_id}")
    print(f"Error: {packet.error_status_name}")
    print(f"Varbinds: {len(packet.varbinds)}")
    
    for vb in packet.varbinds:
        print(f"  - {vb.oid_name} ({vb.oid}) = {vb.value} [{vb.value_type}]")
    
    print("\nHex Dump:")
    print(packet.get_hex_dump())
