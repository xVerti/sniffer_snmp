from queue import Queue
from scapy.all import *
from datetime import datetime
import os
import json
import SQLiteDB

class Analyser(object):
	"""
	Analyse les trames stockées dans la FILE puis envoie les résultats sur une base de donnée
	Applique les filtres définis dans la configuration fournie.
	"""
	def __init__(self, queue:Queue, baseDB, config:dict=None, pcap_dir="captures", lenPcap:int=100):
		self.queue = queue
		self.baseDB = baseDB
		self.config = config if config else {}
		self.pcap_dir = pcap_dir
		self.lenPcap = lenPcap
		self.nb_pkt = 0
		self.file_index = 0
		self.pcap_writer = None

		# Initialisation des tables en base de données (V1 et V2)
		self.baseDB.initDB()

		os.makedirs(pcap_dir, exist_ok=True)
		self.open_new_pcap()

	def open_new_pcap(self):
		if self.pcap_writer:
			self.pcap_writer.close()
		filename = os.path.join(self.pcap_dir, f"capture_{self.file_index:04d}.pcap")
		self.pcap_writer = PcapWriter(filename, append=False, sync=False)
		self.file_index += 1
		self.nb_pkt = 0

	def convert_asn1(self, obj):
		if hasattr(obj, "pretty"): return obj.pretty()
		elif hasattr(obj, "val"): return str(obj.val)
		else: return str(obj)

	def packet_info(self, pkt):
		# --- 1. Timestamp & Couches Réseau ---
		time_stamp = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")

		mac_src = pkt[Ether].src if Ether in pkt else None
		mac_dst = pkt[Ether].dst if Ether in pkt else None
		ip_src = pkt[IP].src if IP in pkt else None
		ip_dst = pkt[IP].dst if IP in pkt else None
		port_src = pkt[UDP].sport if UDP in pkt else None
		port_dst = pkt[UDP].dport if UDP in pkt else None

		# --- 2. Initialisation des champs SNMP (Tous à None par défaut) ---
		res = {
			"time_stamp": time_stamp,
			"mac_src": mac_src, "mac_dst": mac_dst,
			"ip_src": ip_src, "ip_dst": ip_dst,
			"port_src": port_src, "port_dst": port_dst,
			"snmp_oidsValues": [],
			"snmp_version": None, "snmp_community": None, "snmp_pdu_type": None,
			# Champs communs / V2
			"snmp_request_id": None, "snmp_error_status": None, "snmp_error_index": None,
			# Champs V1 Trap
			"snmp_enterprise": None, "snmp_agent_addr": None, 
			"snmp_generic_trap": None, "snmp_specific_trap": None,
			# Champs V2 Bulk
			"snmp_non_repeaters": None, "snmp_max_repetitions": None
		}

		if SNMP in pkt:
			snmp = pkt[SNMP]
			res["snmp_version"] = self.convert_asn1(snmp.version) # 0=v1, 1=v2c
			res["snmp_community"] = self.convert_asn1(snmp.community)

			if hasattr(snmp, "PDU") and snmp.PDU:
				pdu = snmp.PDU
				res["snmp_pdu_type"] = pdu.__class__.__name__

				# ==============================================================================
				# CAS A : SNMP v1 TRAP
				# ==============================================================================
				if res["snmp_pdu_type"] == "SNMPtrap":
					res["snmp_enterprise"] = self.convert_asn1(pdu.enterprise)
					res["snmp_agent_addr"] = self.convert_asn1(pdu.agent_addr)
					res["snmp_generic_trap"] = int(pdu.generic_trap)
					res["snmp_specific_trap"] = int(pdu.specific_trap)
					# Pas de Request ID sur Trap v1

				# ==============================================================================
				# CAS B : SNMP v2 GET-BULK
				# ==============================================================================
				elif res["snmp_pdu_type"] == "SNMPbulk":
					res["snmp_request_id"] = self.convert_asn1(pdu.id)
					res["snmp_non_repeaters"] = self.convert_asn1(pdu.non_repeaters)
					res["snmp_max_repetitions"] = self.convert_asn1(pdu.max_repetitions)

				# ==============================================================================
				# CAS C : STANDARD (Get, Set, Response, Inform, TrapV2)
				# ==============================================================================
				else:
					if hasattr(pdu, "id"):
						res["snmp_request_id"] = self.convert_asn1(pdu.id)
					if hasattr(pdu, "error_status"):
						res["snmp_error_status"] = self.convert_asn1(pdu.error_status)
					if hasattr(pdu, "error_index"):
						res["snmp_error_index"] = self.convert_asn1(pdu.error_index)

				# ==============================================================================
				# EXTRACTION DES VARBINDS
				# ==============================================================================
				if hasattr(pdu, "varbindlist"):
					for elt in pdu.varbindlist:
						val = elt.value
						# Gestion scapy des types complexes
						if hasattr(val, "prettyPrint"): 
							val = val.prettyPrint()
						else: 
							val = str(val)

						res["snmp_oidsValues"].append({
							"oid": self.convert_asn1(elt.oid),
							"value": val
						})
		return res

	# --- Logique de filtrage ---

	def in_whitelist(self, key, value):
		whitelist = self.config.get("whiteList", {})
		values = whitelist.get(key, [])
		return value in values

	def in_filtre(self, pkt_data:dict):
		filtres = self.config.get("filtres", {})
		rule_elts = ["mac_src","mac_dst","ip_src","ip_dst","port_src","port_dst"]
		
		for rule_name, rule in filtres.items():
			match = True
			if not isinstance(rule, dict): continue
			
			for key, val in rule.items():
				if not val: continue
				if key in rule_elts:
					# Conversion en string pour comparaison sûre
					if str(val) != str(pkt_data.get(key)):
						match = False
						break
			
			# Vérification spéciale pour OIDs (contient partiel)
			if match and "snmp_oidsValues" in rule and rule["snmp_oidsValues"]:
				target = rule["snmp_oidsValues"]
				found = False
				for oid_entry in pkt_data.get("snmp_oidsValues", []):
					if target in oid_entry["oid"]:
						found = True
						break
				if not found: match = False

			if match:
				return True, rule_name

		return False, None

	def compare(self, data:dict):
		"""
		Retourne True si le paquet est autorisé.
		Logique STRICTE (AND) pour la Whitelist.
		"""
		if not self.config: return False

		# 1. Whitelist (Logique AND : Src ET Dst doivent être autorisés)
		# MACs
		if data.get("mac_src") and data.get("mac_dst"):
			if self.in_whitelist("MACs", data.get("mac_src")) and self.in_whitelist("MACs", data.get("mac_dst")):
				return True
		
		# IPs
		if data.get("ip_src") and data.get("ip_dst"):
			if self.in_whitelist("IPs", data.get("ip_src")) and self.in_whitelist("IPs", data.get("ip_dst")):
				return True
		
		# Ports
		if data.get("port_src") and data.get("port_dst"):
			if self.in_whitelist("PORTs", str(data.get("port_src"))) and self.in_whitelist("PORTs", str(data.get("port_dst"))):
				return True
		
		# OIDs (Si l'un des OIDs du paquet est dans la liste, on accepte)
		for oid_entry in data.get("snmp_oidsValues", []):
			if self.in_whitelist("OIDs", oid_entry["oid"]):
				return True

		# 2. Filtres
		is_match, rule_name = self.in_filtre(data)
		if is_match:
			print(f"[OK] Règle correspondante : {rule_name}")
			return True

		return False

	# ---------------------------

	def analyser_paquet(self, pkt):
		# 1. Extraction complète
		full_data = self.packet_info(pkt)
		
		# 2. Comparaison et définition du TAG
		full_data["tag"] = None 

		if self.compare(full_data):
			print(f"[+] Paquet autorisé ({full_data['time_stamp']})")
			full_data["tag"] = 0
		else:
			print(f"[!] Paquet suspect/interdit ({full_data['time_stamp']})")
			full_data["tag"] = 1
				
		# 3. Préparation DB
		# Construction du dictionnaire de base commun aux deux versions
		db_data = {
			"time_stamp": full_data["time_stamp"],
			"mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
			"ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
			"port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
			"snmp_community": full_data["snmp_community"],
			"snmp_pdu_type": full_data["snmp_pdu_type"],
			"snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
			"tag": full_data["tag"]
		}

		# 4. Aiguillage et ajout des champs spécifiques selon la version
		version = str(full_data.get("snmp_version")) # "0" = v1, "1" = v2c
		
		if version == "0":
			table_cible = "snmp_v1"
			# Ajout champs V1
			db_data["snmp_enterprise"] = full_data["snmp_enterprise"]
			db_data["snmp_agent_addr"] = full_data["snmp_agent_addr"]
			db_data["snmp_generic_trap"] = full_data["snmp_generic_trap"]
			db_data["snmp_specific_trap"] = full_data["snmp_specific_trap"]
			# Ajout champs standards (compatibilité Get/Set v1)
			db_data["snmp_request_id"] = full_data["snmp_request_id"]
			db_data["snmp_error_status"] = full_data["snmp_error_status"]
			db_data["snmp_error_index"] = full_data["snmp_error_index"]
		else:
			table_cible = "snmp_v2"
			# Ajout champs V2
			db_data["snmp_request_id"] = full_data["snmp_request_id"]
			db_data["snmp_error_status"] = full_data["snmp_error_status"]
			db_data["snmp_error_index"] = full_data["snmp_error_index"]
			db_data["snmp_non_repeaters"] = full_data["snmp_non_repeaters"]
			db_data["snmp_max_repetitions"] = full_data["snmp_max_repetitions"]

		# Nettoyage des valeurs None pour laisser SQLite gérer les NULL
		db_data = {k: v for k, v in db_data.items() if v is not None}

		# Ecriture en Base de Données
		self.baseDB.wrData(table_cible, db_data)
			
		# 5. Enregistrement PCAP
		self.pcap_writer.write(pkt)
		self.nb_pkt += 1
			
		if self.nb_pkt >= self.lenPcap:
			self.open_new_pcap()

	def start_analyse(self):
		print(list(self.queue.queue))
		try:
			while True:
				pkt = self.queue.get()
				self.analyser_paquet(pkt)
				self.queue.task_done()
		except KeyboardInterrupt:
			print("\n[!] Interruption.")
		finally:
			print("[!] Fermeture ressources...")
			if self.pcap_writer: self.pcap_writer.close()
			if hasattr(self.baseDB, 'close'): self.baseDB.close()

if __name__ == "__main__":
	from scapy.layers.l2 import Ether
	from scapy.layers.inet import IP, UDP
	
	# Mock DB pour test sans écriture disque réelle (Adaptée au nouvel appel initDB)
	class MockDB:
		def wrData(self, table, data):
			print(f"   [DB -> {table}] INSERT: {data.get('ip_src')} -> {data.get('ip_dst')}")
		def initDB(self): 
			print("   [DB] Init v1 & v2 tables")
		def close(self): pass

	print("\n--- [TEST] Analyser (Logique Whitelist STRICTE) ---")

	fake_config = {
		"filtres": {
			"rule_web": {"ip_src": "192.168.1.100", "port_dst": "80"}
		},
		"whiteList": {
			"IPs": ["10.0.0.1", "8.8.8.8"],
			"MACs": [], "PORTs": [], "OIDs": []
		}
	}

	analyser = Analyser(Queue(), MockDB(), config=fake_config, pcap_dir="test_cap")

	# Paquets de test
	pkt_A = Ether()/IP(src="192.168.1.100", dst="1.1.1.1")/UDP(sport=10, dport=80)
	pkt_C = Ether()/IP(src="10.0.0.1", dst="8.8.8.8")/UDP(sport=55, dport=55)

	print("\n[i] Test A (Filtre) : ", end="")
	if analyser.compare(analyser.packet_info(pkt_A)): print("AUTORISÉ [OK]")
	else: print("REJETÉ [KO]")

	print("[i] Test C (Whitelist Complète): ", end="")
	if analyser.compare(analyser.packet_info(pkt_C)): print("AUTORISÉ [OK]")
	else: print("REJETÉ [KO]")

	# Nettoyage
	import shutil
	if os.path.exists("test_cap"): shutil.rmtree("test_cap")