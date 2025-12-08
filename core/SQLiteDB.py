import sqlite3

class DataBase(object):
	"""Outils de gestion de la base de données SQLite pour le sniffer."""
	def __init__(self, dbFile:str):
		self.dbFile = dbFile
		self.connection = None
		self.cursor = None

	def open(self):
		"""Ouvre la connexion à la base de données si elle n'est pas déjà ouverte."""
		if self.connection is None:
			self.connection = sqlite3.connect(self.dbFile)
			self.cursor = self.connection.cursor()

	def close(self):
		"""Ferme la connexion à la base de données si elle est ouverte."""
		if self.connection:
			self.connection.close()
			self.connection = None
			self.cursor = None

	def is_valid_identifier(self, name: str):
		"""Retourne True si 'name' est un identifiant valide ou '*', sinon False."""
		if name == "*":
			return True
		return name.isidentifier()

	def table_exists(self, table: str):
		self.open()
		self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
		exists = self.cursor.fetchone() is not None
		self.close()
		return exists

	def initDB(self):
		"""Initialisation de la base de données avec les deux tables V1 et V2."""
		self.open()
		
		# --- TABLE SNMP V1 ---
		# Contient les champs spécifiques au Header Trap V1 (Enterprise, AgentAddr...)
		self.cursor.execute('''CREATE TABLE IF NOT EXISTS snmp_v1 (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			mac_src TEXT, mac_dst TEXT,
			ip_src TEXT, ip_dst TEXT,
			port_src INTEGER, port_dst INTEGER,
			snmp_community TEXT,
			snmp_pdu_type TEXT,
			
			-- Champs spécifiques Trap V1
			snmp_enterprise TEXT,
			snmp_agent_addr TEXT,
			snmp_generic_trap INTEGER,
			snmp_specific_trap INTEGER,
			
			-- Champs Standards (Get/Set/Response)
			snmp_request_id INTEGER,
			snmp_error_status INTEGER,
			snmp_error_index INTEGER,
			
			snmp_oidsValues TEXT,
			tag INTEGER)''')

		# --- TABLE SNMP V2 ---
		# Contient les champs spécifiques Bulk V2 (NonRepeaters, MaxRepetitions)
		self.cursor.execute('''CREATE TABLE IF NOT EXISTS snmp_v2 (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			mac_src TEXT, mac_dst TEXT,
			ip_src TEXT, ip_dst TEXT,
			port_src INTEGER, port_dst INTEGER,
			snmp_community TEXT,
			snmp_pdu_type TEXT,
			
			-- Champs Standards V2
			snmp_request_id INTEGER,
			snmp_error_status INTEGER,
			snmp_error_index INTEGER,
			
			-- Champs spécifiques Bulk V2
			snmp_non_repeaters INTEGER,
			snmp_max_repetitions INTEGER,
			
			snmp_oidsValues TEXT,
			tag INTEGER)''')
			
		self.connection.commit()
		self.close()

	def getChamps(self,table:str):
		"""Retourne la liste des noms de colonnes d'une table."""
		self.open()
		self.cursor.execute(f"PRAGMA table_info({table})")
		colonnes_info = self.cursor.fetchall()
		self.close()
		return colonnes_info

	def getData(self, table:str, columns:list[str], where:str=None, params:tuple=()):
		"""Validation basique pour les requêtes dans la base de données."""
		if not self.table_exists(table):
			raise ValueError(f"La table '{table}' n'existe pas.")
		if not self.is_valid_identifier(table):
			raise ValueError("Nom de table invalide")
		for col in columns:
			if not self.is_valid_identifier(col):
				raise ValueError(f"Nom de colonne invalide: {col}")

		cols = ", ".join(columns)
		sql = f"SELECT {cols} FROM {table}"
		if where:
			sql += f" WHERE {where}"
		self.open()
		try:
			self.cursor.execute(sql, params)
			rows = self.cursor.fetchall()
		finally:
			self.close()
		return rows

	def wrData(self, table: str, data: dict):
		"""
		Écrit une ligne complète dans la base de données SQLite.
		"""
		self.open()
		try:
			# Colonnes et valeurs
			columns = ", ".join(data.keys())
			placeholders = ", ".join(["?"] * len(data))
			values = tuple(data.values())

			sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
			self.cursor.execute(sql, values)
			self.connection.commit()

		except Exception as e:
			print(f"[ERREUR wrData {table}] {e}")
			self.connection.rollback()

		finally:
			self.close()


if __name__ == "__main__":
	import os
	
	db_file = "test_snmp.db"
	# Suppression pour test propre
	if os.path.exists(db_file):
		os.remove(db_file)

	# ********** Initialisation de la base **********
	print("\n********** Initialisation de la base **********")
	db = DataBase(dbFile=db_file)
	db.initDB() # Crée snmp_v1 et snmp_v2
	print("Tables 'snmp_v1' et 'snmp_v2' initialisées.")

	# ********** Affichage des colonnes V1 **********
	print("\n********** Colonnes SNMP V1 **********")
	columns_v1 = db.getChamps(table="snmp_v1")
	for col in columns_v1:
		print(f"  {col[1]} ({col[2]})")

	# ********** Test Insertion SNMP V1 (TRAP) **********
	print("\n[i] Test écriture dans snmp_v1 (TRAP)")
	data_v1 = {
		"time_stamp": "2025-10-24 15:20:00",
		"mac_src": "00:11:22:33:44:55",
		"mac_dst": "FF:FF:FF:FF:FF:FF",
		"ip_src": "10.0.0.1",
		"ip_dst": "10.0.0.254",
		"port_src": 162,
		"port_dst": 162,
		"snmp_community": "public",
		"snmp_pdu_type": "SNMPtrap",
		# Champs Spécifiques V1
		"snmp_enterprise": "1.3.6.1.4.1.9",
		"snmp_agent_addr": "10.0.0.1",
		"snmp_generic_trap": 6,
		"snmp_specific_trap": 12,
		"snmp_oidsValues": '{"oidsValues": []}',
		"tag": 1
	}
	db.wrData("snmp_v1", data_v1)
	print("Données V1 écrites.")

	# ********** Test Insertion SNMP V2 (RESPONSE) **********
	print("\n[i] Test écriture dans snmp_v2 (RESPONSE)")
	data_v2 = {
		"time_stamp": "2025-10-24 15:20:05",
		"mac_src": "AA:BB:CC:DD:EE:FF",
		"mac_dst": "00:00:00:00:00:00",
		"ip_src": "192.168.1.10",
		"ip_dst": "192.168.1.50",
		"port_src": 161,
		"port_dst": 45000,
		"snmp_community": "private",
		"snmp_pdu_type": "RESPONSE",
		# Champs Standards V2
		"snmp_request_id": 987654321,
		"snmp_error_status": 0,
		"snmp_error_index": 0,
		"snmp_oidsValues": '{"oidsValues": [{"oid": "1.3.6.1.2.1.1.5.0", "value": "Switch-Core"}]}',
		"tag": 0
	}
	db.wrData("snmp_v2", data_v2)
	print("Données V2 écrites.")

	# ********** Lecture des données **********
	print("\n[i] Lecture table snmp_v1 :")
	rows_v1 = db.getData(table="snmp_v1", columns=["snmp_pdu_type", "snmp_enterprise", "snmp_specific_trap"])
	print(rows_v1)

	print("\n[i] Lecture table snmp_v2 :")
	rows_v2 = db.getData(table="snmp_v2", columns=["snmp_pdu_type", "snmp_request_id", "snmp_oidsValues"])
	print(rows_v2)