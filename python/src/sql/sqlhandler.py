import sqlite3
from datetime import datetime
from .sqlscripts import SQL_SCRIPTS 
from unittest import TestCase, TestSuite, TextTestRunner

SCRIPT_TYPES = ["p2pkh","p2sh","p2wpkh","p2wsh"]

class DatabaseError(Exception):
	pass

class WalletDB:

# ----- FILE -----
#
# ----------------
	
	def __init__(self, file="Wallet0.db"):
		self.conn = self._connect(file)
		self.cursor = self.conn.cursor()
		self.create_db()

	def _connect(self, file):
		conn = None
		try: 
			conn = sqlite3.connect(file)
			return conn
		except (Exception, sqlite3.Error) as e:
			print(e)

	def _execute(self, script, data=[]):
		try:
			data = self.cursor.execute(script, data)
			self.conn.commit()
			return data
		except sqlite3.Error as e:
			raise DatabaseError(f"Error Executing Command: {e}")

	def close(self):
		self.cursor.close()
		self.conn.close()

# ----- GENERAL -----
#
# -------------------
	def create_db(self):
		self._execute(SQL_SCRIPTS["init"]["scripts"][1])
		self._execute(SQL_SCRIPTS["init"]["utxos"][1])

	def wipe_db(self):
		self._execute(SQL_SCRIPTS["init"]["scripts"][0])
		self._execute(SQL_SCRIPTS["init"]["utxos"][0])

	def restart_db(self):
		for x in SQL_SCRIPTS["init"]["scripts"]:
			self._execute(x)
		for x in SQL_SCRIPTS["init"]["utxos"]:
			self._execute(x)

# ----- UTXOS -----
#
# -----------------
	def new_utxo(self, txid, vout, amount, block_height, status, script_id):
		params = tuple([txid, vout, amount, block_height, status, script_id])
		self._execute(SQL_SCRIPTS["update"]["utxos"]["new"], params)
		return True

	def add_utxo(self, utxo):
		"""
		utxo TUPLE(
			txid STRING,
			vout INTEGER,
			amount INTEGER,
			block_height INTEGER,
			status STRING,
			script INT
		)
		"""
		params = tuple(utxo)
		self._execute(SQL_SCRIPTS["update"]["utxos"]["new"], params)
		return True

	def get_all_utxos(self):
		r = self._execute(SQL_SCRIPTS["query"]["utxos"]["getAll"].strip())
		return list(r)

	def get_utxos_by_script_type(self, script_type):
		""" script type STRING
		options:
		 - "p2pkh"
		 - "p2sh"
		 - "p2wpkh"
		 - "p2wsh"
		"""
		if script_type not in SCRIPT_TYPES:
			raise ValueError("Invalid Script Type.")
		data = tuple([script_type])
		r =  self._execute(SQL_SCRIPTS["query"]["utxos"]["getByScriptType"], data)
		return list(r)

	def get_utxos_by_script_ids(self, script_ids, order="DESC"):
		""" 
		script_ids: list of ints
		script_id is FOREIGN KEY for Script.id 
		"""
		if len(script_ids) ==1:
			params = "(" + str(script_ids[0]) + ")"
		else:
			params = tuple(script_ids)
		script = SQL_SCRIPTS["query"]["utxos"]["getByScriptIDs"].format(params, order)
		r = self._execute(script)
		return list(r) #TODO is this necessary?

	def get_utxos_by_status(self, status):
		"""
		utxo statuses: "unconfirmed", "unspent", "spent"
		"""
		data = tuple([status])
		r = self._execute(SQL_SCRIPTS["query"]["utxos"]["getByStatus"], data)
		return list(r)

	def get_script_name_from_outpoint(self, txid, vout):
		'''
		params: (txid, vout)
		'''
		txid = "\"" + txid + "\""
		script = SQL_SCRIPTS["query"]["utxos"]["getScriptTypefromOutpoint"].format(txid, vout)
		r = self._execute(script)
		return list(r)[0][0]

	def get_utxo_id_from_outpoint(self, txid, vout):
		txid = "\"" + txid + "\""
		script = SQL_SCRIPTS["query"]["utxos"]["getUTXOfromOutpoint"].format(txid, vout)
		r = self._execute(script)
		return list(r)[0][0]

	def get_script_from_outpoint(self, txid, vout):
		txid = "\"" + txid + "\""
		script = SQL_SCRIPTS["query"]["utxos"]["getScriptfromOutpoint"].format(txid, vout)
		r = self._execute(script)
		return list(r)[0]


# ----- SCRIPTS -----
#
# -----------------
	def new_script(self, scriptPubKey, script_type, deriv_path):
		"""
		scriptPubKey STRING NOT NULL,
		scripttype STRING,
		derivationPath STRING
		"""
		params = tuple([scriptPubKey, script_type, deriv_path])
		self._execute(SQL_SCRIPTS["update"]["scripts"]["new"], params)
		return True

	def add_script(self, hd_script_pubkey): # DON'T ADD DUPLICATES
		params = tuple(hd_script_pubkey)
		self._execute(SQL_SCRIPTS["update"]["scripts"]["new"], params)
		return True

	def get_all_scripts(self):
		r = self._execute(SQL_SCRIPTS["query"]["scripts"]["getAll"])
		return list(r)
	def get_scripts_by_id(self, script_ids):
		params = tuple(script_ids)
		script = SQL_SCRIPTS["query"]["scripts"]["getByIDs"].format(params)
		r = self._execute(script)
		return list(r)

	def get_scripts_by_script_type(self, script_type):
		""" script type STRING
		options:
		 - "p2pkh"
		 - "p2sh"
		 - "p2wpkh"
		 - "p2wsh"
		"""
		data = tuple([script_type])
		r = self._execute(SQL_SCRIPTS["query"]["scripts"]["getByScriptType"], data)
		return list(r)

	def find_script_utxos(self, testnet=False):
		""" add utxos to UTXO table for each script """
		pass

	def get_all_script_balances(self, order="DESC"):
		"""
		order: "DESC" or "ASC"
		"""
		r = self._execute(SQL_SCRIPTS["query"]["scripts"]["getAllByAmount"].format(order))
		return list(r)

	def get_scripts_by_id_order_by_amount(self, script_ids, order="DESC"):
		"""
		order: "DESC" or "ASC"
		"""
		params = tuple(script_ids)
		script = SQL_SCRIPTS["query"]["scripts"]["getByIDsOrderByAmount"].format(params, order)
		r = self._execute(script)
		return list(r)


	


if __name__ == "__main__":
	walletDB = WalletDB("test_wallet.db")
	print(walletDB.get_script_from_outpoint("d528297764ee901bfbf693cc12c77f39ce776a0a89f30815b3d3dd2547b0ed7a", 0))