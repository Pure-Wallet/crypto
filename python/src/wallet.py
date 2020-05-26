import json
import blockstream.blockexplorer
from seed import *


class HDPubKey:
	"""
	class for holding a pubkey (S256Point object) and metadata,
	including: 
	-Count (UTXO count)
	-Full Path
	-Label
	Inspiration from Wasabi Wallet.
	"""
	def __init__(self, pubkey, path, label):
		self.pubkey = pubkey
		self.path = path
		self.label = label
		self.txcount = 0
		self.balance = 0
		self.check_state()

	def __repr__(self):
		r = f"""\"PubKey\": {self.pubkey.sec().hex()},\n\
			\"FullKeyPath\": {self.path},\n\
			\"Label\": {self.label},\n\
			\"Count\": {self.count},\n\
			\"UTXOs\": {self.utxos}
			""".strip()
		return r + "\n"

	def to_dict(self):
		return {
			"PubKey": self.pubkey.sec().hex(),
			"FullKeyPath": self.path,
			"Label": self.label,
			"TxCount": self.txcount,
			"Balance": self.balance
		}

	def check_state(self):
		addr = self.pubkey.address()
		tx_hist = blockexplorer.get_address_transactions(addr).chain_stats
		self.txcount = tx_hist['tx_count']
		self.balance = tx_hist['funded_txo_sum'] - tx_hist['spent_txo_sum']
		return self.balance
	def get_utxos(self):
		addr = self.pubkey.address()
		utxos = blockexplorer.get_address_utxo(addr)
		sats = 0
		for utxo in utxos:
			sats += utxo.value
		self.balance = sats
		return 

	def is_used(self):
		return self.txcount > 0

	def empty(self):
		return self.balance == 0

	def set_label(self, label):
		self.label = label

	

class Wallet:
	DEFAULT_GAP_LIMIT = 15
	BASE_PATH = "76'/0'/"
	"""
	A class for storing a single Seed or ExtendedKey in order to manage UTXOs, craft transactions, and more.
	"""
	def __init__(self, name="Wallet0", passphrase="", testnet=False, data=None, watch_only=False):
		self.name = name
		self.passphrase = passphrase
		self.testnet = testnet
		self.key_count = 0
		self.watch_only = watch_only
		
		self.wallet_acct = self.BASE_PATH
		self.acct_chain = 0 # used as 3th layer of derivation path before 4th layer = keys
		self.balance = 0
		self.gap_limit = self.DEFAULT_GAP_LIMIT
		
		self.hdpubkeys = []
		# Load data into wallet, either Seed, Xpub, Xpriv. create necessary keys
		if data is not None:
			#import from seed, xpub, xprv object, or from string xpub or xprv 
			if type(data) == Seed:
				self.seed = data
				self.master_xprv = data.derive_master_priv_key(passphrase=passphrase, testnet=testnet)
				self.acct_xpub = self.derive_key((self.wallet_acct + str(self.acct_chain)), priv=True).to_extended_pub_key()
			elif type(data) == ExtendedPrivateKey:
				self.master_xprv = data
				self.acct_xpub = self.derive_key((self.wallet_acct + str(self.acct_chain)), priv=True).to_extended_pub_key()
				self.seed = None
			elif type(data) == ExtendedPublicKey:
				self.acct_xpub = data
				self.master_xprv = None

			elif type(data) == str:
				if data[:4] == "xprv":
					try:
						self.master_xprv = ExtendedPrivateKey.parse(data)
						self.acct_xpub = self.derive_key(self.wallet_acct, priv=True).to_extended_pub_key()
						self.seed = None
					
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPRIV key.")
				elif data[:4] == "xpub":
					try:
						self.acct_xpub = ExtendedPublicKey.parse(data)
						self.master_xprv = None
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPUB key.")
			
		
		# Generate first GAP_LIMIT keys
		for _ in range(self.gap_limit):
			self.new_pub_key()
		# Scan them all
		sats = 0
		for hpk in self.hdpubkeys:
			sats += hpk.check_state() # returns balance of pukey, also updates balance and txcount
		self.balance = sats

	def mnemonic(self):
		if self.seed:
			return self.seed.mnemonic()
		if self._is_watch_only():
			raise TypeError("Wallet is watch-only. Seed unknown.")
		if self.seed is None and self.master_xprv is not None:
			raise TypeError("Wallet was created from ExtendedPrivateKey. Seed unknown.")

	def derive_key(self, path, priv):
		# if levels.pop() != "m":
		# 	raise ConfigurationError(f"Path must begin with \'m/\'. Begins with {path[0:2]}")
		if priv:
			levels = path.split("/")
			if self.watch_only:
				raise TypeError("Watch only wallets cannot access Private Keys.")
			child = self.master_xprv
			for i in levels:
				if i[-1] == "'":
					child = child.derive_priv_child( SOFT_CAP + int(i[:-1]) )
				else:
					child = child.derive_priv_child( int(i) )
		# public keys
		else:
			child = self.acct_xpub
			#self.acct_xpub is already the xpub for wallet_acct
			# if self.wallet_acct in path:
			# 	path.replace(self.wallet_acct, "")
			levels = path.split("/")
			for i in levels:
				if i == "":
					continue
				if i[-1] == "'": # PubKeys cant make hardened children
					raise TypeError("Hardened Child Keys cannot be derived from Public Parent Key.")
				child = child.derive_pub_child(int(i))

		return child


	def new_pub_key(self, label=""):
		path = str(self.key_count)
		pubkey = self.derive_key(path, priv=False).to_pub_key()
		self.key_count+=1
		fullpath = self.wallet_acct + str(self.acct_chain) + "/" + path
		hpk = HDPubKey(pubkey, path=fullpath, label=label)
		hpk.check_state()
		self.hdpubkeys.append(hpk)
		return pubkey

	def new_address(self, label=""):
		return self.new_pub_key(label=label).address()

	def get_balance(self):
		sats = 0
		for hpk in self.hdpubkeys:
			sats += hpk.get_balance()

#----- EXTERNAL FUNCTIONS -----
#
#------------------------------
	
	def write_json(self, filename=""):
		if filename == "":
			filename = f"{self.name}.json"
		HdPubKeys = []
		data = {}
		with open(f"{filename}.json", "w+") as fp:
			wallet = json.load(fp)
			#verify file matches wallet
			c_wallet = True
			if wallet["XPUB"] != self.acct_xpub.__repr__():
				c_wallet = False
			if wallet["wallet_acct"] != self.wallet_acct:
				c_wallet = False
			if self.testnet:
				if wallet["NETWORK"] != "test":
					c_wallet = False
			else:
				if wallet["NETWORK"] != "main":
					c_wallet = False

			if c_wallet == False:
				raise ConfigurationError("Invalid Wallet. Import failed.")
			#write wallet data


			#add all generated pubkeys
			for hpk in self.hdpubkeys:
				found = False
				for entry in wallet["HdPubKeys"]:
					if entry["FullKeyPath"] == hpk.path:
						found = True
						break
				if not found:
					wallet["HdPubKeys"].append(hpk.to_dict())

	
		

	def write_secret(self, filename=""):
		if filename == "":
			filename = f"{self.name}.dat"
		pass

	def backup(self, filename=""):
		self.write_json(filename)
		self.write_secret(filename)

	def fetch_priv_key(self):
		pass
	@classmethod
	def import_wallet(cls, mnemonic=None, master_key=None):
		pass


if __name__ == "__main__":
	
	xpub = "xpub6CT7mqgEZmPk3MJsNYD5fL37ioKQYxuXLBgvGT5x2CchY8KbUPmYkKVGUXyp5YxbM2YrJtkutp8gLbgnoBtPYnBKxCR7erW2pjs42cMFPTB"
	#s = Seed.new(128)
	w = Wallet(data=xpub, watch_only=True)
	print(w.acct_xpub)
	print(w.balance)
