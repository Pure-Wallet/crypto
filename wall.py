import json
import blockstream.blockexplorer
from seed import *
from helper import hash256
import script

class UTXO:
	"""
	UNUSED
	class for holding a UTXO info:
		-txid (str)
		-index (int)
		-value (int) in sats
	"""
	def __init__(self, txid, idx, value):
		self.txid = txid
		self.idx = idx
		self.value = value

	def to_dict(self):
		return {
			"tx_id": self.txid,
			"idx": self.idx,
			"value": self.value
		}

class HDPubKey:
	"""
	class for holding a pubkey (S256Point object) and metadata,
	including: 
	-Count (UTXO count)
	-Full Path
	-Label
	Inspiration from Wasabi Wallet.
	"""
	def __init__(self, pubkey, path, label=[]):
		self.pubkey = pubkey
		self.path = path
		self.label = label
		self.txcount = 0
		self.balance = 0
		self.check_state()

	def __repr__(self):
		label =  ", ".join(self.label)
		return f"\"PubKey\": {self.pubkey.sec().hex()},\n\"FullKeyPath\": {self.path},\n\"Label\": {label},\n\"Count\": {self.txcount},\n\"Balance\": {self.balance}"
		
	def to_dict(self):
		# utxo_list = []
		# for utxo in self.utxos:
		# 	utxo_list.append(utxo.to_dict())
		return {
			"PubKey": self.pubkey.sec().hex(),
			"FullKeyPath": self.path,
			"Label": self.label,
			"TxCount": self.txcount,
			"Balance": self.balance
		}

	def check_state(self):
		"""
		sets txcount and balance. returns balance
		"""	
		addr = self.pubkey.address()
		tx_hist = blockstream.blockexplorer.get_address(addr).chain_stats
		self.txcount = tx_hist['tx_count']
		self.balance = tx_hist['funded_txo_sum'] - tx_hist['spent_txo_sum']
		return self.balance
		
	def get_utxos(self):
		addr = self.pubkey.address()
		return blockstream.blockexplorer.get_address_utxo(addr)

	def set_confirmed_utxos(self):
		addr = self.pubkey.address()
		utxos = blockstream.blockexplorer.get_address_utxo(addr)
		self.utxos = []
		for utxo in utxos:
			if utxo.status.confirmed:
				self.utxos.append(utxo)
		#return len(self.utxos)

	def is_used(self):
		return self.txcount > 0

	def empty(self):
		return self.balance == 0

	def set_label(self, label):
		self.label.append(label)

	def address(self, testnet=False):
		return self.pubkey.address(testnet=testnet)

class Wallet:
	DEFAULT_GAP_LIMIT = 5
	BASE_PATH = "76'/0'/"
	DUST_LIMIT = 5000
	TX_VERSION = 1
	"""
	A class for storing a single Seed or ExtendedKey in order to manage UTXOs, craft transactions, and more.
	Contains a wallet account (2 layers of depth) and an external (0) and internal (1) account chain, as 
	specified in BIP0032
	"""
	def __init__(self, name="Wallet0", passphrase="", testnet=False, data=None, watch_only=False):
		self.name = name
		self.passphrase = passphrase
		self.testnet = testnet
		self.ext_count = 0
		self.int_count = 0
		self.watch_only = watch_only
		
		self.wallet_acct = self.BASE_PATH
		# this standard is defined in BIP0032
		self.ext_chain = 0 # used as 3th layer of derivation path before 4th layer = keys
		self.int_chain = 1 # used as internal chain, for change addr etc.
		self.balance = 0
		self.gap_limit = self.DEFAULT_GAP_LIMIT
		
		self.hdpubkeys = []
		# Load data into wallet, either Seed, Xpub, Xpriv. create necessary keys
		if data is not None:
			#import from seed, xpub, xprv object, or from string xpub or xprv 
			if type(data) == Seed:
				self.seed = data
				self.master_xprv = data.derive_master_priv_key(passphrase=passphrase, testnet=testnet)
				self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
				#self.ext_xpub = self.derive_key((self.wallet_acct + str(self.ext_chain)), priv=True).to_extended_pub_key()
				#self.int_xpub = self.derive_key((self.wallet_acct + str(self.int_chain)), priv=True).to_extended_pub_key()
			elif type(data) == ExtendedPrivateKey:
				self.master_xprv = data
				self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
				#self.ext_xpub = self.derive_key((self.wallet_acct + str(self.ext_chain)), priv=True).to_extended_pub_key()
				#self.int_xpub = self.derive_key((self.wallet_acct + str(self.int_chain)), priv=True).to_extended_pub_key()
				self.seed = None
			elif type(data) == ExtendedPublicKey: # not fully thought-out. Fix Later
				self.master_xpub = data
				self.master_xprv = None
				self.seed = None

			elif type(data) == str:
				if data[:4] == "xprv":
					try:
						self.master_xprv = ExtendedPrivateKey.parse(data)
						self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
						#self.ext_xpub = self.derive_key(self.wallet_acct + str(self.ext_chain), priv=True).to_extended_pub_key()
						#self.int_xpub = self.derive_key((self.wallet_acct + str(self.int_chain)), priv=True).to_extended_pub_key()
						self.seed = None
					
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPRIV key.")
				elif data[:4] == "xpub": # not useful. Think through
					try:
						self.master_xpub = ExtendedPublicKey.parse(data)
						self.master_xprv = None
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPUB key.")
				else:
					raise ConfigurationError("Invalid import format")
		
		# Generate first GAP_LIMIT keys
		for _ in range(self.gap_limit):
			self.new_pub_key()
		# Scan them all
		self.check_state()

	def mnemonic(self):
		if self.seed:
			return self.seed.mnemonic()
		if self.watch_only:
			raise TypeError("Wallet is watch-only. Seed unknown.")
		if self.seed is None and self.master_xprv is not None:
			raise TypeError("Wallet was created from ExtendedPrivateKey. Seed unknown.")

	def derive_key(self, path, priv):
		"""
		General function for deriving any key in the account.
		"""
		# if levels.pop() != "m":
		# 	raise ConfigurationError(f"Path must begin with \'m/\'. Begins with {path[0:2]}")
		if priv:
			if self.watch_only:
				raise TypeError("Watch only wallets cannot access Private Keys.")
			levels = path.split("/")
			child = self.master_xprv
			for i in levels:
				if i == "":
					continue
				if i[-1] == "'":
					child = child.derive_priv_child( SOFT_CAP + int(i[:-1]) )
				else:
					child = child.derive_priv_child( int(i) )
		# public keys
		else:
			child = self.master_xpub
			levels = path.split("/")
			for i in levels:
				if i == "":
					continue
				if i[-1] == "'": # PubKeys cant make hardened children
					raise TypeError("Hardened Child Keys cannot be derived from Public Parent Key.")
				child = child.derive_pub_child(int(i))

		return child

	def new_pub_key(self, label="", external=True):
		""" 
		generates and returns the next pubkey from the external 
		chain and adds an HDPubKey to self.hdpubkeys
		label is the local label applied to the utxos for utxo selection
		chain = 0 for external 
		chain = 1 for internal (change addresses)
		"""
		# chain = str(self.ext_chain) if external else str(self.int_chain)
		# path = chain + "/" + str(self.ext_count)
		if external:
			path = f"{self.ext_chain}/{self.ext_count}"
			self.ext_count+=1
		else:
			path = f"{self.int_chain}/{self.int_count}"
			self.int_count+=1
		pubkey = self.derive_key(path, priv=False).to_pub_key()
		#print(path)
		
		fullpath = self.wallet_acct + str(self.ext_chain) + "/" + path
		hpk = HDPubKey(pubkey, path=fullpath, label=[label])
		hpk.check_state()
		self.hdpubkeys.append(hpk)
		return pubkey

	def new_address(self, label="", external=True):
		""" returns unused address and stores the associated pubkey in self.hdpubkeys """
		return self.new_pub_key(label=label, external=external).address(self.testnet)

	def check_state(self):
		""" calls check_state on each hdPubKey. Sets balance and updates txcount. """
		sats = 0
		for hpk in self.hdpubkeys:
			sats += hpk.check_state() #returns balance of pukey, also updates balance and txcount
		self.balance = sats

	def get_balance(self):
		""" sets and returns wallet balance """
		sats = 0
		for hpk in self.hdpubkeys:
			sats += hpk.get_balance()
		self.balance = sats
		return sats

	def get_priv_key(self, pubkey):
		""" gets corresponding privkey from a pubkey using pubkey.path """
		if self.watch_only:
			raise TypeError("Watch only wallet")
		return self.derive_key(pubkey.path, priv=True)

#----- TRANSACTION FUNCTIONS -----
#
#---------------------------------
	
	def create_p2pkh(self, amount, address, fee, locktime=0, priority="oldest", data=None):
		pubkeys = self.select_utxos(amount+fee, priority=priority, data=data)
		amountIn = 0
		change_labels = ""
		stripped_pubkeys = []
		for pubkey in pubkeys:
			amountIn += pubkey.balance
			change_labels += pubkey.label.split(" ")
			stripped_pubkeys.append(pubkey.pubkey)
		
		#TX INS
		tx_ins = craft_tx_ins(pubkeys)

		#TX OUTS
		tx_outs = craft_tx_outs

		return Tx(TX_VERSION, tx_ins, tx_outs, locktime, testnet=self.testnet)

	

	def select_utxos(self, amountNfee, priority="oldest", data=None):
		"""
		function for choosing utxos to use for a transaction.
		param: amountNfee is amount to be sent including fee.
		priority allows for options in terms of choosing 
		which utxos to spend. Options:
			- "oldest": uses oldest utxos first (by derivation path, not utxo age)
			- "biggest": uses fewest and biggest utxos possible
			- "smallest": uses fewest number of smallest utxos
			- "below": uses ALL utxos below amount specified in data
		"""
		pAmount = 0
		pubkeys = []
		if priority == "oldest":
			for pubkey in self.hdpubkeys:
				if "NoSpend" not in pubkey.label:
					if pubkey.balance > 0:
						pubkey.set_confirmed_utxos()
						pubkeys.append(pubkey)
						pAmount += pubkey.balance
						if pAmount >= amountNfee:
							break

		elif priority == "biggest":
			raise NotImplementedError("Priority algorithm not implemented yet.")

		elif priority == "smallest":
			raise NotImplementedError("Priority algorithm not implemented yet.")

		elif priority == "below":
			raise NotImplementedError("Priority algorithm not implemented yet.")		
		return pubkeys

	def craft_tx_ins(self, pubkeys):
		tx_ins = []
		for pubkey in pubkeys:
			for utxo in pubkey.utxos:
				tx_ins.append(TxIn(bytes.fromhex(utxo.tx_id), utxo.vout))
		return tx_ins

	def create_tx_out(self, amount, address, script_type=p2pkh_script):
		addr = decode_base58(address)
		return TxOut(amount, script.script_type(addr))

	def craft_tx_outs(self, address, script_type=p2pkh_script):
		target_address = decode_base58(address)
		target_out = craft_tx_out(amount=amount, address=address, script_type=script_type)
		
		change_amount = amountIn - amount - fee
		change_addr = decode_base58(self.new_address(label=change_labels, external=False))
		change_out = craft_tx_out(amount=change_amount, address=change_addr, script_type=script_type)
		
		return [target_out, change_out] # randomize order later

	def sign_tx(self, tx, pubkeys):
		for i in len(tx.tx_ins):
			priv = self.get_priv_key(pubkeys[i])
			if not tx.sign_input(i, priv): 
				raise ValueError("Input Signing Failed")
		return tx

	def _address_check(self, address):
		pass
			
	def broadcast(self, tx):
		if tx.verify():
			raise NotImplementedError("coming soon")
		else:
			raise ValueError("Invalid Transaction")

	def create_p2sh(self, address, amount, fee, priority="oldest", data=None):
		raise NotImplementedError("coming soon")


#----- EXTERNAL FUNCTIONS -----
#
#------------------------------
	
	def write_json(self, filename=""):
		if filename == "":
			filename = f"{self.name}.json"
		HdPubKeys = []
		data = {}
		with open(f"{filename}.json", "w+") as fp:
			#verify file matches wallet
			wallet = self.verify_file(fp)
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

	def verify_file(self, fp):
		wallet = json.load(fp)
		c_wallet = True
		if wallet["XPUB"] != self.ext_xpub.__repr__():
			c_wallet = False
		elif wallet["wallet_acct"] != self.wallet_acct:
			c_wallet = False
		elif self.testnet:
			if wallet["NETWORK"] != "test":
				c_wallet = False
		elif wallet["NETWORK"] != "main":
			c_wallet = False
		if c_wallet == False:
			raise ConfigurationError("Incorrect Wallet. Import failed.")
		else:
			return wallet

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
	
	s = Seed.new(128)
	w = Wallet(data=s, testnet=False, watch_only=False)
	# for tpub in w.hdpubkeys:
	# 	print(tpub.address(w.testnet))
	w.new_pub_key(external=False)
	# w.new_pub_key(external=False)
	# w.new_pub_key(external=False)
	print(w.new_address())
	print(w.new_address())
	print(w.new_address())
	print(w.new_address())
	print(w.new_address())