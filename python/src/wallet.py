import json
from blockstream.blockexplorer import (
	get_address,
	get_address_utxo
)
from seed import *
from ecc import SignatureError
from helper import (
	hash256,
	hash160,
	decode_base58
)
from script import (
	p2pkh_script,
	p2sh_script
)
from encrypt import (
	encrypt,
	decrypt
)
from tx import (
	Tx,
	TxIn, 
	TxOut
)
SEED_PREFIX = b"\x73\x65\x65\x64"
XPRV_PREFIX = b"\x78\x70\x72\x76"



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

	def to_json(self):
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
	def __init__(self, pubkey, path, label=[], testnet=False):
		self.pubkey = pubkey
		self.path = path
		self.label = label
		self.testnet = testnet
		self.txcount = 0
		self.balance = 0
		self.utxos = []
		self.check_state()

	def __repr__(self):
		label =  ", ".join(self.label)
		return f"\"PubKey\": {self.pubkey.sec().hex()},\n\"FullKeyPath\": {self.path},\n\"Label\": {label},\n\"Count\": {self.txcount},\n\"Balance\": {self.balance}"
		
	def to_json(self):
		# utxo_list = []
		# for utxo in self.utxos:
		# 	utxo_list.append(utxo.to_json())
		return {
			"PubKey": self.pubkey.sec().hex(),
			"FullKeyPath": self.path,
			"Label": self.label
		}
	
	@classmethod
	def parse(cls, data):
		sec = bytes(bytearray.fromhex(data["PubKey"]))
		pubkey = S256Point.parse(sec)
		return HDPubKey(pubkey, data["FullKeyPath"], data["Label"])

	def check_state(self):
		"""
		sets txcount and balance. returns balance
		"""	
		addr = self.pubkey.address(testnet=self.testnet)
		tx_hist = get_address(addr).chain_stats
		self.txcount = tx_hist['tx_count']
		self.balance = tx_hist['funded_txo_sum'] - tx_hist['spent_txo_sum']
		return self.balance
		
	def get_utxos(self):
		addr = self.pubkey.address(testnet=self.testnet)
		return get_address_utxo(addr)

	def set_confirmed_utxos(self):
		addr = self.pubkey.address(testnet=self.testnet)
		utxos = get_address_utxo(addr)
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

	def address(self):
		return self.pubkey.address(testnet=self.testnet)

class Wallet:
	DEFAULT_GAP_LIMIT = 5
	DEFAULT_NAME = "Wallet0"
	BASE_PATH = "76'/0'/"
	DUST_LIMIT = 5000
	TX_VERSION = 1
	
	"""
	A class for storing a single Seed or ExtendedKey in order to manage UTXOs, craft transactions, and more.
	Contains a wallet account (2 layers of depth) and an external (0) and internal (1) account chain, as 
	specified in BIP0032
	"""
	def __init__(self, name=DEFAULT_NAME, passphrase="", testnet=False, data=None, watch_only=False):
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
		
			if not self.watch_only:
				
				for _ in range(self.gap_limit):
					self.new_pub_key()
				# Scan them all
				self.check_state()
		else:
			self.seed = None
			self.master_xprv = None
			self.master_xpub = None
		# Generate first GAP_LIMIT keys
		

	def mnemonic(self):
		if self.seed:
			return self.seed.mnemonic()
		if self.watch_only:
			raise TypeError("Wallet is watch-only. Seed unknown.")
		if self.seed is None and self.master_xprv is not None:
			raise TypeError("Wallet was created from ExtendedPrivateKey. Seed unknown.")

	def master_fingerprint(self, xpub):
		return hash160(xpub.to_pub_key().sec())[:4]

	def import_seed(self, seed, passphrase):
		self.seed = seed
		self.master_xprv = seed.derive_master_priv_key(passphrase=passphrase, testnet=self.testnet)
		if self.master_xpub:
			newXpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
			if self.master_fingerprint(self.master_xpub) != self.master_fingerprint(newXpub):
				raise ConfigurationError("Import Failed.")
		else:
			self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
		self.watch_only = False

		
#----- WALLET FUNCTIONS -----
#
#----------------------------

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
				try:
					if i[-1] == "'":
						child = child.derive_priv_child( SOFT_CAP + int(i[:-1]) )
					else:
						child = child.derive_priv_child( int(i) )
				except IndexError:
					continue
			return child
		# public keys
		else:
			child = self.master_xpub
			levels = path.split("/")
			for i in levels:
				try:
					if i[-1] == "'": # PubKeys cant make hardened children
						raise TypeError("Hardened Child Keys cannot be derived from Public Parent Key.")
					child = child.derive_pub_child(int(i))
				except IndexError:
					continue
			return child

	def new_pub_key(self, label=[], external=True):
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
		
		fullpath = self.wallet_acct + path
		if type(label) == str:
			label = [label]
		hpk = HDPubKey(pubkey, path=fullpath, label=label, testnet=self.testnet)
		hpk.check_state()
		self.hdpubkeys.append(hpk)
		return pubkey

	def new_address(self, label=[], external=True):
		""" returns unused address and stores the associated pubkey in self.hdpubkeys """
		if type(label) == str:
			label = [label]
		return self.new_pub_key(label=label, external=external).address(testnet=self.testnet)

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
			sats += hpk.check_state()
		self.balance = sats
		return sats

	def get_priv_key(self, pubkey):
		""" gets corresponding privkey from a pubkey using pubkey.path """
		if self.watch_only:
			raise TypeError("Watch only wallet")
		return self.derive_key(pubkey.path, priv=True).to_priv_key()

#----- TRANSACTION FUNCTIONS -----
#
#---------------------------------
	def create_p2pkh(self, outputs, fee, locktime=0, priority="oldest", data=None):
		"""

		-outputs is a list of tuples (amount, address)
		"""
		amountOut = sum([o[0] for o in outputs])
		pubkeys = self.select_utxos(amountNfee=(amountOut+fee), priority=priority, data=data)

		amountIn = 0
		tx_ins =[]
		change_labels = []
		for pubkey in pubkeys:
			#print(pubkey.pubkey.address(testnet=True))
			change_labels += pubkey.label
			for utxo in pubkey.utxos:
				#TX INS
				tx_ins.append(TxIn(bytes.fromhex(utxo.tx_id), utxo.vout))
				#stripped_pubkeys.append(pubkey.pubkey)
			amountIn += pubkey.balance

		#change output
		change_amount = amountIn - fee - amountOut
		change_addr = decode_base58(self.new_address(label=change_labels, external=False))
		outputs.append((change_amount, change_addr))
		#TX OUTS
		tx_outs = []

		for output in outputs:
			tx_outs.append(Wallet.create_tx_out(output[0], output[1], script_type=p2pkh_script))

		transaction = Tx(self.TX_VERSION, tx_ins, tx_outs, locktime, testnet=self.testnet)
		#Signing
		for i, pubkey in enumerate(pubkeys):
			if not transaction.sign_input(i, self.get_priv_key(pubkey)):
				raise SignatureError(f"Signing Input {i} failed.")
		if not transaction.verify():
			raise TransactionError("Invalid Transaction")
		return transaction

	def create_p2pkh_old(self, amount, address, fee, locktime=0, priority="oldest", data=None):
		pubkeys = self.select_utxos(amountNfee=(amount+fee), priority=priority, data=data)
		
		amountIn = 0
		#change_labels = ""
		#stripped_pubkeys = []
		tx_ins =[]
		for pubkey in pubkeys:
			#print(pubkey.pubkey.address(testnet=True))
			amountIn += pubkey.balance
			#change_labels += " ".join(pubkey.label)
			for utxo in pubkey.utxos:
				#TX INS
				tx_ins.append(TxIn(bytes.fromhex(utxo.tx_id), utxo.vout))
				#stripped_pubkeys.append(pubkey.pubkey)

		#TX OUTS
		tx_outs = self.craft_tx_outs(amountIn=amountIn, amountOut=amount, fee=fee, address=address, script_type=p2pkh_script)
		
		transaction = Tx(self.TX_VERSION, tx_ins, tx_outs, locktime, testnet=self.testnet)
		#Signing
		for i, pubkey in enumerate(pubkeys):
			if not transaction.sign_input(i, self.get_priv_key(pubkey)):
				raise SignatureError(f"Signing Input {i} failed.")
		if not transaction.verify():
			raise TransactionError("Invalid Transaction")
		return transaction

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
				#TODO if "NoSpend" not in pubkey.label:
				if pubkey.balance > 0:
					pubkey.set_confirmed_utxos()
					pubkeys.append(pubkey)
					pAmount += pubkey.balance
					if pAmount >= amountNfee:
						break

		elif priority == "biggest":
			balances = []
			for _ in range(len(self.hdpubkeys))
				nextKey = max(self.hdpubkeys, key=(lambda x: x.balance))
				#TODO if "NoSpend" not in pubkey.label:
				pubkeys.append(nextKey)
				pAmount += nextKey.balance
				if pAmount >= amountNfee:
						break
			
		elif priority == "smallest":
			balances = []
			for _ in range(len(self.hdpubkeys))
				nextKey = min(self.hdpubkeys, key=(lambda x: x.balance))
				#TODO if "NoSpend" not in pubkey.label:
				pubkeys.append(nextKey)
				pAmount += nextKey.balance
				if pAmount >= amountNfee:
						break

		elif priority == "below":
			raise NotImplementedError("Priority algorithm not implemented yet.")

		if pAmount < amountNfee:
			raise TransactionError("Insufficient Funds for this transaction.")		
		return pubkeys

	@staticmethod
	def create_tx_out(amount, address, script_type=p2pkh_script):
		return TxOut(amount, script_type(address))

	# def sign_psbt(self, psbt, pubkeys):
	# 	""" Sign PSBT """
	# 	for i in len(tx.tx_ins):
	# 		priv = self.get_priv_key(pubkeys[i])
	# 		if not tx.sign_input(i, priv): 
	# 			raise ValueError("Input Signing Failed")
	# 	return tx

	def _address_check(self, address):
		""" 
		MUST BE MADE BETTER. Very elementary.
		# - "1" addresses are of course p2pkh
        # - "3" addresses are p2sh but we don't know the redeemScript
        # - "bc1" 42-long are p2wpkh
        # - "bc1" 62-long are p2wsh 
		"""
		#P2PKH
		if address[0] == "1":
			return True
		#P2SH
		elif address[0] == "3":
			return True
		#P2WPKH or P2WSH
		elif address[:3] == "bc1":
			#P2WPKH
			if len(address) == 42:
				return True
			#P2WSH
			if len(address) == 62:
				return True
		else: 
			return False
		
	def broadcast(self, tx): 
		if tx.verify():
			raise NotImplementedError("coming soon")
		else:
			raise TransactionError("Invalid Transaction")

	def create_p2sh(self, address, amount, fee, priority="oldest", data=None):
		raise NotImplementedError("coming soon")

#----- EXTERNAL FUNCTIONS -----
#
#------------------------------
	
	def to_json(self):
		perm = "watch" if self.watch_only else "total"
		netw = "test" if self.testnet else "main"
		d = {
			"MASTER_FINGERPRINT": self.master_fingerprint(self.master_xpub).hex(),
			"ACCT_XPUB": self.master_xpub.__repr__(),
			"ACCT_PATH": self.wallet_acct,
			"NETWORK": netw,
			"PERMISSION": perm,
			"HdPubKeys": [hpk.to_json() for hpk in self.hdpubkeys]
		}
		return d

	@classmethod
	def from_json(self, name, data):
		xpub = ExtendedPublicKey.parse(data["ACCT_XPUB"])
		testnet = data["NETWORK"] == "test"
		w = Wallet(name=name, passphrase="", testnet=testnet, data=xpub, watch_only=True)
		# set watch_only to true in __init__ to avoid generating keys.
		# then set to real value
		w.watch_only = data["PERMISSION"] == "watch"
		w.acct_path = data["ACCT_PATH"]
		ext_count = 0
		int_count = 0
		hdpubkeys = []
		for hpk in data["HdPubKeys"]:
			path = hpk["FullKeyPath"]
			#print(path)
			hdpubkey = HDPubKey.parse(hpk)
			hdpubkeys.append(hdpubkey) 
			#decide if external or internal key
			if w.acct_path in path:#FIX 
				path = path[len(w.acct_path)]
				path = path.replace(w.acct_path, '')
				
				if path[0] == "0":
					#print(path[0])
					ext_count += 1
				elif path[0] == "1":
					#print(path[0])
					int_count += 1
				else:
					#print(path[0])
					pass
		w.hdpubkeys = hdpubkeys
		w.ext_count = ext_count
		w.int_count = int_count
		w.check_state()
		
		return w

	def write_json(self, filename=None):
		if filename is None:
			filename = self.name
		
		json_obj = json.dumps(self.to_json(), indent=4)
		with open(f"{filename}.json", "w+") as fp:
			#verify file matches wallet
			#wallet = self.verify_file(fp)
			#write wallet data
			fp.write(json_obj)
		return True

	@classmethod
	def read_json(cls, filename=DEFAULT_NAME):
		with open(f"{filename}.json", "r") as fp:
			data = json.load(fp) 
		return Wallet.from_json(filename, data)

	def verify_file(self, fp): # UPDATE
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

	def write_secret(self, filename=None, password=None):
		from os import remove
		if filename is None:
			filename = f"{self.name}.dat"
		if self.seed is not None:
			l = len(self.seed.bits) 
			bits = self.seed.bits[:-(l//33)] #take off checksum
			#print(bits)
			seed_bytes = SEED_PREFIX
			seed_bytes += int(bits, 2).to_bytes(len(bits)//8, 'big')
			#print("seedlen0:",len(seed_bytes)-4)
			encrypted_secret = encrypt(seed_bytes, password)
		elif self.master_xprv is not None:
			xprv_bytes = XPRV_PREFIX
			xprv_bytes += self.master_xprv.to_bytes()
			encrypted_secret = encrypt(xprv_bytes, password)
		else:
			raise ConfigurationError("No Secret to Encrypt.")
		try:
			with open(f"{filename}.dat", "wb") as fp:
				fp.write(encrypted_secret.getbuffer())
		except ValueError:
			remove(f"{filename}.dat")

	def read_secret(self, filename, password=None):
		with open(f"{filename}.dat", "rb") as fp:
			fOut = fp.read()
		secret = decrypt(fOut, password)
		if secret[:4] == SEED_PREFIX:
			#print("seedlen1:", len(secret[4:]))
			seed = Seed.from_bytes(secret[4:])
			self.import_seed(seed, passphrase=password)
		elif secret[:4] == XPRV_PREFIX:
			pass
		
	def backup(self, filename=None):
		if filename is None:
			filename is self.name
		self.write_json(filename)
		self.write_secret(filename)

	@classmethod
	def load(cls, filename, password=None):
		w = Wallet.read_json(filename=filename)
		seed = w.read_secret(filename=filename, password=password)
		w.import_seed(seed)

	@classmethod
	def from_mnemonic(cls, mnemonic, lang="english", name=DEFAULT_NAME, passphrase="", testnet=False):
		s = Seed.from_mnemonic(mnemonic, lang=lang)
		return cls(name=name, passphrase=passphrase, testnet=testnet, data=s, watch_only=False)

if __name__ == "__main__":
	
	# s = Seed.new(128)
	

	# w = Wallet(data=s, passphrase="password1", testnet=True, watch_only=False)
	# with open("dump.txt", "w") as fp:
	# 	mnemonic = " ".join(s.mnemonic())
	# 	fp.write(mnemonic)
	# 	fp.write("\n")
	# 	fp.write(w.master_xprv.__repr__())
	
	# w.write_json(filename="test")
	# w.write_secret(filename="test", password="password1")
	# #w2 = Wallet.read_json(filename="test")

	# #w2.read_secret(filename="test", password="password1")
	# #print(w2.hdpubkeys)
	# #print(len(w2.hdpubkeys))
	# print(w.new_address(label="faucet", external=True))


	w2 = Wallet(passphrase="password1", testnet=True, watch_only=False)
	w2.read_secret(filename="test", password="password1")
	# for i in range(7):
	# 	w2.new_pub_key(external=True)
	# for pk in w2.hdpubkeys:
	# 	print(pk.pubkey.address(testnet=True), pk.balance)
	# amount = 80000
	# fee = 400
	# addr = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt"

	# tx = w2.create_p2pkh(amount, addr, fee)
	# print(tx.serialize().hex())

	for i in range(5):
		w2.new_pub_key(external=False)
		w2.new_pub_key(external=True)
	w2.write_json(filename="test")



