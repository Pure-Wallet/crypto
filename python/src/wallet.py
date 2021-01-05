import json
from io import BytesIO
from blockstream.blockexplorer import (
	get_address,
	get_address_utxo,
	get_transaction_hex,
	get_transaction_status,
	post_transaction
)
from seed import *
from psbt import *
from ecc import (
	SignatureError,
	S256Point,
)
from address import (
	Address,
	AddressError
)

from helper import (
	hash256,
	hash160,
	decode_base58, 
	int_to_little,
	little_to_int,
	SIGHASH_ALL, 
	SIGHASH_NONE,
	SIGHASH_SINGLE, 
)
from script import (
	p2pkh_script,
	p2sh_script,
	p2wpkh_script,
	p2wsh_script,
	ScriptError
)
from tx import (
	Tx,
	TxIn, 
	TxOut,
	TransactionError
)
from bech32 import (
	bech32_address_decode,
	h160_to_p2wpkh,
	h256_to_p2wsh,
	Bech32Error
)
from sql.sqlhandler import (
	WalletDB,
	DatabaseError
)

SEED_PREFIX = b"\x73\x65\x65\x64"
XPRV_PREFIX = b"\x78\x70\x72\x76"

XPUB_PFX = b"\x04\x88\xb2\x1e"
XPRV_PFX = b"\x04\x88\xad\xe4"
TPUB_PFX = b"\x04\x35\x87\xcf"
TPRV_PFX = b"\x04\x35\x83\x94"

YPUB_PFX = b"\x04\x9d\x7c\xb2"
YPRV_PFX = b"\x04\x9d\x78\x78"
UPUB_PFX = b"\x04\x4a\x52\x62"
UPRV_PFX = b"\x04\x4a\x4e\x28"

ZPRV_PFX = b"\x04\xb2\x43\x0c"
ZPUB_PFX = b"\x04\xb2\x47\x46"
VPRV_PFX = b"\x04\x5f\x18\xbc"
VPUB_PFX = b"\x04\x5f\x1c\xf6"


class UTXO:
	"""
	UNUSED
	class for holding a UTXO info:
		-txid (str)
		-index (int)
		-value (int) in sats
	"""
	def __init__(self, txid, vout, amount, script_id, block_height=0, status="unconfirmed"):
		self.txid = txid
		self.vout = vout
		self.amount  = amount
		self.block_height = block_height
		self.status = status
		self.script_id = script_id

	def to_json(self):
		return {
			"tx_id": self.txid,
			"vout": self.vout,
			"amount": self.amount,
			"block_height": self.block_height,
			"status": self.status,
			"script_id": self.script_id
		}
	def __iter__(self):
		yield self.txid
		yield self.vout
		yield self.amount
		yield self.block_height 
		yield self.status
		yield self.script_id

	def check_status(self, testnet=False):
		status = get_transaction_status(self.txid, testnet=testnet)
		self.block_height = status.block_height
		self.status = status.confirmed

class HDScriptPubKey:
	def __init__(self, script_pubkey, script_name, deriv_path, label=[], script_id=None, amount=None):
		self.script_pubkey = script_pubkey
		self.script_name = script_name
		self.path = deriv_path
		self.label = label
		self.script_id = script_id
		self.amount = amount

	def __iter__(self):
		yield self.script_pubkey.hex()
		yield self.script_name
		yield self.path

	def get_path_bytes(self):
		''' returns path as concatenated bytes'''
		levels = self.path.split("/")
		path_bytes = b""
		for lev in levels:
			i = 0
			if lev[-1] == "'":
				i = SOFT_CAP
				lev = lev[:-1]
			i += int(lev)
			path_bytes += int_to_little(i, 4)
		return path_bytes

	def address(self, testnet=False):
		return self.script_pubkey.to_address(testnet=testnet)

class Wallet:
	"""
	A class for storing a single Seed or ExtendedKey in order to manage UTXOs, craft transactions, and more.
	Contains a wallet account (2 layers of depth) and an external (0) and internal (1) account chain, as 
	specified in BIP0032
	"""
	DEFAULT_GAP_LIMIT = 10
	DEFAULT_NAME = "Wallet0"
	DUST_LIMIT = 5000000
	ACCOUNT="0'/"
	TX_VERSION = 1
	DEFAULT_SCRIPT_NAME = "p2pkh"
	
	

	def __init__(self, name=DEFAULT_NAME, passphrase="", testnet=False, data=None, watch_only=False, script_type=DEFAULT_SCRIPT_NAME):
		self.name = name
		self.passphrase = passphrase
		self.testnet = testnet
		self.watch_only = watch_only
		self.walletdb = WalletDB(f'{name}.db')
		# set later
		self.script_name = None
		self.purpose_path = None
		self.script_func = None
		self.pub_pfx = None
		self.prv_pfx = None
		self.wallet_acct = None

		# this standard is defined in BIP0032
		self.ext_chain = 0 # used as 3th layer of derivation path before 4th layer = keys
		self.int_chain = 1 # used as internal chain, for change addr etc.
		self.balance = 0
		self.ext_count = 0
		self.int_count = 0
		self.gap_limit = self.DEFAULT_GAP_LIMIT
		# Load data into wallet, either Seed, Xpub, Xpriv. create necessary keys
		if data is not None:
			#import from seed, xpub, xprv object, or from string xpub or xprv 
			if type(data) == Seed:
				self.seed = data
				self._set_script_info(script_type)
				self.wallet_acct = self.determine_path()
				self.master_xprv = data.derive_master_priv_key(passphrase=passphrase, _pfx=self.prv_pfx)
				self.master_xpub = self.master_xprv.to_extended_pub_key()
				self.acct_xprv = self.derive_key(self.wallet_acct, priv=True, absolute=True)
				self.acct_xpub = self.acct_xprv.to_extended_pub_key()
			elif type(data) == ExtendedPrivateKey:
				self.master_xprv = data
				t = self.master_xprv.__repr__()[0]
				self._set_script_info(self._script_type_from_pfx(t))
				self.wallet_acct = self.determine_path()
				self.master_xpub = self.master_xprv.to_extended_pub_key()
				self.acct_xprv = self.derive_key(self.wallet_acct, priv=True, absolute=True)
				self.acct_xpub = self.acct_xprv.to_extended_pub_key()
				self.seed = None
			elif type(data) == ExtendedPublicKey: # not fully thought-out. Fix Later
				self.acct_xpub = data
				t = self.acct_xpub.__repr__()[0]
				self._set_script_info(self._script_type_from_pfx(t))
				self.wallet_acct = self.determine_path()	
				self.master_xprv = None
				self.seed = None

			elif type(data) == str:
				if data[:4] == "xprv":
					try:
						self.master_xprv = ExtendedPrivateKey.parse(data)
						self.acct_xpub = self.derive_key(self.wallet_acct, priv=True).to_extended_pub_key()
						self.seed = None
					
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPRIV key.")
				elif data[:4] == "xpub": # not useful. Think through
					try:
						self.acct_xpub = ExtendedPublicKey.parse(data)
						self.master_xprv = None
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPUB key.")
				else:
					raise ConfigurationError("Invalid import format")
		else:
			self.seed = None
			self.master_xprv = None
			self.acct_xpub = None

	def _set_script_info(self, script_type):
		PURPOSES = {
			"p2pkh": {
				"mpfx": "x",
				"tpfx": "t",
				"path": "44'/", # BIP 44
				"func": self.pubkey_to_p2pkh_script,
				"mprv": b"\x04\x88\xad\xe4", # xprv
				"mpub": b"\x04\x88\xb2\x1e",
				"tprv": b"\x04\x35\x83\x94",
				"tpub": b"\x04\x35\x87\xcf"
			},
			"p2sh-p2wpkh":  { # BIP 49
				"mpfx": "y",
				"tpfx": "u",
				"path": "49'/",
				"func": self.pubkey_to_p2sh_p2wpkh_script,
				"mprv": b"\x04\x9d\x78\x78", # yprv
				"mpub": b"\x04\x9d\x7c\xb2", # ypub
				"tprv": b"\x04\x4a\x4e\x28",
				"tpub": b"\x04\x4a\x52\x62", 

			},
			"p2wpkh": {
				"mpfx": "z",
				"tpfx": "v",
				"path": "84'/", # BIP 84
				"func": self.pubkey_to_p2wpkh_script,
				"mprv": b"\x04\xb2\x43\x0c", # zprv
				"mpub": b"\x04\xb2\x47\x46",
				"tprv": b"\x04\x5f\x18\xbc",
				"tpub": b"\x04\x5f\x1c\xf6"
			}
		}
		try:
			self.script_name = script_type
			self.purpose_path = PURPOSES[script_type]["path"]
			self.script_func = PURPOSES[script_type]["func"]
			if self.testnet:
				pfx = "t"
			else:
				pfx = "m"
			self.pub_pfx = PURPOSES[script_type][pfx + "pub"]
			self.prv_pfx = PURPOSES[script_type][pfx + "prv"]
		except (KeyError, ValueError):
			self._set_script_info(self.DEFAULT_SCRIPT_NAME)

	def _script_type_from_pfx(self, pfx):
		if pfx in ["t", "u", "v"]:
			self.testnet = True
		elif pfx in ["x", "y", "z"]:
			self.testnet = False
		else:
			raise RuntimeError("Invalid prefix")
		if pfx in ["x", "t"]:
			return "p2pkh"
		elif pfx in ["y", "u"]:
			return "p2sh-p2wpkh"
		elif pfx in ["z", "v"]:
			return "p2wpkh"
		

	@classmethod
	def new(cls, name=DEFAULT_NAME, passphrase="", strength=128, testnet=False, lang="english", script_type=DEFAULT_SCRIPT_NAME):
		s = Seed.new(strength=strength, lang=lang)
		return cls(name=name, data=s, passphrase=passphrase, testnet=testnet, script_type=script_type)

	def determine_path(self):
		path = self.purpose_path
		if self.testnet:
			path += "1'/"
		else:
			path += "0'/"
		path += self.ACCOUNT
		return path

	def mnemonic(self):
		if self.seed:
			return self.seed.mnemonic()
		if self.watch_only:
			raise TypeError("Wallet is watch-only. Seed unknown.")
		if self.seed is None and self.master_xprv is not None:
			raise TypeError("Wallet was created from ExtendedPrivateKey. Seed unknown.")

	@staticmethod
	def fingerprint(xpub):
		return hash160(xpub.to_pub_key().sec())[:4]

	def master_fingerprint(self): 
		return self.fingerprint(self.master_xpub)

	def import_seed(self, seed, passphrase):
		self.seed = seed
		self.master_xprv = seed.derive_master_priv_key(passphrase=passphrase, testnet=self.testnet)
		if self.acct_xpub:
			newXpub = self.derive_key(self.wallet_acct, priv=True, absolute=True).to_extended_pub_key()
			if self.master_fingerprint() != self.fingerprint(newXpub):
				raise ConfigurationError("Import Failed.")
		else:
			self.acct_xpub = self.derive_key(self.wallet_acct, priv=True, absolute=True).to_extended_pub_key()
		self.watch_only = False
	
#----- WALLET FUNCTIONS -----
#
#----------------------------

	def derive_key(self, path, priv, absolute=False):
		"""
		General function for deriving any key in the account.
		"""
		# if levels.pop() != "m":
		# 	raise ConfigurationError(f"Path must begin with \'m/\'. Begins with {path[0:2]}")
		if priv:
			if self.watch_only:
				raise TypeError("Watch only wallets cannot access Private Keys.")
			if absolute:
				child = self.master_xprv
			else:
				if path[:len(self.wallet_acct)] == self.wallet_acct:
					path = path[len(self.wallet_acct):]
				child = self.acct_xprv
			levels = path.split("/")
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
			if absolute:
				path = path.replace(self.wallet_acct, "", 1)
			child = self.acct_xpub
			levels = path.split("/")
			for i in levels:
				try:
					if i[-1] == "'": # PubKeys cant make hardened children
						raise TypeError("Hardened Child Keys cannot be derived from Public Parent Key.")
					child = child.derive_pub_child(int(i))
				except IndexError:
					continue
			return child	

	def new_pub_key(self, external=True):
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
		fullpath = self.wallet_acct + path
		# hpk = HDPubKey(pubkey, path=fullpath, label=label, testnet=self.testnet)
		# hpk.check_state()
		# self.hdpubkeys.append(hpk)
		return pubkey, fullpath

	def new_script_pubkey(self, external=True, label=[]):
		pubkey, path = self.new_pub_key(external)
		script_pubkey = self.script_func(pubkey)
		hd_spk = HDScriptPubKey(script_pubkey, self.script_name, path, label)
		self.sql_add_script_pubkey(hd_spk)
		return script_pubkey

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

	def get_priv_key(self, i):
		""" gets corresponding privkey from a pubkey using pubkey.path """
		if self.watch_only:
			raise TypeError("Watch only wallet")
		return self.derive_key(self.hdpubkeys[i].path, priv=True).to_priv_key()

	def __find_priv_key(self, sec):
		for i, p in enumerate(self.hdpubkey):
			if p.pubkey.sec() == sec:
				return self.get_priv_key(i)
		return False

	def priv_key_match(self, hd_script_pubkey):
		pass
	def generate_x_keys(self, x, external=True):
		for i in range(x):
			self.new_pub_key(external=external)
		return self.get_balance

	@classmethod
	def pubkey_to_p2pkh_script(cls, pubkey):
		h160 = pubkey.hash160()
		return p2pkh_script(h160)

	@classmethod
	def pubkey_to_p2wpkh_script(cls, pubkey):
		h160 = pubkey.hash160()
		return p2wpkh_script(h160)

	@classmethod
	def pubkey_to_p2sh_p2wpkh_script(cls, pubkey):
		# redeem script is p2wpkh script
		redeemscript = cls.pubkey_to_p2wpkh_script(pubkey)
		# h160 is hash of redeemscript
		h160 = hash160(redeemscript.serialize())
		return p2sh_script(h160)

	def new_legacy_address(self, label=[], external=True):
		""" returns unused address and stores the associated pubkey in self.hdpubkeys """
		return self.new_pub_key(label=label, external=external).pubkey.address(testnet=self.testnet)

	def new_p2wpkh_address(self, label=[], external=True):
		""" returns unused address and stores the associated pubkey in self.hdpubkeys """
		pk = self.new_pub_key(label=label, external=external).pubkey
		h160 = pk.hash160()
		return h160_to_p2wpkh(h160, witver=0, testnet=self.testnet)

	def new_address(self, external=True, label=[]):
		return self.new_script_pubkey(external=external, label=label).to_address(testnet=self.testnet)

	@classmethod
	def address_to_script_pubkey(cls, addr):
		return Script.from_address(addr)

#----- TRANSACTION FUNCTIONS -----
#
#---------------------------------
	''' 
	Flow: 
	- create_p2pkh selects utxos and constructs unsigned TX
		- if auto_sign: signs it and returns tx_bytes (ready for broadcast)
		- else returns updated & serialized PSBT (ready for Signing)

	- sign_psbt accepts serialized psbt and adds partial sigs
	- finalize
	- extract
	- broadcast
	
	'''
	
	def _address_check(self, address):
		""" 
		MUST BE MADE BETTER. Very elementary.
		- "1" addresses are of course p2pkh
        - "3" addresses are p2sh but we don't know the redeemScript
        - "bc1" 42-long are p2wpkh
        - "bc1" 62-long are p2wsh 
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
			elif len(address) == 62:
				return True
			else:
				return False
		else: 
			return False
	
	@classmethod
	def create_tx_out_from_address(cls, amount, address):
		script_pubkey = Script.from_address(address)
		return TxOut(amount, script_pubkey)

	@classmethod
	def create_tx_out(cls, amount, script_pubkey):
		return TxOut(amount, script_pubkey)

	@classmethod
	def create_tx_in(cls, prev_tx, vout, script_sig=None):
		if type(prev_tx) == str:
			prev_tx = bytes.fromhex(prev_tx)
		return TxIn(prev_tx, vout, script_sig)

	@classmethod
	def contains_segwit(cls, script_pubkeys):
		for s in script_pubkeys:
			if s.is_p2wpkh_script_pubkey() or s.is_p2wsh_script_pubkey():
				return True
		return False

	@classmethod
	def create_unfunded_transaction(cls, outputs, testnet=False, version=1, locktime=0):
		"""
		-inputs is a list of tuples(bytes prev_txid, int vout)
		-outputs is a list of tuples (int amount, Script script_pubkey)
		returns Tx object
		"""
		tx_outs = [cls.create_tx_out(o[0], o[1]) for o in outputs]
		return Tx(version, [], tx_outs, locktime=locktime, testnet=testnet, segwit=False)


	def fund_transaction(self, tx, priority="biggest", exclude_script_types=[], sighash_type=SIGHASH_ALL):
		# if psbt: #UNUSED WOULDNT WORK
		# 	tx = Tx.parse(BytesIO(psbt.get_unsigned_tx()))
		# if tx is None:
		# 	raise RuntimeError("No transaction to fund.")
		amountOut = tx.amount_out()
		utxos, segwit = self.utxo_selection(amountOut, priority=priority, exclude_script_types=exclude_script_types)
		tx_ins = []
		for utxo in utxos:
			tx_in = self.create_tx_in(utxo.txid, utxo.vout)
			tx_ins.append(tx_in)
		tx.tx_ins = tx_ins
		tx.segwit = segwit
		#outpoints = [(tx_in.prev_txid(), tx_in.vout) for tx_in in  tx_obj.tx_ins]
		psbt_cr = Creator.from_tx(tx, segwit)
		psbt_up = Updater(psbt_cr.serialize())
		for idx, tx_in in enumerate(tx.tx_ins):
			script = self.sql_get_script_from_utxo(tx_in.prev_txid(), tx_in.vout)
			tx_hex = get_transaction_hex(tx_in.prev_txid())
			if script.script_name in ["p2wpkh", "p2wsh", "p2sh-p2wpkh"]:
				psbt_up.add_witness_utxo(idx, tx_hex, tx_in.vout)
			else:
				psbt_up.add_nonwitness_utxo(idx, tx_hex)
			if script.script_name == "p2sh-p2wpkh":
				#TODO get path and generate redeemScript
				# add redeemScript to input
				raise NotImplementedError
			tx.segwit = segwit
			psbt_up.set_unsigned_tx(tx.serialize)

			psbt_up.add_sighash_type(idx, sighash_type)
			pubkey = self.derive_key(script.path, priv=False, absolute=True)
			path = script.get_path_bytes()
			psbt_up.add_input_pubkey(idx, pubkey, self.master_fingerprint(), path)
		return psbt_up.serialize()

	def update_funded_psbt(self, ser_psbt):
		""" redundant with fund_transaction """
		psbt_up = Updater(ser_psbt)
		tx_obj = psbt_up.psbt.get_tx_obj()
		outpoints = [(tx_in.prev_txid(), tx_in.vout) for tx_in in  tx_obj.tx_ins]
	
	def utxo_selection(self, amountOut, priority="biggest", exclude_script_types=[]):
		scripts_to_use = []
		amountIn = 0
		excluded = 0
		segwit = False
		if priority in ["biggest", "smallest"]:
			scripts = self.sql_find_unspent_scripts()
			if priority == "smallest":
				sorted_scripts = sorted(scripts, key=lambda item: item.amount)
			else:
				sorted_scripts = sorted(scripts, key=lambda item: item.amount, reverse=True)
			for s in sorted_scripts:
				if s.script_name not in exclude_script_types and "FREEZE" not in s.label:
					amountIn += s.amount
					scripts_to_use.append(s.script_id)
					if s.script_name in ["p2wpkh", "p2wsh", "p2sh-p2wpkh"]:
						segwit = True
				else:
					excluded += 1
				if amountIn  > amountOut:
					break
		# Check amountIn > AmountOut
		if amountIn < amountOut:
			raise TransactionError(f"Insufficient Funds: {excluded} scriptPubKeys were excluded.")
		utxos = self.sql_get_utxos_by_script_ids(scripts_to_use)
		return utxos, segwit

	def get_utxos_from_hd_script_pubkey(self, scripts_to_use):
		# get UTXOs from each Script
		utxo_list = self.walletdb.get_utxos_by_script_ids([s.script_id for s in scripts_to_use])
		utxos = [UTXO(
			txid=utxo[0], 
			vout=utxo[1], 
			amount=utxo[2], 
			script_id=utxo[5],
			block_height=utxo[3], 
			status=utxo[4]) 
			for utxo in utxo_list]
		return utxos
	
	def sign_psbt(self, serialized_psbt):
		""" 
		Sign PSBT. Currently assumes inputs are 
		ordered the same in unsigned tx and psbt. 
		For now, only SIGHASH_ALL is approved. 
		- If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
		- TODO If a witness UTXO is provided, no non-witness signature may be created
		- TODO If a redeemScript is provided, the scriptPubKey must be for that redeemScript
		- TODO If a witnessScript is provided, the scriptPubKey or the redeemScript must be for that witnessScript
		- TODO If a sighash type is provided, the signer must check that the sighash is acceptable. If unacceptable, they must fail.
		- If a sighash type is not provided, the signer signs using SIGHASH_ALL
		"""
		psbt_si = Signer(serialized_psbt)
		tx_obj = Tx.parse(BytesIO(psbt_si.get_unsigned_tx()))
		for i in range(len(psbt_si.psbt.maps["inputs"])):
			curr_input = psbt_si.psbt.maps["inputs"][i]
			# check prev_tx_id
			if IN_NON_WITNESS_UTXO in curr_input:
				psbt_tx_id = hash256(curr_input[IN_NON_WITNESS_UTXO])
				gutx_tx_id = tx_obj.tx_ins[i].prev_tx
				if psbt_tx_id != gutx_tx_id:
					raise PSBTError(f"UTXO {i} and Unsigned TX input {i} have different prev_tx_id: {psbt_tx_id} vs {gutx_tx_id}")
			# TODO SegWit
			elif IN_WITNESS_UTXO in curr_input:
				pass
			# TODO Handle RedeemScripts
			#  Look for redeemScripts
			if IN_REDEEM_SCRIPT in curr_input:
				raise NotImplementedError("Redeem Scripts not signable Yet. Unknown how to find ScriptPubKey")
			# read sighash
			sighash_type = psbt_si.get_sighash_type(i)
			if sighash_type is None:
				sighash_type = SIGHASH_ALL
			elif sighash_type != SIGHASH_ALL:
				raise NotImplementedError("Other sighash types not yet supported.")
			# sign
			pubkey_sec, fingerprint, path = psbt_si.get_bip32_info(i)
			if fingerprint.hex() == self.master_fingerprint():
				privkey = self.derive_key(path, priv=True, absolute=True).to_priv_key()
				if privkey.point.sec() == pubkey_sec:
					script_sig = tx_obj.sign_input(i, privkey, sighash_type)
					if not script_sig:
						raise SignatureError(f"Signing of input {i} failed.")
					sig = script_sig.cmds[0]
					psbt_si.add_partial_sig(sig, pubkey_sec, i)
				else:
					raise PSBTWarning(f"Private Key does not match pubkey provided. Skipping input {i}...")
			else:
				raise PSBTWarning(f"Fingerprint does not match this wallet. Skipping input {i}...")
		return psbt_si.serialize()

	@staticmethod
	def finalize_psbt(serialized_psbt):
		return Finalizer(serialized_psbt)

	@staticmethod
	def extract_psbt(serialized_psbt):
		return Extractor(serialized_psbt)

	def quick_sign(self, serialized_psbt):
		return self.extract_psbt(self.finalize_psbt(self.sign_psbt(serialized_psbt)))

	@staticmethod
	def broadcast(tx_bytes):
		tx_obj = Tx.parse(BytesIO(tx_bytes))
		if tx_obj.verify():
			post_transaction(tx_obj.serialize().hex())
		else:
			raise TransactionError("Invalid Transaction.")

	def create_p2sh(self, address, amount, fee, priority="oldest", data=None):
		raise NotImplementedError("coming soon")

#----- SQL FUNCTIONS -----
#
#-------------------------
	def get_balance(self):
		unspent_scripts = self.sql_find_unspent_scripts()
		return sum([s.amount for s in unspent_scripts])

	def sql_add_script_pubkey(self, hd_script_pubkey):
		self.walletdb.add_script(hd_script_pubkey)

	def sql_add_utxo(self, utxo):
		self.walletdb.add_utxo(utxo)

	def sql_get_all_utxos(self):
		pass #TODO

	def rescan_scripts(self):
		scripts = self.walletdb.get_all_scripts()
		for s in scripts:
			script_id = s[0]
			script = Script.parse(BytesIO(bytes.fromhex(s[1])))
			addr = script.to_address(testnet=self.testnet)
			utxos = get_address_utxo(addr, testnet=self.testnet)
			for u in utxos:
				self.sql_add_utxo(UTXO(u.tx_id, u.vout, u.amount, script_id, u.block_height, u.status))

	def sql_find_unspent_scripts(self):
		scripts = self.walletdb.get_all_scripts()
		unspent_scripts = []
		for s in scripts:
			script_id = s[0]
			script = Script.parse(BytesIO(bytes.fromhex(s[1])))
			addr = script.to_address(testnet=self.testnet)
			utxos = get_address_utxo(addr, testnet=self.testnet)
			for u in utxos:
				self.sql_add_utxo(UTXO(u.tx_id, u.vout, u.amount, script_id, u.block_height, u.status))
				if u.amount > 0 and u.status not in ["spent", "unconfirmed"]:
					amt = sum([u.amount for u in utxos])
					hdspk = HDScriptPubKey(script, s[2], s[3], script_id=script_id, amount=amt)
					unspent_scripts.append(hdspk)
					break
		return unspent_scripts

	def sql_get_utxos_by_script_ids(self, script_ids, order="DESC"):
		utxos = self.walletdb.get_utxos_by_script_ids(script_ids, order=order)
		return [UTXO(txid=u[0], vout=u[1], amount=u[2], block_height=u[3], status=u[4], script_id=u[5]) for u in utxos]

	def sql_find_unspent_utxos(self):
		pass

	def sql_get_script_name_from_utxo(self, txid, vout):
		"""
		outpoint: (txid, vout)
		"""
		return self.walletdb.get_script_name_from_utxo(txid, vout)

	def sql_get_script_from_utxo(self, txid, vout):
		"""
		outpoint: (txid, vout)
		"""
		s = self.walletdb.get_script_from_utxo(txid, vout)
		script_pubkey = Script.parse(BytesIO(bytes.fromhex(s[1])))
		return HDScriptPubKey(script_pubkey, s[2], s[3])


#----- FILE FUNCTIONS -----
#
#--------------------------

	def to_json(self):
		perm = "watch" if self.watch_only else "total"
		netw = "test" if self.testnet else "main"
		d = {
			"FINGERPRINT": self.fingerprint().hex(),
			"ACCT_XPUB": self.acct_xpub.__repr__(),
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
			
			hdpubkey = HDPubKey.parse(hpk)
			hdpubkeys.append(hdpubkey) 
			#decide if external or internal key
			if w.acct_path in path:#FIX 
				path = path[len(w.acct_path)]
				path = path.replace(w.acct_path, '')
				if path[0] == "0":
					ext_count += 1
				elif path[0] == "1":
					int_count += 1
				else:
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
		from encrypt import (
			encrypt,
			decrypt
		)
		if filename is None:
			filename = f"{self.name}.dat"
		if self.seed is not None:
			l = len(self.seed.bits) 
			bits = self.seed.bits[:-(l//33)] #take off checksum
			seed_bytes = SEED_PREFIX
			seed_bytes += int(bits, 2).to_bytes(len(bits)//8, 'big')
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
		from encrypt import (
			encrypt,
			decrypt
		)
		with open(f"{filename}.dat", "rb") as fp:
			fOut = fp.read()
		secret = decrypt(fOut, password)
		if secret[:4] == SEED_PREFIX:
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

	def dump_to_text_file(self, filename="dump.txt"):
		with open(filename, "w") as fp:
			mnemonic = " ".join(s.mnemonic())
			fp.write(mnemonic)
			fp.write("\n")
			fp.write(w.master_xprv.__repr__())

if __name__ == "__main__":
	vprv = ExtendedPrivateKey.parse("vprv9DMUxX4ShgxMMgFg47GgyXn6c7RJfHDuGaq7p6xpUrpnwZSd5pYkcpiFXhBpbkPaPT8d3761jfK15mhxa7a1EzAqvECGNS9p9zZwmcBFpd2")
	w = Wallet(data=vprv, passphrase="password1")
	addr = Address("tb1q3flmxda7pnc0dpae6upqht5ru4l7u97l36jvxl") # to me
	addr2 = Address("tb1qrk0tyy2met20gcpfxg835ldqvckpam5s4p0nj6") # to david
	amt = 50000
	amt2 = 48000
	w.new_address()
	w.new_address()
	w.new_address()
	print(w.get_balance())
	tx_out = (amt, Wallet.address_to_script_pubkey(addr))
	tx_out2 = (amt2, Wallet.address_to_script_pubkey(addr2))
	tx = w.create_unfunded_transaction([tx_out, tx_out2])
	psbt_ser = w.fund_transaction(tx)



