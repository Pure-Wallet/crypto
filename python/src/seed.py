
import random
from secrets import token_bytes
import os
from hashlib import (
	sha256, 
	sha512, 
	pbkdf2_hmac
)
import hmac
from ecc import (
	PrivateKey,
	S256Point,
	N, 
	G, 
	P
)
import unicodedata
from helper import (
	encode_base58,
	a2b_base58,
	hash256,
	hash160
)

"""
Disclaimer: 

Credit: Parts of the Seed class are derived from Trezor's reference 
implementation, linked from bip 0039. Link: https://github.com/trezor/python-mnemonic/blob/master/mnemonic/mnemonic.py
Functions taken from here will be noted with 'taken from Trezor Ref-Implementation'

mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
"""
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

PREFIXES = {
	XPRV_PFX: XPUB_PFX,
	TPRV_PFX: TPRV_PFX,
	YPRV_PFX: YPUB_PFX,
	UPRV_PFX: UPUB_PFX,
	ZPRV_PFX: ZPUB_PFX,
	VPRV_PFX: VPUB_PFX
}


STRENGTHS = [128, 160, 192, 224, 256]
CS_STRENGTHS = [132, 165, 198, 233, 264]
SOFT_CAP = 2**31 #2**31 = range of unhardened keys
HARD_CAP = SOFT_CAP<<1 #2**32 = range of hardened keys
PBKDF2_ROUNDS = 2048
RADIX = 2048 # length of wordlist
# this message adapted from https://github.com/richardkiss/pycoin/blob/master/pycoin/key/bip32.py
INVALID_KEY_MSG = """
You have found an invalid key!! Please save this XPub, XPriv, and the i (the number of the child).
This data will help Bitcoin devs. If there are any coins in this wallet, move them before sharing
key info. 
e-mail "Richard Kiss" <him@richardkiss.com> or "Matt Bogosian" <mtb19@columbia.edu> for
instructions on how best to donate it without losing your bitcoins.

To continue and generate a valid key, simply increment i (the child_num). 

WARNING: DO NOT SEND ANY WALLET INFORMATION UNLESS YOU WANT TO LOSE ALL
THE BITCOINS IT CONTAINS.
""".strip()

class ConfigurationError(Exception):
	pass

def binary_search(nList, target, low=0, high=None):
	if high is None:
		 high = len(nList)
	if low > high:
		return -1
	pos = (low + high) // 2
	if nList[pos] > target:
		return binary_search(nList, target, low, pos-1)
	elif nList[pos] < target:
		return binary_search(nList, target, pos+1, high)
	else:
		return pos

def getRandom(length):
	return token_bytes(length//8)
	#return sha256(os.urandom(length)).digest()[:length//8]

# taken from Trezor Ref-Implementation
def get_directory():
    return os.path.join(os.path.dirname(__file__), "wordlist")

def main():
	s1 = Seed.new(128)
	xprv = s1.derive_master_priv_key()
	xpub = xprv.to_extended_pub_key()
	print("Seed:", s1)
	print("Mnemonic:", s1.mnemonic())
	print("xprv:", xprv)
	print("xpub:", xpub)
	print("other", encode_base58(b"\x78\x70\x72\x76"))

class Seed:
	""" 
	A class for storing bits of entropy of len [128, 160, 192, 224, 256] for processing
	into BIP32 Master Extended Private Keys and BIP39 Mnemonic Phrases. 
	Language defaults to English and Length defaults to 128 bits (12 words)
	"""
	def __init__(self, bits="", strength=0, lang="english"):
		if lang != "english":
			raise ConfigurationError(f"Language {lang} not implemented. Use English, Spanish, French, Japanese, Chinese, Korean, or Italian.")
		self.bits = bits
		self.check_sum()
		self.strength = strength if bits == "" else (len(bits) - len(bits)//33)
		#taken from Trezor Ref-Implementation
		with open(f"{get_directory()}/{lang}.txt", "r", encoding="utf-8") as f:
			self.wordlist = [w.strip() for w in f.readlines()]
		if len(self.wordlist) != RADIX:
			error = f"Wordlist should contain {RADIX} words, but it contains {len(self.wordlist)} words."
			raise ConfigurationError(error)

	def __repr__(self):
		if self.bits == "":
			return "Seed(null)"
		else:
			return f"Seed(\"{self.seed().hex()}\")"

	def set_entropy(self, entropy):
		""" takes entropy as hex string and converts to bits. """
		if self.bits != "":
			raise ConfigurationError("Bits cannot be altered once set. Create a new Seed object.")
		#if len(entropy) in [s//4 for s in STRENGTHS]:
		strength = len(entropy)*4
		checksumlen = strength//32
		entropy = bytes(bytearray.fromhex(entropy))
		chash = sha256(entropy).hexdigest()
		checksum = bin(int(chash, 16))[2:].zfill(256)[:checksumlen]
		entropy = bin(int.from_bytes(entropy, 'big'))[2:].zfill(strength) + checksum
		# elif len(entropy) in [s//4 for s in CS_STRENGTHS]:
		# 	pass
		# else:
		# 	raise ConfigurationError("Invalid Entropy Length")
		self.bits = entropy
		self.strength = strength

	def generate(self, strength=128):
		""" 
		Generates random entropy using the getRandom function. Sets self.bits to entropy
		and self.strength to strength. 		
		"""
		if self.strength != 0 and self.strength != strength:
				raise ConfigurationError(f"Strength already set to {self.strength}. Cannot be changed to {strength}.")
		if strength not in STRENGTHS:
				raise ConfigurationError(f"strength must be in {STRENGTHS}, not {strength}")
		checksumlen = strength//32
		rand = getRandom(strength)
		chash = sha256(rand).digest()
		checksum = bin(int.from_bytes(chash, 'big'))[2:].zfill(256)[:checksumlen]
		bits = bin(int.from_bytes(rand, 'big'))[2:].zfill(strength) + checksum
		self.bits = bits
		self.strength = strength

	@classmethod
	def new(cls, strength=128, lang="english"):
		"""
		classmethod for generating new Seed object with entropy from getRandom
		"""
		if strength not in STRENGTHS:
			raise ConfigurationError(f"Strength must be in {STRENGTHS}, not {strength}")
		checksumlen = strength//32
		rand = getRandom(strength)
		chash = sha256(rand).hexdigest()
		checksum = bin(int(chash, 16))[2:].zfill(256)[:checksumlen]
		bits = bin(int.from_bytes(rand, 'big'))[2:].zfill(strength) + checksum
		return cls(bits=bits, strength=strength, lang=lang)

	def mnemonic(self):
		"""
		returns list of seed phrase words of length [12, 15, 18, 21, 24] from entropy.
		If no entropy exists, Seed::generate is called to create new entropy.
		"""
		if self.bits == "":
			self.generate(128)
		mnemonic = []
		for i in range(0, len(self.bits), 11):
			idx = int(self.bits[i : i+11], 2)
			mnemonic.append((self.wordlist[idx]))
		return mnemonic
	
	@classmethod
	def from_mnemonic(cls, mnemonic, lang="english"):
		with open("%s/%s.txt" % (get_directory(), lang), "r", encoding="utf-8") as f:
			wordlist = [w.strip() for w in f.readlines()]
		if len(wordlist) != RADIX:
			error = f"Wordlist should contain {RADIX} words, but it contains {len(wordlist)} words."
			raise ConfigurationError(error)
		try:
			if lang == "english": # binary search only possible for english 
				bits = map(lambda m: bin(binary_search(wordlist, m))[2:].zfill(11), mnemonic)
				bits = "".join(bits)
			else:
				bits =  map(lambda m: bin(wordlist.index(m))[2:].zfill(11), mnemonic)
				bits = "".join(bits)
		except ValueError:
			raise ConfigurationError("Invalid Mnemonic Phrase.")
		strength = len(mnemonic)*11
		strength -= (strength//33) #remove chekcsum from strength
		return cls(bits=bits, strength=strength, lang=lang)

	@classmethod 
	def from_bits(cls, entropy, lang="english"):
		"""
		a Seed can be parsed from a from binary string of bits
		binary str -> entropy bits
		"""
		if pfx(entropy) == str:
			return cls(entropy, lang)
		else:
			raise ValueError("Seed::parse requires entropy bits as binary string")

	@classmethod
	def from_bytes(cls, data, lang="english"):
		"""
		Load a seed from bytes (including checksum)
		bytes -> bits
		"""
		checksumlen = len(data)//4
		chash = sha256(data).digest()
		checksum = bin(int.from_bytes(chash, 'big'))[2:].zfill(256)[:checksumlen]
		#print("seedlen2:",len(data))
		strength = len(data)*8
		#print("strength:",strength)
		bits = bin(int.from_bytes(data, 'big'))[2:].zfill(strength)
		bits += checksum
		return cls(bits, strength=strength, lang=lang)

	def check_sum(self):
		"""
		Checks checksum of entropy.
		"""
		if self.bits == "":
			raise ConfigurationError("No entropy bits. Nothing to check. Call generate() first.")
		l = len(self.bits)
		strength = l - (l//33)
		entropy = self.bits[:strength]
		checksum = self.bits[strength:]
		chash = sha256(int(entropy,2).to_bytes(l//8, 'big')).hexdigest()
		return checksum == bin(int(chash, 16))[2:].zfill(256)[:l//33]
		
	# taken from Trezor Ref-Implementation
	def seed(self, passphrase=""):
		"""
		returns bytes of seed, which is used to derive master XPriv key (Seed::derive_master_priv_key)
		"""
		m = " ".join(self.mnemonic())
		unicodedata.normalize("NFKD", m)
		p = unicodedata.normalize("NFKD", passphrase)
		p = "mnemonic" + p
		m = m.encode("utf-8")
		p = p.encode("utf-8")
		stretched = pbkdf2_hmac("sha512", m, p, PBKDF2_ROUNDS)
		return stretched[:64]

	def derive_master_priv_key(self, passphrase="", _pfx=XPRV_PFX):
		"""
		returns XPRIV key as defined in BIP39 from seed. 
		"""
		if self.bits == "":
			self.generate(strength=128)
		ii = hmac.new(b"Bitcoin seed", self.seed(passphrase), digestmod=sha512).digest()
		xprv = _pfx
		# 1 for depth, 4 for empty parent fingerprint, 4 for empty child number
		xprv += b"\x00" * 9
		# add chain code 32 bytes
		xprv += ii[32:]  
		# add master key 33 bytes
		xprv += b"\x00" + ii[:32]  
		# add checksum
		checksum = hash256(xprv)[:4] 
		xprv += checksum
		#return encode_base58_checksum(xprv)
		#print(len(xprv))
		return ExtendedPrivateKey(xprv)
		
	@classmethod
	def to_master_priv_key(cls, seed=None, strength=128, passphrase="", lang="english", _pfx=XPRV_PFX):
		"""
		classmethod for generating new seed and returning master xprv key. 
		Strength defaults to 128, and testnet defaults to False.
		Seed can also optionally be set to bytes to load master xprv from seed.
		"""
		if seed is None:
			seed = Seed.new(strength=strength, lang=lang).seed(passphrase)
		ii = hmac.new(b"Bitcoin seed", seed, digestmod=sha512).digest()
		xprv = _pfx
		# 1 for depth, 4 for empty parent fingerprint, 4 for empty child number
		xprv += b"\x00" * 9
		# add chain code 32 bytes
		xprv += ii[32:]  
		# add master key 33 bytes
		xprv += b"\x00" + ii[:32]
		# add checksum
		checksum = hash256(xprv)[:4] 
		xprv += checksum
		return ExtendedPrivateKey(xprv)

class ExtendedPrivateKey:
	"""
	Class for BIP32 Extended Private Keys (XPRVs). Capable of deriving hardened and normal children
	as well as Extended Public Keys (XPUBs). Parse XPRVs either from base58-encoded string or directly from 
	a seed using parse or from_seed respectively.
	Both XPRVs and XPUBS can be used in a Wallet object.
	"""
	def __init__(self, xprv):
		self.pfx = xprv[:4]
		self.depth = xprv[4:5]
		self.parent = xprv[5:9]
		self.child_num = xprv[9:13]
		self.chaincode = xprv[13:45]
		self.key = xprv[45:-4]
		self.checksum = xprv[-4:]
		
		if not self.check_sum():
			raise ConfigurationError("Invalid Checksum for ExtendedPrivKey")

	def __repr__(self):
		return encode_base58(self.serialize())

	def serialize(self):
		return self.pfx + self.depth + self.parent + self.child_num + self.chaincode + self.key + self.checksum

	def to_priv_key(self):
		return PrivateKey(int.from_bytes(self.key, 'big'))

	def to_pub_key(self):
		return self.to_priv_key().point

	def to_extended_pub_key(self):
		_pfx = PREFIXES[self.pfx]
		xpub = _pfx
		xpub += self.depth
		xpub += self.parent
		xpub += self.child_num
		xpub += self.chaincode
		xpub += self.to_pub_key().sec()
		checksum = hash256(xpub)[:4]
		xpub += checksum
		return ExtendedPublicKey(xpub)

	def derive_priv_child(self, i):
		if i >= HARD_CAP:
			return ValueError("Chosen i is not in range [0, 2**32-1]")
		if i >= SOFT_CAP: # hardened
			ii = hmac.new(self.chaincode, self.key + i.to_bytes(4, 'big'), digestmod=sha512).digest()
		else: #unhardened
			ii = hmac.new(self.chaincode, self.to_priv_key().point.sec() + i.to_bytes(4, 'big'), digestmod=sha512).digest()

		key = (int.from_bytes(ii[:32], 'big') + int.from_bytes(self.key, 'big'))%N # from ecc.py
		fingerprint = hash160(self.to_pub_key().sec())[:4]
		child_xprv = self.pfx
		child_xprv += (self.depth[0] + 1).to_bytes(1, 'big')
		child_xprv += fingerprint
		child_xprv += i.to_bytes(4, 'big')
		# add chaincode 
		child_xprv += ii[32:]
		# add key
		child_xprv += b"\x00" + key.to_bytes(32 , 'big')
		checksum = hash256(child_xprv)[:4] 
		child_xprv += checksum
		return self.__class__(child_xprv)

	def derive_pub_child(self, i):
		if i >= HARD_CAP:
			return ValueError("Chosen i is not in range [0, 2**32-1]")
		return self.derive_priv_child(i).to_extended_pub_key()

	def check_sum(self):
		xprv = self.serialize()[:-4]
		if self.checksum != hash256(xprv)[:4]:
			return False
		return True

	def to_bytes(self):
		return self.serialize()

	@classmethod
	def from_seed(cls, seed, passphrase=""):
		return Seed.to_master_priv_key(seed=seed, passphrase=passphrase)

	@classmethod
	def parse(cls, xprv): # from xprv string
		return cls(a2b_base58(xprv))

	def get_pfx(self):
		return self.pfx

class ExtendedPublicKey:
	"""
	Class for BIP32 Extended Public Keys (XPRVs). Capable of deriving unhardened  children.
	Parse XPUBs either from base58-encoded string or directly from 
	a seed using parse or from_seed respectively. 
	Load an XPUB into a Wallet object to create a watch-only wallet.
	"""
	def __init__(self, xpub):
		self.pfx = xpub[:4]
		self.depth = xpub[4:5]
		self.parent = xpub[5:9]
		self.child_num = xpub[9:13]
		self.chaincode = xpub[13:45]
		self.key = xpub[45:-4]
		self.checksum = xpub[-4:]
		if not self.check_sum():
			raise ConfigurationError("Invalid Checksum for ExtendedPrivKey")
		try: #TODO use assert
			point = S256Point.parse(self.key)
		except ValueError:
			raise ConfigurationError("Point is not on the curve, invalid key.")
			
	def __repr__(self):
		return encode_base58(self.serialize())

	def serialize(self):
		return self.pfx + self.depth + self.parent + self.child_num + self.chaincode + self.key + self.checksum

	def check_sum(self):
		xpub = self.serialize()[:-4]
		if self.checksum != hash256(xpub)[:4]:
			return False
		return True
		
	def to_pub_key(self):
		return S256Point.parse(self.key)

	def derive_pub_child(self, i):
		if i >= HARD_CAP:
			return ValueError("Chosen i is not in range [0, 2**32-1]")
		# Not quite sure if this is true
		# if int.from_bytes(self.child_num, 'big') >= SOFT_CAP:
		# 	raise TypeError("Hardened Public Keys cannot derive child keys. Use Extended Private key.")
		if i >= SOFT_CAP:
			raise TypeError("Hardened Keys cannot be be derived from Extended Pub Keys. Use Extended Private key.")
		else:
			ii = hmac.new(self.chaincode, self.key + i.to_bytes(4, 'big'), digestmod=sha512).digest()
		fingerprint = hash160(self.key)[:4]
		# edge case: invalid keys
		key_num = int.from_bytes(ii[:32], 'big')
		point = key_num * G
		if key_num >= N or point.x is None:
			raise ValueError(INVALID_KEY_MSG)
		child_key = point + S256Point.parse(self.key)
		child_chaincode = ii[32:]
		#assemble new xpub
		child_xpub = self.pfx
		child_xpub += (self.depth[0] + 1).to_bytes(1, 'big')
		child_xpub += fingerprint
		child_xpub += i.to_bytes(4, 'big')
		child_xpub += child_chaincode
		child_xpub += child_key.sec()
		checksum = hash256(child_xpub)[:4]
		child_xpub += checksum
		return self.__class__(child_xpub)

	@classmethod
	def parse(cls, xpub): # from xpub string
		return cls(a2b_base58(xpub))

	@classmethod
	def from_seed(cls, seed):
		return ExtendedPrivateKey.from_seed(seed=seed).to_extended_pub_key()

	def get_pfx(self):
		return encode_base58(self.pfx)



def test_bip49():
	seed_words = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
	c_master_seed = "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd"
	# Account 0, root = m/49'/1'/0'
	c_account0Xpriv = "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n"
	c_account0Xpub = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"
	# Account 0, first receiving private key = m/49'/1'/0'/0/0
	c_account0recvPrivateKey = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ"
	c_account0recvPrivateKeyHex = "c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8"
	c_account0recvPublickKeyHex = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"

	seed = Seed.from_mnemonic(seed_words)
	master_seed = seed.derive_master_priv_key(_pfx=UPRV_PFX)
	if master_seed.__repr__() != c_master_seed: # Check Seed derivation
		print(master_seed)
		print(c_master_seed)
	purp49xprv = master_seed.derive_priv_child(SOFT_CAP + 49)
	acct0xprv = purp49xprv.derive_priv_child(SOFT_CAP + 1).derive_priv_child(SOFT_CAP)
	if acct0xprv.__repr__() != c_account0Xpriv: # Check Acct XPRV
		print(acct0xprv)
		print(c_account0Xpriv)
	acct0xpub = acct0xprv.to_extended_pub_key()
	if acct0xpub.__repr__() != c_account0Xpub: # Check Acct Xpub
		print(acct0xpub)
		print(c_account0Xpub)
	acct0recvPrivKey = acct0xprv.derive_priv_child(0).derive_priv_child(0).to_priv_key()
	if acct0recvPrivKey.__repr__() != c_account0recvPrivateKeyHex:
		print(acct0recvPrivKey)
		print(c_account0recvPrivateKey)
	if acct0recvPrivKey.wif(testnet=True) != c_account0recvPrivateKey:
		print(acct0recvPrivKey.wif())
		print(c_account0recvPrivateKey)
	acct0recvPubKey = acct0recvPrivKey.point
	if acct0recvPubKey.sec().hex() != c_account0recvPublickKeyHex:
		print(acct0recvPubKey.sec().hex())
		print(c_account0recvPublickKeyHex)

def test_bip84():
	mnemonic = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
	c_rootpriv = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
	c_rootpub  = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"	
	# Account 0, root = m/84'/0'/0'
	c_xpriv = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
	c_xpub  = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"	
	# Account 0, first receiving address = m/84'/0'/0'/0/0
	c_privkey = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"
	c_pubkey  = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
	c_address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	
	seed = Seed.from_mnemonic(mnemonic)
	master_key = seed.derive_master_priv_key(_pfx=ZPRV_PFX)
	if master_key.__repr__() != c_rootpriv:
		print(master_key.__repr__())
		print(c_rootpriv)
	master_pub = master_key.to_extended_pub_key()
	if master_pub.__repr__() != c_rootpub:
		print(master_pub.__repr__())
		print(c_rootpub)
	purp84xprv = master_key.derive_priv_child(SOFT_CAP + 84)
	acct0xprv = purp84xprv.derive_priv_child(SOFT_CAP).derive_priv_child(SOFT_CAP)
	if acct0xprv.__repr__() != c_xpriv:
		print(acct0xprv.__repr__())
		print(c_xpriv)
	acct0xpub = acct0xprv.to_extended_pub_key()
	if acct0xpub.__repr__() != c_xpub:
		print(acct0xpub.__repr__())
		print(c_xpub)
	acct0recvPrivKey = acct0xprv.derive_priv_child(0).derive_priv_child(0).to_priv_key()
	if acct0recvPrivKey.wif() != c_privkey:
		print(acct0recvPrivKey.__repr__())
		print(c_privkey)
	acct0recvPubKey = acct0recvPrivKey.point
	if acct0recvPubKey.sec().hex() != c_pubkey:
		print(acct0recvPubKey.sec().hex())
		print(c_pubkey)

if __name__ == "__main__":
	# test_bip49()
	# test_bip84()
	# main()
	#xpub = ExtendedPublicKey.parse()
	pass