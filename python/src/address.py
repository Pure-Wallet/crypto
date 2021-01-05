from bech32 import (
	bech32_address_decode,
	Bech32Error
)
from helper import (
	decode_base58
)



P2SH_MAIN_PREFIX = b'\x05'
P2SH_TEST_PREFIX = b'\xcf'
P2PKH_MAIN_PREFIX = b'\x00'
P2PKH_TEST_PREFIX = b'\x6f'

SW_MAIN_HRP = "bc"
SW_TEST_HRP = "tb"
LEGACY_TEST_PREFIX = ["m", "n", "2"]
LEGACY_MAIN_PREFIX = ["1", "3"]


class AddressError(ValueError):
	pass

class Address:
	def __init__(self, addr):
		self.addr = addr
		if addr[:2] in [SW_MAIN_HRP] or addr[0] in LEGACY_MAIN_PREFIX:
			self.testnet=False
		elif addr[:2] in [SW_TEST_HRP] or addr[0] in LEGACY_TEST_PREFIX:
			self.testnet=True
		else:
			raise AddressError("Invalid Address Prefix.")

	def __repr__(self):
		return self.addr
		
	@classmethod
	def from_script_pubkey(cls, script_pubkey, testnet=False):
		return script_pubkey.to_address(testnet)

	@classmethod
	def from_pubkey(cls, pubkey, script_type, testnet=False):
		raise NotImplementedError