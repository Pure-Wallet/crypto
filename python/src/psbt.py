from enum import IntEnum
from io import BytesIO
from base64 import (
	b64encode,
	b64decode
)
from tx import (
	Tx,
	TxIn,
	TxOut,
	TransactionError
)
from ecc import ()
	PrivateKey, 
	S256Point
)
from helper import (
	encode_varint,
	read_varint
)



MAGIC = b"\x70\x73\x62\x74" # "psbt"
HEAD_SEPARATOR = b"\xff"
DATA_SEPARATOR = b'\x00'

GLOBAL_UNSIGNED_TX = b"\x00"
GLOBAL_XPUB = b"\x01"
GLOBAL_VERSION = b"\xFB"

IN_NON_WITNESS_UTXO = b"\x00"
IN_WITNESS_UTXO =  b"\x01"
IN_PARTIAL_SIG = b"\x02"
IN_SIGHASH_TYPE = b"\x03"
IN_REDEEM_SCRIPT = b"\x04"
IN_WITNESS_SCRIPT = b"\x05"
IN_BIP32_DERIVATION = b"\x06"
IN_FINAL_SCRIPT_SIG = b"\x07"
IN_FINAL_SCRIPTWITNESS = b"\x08"

OUT_REDEEM_SCRIPT = b"\x00"
OUT_WITNESS_SCRIPT =  b"\x01"
OUT_BIP32_DERIVATION = b"\x02"

class PSBTError(Exception):
	pass

class PSBT:
	"""
	class for constructing, signing, and handling PSBTs as defined in BIP0174. 
	{0x70736274}|{0xff}|{global key-value map}|{input key-value map}|...|
	{input key-value map}|{output key-value map}|...|{output key-value map}|
	
	This class is mostly taken from Jason Les (@heyitscheet) from 
	https://github.com/Jason-Les/python-psbt/blob/88ec7b0f9f5fbc6f665a9fbeae9ecb01db7d2f58/psbt.py#L67
	"""
	def __init__(self, maps=None):
		if maps is None:
			self.maps = {
				"global":{},
				"inputs":[],
				"outputs":[]
			}
		else:
			self.maps = maps

	def __repr__(self):
		result = ""
		for g in sorted(self.maps["global"].keys()):
			result += f"{g.hex()}:{self.maps["global"][g].hex()} "
		result += DATA_SEPARATOR.hex() + " "
		for i in self.maps["inputs"]:
			for k in sorted(i):
				result += f"{k.hex()}:{i[k].hex()} "
			result += DATA_SEPARATOR.hex() + " "
		for o in self.maps["outputs"]:
			for k in sorted(o):
				result += f"{k.hex()}:{o[k].hex()} "
			result += DATA_SEPARATOR.hex() + " "
		return result
# ----- SERIALIZATION -----
#
# -------------------------



	def serialize_pair(self, key, value):
		kv_bytes = encode_varint(len(key)) + key
		kv_bytes += encode_varint(len(value)) + value
		return kv_bytes

	def parse_pair(self, stream):
		key_length = read_varint(stream)
		if key_length == 0: #separator
			return None, None
		key = stream.read(key_length)
		val_length = read_varint(stream)
		value = stream.read(val_length)
		return key, value

	def serialize(self):
		result = MAGIC + HEAD_SEPARATOR
		# Serialize each global pair
		for g in sorted(self.maps["global"].keys()):
			result += serialize_pair(key=g, value=self.maps["global"][g])
		result += DATA_SEPARATOR
		# Serialize each input
		for i in self.maps["inputs"]:
			for k in sorted(i):
				result += serialize_pair(key=k, value=i[k])
			result += DATA_SEPARATOR
		# Serialize each output
		for o in self.maps:
			for k in sorted(o):
				result += serialize_pair(key=k, value=o[k])
			result += DATA_SEPARATOR
		return result

	@classmethod
	def parse(cls, stream):
		if stream.read(4) != MAGIC:
			raise PSBTError("Invalid PSBT: MAGIC")
		if stream.read(1) != HEAD_SEPARATOR:
			raise PSBTError("Invalid PSBT: Head Separator '0xff' missing")

		new_map = {
			"global":{},
			"inputs":[],
			"outputs":[]
		}
		expect_global = True
		in_count = 0
		out_count = 0

		while expect_global or in_count or out_count:
			try:
				new_key, new_val = self.parse_pair(stream)
			except IndexError:
				raise PSBTError("Parsing Error")
			if expect_global:
				# separator 0x00 reached. End of Globals
				if new_key is None:
					expect_global = False
					continue

				new_map["global"][new_key] = new_value
				if new_key == GLOBAL_UNSIGNED_TX:
					unsigned_tx = Tx.parse(BytesIO(new_val))
					in_count = len(unsigned_tx.tx_ins)
					out_count = len(unsigned_tx.tx_outs)
					# create correct number of empty inputs and outputs
					[new_map["inputs"].append({}) for _ in range(in_count)]
					[new_map["outputs"].append({}) for _ in range(out_count)]
			elif in_count:
				# separator means end of input
				if new_key is None:
					in_count -= 1
					continue
				current = abs(len(new_map["inputs"]) - in_count)
				new_map["inputs"][current][new_key] = new_val

				
			elif out_count:
				if new_key is None:
					out_count -= 1
					continue
				current = abs(len(new_map["outputs"]) - out_count)
				new_map["outputs"][current][new_key] = new_val
		return cls(maps=new_map)

	@classmethod
	def parse_b64(cls, b64):
		return PSBT.parse(BytesIO(b64decode(b64)))

	def b64encode(self):
		""" returns string base64 encoding of psbt """
		return b64encode(self.serialie()).decode("utf-8")

# ----- INPUTS -----
#
# ------------------
	def add_input(self):
		pass

# ------ OUTPUTS ------
#
# ---------------------
	def add_redeem_script(self, redeem_script):
		 return PSBTOutput.REDEEM_SCRIPT + redeem_script
		

	def add_bip32_derivation(self, pubkey, fingerprint, path):

