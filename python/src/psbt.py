from enum import IntEnum
from io import BytesIO
from base64 import (
	b64encode,
	b64decode
)
from script import Script
from op import (
	OP_CODE_FUNCTIONS,
	OP_CODE_NAMES
)
from tx import (
	Tx,
	TxIn,
	TxOut,
	TransactionError
)
from ecc import (
	PrivateKey, 
	S256Point
)
from helper import (
	encode_varint,
	read_varint,
	int_to_little,
	little_to_int,
	hash256
)




MAGIC = b"\x70\x73\x62\x74" # "psbt"
HEAD_SEPARATOR = b"\xff"
DATA_SEPARATOR = b"\x00"

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
class PSBTWarning(Warning):
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
			result += f'{g.hex()}:{self.maps["global"][g].hex()}'
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

	def __str__(self):
		# String version of psbt (in hex) for debugging
		result = ('Globals\n===========\n')
		for g in sorted(self.maps['global'].keys()):
			result += '\t{} : {}\n'.format(g.hex(), self.maps['global'][g].hex())
		result += 'Inputs\n===========\n'  
		for i in self.maps['inputs']:
			for k in sorted(i):
				result += ('\t{} : {}\n'.format(k.hex(), i[k].hex()))
		result += 'Outputs\n===========\n'         
		for o in self.maps['outputs']:
			for k in sorted(o):
				result += '\t{} : {}\n'.format(k.hex(), o[k].hex())   
		return result
# ----- SERIALIZATION -----
#
# -------------------------


	@staticmethod
	def serialize_pair(key, value):
		kv_bytes = encode_varint(len(key)) + key
		kv_bytes += encode_varint(len(value)) + value
		return kv_bytes

	@staticmethod
	def parse_pair(stream):
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
			result += self.serialize_pair(key=g, value=self.maps["global"][g])
		result += DATA_SEPARATOR
		# Serialize each input
		for i in self.maps["inputs"]:
			for k in sorted(i):
				result += self.serialize_pair(key=k, value=i[k])
			result += DATA_SEPARATOR
		# Serialize each output
		for o in self.maps["outputs"]:
			for k in sorted(o):
				result += self.serialize_pair(key=k, value=o[k])
			result += DATA_SEPARATOR
		return result

	@classmethod
	def parse(cls, stream):
		if stream.read(4) != MAGIC:
			raise PSBTError("Invalid PSBT: MAGIC")
		if stream.read(1) != HEAD_SEPARATOR:
			raise PSBTError("Invalid PSBT: Head Separator 0xff missing")

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
				new_key, new_val = cls.parse_pair(stream)
			except IndexError:
				raise PSBTError("Parsing Error")
			if expect_global:
				# separator 0x00 reached. End of Globals
				if new_key is None:
					expect_global = False
					continue

				new_map["global"][new_key] = new_val
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
		return b64encode(self.serialize()).decode("utf-8")

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
		pass

class PSBT_Role:
	""" Class for PSBT Roles of Creator, Updater, SIgner, Finalizer """
	def __init__(self, serialized_psbt):
		self.psbt=psbt.parse(BytesIO(serialized_psbt))

	def serialize(self):
		return self.psbt.serialize()

	def make_file(self, filename=None):
		ext = "psbt"
		if filename is None:
			filename = hash256(self.psbt.maps["global"][GLOBAL_UNSIGNED_TX]).hex()[:8] + \
            "-{}-".format(self.role) + hash256(self.serialized()).hex()[-8:]
		with open("{}.{}".format(filename, ext), "wb") as fp:
			fp.write(self.serialize())
		return

	def _get_input_index(self, pubkey):
		count = 0
		for i in self.psbt.maps["inputs"]:
			if (IN_BIP32_DERIVATION+pubkey) in i:
				return count
			count += 1
		return None

	def _is_non_witness_input(self, an_input):
		for k in an_input.keys():
			if k[:1] == IN_NON_WITNESS_UTXO:
				return True
		return False

	def _is_witness_input(self, an_input):
		for k in an_input.keys():
			if k[:1] == IN_WITNESS_UTXO:
				return True
		return False

	def get_unsigned_tx(self):
		return self.psbt.maps["global"][GLOBAL_UNSIGNED_TX]

	def get_utxo(self, input_idx):
		return self.psbt.maps["inputs"][input_index].get(IN_NON_WITNESS_UTXO, 
            self.psbt.maps["inputs"][input_index].get(IN_WITNESS_UTXO))

	def get_output_redeem_script(self, output_index):
		try:
			return self.psbt.maps["outputs"][output_index][OUT_REDEEM_SCRIPT]
		except KeyError:
			raise PSBTError("Either this output index is out of bounds or there is no redeemScript for it")
        
	def get_output_witness_script(self, output_index):
		try:
			return self.psbt.maps["outputs"][output_index][OUT_WITNESS_SCRIPT]
		except KeyError:
			raise PSBTError("Either this output index is out of bounds or there is no witnessScript for it")
        
	def _find_psbt_input(self, prev_tx):
		for idx, inp in enumerate(self.psbt.maps["inputs"]):
			if IN_NON_WITNESS_UTXO in inp:
				if prev_tx == hash256(inp[IN_NON_WITNESS_UTXO])[::-1]:
					return idx
			elif IN_WITNESS_UTXO in i:
				return None
			else:
				#MAYBE RAISE ERROR
				return None

	

class Creator(PSBT_Role):
	def __init__(self, inputs, outputs, version=1, input_sequence=0xffffffff, locktime=0):
		self.role = "Creator"
		self.inputs = []
		self.outputs = []
		for i in inputs:
			self.inputs.append(TxIn(prev_tx=i[0], prev_index=i[1], script_sig=b"", sequence=input_sequence))
		for o in outputs:
			self.outputs.append(TxOut(amount=o[0], script_pubkey=o[1]))
		self.tx_obj = Tx(version=version, tx_ins=self.inputs, tx_outs=self.outputs, locktime=locktime)
		serialized_tx = self.tx_obj.serialize()
		ser_psbt = MAGIC + HEAD_SEPARATOR + self.serialize_pair(key=GLOBAL_UNSIGNED_TX, value=serialized_tx)
		ser_psbt += DATA_SEPARATOR + (DATA_SEPARATOR*len(self.inputs)) + (DATA_SEPARATOR*len(self.outputs))
		self.psbt = PSBT.parse(BytesIO(ser_psbt))

	def get_utxo(self, input_index):
		raise PSBTError("Function out of scope for this role")

	def _get_input_index(self, pubkey):
		raise PSBTError("Function out of scope for this role")

	def _is_witness_input(self, an_input):
		raise PSBTError("Function out of scope for this role")

	def get_output_redeem_script(self, output_index):
		raise PSBTError("Function out of scope for this role")
	
	def get_output_witness_script(self, output_index):
		raise PSBTError("Function out of scope for this role")

class Updater(PSBT_Role):
	def __init__(self, serialized_psbt):
		super().__init__(serialized_psbt)
		self.role = "Updater"

#INPUTS
	def add_nonwitness_utxo(self, idx, tx):
		''''utxo in raw bytes'''
		self.psbt.maps["inputs"][idx][IN_NON_WITNESS_UTXO] = tx

	def add_witness_utxo(self, idx, tx, vout):
		tx_obj = Tx.parse(BytesIO(utxo))
		value = tx_obj.tx_outs[vout].serialize()
		self.psbt.maps["inputs"][idx][IN_WITNESS_UTXO] = utxo

	def add_sighash_type(self, idx, sighash):
		self.psbt.maps["inputs"][idx][IN_SIGHASH_TYPE] = int_to_little(n=sighash, length=4)


	def add_input_redeem_script(self, idx, script):
		self.psbt.maps["inputs"][idx][IN_REDEEM_SCRIPT] = script

	def add_input_witness_script(self, idx, script):
		self.psbt.maps["inputs"][idx][IN_WITNESS_SCRIPT] = script  

	def add_input_pubkey(self, idx, pubkey, fingerprint, path):
		self.psbt.maps["inputs"][idx][IN_BIP32_DERIVATION+pubkey] = fingerprint+path

# OUTPUTS
	def add_output_redeem_script(self, idx, script):
		self.psbt.maps["outputs"][idx][OUT_REDEEM_SCRIPT] = script

	def add_output_witness_script(self, idx, script):
		self.psbt.maps["outputs"][idx][OUT_WITNESS_SCRIPT] = script

	def add_output_pubkey(self, idx, pubkey, fingerprint, path):
		self.psbt.maps["outputs"][idx][OUT_BIP32_DERIVATION+pubkey] = fingerprint+path

class Signer(PSBT_Role):
	def __init__(self, serialized_psbt):
		self.role = "Signer"
		self.psbt = PSBT.parse(BytesIO(serialized_psbt))
		for i in range(len(self.psbt.maps["inputs"])):
			if self.get_utxo(i) is None:
				raise PSBTError("Not all inputs have UTXOs filled in.")

	def get_input_pubkey(self, idx):
		return self.psbt.maps["inputs"][idx][IN_BIP32_DERIVATION][1:]

	def get_bip32_path(self, idx, pubkey): # !!! CONFUSION?? HOW TO USE
		return self.psbt.maps["inputs"][idx][IN_BIP32_DERIVATION+pubkey]

	def get_sighash_type(self, idx):
		found = self.psbt.maps["inputs"][idx].get(IN_SIGHASH_TYPE)
		if found is None:
			raise PSBTWarning(f"No SIGHASH key for input {idx}")
			return None
		else:
			return little_to_int(found)

	def check_sighash(self, idx, sighash):
		return sighash == self.get_sighash_type(idx)

	def add_partial_sig(self, new_sig, pubkey, idx=None):
		if idx is None:
			idx = self._get_input_index(pubkey)
		# Note: Assumes that the sighash type is only the last byte of sig. 
		# Note: Assumes inputs in psbt and indexed the same as in unsigned tx
		this_sighash = little_to_int(new_sig[-1:])
		if idx is not None:
			if not self.check_sighash(idx=idx, sighash=this_sighash):
				raise PSBTError(f"Sighash type {this_sighash} on Signature does not match specified Sighash ({self.get_sighash_type(idx)}) for this input.")
			curr_input = self.psbt.maps["inputs"][idx]
			if IN_NON_WITNESS_UTXO in curr_input:
				global_txid = Tx.parse(BytesIO(self.psbt.maps["global"][GLOBAL_UNSIGNED_TX])).tx_ins[idx].prev_tx
				curr_txid = hash256(curr_input[IN_NON_WITNESS_UTXO])[::-1]
				if global_txid != curr_txid:
					raise PSBTError("UTXO of this input does not match the UTXO specified in global unsigned Tx")
			elif IN_WITNESS_UTXO in curr_input:
				raise NotImplementedError("SegWit Not yet implemented.")

			self.psbt.maps["inputs"][idx][IN_PARTIAL_SIG+pubkey] = new_sig
		else:
			raise PSBTError("Signature cannot be added. The Pubkey provided is not avaialbe in this PSBT")
		return

	def get_output_pubkey(self, idx):
		return self.psbt.maps["outputs"][idx][IN_BIP32_DERIVATION][1:]

class Combiner(PSBT_Role):
	def __init__(self, *psbts):
		self.role = "Combiner"
		self.psbt = PSBT.parse(BytesIO(psbts[0]))
		self.base_num_inputs = len(self.psbt.maps["inputs"])
		self.base_num_outputs = len(self.psbt.maps["outputs"])
		[self.combine(p) for p in psbts]

	def matching(self, other_psbt):
		return self.psbt.maps["global"][GLOBAL_UNSIGNED_TX] == other_psbt.maps["global"][GLOBAL_UNSIGNED_TX]

	def combine(self, *psbts):
		for p in psbts:
			curr = PSBT.parse(BytesIO(p))
			if self.matching(curr):
				self.psbt.maps["global"].update(curr.maps["global"])
				curr_num_inputs = len(curr.maps["inputs"])
				if curr_num_inputs != self.base_num_inputs:
					raise PSBTError(f"Number of input maps in the following PSBT does not match that of base: {curr.base}")
				for i in range(curr_num_inputs):
					self.psbt.maps["inputs"][i].update(curr.maps["inputs"][i])
					if self._is_non_witness_input(i) and self._is_witness_input(i):
						raise PSBTError(f"Input {i} cannot have a Witness UTXO and a Non-Witness UTXO")

				curr_num_outputs = len(curr.maps["outputs"])
				if curr_num_outputs != self.base_num_outputs:
					raise PSBTError(f"Number of output maps in the following PSBT does not match that of base: {curr.base}")
				for o in range(len(curr.maps["outputs"])):
					self.psbt.maps["outputs"][o].update(curr.maps["outputs"][o])
			else:
				raise PSBTWarning("A PSBT being combined does not have matching a unsigned \
                transaction value and was not added")
		return True

class Finalizer(PSBT_Role):
	def __init__(self, serialized_psbt):
		self.role = "Finalizer"
		self.psbt = PSBT.parse(BytesIO(serialized_psbt))
		for i in self.psbt.maps["inputs"]:
			if not self._check_for_sig(i):
				continue
			if IN_SIGHASH_TYPE not in i.keys():
				continue
			if self._is_witness_input(i):
				if IN_WITNESS_SCRIPT not in i.keys():
					continue
				# Step 3b: Then create scriptWitness
				new_scriptWitness = self._make_multisig_script(inp=i, witness=True)
				# Complete scriptWitness by adding the number of witness items to the beginning 
				new_scriptWitness.insert(0, len(new_scriptWitness))
				# Add key-type PSBT_IN_FINAL_SCRIPTWITNESS to PSBT with the finalized scriptWitness as its value     
				i[IN_FINAL_SCRIPTWITNESS] = Script(new_scriptWitness).serialize()
				# Add key-type PSBT_IN_FINAL_SCRIPTSIG to PSBT with the finalized scriptSig as its value
				# For witness inputs, this is the redeemScript preceded by its length
				i[IN_FINAL_SCRIPTSIG] = encode_varint(len(i[IN_REDEEM_SCRIPT])) + i[IN_REDEEM_SCRIPT]
			elif IN_REDEEM_SCRIPT in i.keys(): # ASSUME MULTISIG
				i[IN_FINAL_SCRIPTSIG] = Script(self._make_multisig_script(i)).serialize()
			else: # ASSUME P2PKH
				found_sec = False
				for k in i.keys():
					if k[:1] == IN_PARTIAL_SIG: # WTF IS THIS LOGIC???
						if found_sec:
							continue
						sec = k[1:]
						sig = i[k]
						found_sec = True
				i[IN_FINAL_SCRIPTSIG] = Script([sig, sec]).serialize()
			self._clear_keyvalues(i)

		
	def _check_for_sig(self, an_input):
		for k in an_input.keys():
			if k[:1] == IN_PARTIAL_SIG:
				return True
		return False

	def _clear_keyvalues(self, an_input):
		to_delete = []
		for k in an_input.keys():
			if k[:1] in [IN_PARTIAL_SIG, IN_SIGHASH_TYPE, IN_REDEEM_SCRIPT, IN_WITNESS_SCRIPT, IN_BIP32_DERIVATION]:
				to_delete.append(k)
		for k in to_delete:
			del inp[k]
		return

	def _make_multisig_script(self, an_input, witness=False):
		new_script = []
		new_script.append(0)
		if witness:
			redeemScript = Script.parse(an_input[IN_WITNESS_SCRIPT])
		else:
			redeemScript = Script.parse(an_input[IN_REDEEM_SCRIPT])
		if redeemScript.cmds[-1] != 174:
			raise ValueError("Present redeemScript is not multisig and not understood")
		sigs_required = int(OP_CODE_FUNCTIONS[redeemScript.cmds[0]][3:])
		total_sigs = int(OP_CODE_FUNCTIONS[redeemScript.cmds[-2]][3:])
		found_sigs = 0
		for pk_i in range(total_sigs):
			if found_sigs >= sigs_required:
				break
			try_key = IN_PARTIAL_SIG + redeemScript.sec_pubkey(pk_i)
			if try_key in an_input:
				new_script.append(an_input[try_key])
				found_sigs += 1
		if found_sigs < sigs_required:
			raise ValueError("Insufficient Sigs present")
		new_script.append(redeemScript.serialize())
		return new_script

class Extractor(PSBT_Role):
	def __init__(self, serialized_psbt):
		self.tx_obj = Tx.parse(BytesIO(self.psbt.maps["global"][GLOBAL_UNSIGNED_TX]))
		for i in range(len(self.psbt.maps["inputs"])):
			curr_input = self.psbt.maps["inputs"][i]
			if self._is_witness_input(curr_input):
				try:
					# Add final scriptWit 
					self.tx_obj.tx_ins[i].witness_program = curr_input[IN_FINAL_SCRIPTWITNESS]
				except KeyError:
					raise PSBTError("PSBT input is missing finalized scriptWitness")
				if IN_FINAL_SCRIPTSIG in curr_input:
					self.tx_obj.tx_ins[i].script_sig = Script.parse(curr_input[IN_FINAL_SCRIPTSIG])
			else:
				try:
					self.tx_obj.tx_ins[i].script_sig = Script.parse(curr_input[IN_FINAL_SCRIPTSIG])
				except KeyError:
					raise PSBTError("PSBT input is missing finalized scriptSig")
			
		# FINISH ON OWN

	def extract(self):
		return self.tx_obj.serialize()


if __name__ == "__main__":
	# psbt_bytes = bytes.fromhex("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000")
	# ans_b64 = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"
	# psbt = PSBT.parse(BytesIO(psbt_bytes))
	# print(psbt.__str__())
	# print(ans_b64 == psbt.b64encode())
	ans_psbt = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"
	# xprv = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
	# w = Wallet(data=xprv, testnet=True)
	outputs = [["0014d85c2b71d0060b09c9886aeb815e50991dda124d", 149990000], 
				["001400aea9a2e5f0f876a588df5546e8742d1d87008f", 100000000]]
	inputs = [["75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858"]
				["1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83"]]
	psbt_cr = Creator(inputs, outputs).serialize()
	psbt_up = Updater(psbt_cr)
	for i in range(2):
		tx_hex = bytes.fromhex(get_transaction_hex(inputs[i][0]))
		psbt_up.add_nonwitness_utxo(i, tx_hex)
	print(psbt_up.serialize().hex() == ans_psbt)


