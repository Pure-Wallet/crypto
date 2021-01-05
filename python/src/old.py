
class HDPubKey:
	"""
	class for holding a pubkey (S256Point object) and metadata,
	including: 
	-Count (UTXO count)
	-Full Path
	-Label
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

	def get_path(self):
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
		addr = self.address()
		tx_hist = get_address(address=addr, testnet=self.testnet).chain_stats
		self.txcount = tx_hist['tx_count']
		self.balance = tx_hist['funded_txo_sum'] - tx_hist['spent_txo_sum']
		return self.balance
		
	def get_utxos(self):
		addr = self.address()
		return get_address_utxo(address=addr, testnet=self.testnet)



	def set_confirmed_utxos(self):
		addr = self.address()
		utxos = get_address_utxo(address=addr, testnet=self.testnet)
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

def __create_p2pkh(self, outputs, fee, locktime=0, priority="oldest", auto_sign=False, data=None):
		"""
		-outputs is a list of tuples (amount : int, address : str)
		"""
		amountOut = sum([o[0] for o in outputs])
		pubkeys = self.select_utxos(amountOut=(amountOut+fee), priority=priority, data=data)
		amountIn = 0
		tx_ins =[]
		change_labels = []
		for pubkey in pubkeys:
			#print(pubkey.pubkey.address(testnet=True))
			change_labels += pubkey.label
			for utxo in pubkey.utxos:
				#TX INS
				tx_ins.append((bytes.fromhex(utxo.tx_id), utxo.vout))

			amountIn += pubkey.balance
		for i in tx_ins:
			print(i[0].hex())
		print("-----")
		#TX OUTS
		#change output
		change_amount = amountIn - fee - amountOut
		if change_amount:
			change_pub_key = self.new_pub_key(label=change_labels, external=False)
			change_addr = decode_base58(change_pub_key.pubkey.address(testnet=self.testnet))
			outputs.append((change_amount, change_addr))
		
		tx_outs = [(o[0], p2pkh_script(o[1])) for o in outputs]
		#print(tx_outs)
		#Signing
		if(auto_sign):
			tx_obj = Tx(self.TX_VERSION, tx_ins, tx_outs, locktime, testnet=self.testnet)
			for i in range(len(pubkeys)):
				if not tx_obj.sign_input(i, self.get_priv_key(i)):
					raise SignatureError(f"Signing Input {i} failed.")
			if not tx_obj.verify():
				raise TransactionError("Invalid Transaction")
			return tx_obj.serialize()
		else:
			psbt_cr = Creator(tx_ins, tx_outs, locktime=locktime).serialize()
			psbt_up = Updater(psbt_cr)
			psbt_up.add_output_pubkey(-1, change_pub_key.pubkey.sec(), self.master_fingerprint(), change_pub_key.get_path())
			for i in range(len(pubkeys)):
				psbt_up.add_input_pubkey(i, self.hdpubkeys[i].pubkey.sec(), self.master_fingerprint(), pubkey.get_path())
				psbt_up.add_sighash_type(i, sighash=SIGHASH_ALL)
				prev_hex = get_transaction_hex(tx_ins[i][0].hex(), testnet=self.testnet)
				print(prev_hex)
				prev_tx = hash256(bytes.fromhex( prev_hex ))[::-1]
				print(prev_tx.hex())
				psbt_up.add_nonwitness_utxo(i, prev_tx )
			return psbt_up.serialize()

	def __select_utxos(self, amountOut, priority="oldest", data=None):
		"""
		function for choosing utxos to use for a transaction.
		param: amountOut is amount to be sent including fee.
		priority allows for options in terms of choosing 
		which utxos to spend. Options:
			- "oldest": uses oldest utxos first (by derivation path, not utxo age)
			- "biggest": uses fewest and biggest utxos possible
			- "smallest": uses fewest number of smallest utxos
			- "below": uses ALL utxos below amount specified in data
		"""
		balance = self.get_balance()
		if balance < amountOut:
			raise TransactionError("Insufficient Funds for this transaction.")		
		pAmount = 0
		pubkeys = []
		if priority == "oldest":
			for pubkey in self.hdpubkeys:
				#TODO if "NoSpend" not in pubkey.label:
				if pubkey.balance > 0:
					pubkey.set_confirmed_utxos()
					for _ in pubkey.utxos:
						pubkeys.append(pubkey)
					pAmount += pubkey.balance
					if pAmount >= amountOut:
						break
		elif priority == "biggest":
			balances = []
			for _ in range(len(self.hdpubkeys)):
				nextKey = max(self.hdpubkeys, key=(lambda x: x.balance))
				#TODO if "NoSpend" not in pubkey.label:
				pubkeys.append(nextKey)
				pAmount += nextKey.balance
				if pAmount >= amountOut:
					break
		elif priority == "smallest":
			balances = []
			pAmount = 0
			for _ in range(len(self.hdpubkeys)):
				nextKey = min(self.hdpubkeys, key=(lambda x: x.balance))
				if "NoSpend" not in pubkey.label:
					pubkeys.append(nextKey)
					pAmount += nextKey.balance
					if pAmount >= amountOut:
						break

		elif priority == "below":
			raise NotImplementedError("Priority algorithm not implemented yet.")		
		return pubkeys
def __create_p2pkh(self, outputs, fee, locktime=0, priority="oldest", auto_sign=False, data=None):
		"""
		-outputs is a list of tuples (amount : int, address : str)
		"""
		amountOut = sum([o[0] for o in outputs])
		pubkeys = self.select_utxos(amountOut=(amountOut+fee), priority=priority, data=data)
		amountIn = 0
		tx_ins =[]
		change_labels = []
		for pubkey in pubkeys:
			#print(pubkey.pubkey.address(testnet=True))
			change_labels += pubkey.label
			for utxo in pubkey.utxos:
				#TX INS
				tx_ins.append((bytes.fromhex(utxo.tx_id), utxo.vout))

			amountIn += pubkey.balance
		for i in tx_ins:
			print(i[0].hex())
		print("-----")
		#TX OUTS
		#change output
		change_amount = amountIn - fee - amountOut
		if change_amount:
			change_pub_key = self.new_pub_key(label=change_labels, external=False)
			change_addr = decode_base58(change_pub_key.pubkey.address(testnet=self.testnet))
			outputs.append((change_amount, change_addr))
		
		tx_outs = [(o[0], p2pkh_script(o[1])) for o in outputs]
		#print(tx_outs)
		#Signing
		if(auto_sign):
			tx_obj = Tx(self.TX_VERSION, tx_ins, tx_outs, locktime, testnet=self.testnet)
			for i in range(len(pubkeys)):
				if not tx_obj.sign_input(i, self.get_priv_key(i)):
					raise SignatureError(f"Signing Input {i} failed.")
			if not tx_obj.verify():
				raise TransactionError("Invalid Transaction")
			return tx_obj.serialize()
		else:
			psbt_cr = Creator(tx_ins, tx_outs, locktime=locktime).serialize()
			psbt_up = Updater(psbt_cr)
			psbt_up.add_output_pubkey(-1, change_pub_key.pubkey.sec(), self.master_fingerprint(), change_pub_key.get_path())
			for i in range(len(pubkeys)):
				psbt_up.add_input_pubkey(i, self.hdpubkeys[i].pubkey.sec(), self.master_fingerprint(), pubkey.get_path())
				psbt_up.add_sighash_type(i, sighash=SIGHASH_ALL)
				prev_hex = get_transaction_hex(tx_ins[i][0].hex(), testnet=self.testnet)
				print(prev_hex)
				prev_tx = hash256(bytes.fromhex( prev_hex ))[::-1]
				print(prev_tx.hex())
				psbt_up.add_nonwitness_utxo(i, prev_tx )
			return psbt_up.serialize()

	def __select_utxos(self, amountOut, priority="oldest", data=None):
		"""
		function for choosing utxos to use for a transaction.
		param: amountOut is amount to be sent including fee.
		priority allows for options in terms of choosing 
		which utxos to spend. Options:
			- "oldest": uses oldest utxos first (by derivation path, not utxo age)
			- "biggest": uses fewest and biggest utxos possible
			- "smallest": uses fewest number of smallest utxos
			- "below": uses ALL utxos below amount specified in data
		"""
		balance = self.get_balance()
		if balance < amountOut:
			raise TransactionError("Insufficient Funds for this transaction.")		
		pAmount = 0
		pubkeys = []
		if priority == "oldest":
			for pubkey in self.hdpubkeys:
				#TODO if "NoSpend" not in pubkey.label:
				if pubkey.balance > 0:
					pubkey.set_confirmed_utxos()
					for _ in pubkey.utxos:
						pubkeys.append(pubkey)
					pAmount += pubkey.balance
					if pAmount >= amountOut:
						break
		elif priority == "biggest":
			balances = []
			for _ in range(len(self.hdpubkeys)):
				nextKey = max(self.hdpubkeys, key=(lambda x: x.balance))
				#TODO if "NoSpend" not in pubkey.label:
				pubkeys.append(nextKey)
				pAmount += nextKey.balance
				if pAmount >= amountOut:
					break
		elif priority == "smallest":
			balances = []
			pAmount = 0
			for _ in range(len(self.hdpubkeys)):
				nextKey = min(self.hdpubkeys, key=(lambda x: x.balance))
				if "NoSpend" not in pubkey.label:
					pubkeys.append(nextKey)
					pAmount += nextKey.balance
					if pAmount >= amountOut:
						break

		elif priority == "below":
			raise NotImplementedError("Priority algorithm not implemented yet.")		
		return pubkeys
