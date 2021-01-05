from io import BytesIO
from unittest import TestCase

import json
import requests

from ecc import PrivateKey
from helper import (
    encode_varint,
    hash256,
    int_to_little,
    little_to_int,
    read_varint,
    SIGHASH_ALL,
)
from script import (
    Script,
    p2pkh_script,
    p2wpkh_script,
    p2sh_script,
    p2wsh_script
)

class TransactionError(Exception):
    pass

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            # make sure the tx we got matches to the hash we requested
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)

class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    def wtxid(self):
        '''Human-readable hexadecimal of the witness txid'''
        return self.whash().hex()

    def hash(self):
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize_legacy())[::-1]

    def whash(self):
        if not self.segwit:
            return self.hash()
        return hash256(self.serialize_segwit())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        s.read(4)
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        '''Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        # s.read(n) will return n bytes
        # version is an integer in 4 bytes, little-endian
        version = little_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # parse num_inputs number of TxIns
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # parse num_outputs number of TxOuts
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is an integer in 4 bytes, little-endian
        locktime = little_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        version = little_to_int(s.read(4))
        marker = s.read(2)
        if marker != b'\x00\x01':
            raise RuntimeError(f"Not a SegWit Transaction: {marker}")
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        for tx_in in inputs:
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            tx_in.witness = items
        locktime = little_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)

    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else: 
            return self.serialize_legacy()

    def serialize_segwit(self):
        result = int_to_little(self.version, 4)
        result += b'\x00\x01'
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        # Witness
        for tx_in in self.tx_ins:
            result += int_to_little(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little(item, 1)
                else:
                    result += encode_varint(len(item)) + item
        result += int_to_little(self.locktime, 4)
        return result

    def serialize_legacy(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little(self.locktime, 4)
        return result

    def amount_out(self):
        output_sum = 0
        for tx_out in self.tx_outs:
            # use TxOut.amount to sum up the output amounts
            output_sum += tx_out.amount
        return output_sum

    def amount_in(self):
        input_sum = 0
        for tx_in in self.tx_ins:
            # use TxIn.value() to sum up the input amounts
            input_sum += tx_in.value(self.testnet)
        return input_sum

    def fee(self):
        '''Returns the fee of this transaction in satoshis'''
        return self.amount_in() - self.amount_out()

    def hash_prevouts(self): 
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little(tx_in.prev_index, 4)
                all_sequence += int_to_little(tx_in.sequence, 4)
            self._hash_prevouts = hash256(all_prevouts)
            self._hash_sequence = hash256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)
        return self._hash_outputs

    def sig_hash_bip143(self, idx, redeem_script=None, witness_script=None, sighash_type=SIGHASH_ALL):
        '''Returns the integer representation of the hash that needs to get
        signed for index idx'''
        tx_in = self.tx_ins[idx]
        # per BIP143 spec
        s = int_to_little(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.cmds[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(self.testnet).cmds[1]).serialize()
        s += script_code
        s += int_to_little(tx_in.value(), 8)
        s += int_to_little(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little(self.locktime, 4)
        s += int_to_little(sighash_type, 4)
        return int.from_bytes(hash256(s), 'big')

    def sig_hash(self, idx, sighash_type=SIGHASH_ALL, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index idx'''
        # start the serialization with version
        # use int_to_little in 4 bytes
        s = int_to_little(self.version, 4)
        # add how many inputs there are using encode_varint
        s += encode_varint(len(self.tx_ins))
        # loop through each input using enumerate, so we have the input index
        for i, tx_in in enumerate(self.tx_ins):
            # if the input index is the one we're signing
            if i == idx:
                # if the RedeemScript was passed in, that's the ScriptSig
                if redeem_script:
                    script_sig = redeem_script
                # otherwise the previous tx's ScriptPubkey is the ScriptSig
                else:
                    script_sig = tx_in.script_pubkey(self.testnet)
            # Otherwise, the ScriptSig is empty
            else:
                script_sig = None
            # add the serialization of the input with the ScriptSig we want
            s += TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            ).serialize()
        # add how many outputs there are using encode_varint
        s += encode_varint(len(self.tx_outs))
        # add the serialization of each output
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        # add the locktime using int_to_little in 4 bytes
        s += int_to_little(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little in 4 bytes
        s += int_to_little(sighash_type, 4)
        # hash256 the serialization
        h256 = hash256(s)
        # convert the result to an integer using int.from_bytes(x, 'big')
        return int.from_bytes(h256, 'big')

    def verify_input(self, idx):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[idx]
        # grab the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        # check to see if the ScriptPubkey is a p2sh using
        # Script.is_p2sh_script_pubkey()
        if script_pubkey.is_p2sh_script_pubkey(): #P2SH
            # the last cmd in a p2sh is the RedeemScript
            cmd = tx_in.script_sig.cmds[-1]
            # prepend the length of the RedeemScript using encode_varint
            raw_redeem = encode_varint(len(cmd)) + cmd
            # parse the RedeemScript
            redeem_script = Script.parse(BytesIO(raw_redeem))
            if redeem_script.is_p2wpkh_script_pubkey(): # P2SH-P2WPKH
                z = self.sig_hash_bip143(idx, redeem_script)
                witness = tx_in.witness
            elif redeem_script.is_p2wsh_script_pubkey(): # P2SH-P2WSH
                cmd = tx_in.witness[-1]
                raw_witness = encode_varint(len(cmd)) + cmd
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(idx, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(idx, redeem_script)
                witness = None
        # otherwise RedeemScript is None
        else: #P2(W)PKH
            redeem_script = None
            if script_pubkey.is_p2wpkh_script_pubkey(): # P2WPKH
                z = self.sig_hash_bip143(idx)
                witness = tx_in.witness
            elif script_pubkey.is_p2wsh_script_pubkey():
                cmd = tx_in.witness[-1]
                raw_witness = encode_varint(len(cmd)) + cmd
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(idx, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(idx) # P2PKH
                witness = None
        # combine the current ScriptSig and the previous ScriptPubKey
        combined = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
        # evaluate the combined script
        return combined.evaluate(z, witness)

    def verify(self):
        '''Verify this transaction'''
        # check that we're not creating money
        if self.fee() < 0:
            return False
        # check that each input has a valid ScriptSig
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_input(self, idx, private_key, sighash_type=SIGHASH_ALL):
        '''Signs the input using the private key'''
        # get the signature hash (z)
        tx_in = self.tx_ins[idx]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        if script_pubkey.is_p2wpkh_script():
            z = self.sig_hash_bip143(idx)
        elif script_pubkey.is_p2pkh_script():
            z = self.sig_hash(idx, sighash_type=sighash_type)
        #TODO p2sh-p2wpkh
        elif script_pubkey.is_p2wsh_script():
            #z = self.sig_hash_bip143(idx, witness_script=tx_in.witness)
            raise NotImplementedError
        else:
            raise NotImplementedError
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the sighash_type to der (use sighash_type.to_bytes(1, 'big'))
        sig = der + sighash_type.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.point.sec()
        # initialize a new script with [sig, sec] as the cmds
        script_sig = Script([sig, sec])
        # change input's script_sig to new script
        if tx_in.segwit:
            self.tx_ins[idx].witness = script_sig
        else:
            self.tx_ins[idx].script_sig = script_sig
        # return whether sig is valid using self.verify_input
        if self.verify_input(idx):
            return script_sig
        else:
            return False

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        tx_in = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if tx_in.prev_tx != b'\x00' * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if tx_in.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first cmd
        
        # convert the cmd from little endian to int
        raise NotImplementedError

class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence
        self.witness = None

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is an integer in 4 bytes, little endian
        prev_index = little_to_int(s.read(4))
        # use Script.parse to get the ScriptSig
        script_sig = Script.parse(s)
        # sequence is an integer in 4 bytes, little-endian
        sequence = little_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        '''Get the ScriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outs[self.prev_index].script_pubkey

    def prev_txid(self):
        return self.prev_tx.hex()

class TxOut:
    
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # amount is an integer in 8 bytes, little endian
        amount = little_to_int(s.read(8))
        # use Script.parse to get the ScriptPubKey
        script_pubkey = Script.parse(s)
        # return an instance of the class (see __init__ for args)
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


if __name__ == "__main__":
    tx_hex = "02000000000101a3b4f99bd23f5dc3c034cbf3137a50d753e854e9848ee9e18a59a2dfbf9039bf0200000000fdffffff068b900000000000001976a9144791403ceae6028944b6da8145a60fe260c7b13b88ac3a9b01000000000017a914302f569306e91fdcd1ec6bae011bedb614f9f66787f2b001000000000017a91427066bd35a6f2cb4bcc44eae5b7c8d3f8241e10e87089c0200000000001976a914208160b23fd6f9f95e1ff8e27dee50fb9fcde78688acf85c0b000000000017a9143d7712743c87ef9e77566a6fcbb0ffbb19d0eb80878c0e58730000000016001475abca1314d1715497490ce64dd4afae59529035024730440220318eb370fb69f31bbfbbd74f5b7abc1d6d9c36ed1ec233c3216353e916842eef0220401b01e97c4022e37625eaea0b4a6ee47091efbee1d807a803054386cfafc01b012103d3ffa479ec5ca055807b5571a6806e35c6dc3c1641ebde2afd23c436fa43379c06230a00"
    txid = "c1ac7573f90afa4a518a98a56faf98729e239d959754de93dc303dcf86fe75b1"
    prev_txid = "bf3990bfdfa2598ae1e98e84e954e853d7507a13f3cb34c0c35d3fd29bf9b4a3"
    tx_obj = Tx.parse(BytesIO(bytes.fromhex(tx_hex)))
    print(tx_obj.id() == txid)
    tx_in = tx_obj.tx_ins[0]
    print(tx_in.prev_txid() == prev_txid)