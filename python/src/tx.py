from io import BytesIO
from unittest import TestCase

import json
import requests

from helper import (
    encode_varint,
    hash256,
    int_to_little,
    little_to_int,
    read_varint,
)
from script import Script


class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
        	tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
        	tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins: {}\ntx_outs: {}\nlocktime: {}'.format(
            self.id(),
            self.version,
            tx_ins, 
            tx_outs, 
            self.locktime)
        
    def id(self):
        '''representation of the hash of the tx'''
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, stream, testnet=False):
        version = little_to_int(stream.read(4))
        #get tx_ins
        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))
        #get tx_outs
        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))
        locktime = little_to_int(stream.read(4))

        return cls(version, inputs, outputs, locktime=locktime, testnet=testnet)

    def serialize(self):
        '''Returns the byte serialization of the TX'''
        result = int_to_little(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little(self.locktime, 4)
        return result

    def fee(self, testnet=False):
        fee = 0
        for tx_in in self.tx_ins:
            fee += tx_in.value(testnet=testnet)
        for tx_out in self.tx_outs:
            fee -= tx_out.amount

class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(self.prev_tx.hex(), self.prev_index)


    @classmethod
    def parse(cls, stream):
        '''Takes a byte stream and parses the tx_input at the start return a TxIn object
        Each TxIn takes:
        1) Prev_tx: a hash256 of the previous tx, always 32 bytes. we read tthis in 
        backwards because it's little-Endian
        2) Prev_index: which previous input was used to create the present input, next 4 bytes
        3) script_sig ???, variable len
        4) last 4 byttes is the sequence (unused mostly)
        '''
        prev_tx = stream.read(32)[::-1] 
        prev_index = little_to_int(stream.read(4))
        #stream = BytesIO(bytes.fromhex(stream))
        script_sig = Script.parse(stream)
        sequence = little_to_int(stream.read(4))

        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        ''''Returns byte Serialization of the Tx Input'''
        result = self.prev_tx[::-1]
        result += int_to_little(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get output Vvalue by looking up TX hash (id) returns amount in sats'''
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        '''Get ScriptPubKey via tx hash (id). Returns Script Obj'''
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey



class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}: {}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, stream):
        amount = little_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)

        return cls(amount=amount, script_pubkey=script_pubkey)

    def serialize(self):
        '''Returns byte Serialization of the TX Output'''
        result = int_to_little(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://testnet.programmingbitcoin.com'
        else:
            return 'https://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError('Not same TX id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

