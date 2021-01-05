from io import BytesIO
from logging import getLogger
from unittest import TestCase

from helper import (
    encode_varint,
    int_to_little,
    little_to_int,
    read_varint,
    encode_base58_checksum,
    decode_base58
)
from op import (
    op_equal,
    op_hash160,
    op_verify,
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)
from bech32 import (
    h160_to_p2wpkh,
    h256_to_p2wsh,
    bech32_address_decode,
    Bech32Error
)

from address import (
    P2SH_MAIN_PREFIX,
    P2SH_TEST_PREFIX,
    P2PKH_MAIN_PREFIX,
    P2PKH_TEST_PREFIX,
    LEGACY_TEST_PREFIX,
    LEGACY_MAIN_PREFIX,
    Address
)



def p2pkh_script(h160):
    '''Takes a hash160 and returns the p2pkh ScriptPubKey'''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


def p2sh_script(h160):
    '''Takes a hash160 and returns the p2sh ScriptPubKey'''
    return Script([0xa9, h160, 0x87])

def p2wpkh_script(h160):
    '''Takes a hash160 and returns p2wpkh ScriptPubKey'''
    return Script([0x00, h160])

def p2wsh_script(h256):
    '''Takes a hash256 and returns p2wsh ScriptPubKey'''
    return Script([0x00, h256])



LOGGER = getLogger(__name__)

class ScriptError(ValueError):
    pass

class Script:

    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        # get the length of the entire field
        length = read_varint(s)
        # initialize the cmds array
        cmds = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                # we have a cmd set n to be the current byte
                n = current_byte
                # add the next n bytes as an cmd
                cmds.append(s.read(n))
                # increase the count by n
                count += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = little_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = little_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # we have an opcode. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of cmds
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        # initialize what we'll send back
        result = b''
        # go through each cmd
        for cmd in self.cmds:
            # if the cmd is an integer, it's an opcode
            if type(cmd) == int:
                # turn the cmd into a single byte integer using int_to_little
                result += int_to_little(cmd, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(cmd)
                # for large lengths, we have to use a pushdata opcode
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_little(length, 1)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += int_to_little(76, 1)
                    result += int_to_little(length, 1)
                elif length >= 0x100 and length <= 520:
                    # 77 is pushdata2
                    result += int_to_little(77, 1)
                    result += int_to_little(length, 2)
                else:
                    raise ValueError('too long a cmd')
                if type(cmd) == str:
                    print(cmd)
                result += cmd
        return result

    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def hex(self):
        return self.serialize().hex()

    def evaluate(self, z, witness=None):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                # do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                # add the cmd to the stack
                stack.append(cmd)
                # p2sh rule: if the next 3 cmds are: OP_HASH160 (0xa9) <20 byte hash> OP_EQUAL (0x87) this is redeemScript
                if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:
                    # we execute the next three opcodes
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    # final result should be a 1
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    # hashes match! now add the RedeemScript
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)
                # Witness program v0 rule: if stack cmds are: 0 <20 byte hash> this is p2wpkh
                if len(stack) == 2 and stack[0] in [b'', b'\x00'] and type(stack[1]) == bytes and len(stack[1]) == 20:
                    h160 = stack.pop()
                    stack.pop()
                    cmds.extend(witness)
                    cmds.extend(p2pkh_script(h160).cmds)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 \
            and self.cmds[1] == 0xa9 \
            and type(self.cmds[2]) == bytes and len(self.cmds[2]) == 20 \
            and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_pubkey(self):
        '''Returns whether this follows the
        OP_HASH160 <20 byte hash> OP_EQUAL pattern.'''
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
            and self.cmds[2] == 0x87

    def is_p2wpkh_script_pubkey(self):
        '''Returns whether this follows the OP_0 <20 byte hash> pattern.'''
        return len(self.cmds) == 2 and self.cmds [0] == 0x00 and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20

    def is_p2wsh_script_pubkey(self):
        '''Returns whether this follows the OP_0 <32 byte hash> pattern.'''
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 32

    def to_address(self, testnet=False):
        # TODO maybe pass script type ?
        if self.is_p2pkh_script_pubkey():
            h160 = self.cmds[2]
            prefix = P2PKH_TEST_PREFIX if testnet else P2PKH_MAIN_PREFIX
            return Address(encode_base58_checksum(prefix + h160))
        elif self.is_p2sh_script_pubkey():
            h160 = self.cmds[1]
            prefix = P2SH_TEST_PREFIX if testnet else P2SH_MAIN_PREFIX
            return Address(encode_base58_checksum(prefix + h160))
        elif self.is_p2wpkh_script_pubkey():
            h160 = self.cmds[1]
            return Address(h160_to_p2wpkh(h160, witver=0, testnet=testnet))
        elif self.is_p2wsh_script_pubkey():
            h256 = self.cmds[1]
            return Address(h256_to_p2wsh(h256, witver=0, testnet=testnet))
        else:
            return None

    @classmethod
    def from_address(cls, address):
        testnet = address.testnet
        addr = address.addr
        try: # Bech32
            witver, decoded = bech32_address_decode(addr, testnet=testnet)
            if witver != 0:
                raise NotImplementedError("SegWit versions > 0 not yet supported.")
            if len(decoded) == 20:
                return p2wpkh_script(bytes(decoded))
            # bech32_decode raises error on all other lens
            else: # len = 32
                return p2wsh_script(bytes(decoded))
        except (Bech32Error, NotImplementedError):
            pass
        try: # Base58
        	parsed = decode_base58(addr) 
        	if testnet:
        		pkh = LEGACY_TEST_PREFIX[:2]
        		sh = LEGACY_TEST_PREFIX[2]
        	else:
        		pkh = LEGACY_MAIN_PREFIX[:1]
        		sh = LEGACY_MAIN_PREFIX[1]
        	if addr[0] in pkh:
        		return p2pkh_script(parsed)
        	elif addr[0] == sh:
        		return p2sh_script(parsed)
        	else:
        		raise ScriptError("Invalid mainnet legacy address prefix.")
            
        except Exception as e:
        	raise ScriptError(f"Failed to parse address. Error: {e}")

            
    #TODO create "derive script type" function

class ScriptTest(TestCase):

    def test_parse(self):
        script_pubkey = BytesIO(bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
        script = Script.parse(script_pubkey)
        want = bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertEqual(script.cmds[0].hex(), want.hex())
        want = bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertEqual(script.cmds[1], want)

    def test_serialize(self):
        want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)

if __name__ == "__main__":
    hex_spk = '160014006a7625ec5952ad2fc2e8fc35379995feff9245'
    bytes_spk = BytesIO(bytes.fromhex(hex_spk))
    script = Script.parse(bytes_spk)
    print(script)