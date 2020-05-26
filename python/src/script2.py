from io import BytesIO
from logging import getLogger
from unittest import TestCase

from helper import (
    read_varint,
    encode_varint,
    little_to_int,
    int_to_little
)

from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)

LOGGER = getLogger(__name__)

class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __add__(self, other):
        return self.__class__(self.cmds + other.cmds)


    @classmethod
    def parse(cls, stream):
        length = read_varint(stream)
        cmds =[]  # list of commands
        count = 0 # like iterator of where we are in stream.
        while count < length:
            current = stream.read(1) # this byte determines opCode or element    
            count +=1
            current_byte = current[0]
            if current_byte >= 1 and current_byte <= 75: # elements are 1-75
                n = current_byte # length of next element
                cmds.append(stream.read(n))
                count += n # how much we've read
            elif current_byte == 76: #OP_PUSHDATA1
                data_length = little_to_int(stream.read(1)) #read length of next cmd
                cmds.append(stream.read(data_length))
                count += data_length + 1
            elif current_byte == 77: #OP_PUSHDATA2
                data_length = little_to_int(stream.read(2))
                cmds.append(stream.read(data_length))
                count += data_length + 2
            else:     # all others are OP_CODES
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('Parsing Script Failed')
        return cls(cmds)

    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:  #all OP_CODEs are ints
                result += int_to_little(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little(length, 1)
                elif length > 75 and length < 0x100:
                    result += int_to_little(76, 1)  #add OP_PUSHDATA1 first, then rest
                    result += int_to_little(length, 1)
                elif length >= 0x100 and length <= 520:
                    result += int_to_little(77, 1) # add OP_PUSHDATA2
                    result += int_to_little(length, 1)
                else:
                    raise ValueError('command too long (>520 bytes)')
                result += cmd # add the actual element to result
            return result

    def serialize(self): 
        result = self.raw_serialize()
        total = len(result) #add preceding length byte
        return encode_varint(total) + result


    def evaluate(self, z):
        for cmd in self.cmds:
            print("CMD: " , cmd)
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0) #each time, take first element out of cmds and execute it
            if type(cmd) == int: # OP_CODE
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100): # OP_IF and OP_NOTIF
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108): #OP_TOALTSTACK, OP_FROMALTSTACK
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175): #OP_CHECKSIG/(VERIFY) / OP_CHECKMULTISIG/(VERIFY)
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    print('other op')
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                stack.append(cmd) # Elements
        if len(stack) == 0:
            print("len(stack) = 0")
            return False
        if stack.pop() == b'':
            return False
        return True
