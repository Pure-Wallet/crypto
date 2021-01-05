# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32 and segwit addresses."""

import helper

BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
SW_SEPARATOR = "1"
SW_TEST_PREFIX = "tb"
SW_MAIN_PREFIX = "bc"

class Bech32Error(ValueError):
	pass

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_expand_hrp(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_expand_hrp(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_expand_hrp(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + SW_SEPARATOR + ''.join([BECH32_ALPHABET[d] for d in combined])


def _bech32_decode(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        raise Bech32Error("Invalid Characters in Bech32 address.")
    bech = bech.lower()
    pos = bech.rfind(SW_SEPARATOR)
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        raise Bech32Error("Separator is in invalid position in Bech32 address.")
    if not all(x in BECH32_ALPHABET for x in bech[pos+1:]):
        raise Bech32Error("Invalid Characters in Bech32 address.")
    hrp = bech[:pos]
    data = [BECH32_ALPHABET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        raise Bech32Error("Invalid Checksum in Bech32 address.")
    return hrp, data[:-6]


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise Bech32Error("Error converting to/from Bech32")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise Bech32Error("Error converting to/from Bech32")
    return ret


def bech32_decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = _bech32_decode(addr)
    if hrpgot != hrp:
        raise Bech32Error(f"HRP does not match: {hrpgot} vs. {hrp}")
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        raise Bech32Error("Invalid Bech32 address length.")
    if data[0] > 16:
        raise Bech32Error("Invalid SegWit version byte.")
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        raise Bech32Error("Inalid Bech32 address length.")
    return data[0], decoded


def bech32_encode(hrp, witver, witprog):
    """Encode a segwit address."""
    ret = _bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))
    try:
        bech32_decode(hrp, ret)
        return ret
    except Bech32Error as e:
        raise Bech32Error(f"Encoding Failed. Error: {e}")

def bech32_address_decode(addr, testnet=False):
	hrp = SW_TEST_PREFIX if testnet else SW_MAIN_PREFIX 
	return bech32_decode(hrp, addr)

def h160_to_p2wpkh(h160, witver=0, testnet=False):
	hrp = SW_TEST_PREFIX if testnet else SW_MAIN_PREFIX 
	return bech32_encode(hrp, witver, list(h160))

def h256_to_p2wsh(h256, witver=0, testnet=False):
	hrp = SW_TEST_PREFIX if testnet else SW_MAIN_PREFIX 
	return bech32_encode(hrp, witver, list(h256))

if __name__ == "__main__":
	# pubkey = S256Point.parse(bytes.fromhex())
	# print(pubkey)
	hrp = "bc"
	addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	pubkey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	# data = _bech32_decode(addr)[1]

	# print(bech32_verify_checksum(hrp, data))
	#h160 = helper.hash160(bytes.fromhex(pubkey))
	#print(h160_to_p2wpkh(h160))
	#print(bech32_decode(hrp, addr))
	witver, decoded = bech32_address_decode("bc1qf3aldepeqxthwmkcscdkt2ma8a6a7fw06cf6yj")
	print("Witver: ", witver)
	print(bytes(decoded).hex())
	