import unittest
import json
from src.seed import *



class SeedTest(unittest.TestCase):
	lengths = [128, 160, 192, 224, 256]

	def test_generate(self):
		for i in self.lengths:
			s1 = Seed()
			s1.generate(i)
			self.assertEqual(len(s1.mnemonic()), (i+(i//32))//11)

	def test_generate_fail(self):
		s1 = Seed()
		with self.assertRaises(ConfigurationError):
			s1.generate(133)

	def test_mnemonic(self):
		for i in self.lengths:
			s1 = Seed()
			s1.generate(i)
			self.assertEqual(len(s1.mnemonic()), (i+(i//32))//11)
			self.assertEqual(len(s1.bits), i+i//32)

	def test_repr(self):
		c_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
		entropy = "00000000000000000000000000000000"
		s1 = Seed()
		s1.set_entropy(entropy)
		self.assertEqual(s1.seed(passphrase="TREZOR").hex(), c_seed)

	def test_repr_null(self):
		c_seed = "Seed(null)"
		s1 = Seed()
		self.assertEqual(s1.__repr__(), c_seed)

	def test_from_bits(self):
		s1 = Seed(bits="110011010100001111111010010110110110001110001011111000010010000001000010010100011000000111110101101111110111011001100000010101101011100011011001011100110101100001001011011000101011111010111001101101111011010000100010101111011101110111001000011010100001010100100001")
		self.assertEqual(s1.mnemonic(), ['snap', 'cabin', 'nothing', 'shove', 'safe', 'mother', 'announce', 'coral', 'volcano', 'wing', 'object', 'pulp', 'mirror', 'rifle', 'gentle', 'hobby', 'salt', 'soap', 'unfair', 'earth', 'tape', 'tomorrow', 'portion', 'picnic'])

	def test_parse(self):
		s1 = Seed.from_mnemonic(['snap', 'cabin', 'nothing', 'shove', 'safe', 'mother', 'announce', 'coral', 'volcano', 'wing', 'object', 'pulp', 'mirror', 'rifle', 'gentle', 'hobby', 'salt', 'soap', 'unfair', 'earth', 'tape', 'tomorrow', 'portion', 'picnic'])
		self.assertEqual(s1.bits, "110011010100001111111010010110110110001110001011111000010010000001000010010100011000000111110101101111110111011001100000010101101011100011011001011100110101100001001011011000101011111010111001101101111011010000100010101111011101110111001000011010100001010100100001")

	def test_full(self):
		s1 = Seed()
		s1.generate(256)
		m1 = s1.mnemonic()
		s2 = Seed.from_mnemonic(m1)
		self.assertEqual(s2.bits, s1.bits)

	#
	def test_vectors(self):
		"""
		test vectors (vectors.json) taken from https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json
		These are the official BIP39 test vectors
		"""
		f = open("vectors.json")
		vectors = json.load(f)
		for test in vectors["english"]:
			entropy = test[0]
			strength = len(entropy)*4 
			bits_len = strength + len(entropy)//8
			c_mnemonic = test[1]
			c_seed = test[2]
			c_xprv = test[3]
			s1 = Seed()
			s1.set_entropy(entropy)
			self.assertEqual(c_mnemonic.split(" "), s1.mnemonic())
			self.assertEqual(s1.seed(passphrase="TREZOR").hex(), c_seed)
			self.assertEqual(s1.derive_master_priv_key(passphrase="TREZOR").__repr__(), c_xprv)
		f.close()

	def test_full1(self):
		entropy = "00000000000000000000000000000000"
		mnemonic =  ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
		seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
		xprv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
		s1 = Seed()
		s1.set_entropy(entropy)
		self.assertEqual(mnemonic, s1.mnemonic())
		self.assertEqual(s1.seed(passphrase="TREZOR").hex(), seed)
		self.assertEqual(s1.derive_master_priv_key(passphrase="TREZOR").__repr__(), xprv)

	def test_full2(self):
		entropy = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
		mnemonic =  ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "yellow"]
		seed = "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
		xprv = "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
		s1 = Seed()
		s1.set_entropy(entropy)
		self.assertEqual(mnemonic, s1.mnemonic())
		self.assertEqual(s1.seed(passphrase="TREZOR").hex(), seed)
		self.assertEqual(s1.derive_master_priv_key(passphrase="TREZOR").__repr__(), xprv)

class ExtendedPublicKeyTest(unittest.TestCase):
	def test_init(self):
		s1 = Seed()
		xprv = s1.derive_master_priv_key(testnet=False)
		xpub = xprv.to_extended_pub_key()
		self.assertTrue(xpub.__repr__()[:4] == "xpub")
		self.assertIn(xpub.to_pub_key().sec()[:1], [b'\x02', b'\x03'])
		self.assertTrue(xpub.to_pub_key().address()[:1] == "1")
		
	def test_from_seed(self):
		seed = bytes(bytearray.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))
		c_xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
		xpub = ExtendedPublicKey.from_seed(seed)
		self.assertEqual(xpub.__repr__(), c_xpub)

	def test_parse(self):
		xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
		XPUB = ExtendedPublicKey.parse(xpub)
		self.assertEqual(xpub, XPUB.__repr__())

	def test_derive_child_0(self):
		xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
		c_child_xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
		XPUB = ExtendedPublicKey.parse(xpub)
		self.assertEqual(xpub, XPUB.__repr__())
		child_0 = XPUB.derive_pub_child(0)
		self.assertEqual(c_child_xpub, child_0.__repr__())

	def test_derive_child_0_0to9(self):
		xprv = "xprv9s21ZrQH143K4LC8k1BTTtAeGxK9cJqo9zrySXP8oaGcucr6Z5BnoA8DdFGCgc38eJWVSYqeiyGHUN1KpisxViAzydt2XesW66sHUJjvws1"
		c_xpub = "xpub661MyMwAqRbcGpGbr2iTq27Npz9e1mZeXDnaEunkMuobnRBF6cW3LxShUWBcLKrvzbvVo5qo5Vef6o47dHq1V3zRYUxU4BAGwQ2KjXjxjJh"
		c_addrs = ["1Wco4H7iz6JytoUibAmarL14tov1ABPrP",  # m/0/0
					"1NQ676mCZyZfs3F5WTWFUnNdnx1VzCDfCR", 
					"1HUPTtmiYxsZJAZDGVUvva3eAvKmg8snG2",
					"1KspMbVb8RWCYtcMcAYZS4Xx6hFyvmAsKJ",
					"1Eaejmid3isSvXyyGLBHXDwWpiNbrbcf6J",
					"1KgjEhZr3XLw7dRmYC8gbRPLnyuHLPSNzQ",
					"14ogtPMchvD1CrFaSURpwYxFjxdhYcZcA3",
					"16JRCdCXuAgy1xm8g1wDy6ZkHYQvCxWSSS",
					"1Ej6ZD2wZViBFyczBRn1dfSz6t2kaPwMCB",
					"1DTdaKym4DfnMt4x3dKswBVMscpkdigvwd"] # m/0/9
		XPRV = ExtendedPrivateKey.parse(xprv)
		XPUB = XPRV.to_extended_pub_key()
		child0 = XPUB.derive_pub_child(0)
		for i in range(10):
			child0_x = child0.derive_pub_child(i).to_pub_key()
			self.assertEqual(child0_x.address(), c_addrs[i])

class ExtendedPrivateKeyTest(unittest.TestCase):
	def test_init(self):
		s1 = Seed()
		xprv = s1.derive_master_priv_key(testnet=False)
		self.assertEqual(xprv.__repr__()[:4], "xprv")

	def test_from_seed(self):
		entr = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		c_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
		xprv = ExtendedPrivateKey.from_seed(seed=entr)
		self.assertEqual(c_xprv, xprv.__repr__())

	def test_parse(self):
		xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
		XPRV = ExtendedPrivateKey.parse(xprv)
		self.assertTrue(XPRV.__repr__() == xprv)
	
	def test_to_xpub(self):
		xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
		xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
		XPRV = ExtendedPrivateKey.parse(xprv)
		self.assertEqual(xpub, XPRV.to_extended_pub_key().__repr__())

	def test_to_pub_child(self):
		xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
		c_child_xprv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
		c_child_xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
		XPRV = ExtendedPrivateKey.parse(xprv)
		child_xprv = XPRV.derive_priv_child(0)
		child_xpub = XPRV.derive_pub_child(0)
		self.assertEqual(c_child_xprv, child_xprv.__repr__())
		self.assertEqual(c_child_xpub, child_xpub.__repr__())

	def test_full(self):
		c_xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
		c_xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
		entr = bytes(bytearray.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
		xprv = ExtendedPrivateKey.from_seed(seed=entr)
		self.assertEqual(xprv.__repr__(), c_xprv)
		self.assertEqual(xprv.to_extended_pub_key().__repr__(), c_xpub)

	def test_derive_child_0(self):
		entr = bytes(bytearray.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
		c_child_xprv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
		xprv = ExtendedPrivateKey.from_seed(seed=entr)
		child_xprv = xprv.derive_priv_child(0)
		self.assertEqual(c_child_xprv, child_xprv.__repr__())

	#tests for retention of leading zeros (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) Test Vector 3
	def test_derive_children(self):
		entr = bytes(bytearray.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))
		c_xprv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
		c_xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
		#hardened children m/0'
		c_child_xprv = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
		c_child_xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
		xprv = ExtendedPrivateKey.from_seed(seed=entr)
		self.assertEqual(c_xprv, xprv.__repr__())
		self.assertEqual(c_xpub, xprv.to_extended_pub_key().__repr__())
		self.assertEqual(c_child_xprv, xprv.derive_priv_child(2**31).__repr__())
		self.assertEqual(c_child_xpub, xprv.derive_pub_child(2**31).__repr__())

	def test_derive_hardened_child(self):
		entr = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		xprv = ExtendedPrivateKey.from_seed(seed=entr)
		c_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
		c_child_xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
		child_xprv = xprv.derive_priv_child(2**31)
		self.assertEqual(c_xprv, xprv.__repr__())
		self.assertEqual(c_child_xprv, child_xprv.__repr__())

class Bip32Test(unittest.TestCase):

	def test_sign(self):
		m = Seed.to_master_priv_key()
		msg = b"hello world"
		z = int.from_bytes(hash256(msg), 'big')
		m_0 = m.derive_priv_child(0)
		pub = m_0.to_pub_key()
		prv = m_0.to_priv_key()
		sig = prv.sign(z)
		self.assertTrue(pub.verify(z, sig))

if __name__ == "__main__":
	unittest.main()