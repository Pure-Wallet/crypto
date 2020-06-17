import unittest
from src.wallet import *

class WalletTest(unittest.TestCase):
	def test_init(self):
		s = Seed.new(128)
		w = Wallet(data=s, watch_only=False)
		if(w.balance != 0):
			print(w.master_xprv)
		self.assertEqual(w.wallet_acct, Wallet.BASE_PATH)
		self.assertEqual(w.key_count, Wallet.DEFAULT_GAP_LIMIT)
		self.assertEqual(w.key_count, len(w.hdpubkeys))

# ----- Test imports -----
#
# ------------------------
	def test_import_from_seed(self):
		pass
	def test_import_from_xprv(self):
		pass
	def test_import_from_xpub(self):
		pass
# ----- Test displays -----
#
# ------------------------

	def test_mnemonic(self):
		pass

	def test_mnemonic_fail(self):
		pass

	def test_mnemonic_recovery(self):
		s = Seed.new(128)
		w = Wallet(data=s, testnet=False, watch_only=False)
		wList = [pubkey.pubkey for pubkey in w.hdpubkeys]
		m = w.mnemonic()
		w2 = Wallet.from_mnemonic(mnemonic=m)
		w2List = [pubkey.pubkey for pubkey in w2.hdpubkeys]
		self.assertEqual(wList, w2List)

# ----- Test Keys --------
#
# ------------------------

	def test_new_pub_key(self):
		pass

	def test_new_address(self):
		pass

	def test_check_state(self):
		pass

	def test_sign_msg(self):
		s = Seed.new(128)
		w = Wallet(data=s, watch_only=False)
		msg = int.from_bytes(hash256(b'Hello Sachin'), 'big')
		pub = w.new_pub_key()
		priv = w.get_priv_key(w.hdpubkeys[-1]).to_priv_key()
		sig = priv.sign(msg)
		self.assertTrue(pub.verify(msg, sig))

	
if __name__ == "__main__":
	unittest.main()