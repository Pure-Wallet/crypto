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

	def test_mnemonic(self):
		pass

	def test_mnemonic_fail(self):
		pass

	def test_new_pub_key(self):
		pass

	def test_new_address(self):
		pass

	def test_check_state(self):
		pass

	