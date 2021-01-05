from wallet import *

def test_pubkey_to_p2wpkh_addr():
	c_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	pubkey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pk = S256Point.parse(bytes.fromhex(pubkey))
	scriptpubkey = Wallet.pubkey_to_pkh_script(pk, p2wpkh_script)
	addr = Wallet.get_scriptpubkey_to_p2wpkh_address(scriptpubkey)
	assert c_addr == addr

def test_bip32_44_84():
	mn = ["height", "turn", "robust", "prepare", "fatal", "tragic", "deny", "swarm", "vote", "hour", "oxygen", "steak"]
	c_master_xprv = "zprvAWgYBBk7JR8GktKQp8HtLnRVsExT2YDTtqeKo4Jp9cxLjbkTxXAqDW9zx7h3NtqqocQ6SxPYJSCbG17qZA5PDmUvEoZhiDBKfnLNsg7CKS3"
	c_acct_xprv = "zprvAd1HRQk8HQiiSe5wJgXygusAsYfXiEpUXxEXEwYj38ZyyfkaxBqEJE8Tny3m2mrVH3nezbyYvVDHj1jMrcjiXFamfbWtr8wAGxf4BwuENcX"
	c_acct_xpub = "zpub6qzdpvH27nH1f8AQQi4z43ouRaW27hYKuBA83KxLbU6xrU5jVj9Ur2SweEPMntJ6pk8HEY7eRaLZfqsL2HPwBSjpnpWt7jNhFekg3E71ign"
	c_acct_0_0_addr = "bc1qr34ug6lmlu0x9u062vyw9enfvrye7hxk76eagh"
	c_acct_0_1_addr = "bc1q8xevajmzh9nkf4zp92j59y59f05ydgz5c2rv4z"
	#BIP 84
	seed = Seed.from_mnemonic(mn)
	w = Wallet(data=seed, testnet=False, script_type="p2wpkh")
	# print(w.mnemonic() == mn)
	print(w.master_xprv.__repr__() == c_master_xprv)
	print(w.acct_xprv.__repr__() == c_acct_xprv)
	print(w.acct_xpub.__repr__() == c_acct_xpub)
	#acct_int_xprv = w.derive_key("0", priv=True)
	#print(acct_int_xprv)
	print(w.new_address() == c_acct_0_0_addr)
	print(w.new_address() == c_acct_0_1_addr)