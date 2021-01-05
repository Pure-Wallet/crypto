from wallet import *
import seed
import io

def recoverWallet(mnemonic):
	s = seed.Seed.from_mnemonic(mnemonic)
	return Wallet(data=s, passphrase="Sachin", testnet=True)

def create_tx():
	mn = ["type", "text", "announce", "affair", "upset", "image", "bargain", "left", "youth", "impose", "tortoise", "project"]
	s = seed.Seed.from_mnemonic(mn)
	w = Wallet(data=s, passphrase="Sachin", testnet=True)
	#print(w2.master_xprv)
	#print(w.get_balance())
	addr = w.hdpubkeys[3].address()
	print(addr)
	# addr = decode_base58(addr)
	# outputs = [(85500, addr)]
	# s_psbt = w.create_p2pkh(outputs, 2500)
	# return w.quick_sign(s_psbt)


def create_wallet():
	return Wallet.new(passphrase="Sachin", testnet=True)

def new_wallet():
	w = create_wallet()
	with open("wallet.txt", "w+") as fp:
		fp.write(" ".join(w.mnemonic()))
		fp.write(f"\n{w.master_xprv}")
	w.write_json(filename="wallet")

def check_tx(txid, testnet):
	c_txid = bytes.fromhex(txid)
	_hex = get_transaction_hex(txid, testnet)
	_tx = bytes.fromhex(_hex)
	if hash256(_tx)[::-1].hex() == c_txid.hex():
		print("True")
	else:
		print(hash256(_tx)[::-1].hex(), "\nVS\n", c_txid.hex())

def c_tx(_hex, _id):
	_txid = hash256(bytes.fromhex(_hex))[::-1].hex()
	if _id == _txid:
		print("True")
	else:
		print(_id, "\nVS\n", _txid)

def main():
	#c_tx("0100000001d6e081cf1afba8c809f8acc09215cecfc6bedb21bb3cd63a9404187449563c78010000006a47304402203101e220b37460352b533ccdba4f6ab01430f55b63e9bcb011404439082902c902206dadc2cbc36f3729023db66e8d3d1ec23c41380ac80d66544e1b1be35b671c0a0121026776653d150e2bc61c10ce2b23bc03cf6940cf8926ca23ccb5cbb6c20e80d33dffffffff025525ed00000000001976a914f2a6db22cd3c0a0815256fb74b7dfc0938c64bd888accf142c26000000001976a9146406a0a47d4ed716f6ddf2eeca20c725932763f188ac00000000", "fb6d6e8bb416ef4e626b38cc138cbf9f10539fa3a3a3039fc9b7dad3e8bb5f59")
	#check_tx("8f6af28adfacf5750b4be031c66dfcb4b20612caa1d24aa27064ef98bc7aaef7", True)
	#check_tx("fb6d6e8bb416ef4e626b38cc138cbf9f10539fa3a3a3039fc9b7dad3e8bb5f59", False)
	
	print(create_tx())

if __name__ == "__main__":
	main()