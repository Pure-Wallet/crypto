from encrypt import encrypt, decrypt



def main():
	# data = b'Hello World'
	# secret = encrypt(data, "password1")
	# with open(f"test.dat", "wb") as fp:
	# 	fp.write(secret.getbuffer())

	# with open(f"test.dat", "rb") as fp:
	# 	fOut = fp.read()
	# plaintxt = decrypt(fOut, "password1")
	# # print(type(plaintxt), plaintxt)
	# print(plaintxt[:4] == b"\x48\x65\x6c\x6c")


	acct_path = "76'/0'/"
	path = "76'/0'/0/1"
	print(path.replace(acct_path, ''))
	print(path)


if __name__ == "__main__":
	main()