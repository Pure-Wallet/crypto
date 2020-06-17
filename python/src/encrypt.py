import pyAesCrypt
import io

BUFFER_SIZE = 64 * 1024

def encrypt(data, password=None):
	if password is None:
		password = "password"
	if type(data) == str:
		data = data.encode()
	elif type(data) != bytes:
		raise TypeError("Data must be string or bytes.")
	fIn = io.BytesIO(data)
	fOut = io.BytesIO()
	#with open("Wallet0.dat", "w") as fp:
	pyAesCrypt.encryptStream(fIn, fOut, password, BUFFER_SIZE)
	#print(str(fOut.getvalue().hex()))
	#ctlen = len(fOut.getvalue())
	fOut.seek(0)
	return fOut
	# with open(f"{filename}.dat", "wb") as fp:
	# 	fp.write(fOut.getbuffer())
	# pyAesCrypt.decryptStream(fOut, fDec, password, bufferSz, ctlen)
	# print(str(fDec.getvalue()))

def decrypt(data, password=None):
	if password is None:
		password = "password"
	fIn = io.BytesIO(data)
	#print(type(fIn))
	ctlen = len(fIn.getvalue())
	fOut = io.BytesIO()
	pyAesCrypt.decryptStream(fIn, fOut, password, BUFFER_SIZE, ctlen)
	#print(str(fOut.getvalue()))
	return fOut.getvalue()

def encrypt_file(filename, password=None):
	pass

def decrypt_file(filename, password=None):
	if password is None:
		password = "password"
	fp = open(f"{filename}.dat", "rb")
	fIn = io.BytesIO(fp.read())
	#print(type(fIn))
	ctlen = len(fIn.getvalue())
	fOut = io.BytesIO()
	pyAesCrypt.decryptStream(fIn, fOut, password, BUFFER_SIZE, ctlen)
	#print(str(fOut.getvalue()))
	return fOut.getvalue()


if __name__ == "__main__":
	pass