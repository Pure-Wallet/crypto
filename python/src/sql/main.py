from sqlhandler import WalletDB
from sqlscripts import SQL_SCRIPTS

def populate_utxo_table(walletDB):
	for script in SQL_SCRIPTS["testing"]["utxos"]["populate"]:
		walletDB._execute(script)
	return True

def populate_script_table(walletDB):
	for script in SQL_SCRIPTS["testing"]["scripts"]["populate"]:
		walletDB._execute(script)
	return True

def write_test_data(walletDB):
	walletDB.create_db()
	with open("sql/test_scripts.txt", "r") as fp:
		while True:
			script = fp.readline()
			if script == "":
				break
			data = script.split(" ")
			walletDB.new_script(data[0], data[1], data[2].strip())
	with open("sql/test_utxos.txt", "r") as fp:
		while True:
			utxo = fp.readline()
			if utxo == "":
				break
			data = utxo.split(" ")
			walletDB.new_utxo(data[0], int(data[1]), int(data[2]), int(data[3]), data[4], int(data[5]))
	
def query_all_utxos(walletDB):
	utxos = walletDB.get_all_utxos()
	for u in utxos:
		print(u)

def query_all_scripts(walletDB):
	scripts = walletDB.get_all_scripts()
	for s in scripts:
		print(s)

def query_utxos_by_script_ids(walletDB, sids):
	utxos = walletDB.get_utxos_by_script_ids(sids)
	for u in utxos:
		print(u)

def query_scripts_by_id(walletDB, sids):
	s = walletDB.get_scripts_by_id(sids)
	for script in s:
		print(script)

def query_scripts_by_type(walletDB, script_type):
	s = walletDB.get_scripts_by_script_type(script_type)
	for script in s:
		print(script)

def query_utxos_by_script_type(walletDB, script_type):
	utxos = walletDB.get_utxos_by_script_type("p2pkh")
	for u in utxos:
		print(u)

def query_script_balances(walletDB):
	scripts = walletDB.get_script_balances()
	return list(scripts)


if __name__ == "__main__":
	walletDB = WalletDB("test_wallet.db")
	write_test_data(walletDB)
	#query_utxos_by_script_ids(walletDB, [1,2,4])
	#query_all_utxos(walletDB)
	query_scripts_by_id(walletDB, [1,2,4])