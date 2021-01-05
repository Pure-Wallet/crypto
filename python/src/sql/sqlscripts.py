
SQL_SCRIPTS = {
	"init": {
		"scripts": ["""
					DROP TABLE IF EXISTS Scripts;
					""",
					"""
					CREATE TABLE IF NOT EXISTS Scripts (
						id INTEGER PRIMARY KEY,
						scriptPubKey STRING NOT NULL,
						scriptType STRING,
						derivationPath STRNG,
						UNIQUE(derivationPath)
					);
					"""],
		"utxos": ["""
				DROP TABLE IF EXISTS UTXOs;
				""",
				"""
				CREATE TABLE IF NOT EXISTS UTXOs (
					id INTEGER PRIMARY KEY,
					txid STRING NOT NULL,
					vout INTEGER NOT NULL,
					amount INTEGER,
					block_height INTEGER,
					status STRING,
					script_id INT NOT NULL,
					FOREIGN KEY (script_id)
						REFERENCES Scripts (id),
					UNIQUE(txid, vout)
					);
					
				"""]
	},
	
			
				
	"update": {
		"scripts": {
			"new": """
					INSERT OR IGNORE INTO Scripts (scriptPubKey, scriptType, derivationPath) VALUES(?,?,?);
					""",
			"remove": """ """,

		},
		"utxos": {
			"new": """
						INSERT OR IGNORE INTO UTXOs (txid, vout, amount, block_height, status, script_id) VALUES(?,?,?,?,?,?)
						""",
			"status": """ 
						""",
			
		}
	},
	"query": {
		"scripts": {
			"getAll": """ 
						SELECT * FROM Scripts;
						 """,
			"getByScriptType": """
						SELECT * FROM Scripts
						WHERE scripttype = (?);
						""",
			"getByIDs": """
						SELECT * FROM Scripts
						WHERE id IN {};
						""",
			"getAllByAmount": """
							SELECT S.id, S.scriptType, sum(U.amount) 
							FROM Scripts AS S
							LEFT JOIN UTXOs AS U ON U.script_id = S.id
							GROUP BY U.script_id
							ORDER BY U.amount {};
							""",
			"getByIDsOrderByAmount": """
							SELECT S.id, S.scriptType, sum(U.amount) 
							FROM Scripts AS S
							WHERE S.id in {}
							LEFT JOIN UTXOs AS U ON U.script_id = S.id
							GROUP BY U.script_id
							ORDER BY U.amount {};
							""",


		},
		"utxos": {
			"getAll": """ 
						SELECT * FROM UTXOs;
						""",
			"getByScriptType": """
						SELECT UTXO.script_id, UTXO.id, UTXO.txid, UTXO.vout, UTXO.amount, UTXO.status
						FROM UTXOs AS UTXO
						LEFT JOIN Scripts as Script ON Script.scripttype = (?)
						AND UTXO.script_id = Script.id;

						""",
			"getByStatus": """
						SELECT Script.id, UTXO.id, UTXO.txid, UTXO.vout, UTXO.amount, UTXO.status
						FROM UTXOs AS UTXO
						LEFT JOIN Scripts as Script ON Script.status = (?)
						AND UTXO.script_id = Script.id;

						""",
			"getByScriptIDs": """
						SELECT txid, vout, amount, block_height, status, script_id FROM UTXOs
						WHERE script_id IN {}
						ORDER BY amount {};
						""",
			"getScriptTypefromOutpoint": """
							SELECT s.scriptType
							FROM Scripts AS s
							WHERE S.id = (
								SELECT u.script_id 
								FROM UTXOs AS u
								WHERE u.txid = {}
								AND u.vout = {})
							;
							""",
			"getUTXOfromOutpoint": """
									SELECT * FROM UTXOs
									WHERE txid = {}
									AND vout = {};
									""",

			"getScriptfromOutpoint": """
									SELECT *
									FROM Scripts AS s
									WHERE S.id = (
										SELECT u.script_id 
										FROM UTXOs AS u
										WHERE u.txid = {}
										AND u.vout = {})
									;
									""",

		}
	},
	"testing": {
		"scripts": {
			"populate": ["""
						INSERT INTO Scripts (scriptPubKey, scriptType, derivationPath) VALUES(
							"76a9141f6288d4202743989f04230219b0022fea5f638588ac",
							"p2pkh",
							"m/76'/0'/0"
						);
						""", 
						"""
						INSERT INTO Scripts (scriptPubKey, scriptType, derivationPath) VALUES(
							"76a91427b80fd4911934dc25cb1021f1f3a2626f8069cd88ac",
							"p2pkh",
							"m/76'/0'/1"
						);
						""", 
						"""
						INSERT INTO Scripts (scriptPubKey, scriptType, derivationPath) VALUES(
							"76a914036a71888b317f917ea540ab91f1fc0eb1f8389a88ac",
							"p2pkh",
							"m/76'/0'/2"
						);
						"""],
			"update": """
						""",
		},
		"utxos": {
			"populate": ["""
						INSERT INTO UTXOs (txid, vout, amount, block_height, status, script_id) VALUES(
							"85859b3de6b4efe74d178911e4fd10d31995d9a71a36a7843a22da7dadc302ed",
							0,
							388416000,
							5,
							"unspent",
							1
						);""",
						"""
						INSERT INTO UTXOs (txid, vout, amount, block_height, status, script_id) VALUES(
							"85859b3de6b4efe74d178911e4fd10d31995d9a71a36a7843a22da7dadc302ed",
							1,
							382904000,
							5,
							"unspent",
							2
						);""",
						"""
						INSERT INTO UTXOs (txid, vout, amount, block_height, status, script_id) VALUES(
							"85859b3de6b4efe74d178911e4fd10d31995d9a71a36a7843a22da7dadc302ed",
							2,
							382904000,
							5,
							"unspent",
							3
						);
						"""],
			"update": """
						""",
		}
	},
}