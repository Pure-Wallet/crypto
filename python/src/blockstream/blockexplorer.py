import requests
from io import BytesIO


# --------------- API UTIL -----------------
MAIN_URL = 'https://blockstream.info/api/'
TEST_URL = 'https://blockstream.info/testnet/api/'

def post_api(endpoint, data, testnet=False):
    BASE_URL = TEST_URL if testnet else MAIN_URL
    url = BASE_URL + endpoint
    try: 
        response = requests.post(url, data)
    except Exception as e:
        response = e
    return handle_response(response)

def call_api(endpoint, testnet=False):
    """
    Build the API URL and request data
    :param str endpoint: specific api endpoint to hit
    :return response: server's reponse to the request
    """
    BASE_URL = TEST_URL if testnet else MAIN_URL
    url = BASE_URL + endpoint
    try:  # try to get json data
        response = requests.get(url).json()
    except ValueError:  # if bytes, convert to str
        response = requests.get(url).content.decode('utf-8')
    except Exception as e:
        response = e
    return handle_response(response)


def handle_response(response):
    """
    Responses from blockstream's API are returned in json or str
    :param response: http response object from requests library
    :return response: decoded response from api
    """
    if isinstance(response, Exception):
        print(response)
        return response
    else:
        return response

# ---------------FUNCTIONS-----------------

def get_transaction(tx_id, testnet=False):
    """
    Request information about a transaction by ID
    :param str tx_id: transaction ID 
    :return: an instance of :class:`Transaction` class
    """
    resource = f'tx/{tx_id}'
    tx_data = call_api(resource, testnet)
    return Transaction(tx_data, testnet)


def get_transaction_status(tx_id, testnet=False):
    """
    Request the transaction confirmation status
    :param str tx_id: transaction ID
    :return: an instance of :class:`TransactionStatus` class
    """
    resource = f'tx/{tx_id}/status'
    response = call_api(resource, testnet)
    return TransactionStatus(response, testnet)


def get_transaction_hex(tx_id,testnet=False):
    """
    Request the raw transaction in hex
    :param str tx_id: transaction ID
    :return: dictionary containing tx hex
    """
    resource = f'tx/{tx_id}/hex'
    response = call_api(resource, testnet)
    return response  # figure this better maybe


def get_transaction_merkle_proof(tx_id,testnet=False):
    """
    Request the merkle intrusion proof of a transaction
    :param str tx_id: transaction ID
    :return: an instance of :class:`TransactionMerkle` class
    """
    resource = f'tx/{tx_id}/merkle-proof'
    response = call_api(resource, testnet)
    return TransactionMerkleProof(response, testnet)


def get_transaction_output_status(tx_id, vout,testnet=False):
    """
    Request the spending status of a transaction output
    :param str tx_id: transaction ID
    :param str vout: transaction output
    :return: an instance of :class:`TransactionOutput` class
    """
    resource = f'tx/{tx_id}/outspend/{vout}'
    response = call_api(resource, testnet)
    return TransactionOutput(response, testnet)


def get_all_transaction_outputs_statuses(tx_id,testnet=False):
    """
    Request the spending status of all transaction outputs
    :param str tx_id: transaction ID
    :return list: a list of :class:`TransactionOutput` objects
    """
    resource = f'tx/{tx_id}/outspends'
    response = call_api(resource, testnet)
    outspends = []
    for output in response:
        outspends.append(TransactionOutput(output, testnet))
    return outspends


def post_transaction(tx_hex, testnet=False):
    """
    Broadcast a raw transaction to the network
    """
    return post_api("tx", tx_hex, testnet=testnet)
    


def get_address(address, testnet=False):
    """
    Request address information
    :param str address: a bitcoin address/scripthash
    :return: an instance of :class:`Address` class
    """
    resource = f'address/{address}'
    response = call_api(resource, testnet)
    #print(Address(response, testnet))
    return Address(response, testnet)

def get_address_transactions(address, testnet=False):
    """
    Request all transactions for an address, newest first
    """
    resource = f'address/{address}/txs'
    response = call_api(resource, testnet)
    transactions = []
    for tx in response:
        transactions.append(Transaction(tx, testnet))
    return transactions


def get_confirmed_transaction_history(address, testnet=False, ls_tx_id=''):
    """
    Request confirmed transaction history for an address, newest first
    25 per page
    :param str address: a bitcoin address
    :param str ls_tx_id: last transaction ID
    :return list: 
    """
    resource = f'address/{address}/txs/chain/{ls_tx_id}'
    response = call_api(resource, testnet)
    confirmed_transactions = []
    for tx in response:
        confirmed_transactions.append(Transaction(tx, testnet))
    return confirmed_transactions


def get_address_mempool(address,testnet=False):
    """
    Request unconfirmed transaction history of an address, newest first
    up to 50 transactions no paging
    :param str address: a bitcoin address
    :return list: a list of :class:`Transaction` objects
    """
    resource = f'address/{address}/txs/mempool'
    response = call_api(resource, testnet)
    mempool_transactions = []
    for tx in response:
        mempool_transactions.append(Transaction(tx, testnet))
    return mempool_transactions


def get_address_utxo(address,testnet=False):
    """
    Request the list of unspent transaction outputs associated with
    an address
    :param str address: a bitcoin address
    :return list: a list of :class:`UTXO` objects
    """
    resource = f'address/{address}/utxo'
    response = call_api(resource, testnet)
    utxo_list = []
    for utxo in response:
        utxo_list.append(UTXO(utxo, testnet))
    return utxo_list


def get_block_by_hash(block_hash,testnet=False):
    """
    Request a given block by hash
    :param str block_hash: a bitcoin block hash
    :return: an instance of :class:`Block` class
    """
    resource = f'block/{block_hash}'
    response = call_api(resource, testnet)
    return Block(response, testnet)


def get_block_by_height(height,testnet=False):
    """
    Request a given block by height
    :param str height: a bitcoin block height
    :return: an instance of :class:`Block` class
    """
    block_hash = get_block_hash_from_height(height, testnet)
    resource = f'block/{block_hash}'
    response = call_api(resource, testnet)
    return Block(response, testnet)


def get_block_hash_from_height(height,testnet=False):
    """
    Request a block hash by specifying the height
    :param str height: a bitcoin block height
    :return: a bitcoin block address
    """
    resource = f'block-height/{height}'
    return call_api(resource, testnet)


def get_block_status(block_hash,testnet=False):
    """
    Request the block status
    :param str block_hash: a bitcoin block hash
    :return: an instance of :class:`BlockStatus` class
    """
    resource = f'block/{block_hash}/status'
    response = call_api(resource, testnet)
    return BlockStatus(response, testnet)



def get_block_transactions(block_hash, testnet=False, start_index='0'):
    """
    Request a list of transactions in a block (up to 25)
    :param str block_hash: a bitcoin block hash
    :param str start_index: index of transaction list to start from
    """
    resource = f'block/{block_hash}/txs/{start_index}'
    response = call_api(resource, testnet)
    transactions = []
    for tx in response:
        transactions.append(Transaction(tx, testnet))
    return transactions


def get_transaction_ids(block_hash, testnet=False):
    """
    Request a list of all transaction IDs in a block
    :param str block_hash: a bitcoin block hash
    :return: a list of transaction IDs in the block
    """
    resource = f'block/{block_hash}/txids'
    response = call_api(resource, testnet)
    return response


def get_blocks(testnet=False, start_height=''):
    """
    Request the 10 newest blocks starting at tip (most recent)
    or at start_height (optional)
    :param str start_height: block height
    :return: a list of :class:`Block` objects
    """
    resource = f'blocks/{start_height}'
    response = call_api(resource, testnet)
    blocks = []
    for block in response:
        blocks.append(Block(block, testnet))
    return blocks


def get_last_block_height(testnet=False):
    """
    Request the height of the last block
    :return dict: most recent block height in bitcoin
    """
    resource = 'blocks/tip/height'
    return call_api(resource, testnet)


def get_last_block_hash(testnet=False):
    """
    Request the hash of the last block
    """
    resource = 'blocks/tip/hash'
    return call_api(resource, testnet)


def get_mempool(testnet=False):
    """
    Request mempool backlog statistics
    """
    resource = 'mempool'
    response = call_api(resource, testnet)
    return Mempool(response, testnet)


def get_mempool_transaction_ids(testnet=False):
    """
    Request the full list of transactions IDs currently in the mempool,
    as an array
    :return list: a list of transaction IDs
    """
    resource = 'mempool/txids'
    return call_api(resource, testnet)


def get_mempool_recent_transactions(testnet=False):
    """
    Request a list of the last 10 transactions to enter the mempool
    :return list: a list of transaction IDs
    """
    resource = 'mempool/recent'
    response = call_api(resource, testnet)
    transactions = []
    for tx in response:
        transactions.append(MempoolRecent(tx, testnet))
    return transactions


def get_fee_estimates(testnet=False):
    """
    Request an object where the key is the confirmation target (in number
    of blocks) and the value is estimated fee rate (in sat/vB)
    :return: an instance of :class:`FeeEstimate` class
    """
    resource = 'fee-estimates'
    response = call_api(resource, testnet)
    return FeeEstimates(response, testnet)


class BlockStatus:
    """Bitcoin block status utility."""
    def __init__(self, status, testnet=False):
        self.in_best_chain = status['in_best_chain']
        self.height = status['height']
        self.next_best = status['next_best']


class Block:
    """Bitcoin block utility class"""
    def __init__(self, block, testnet=False):
        self.id = block['id']
        self.height = block['height']
        self.version = block['version']
        self.timestamp = block['timestamp']
        self.tx_count = block['tx_count']
        self.size = block['size']
        self.weight = block['weight']
        self.merkle_root = block['merkle_root']
        self.previous_block_hash = block['previousblockhash']
        self.nonce = block['nonce']
        self.bits = block['bits']


class Address:
    """Bitcoin Address utility class."""
    def __init__(self, address, testnet=False):
        self.address = address['address']  # str
        self.chain_stats = address['chain_stats']  # dict
        self.mempool_stats = address['mempool_stats']  # dict


class UTXO:
    """Bitcoin UTXO utility class."""
    def __init__(self, utxo, testnet=False):
        self.tx_id = utxo['txid']
        self.vout = utxo['vout']
        self.status = TransactionStatus(utxo['status'])
        self.value = utxo['value']
        self.testnet = testnet
    def get_tx(self):
        return get_transaction(self.tx_id, self.testnet)


class TransactionStatus:
    """Transaction status utility."""
    def __init__(self, status, testnet=False):
        self.confirmed = status['confirmed']
        self.block_height = status['block_height']
        self.block_hash = status['block_hash']
        self.block_time = status['block_time']


class TransactionMerkleProof:
    """Tx Merkle proof utility."""
    def __init__(self, merkle, testnet=False):
        self.block_height = merkle['block_height']
        self.merkle = merkle['merkle']
        self.pos = merkle['pos']


class TransactionOutput:
    """Tx Output utility."""
    def __init__(self, output, testnet=False):
        self.spend = output['spent']
        self.tx_id = output['txid']
        self.vin = output['vin']
        self.status = TransactionStatus(output['status'])


class Transaction:
    """Bitcoin Transaction utility class."""
    def __init__(self, transaction, testnet=False):
        self.id = transaction['txid']
        self.version = transaction['version']
        self.locktime = transaction['locktime']
        self.vin = transaction['vin']
        self.vout = transaction['vout']
        self.size = transaction['size']
        self.weight = transaction['weight']
        self.fee = transaction['fee']
        self.status = TransactionStatus(transaction['status'])


class Mempool:
    """Bitcoin Mempool utility class."""
    def __init__(self, mempool, testnet=False):
        self.count = mempool['count']
        self.vsize = mempool['vsize']
        self.total_fee = mempool['total_fee']
        self.fee_histogram = mempool['fee_histogram']


class MempoolRecent:
    """Recent TXs in mempool utility."""
    def __init__(self, info, testnet=False):
        self.tx_id = info['txid']
        self.fee = info['fee']
        self.vsize = info['vsize']
        self.value = info['value']


class FeeEstimates:
    """Fee Estimates utility class."""
    def __init__(self, data, testnet=False):
        self.two_blocks = data['2']
        self.three_blocks = data['3']
        self.four_blocks = data['4']
        self.six_blocks = data['6']
        self.ten_blocks = data['10']
        self.twenty_blocks = data['20']
        self.onefourfour_blocks = data['144']
        self.fivezerofour_blocks = data['504']
        self.tenzeroeight_blocks = data['1008']

if __name__ == "__main__":
    # hx = get_transaction_hex("2f4262a2c2111799d0edf8591bb30b0cefe06cfb03a364a2dad37c18b4cd7ef4", testnet=False)
    # print(hx)
    reply = post_transaction("02000000014854f3a834d7c48653fbf71a52370903fe497918c8258bf4065a788808c26e11090000006a47304402207e0eeb6b059c0298059b942efe33522279ec857ccda1fd0a0f7b86c8a54b1b5d02200cb9ef4309c7306f71e3a92303e982102a8196947158d7aba60b3f218ebf4865012102853e01522ba5269df6fa210bb87ca14b2e630110ca56f05d0814461b5d5eeaaafeffffff02603270240100000017a91469f375f799932a576c56301e0d540a95c5236ae1874c28c317010000001976a9140b7adc14d6857c9d3bb25b3059b86a583beb41a588acb4be0900", testnet=False)
    print(reply)
