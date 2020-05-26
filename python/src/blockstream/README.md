# blockstream
A python 3 wrapper class for blockstream.info's Bitcoin block explorer API

Written in Python 3

Docs: https://github.com/pasquantonio/blockstream/blob/master/docs.md

Block explorer: https://blockstream.info

API Reference: https://github.com/Blockstream/esplora/blob/master/API.md

## Install
```
pip install blockstream
```

if not in a python3 virtualenv make sure to use python3
```
pip3 install blockstream
```

## Usage
```python
from blockstream import blockexplorer

# get transaction by id
tx_id = '56a5b477182cddb6edb460b39135a3dc785eaf7ea88a572052a761d6983e26a2'
tx = blockexplorer.get_transaction(tx_id)

# get address data
address = '3ADPkym6mQ2HyP7uASh5g3VYauhCWZpczF'
addr_info = blockexplorer.get_address(address)
```

## Examples
Reference examples.py to see each method in use

## Issues
the `scripthash` endpoint seems to be broken, however you can get data about a scripthash address by calling the `address` endpoint. I have decided to remove the functions to hit the `scripthash` endpoint for now.

## Donations
BTC: `3ADPkym6mQ2HyP7uASh5g3VYauhCWZpczF`
