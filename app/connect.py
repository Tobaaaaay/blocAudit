import json
from web3 import Web3, HTTPProvider

# create a web3.py instance w3 by connecting to the local Ethereum node
w3 = Web3(HTTPProvider("http://localhost:8545"))

print(w3.isConnected())

# Initialize a local account object from the private key of a valid Ethereum node address
# local_acct = w3.eth.account.from_key("9517a80001914e71972ed6cab371090b65dfa503c0ce2dc6fa02e46137149ef1")
local_acct = w3.eth.account.from_key("b4707a85f5777123d53e5c08cf10ccb46b8781470712eddf6da1594c2976317d")

# compile your smart contract with truffle first
truffleFile = json.load(open('./build/contracts/AuditingFinal.json'))
abi = truffleFile['abi']
bytecode = truffleFile['bytecode']

# Initialize a contract object with the smart contract compiled artifacts
contract = w3.eth.contract(bytecode=bytecode, abi=abi)

# build a transaction by invoking the buildTransaction() method from the smart contract constructor function
# construct_txn = contract.constructor(3000, '0xb95A8c720bbDD408f97CccF07de6ceD493bDbc74').buildTransaction({
    
construct_txn = contract.constructor(3000, '0xAC83c83579495Cb09F39453Afce2b9b8BBDaD8e8').buildTransaction({
    'from': local_acct.address,
    'nonce': w3.eth.getTransactionCount(local_acct.address),
    'gas': 1728712,
    'gasPrice': w3.toWei('21', 'gwei')})

# sign the deployment transaction with the private key
signed = w3.eth.account.sign_transaction(construct_txn, local_acct.key)

# broadcast the signed transaction to your local network using sendRawTransaction() method and get the transaction hash
tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
print(tx_hash.hex())

# collect the Transaction Receipt with contract address when the transaction is mined on the network
tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print("Contract Deployed At:", tx_receipt['contractAddress'])
contract_address = tx_receipt['contractAddress']

# Initialize a contract instance object using the contract address which can be used to invoke contract functions
contract_instance = w3.eth.contract(abi=abi, address=contract_address)