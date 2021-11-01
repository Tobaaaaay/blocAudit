# from base64 import b64encode
# import rsa
# from cryptography.fernet import Fernet
# from io import BytesIO
# import csv
# import rsa
# from zipfile import ZipFile
# import boto3
# import logging
# import pandas as pd
# from flask import Flask,render_template,request,redirect,jsonify,make_response
# import os
# import shutil
# from werkzeug.utils import  secure_filename

# # filename = "heart.csv"
# # chunk_size = 30  # how many records I want per file
# # batchNumber = 1  # added to each chunked file for identification
# # name = filename.split(".",1)[0]
# # print("hekki")
# # print(name)

# # # error_bad_lines=False
# # storage =[]
# # for chunk in pd.read_csv(filename, chunksize=chunk_size):
# #     chunk.to_csv(name + str(batchNumber) + '.csv', index=False)
# #     storage.append(name + str(batchNumber) + '.csv')
# #     batchNumber += 1

# # for x in range(len(storage)):
# #     print storage[x]


# # sha256= SHA256.new()
# # sha256.update("Hello")
# # # print asha2.hexdigest()

# #---------------------ENCRYTPTION AND DECRYPTION----------------------------------------------

# #generate a public and private key and symmetric key
# symmetrickey = Fernet.generate_key()
# # print(symmetrickey)
# (publicKey,privateKey) = rsa.newkeys(2048)

# #write & store symmetric key to file
# writeSymmetricKey= f.open("symmetric.key","wb")
# writeSymmetricKey.write(symmetrickey)
# writeSymmetricKey.close()

# #write & store public key for RSA
# writePublicKey = f.open("public.key","wb")
# writePublicKey.write(publicKey)
# writePublicKey,close()

# #write & store private key for RSA
# writePrivateKey = f.open("private.key","wb")
# writePrivateKey.write(publicKey)
# writePrivateKey.close()

# #load key from symmetric file
# readsymmetrickey = open("symmetric.key","rb")
# skey = readsymmetrickey.read()

# #create the cipher with the loaded symmetric key
# cipher = Fernet(skey)

# #open file for encrytion
#  file = open("FILENAME",wb)
#  fileData = file.read()

# # encrypt and write the encrypted data
# encryptedData = cipher.encrypt(fileData)
# encryptedFile = open("ENCRYTEDFILENAME","wb")
# encryptedFile.write(encryptedData)

# #open & read the Public Key File
# pKey = open("public.key",)'rb')
# pKeYData = pKey.read()

# #load the publick fey from its file
# pubKey = rsa.PublicKey.load_pkcs1(pKeYData)

# #encrypt the symmetric key file with public key
# encrypt_key = rsa.encrypt(key,pubKey)

# #encrypt the encrypted symmetric to a file
# ekey= open('encrypt_key.key','wb')
# ekey.write(encrypt.key)


# #write the encrypted symmetric key to a file
# ekey = open(encrypted_key,"wb")
# ekey.write(encrypted_key)

# #load private key
# privKey = open('privatekey','rb')
# pKey = privKey,read()
# private_key = rsa.PrivateKey.load_pkcs1(privData)


# e = open('encrypted_key','rb')
# ekey = e.read()
# decryptedPublicKey = rsa.decrypt.(ekey,private_key)

# cipher=Fernet(decryptedPublicKey)

# #decrypt data with symmetric
# decrypt_data = cipher.decrypt(FILENAME)
# print(decrypt_data.decode())


# # share the encrypted symmetric

# #to decrypt the file you will need the encrypted symmetric key and the RSA private key


# #----------------------------0--------------------------------------------------------------------------------------------------------#





# message =b'hello there'
# crypto = rsa.encrypt(symmetrickey,publicKey)
# print(crypto)
# decrypt = rsa.decrypt(crypto,privateKey)
# print(decrypt)
# print(decrypt.decode())



#to decrypt the file you will need the encrypted symmetric key and the RSA private key
#-----------------------CODE to transfer files to Amazon Cloud--------------------------------------------------------------------#

# s3 = boto3.resource('s3')
# for bucket in s3.buckets.all():
    # print(bucket.name)

# def upload_file(file_name, bucket, object_name=None):
    # The upload_file method accepts a file name, a bucket name, and an object name. The method handles large files by splitting them into smaller chunks and uploading each chunk in parallel.

# import logging
# import boto3
# from botocore.exceptions import ClientError


# def upload_file(file_name, bucket, object_name=None):
#     """Upload a file to an S3 bucket

#     :param file_name: File to upload
#     :param bucket: Bucket to upload to
#     :param object_name: S3 object name. If not specified then file_name is used
#     :return: True if file was uploaded, else False
#     """
# The upload_file method accepts a file name, a bucket name, and an object name. The method handles large files by splitting them into smaller chunks and uploading each chunk in parallel.

# import logging
# import boto3
# from botocore.exceptions import ClientError


#  def upload_file(file_name, bucket, object_name=None):
#     """Upload a file to an S3 bucket

#     :param file_name: File to upload
#     :param bucket: Bucket to upload to
#     :param object_name: S3 object name. If not specified then file_name is used
#     :return: True if file was uploaded, else False
#     """

#     # If S3 object_name was not specified, use file_name
#     if object_name is None:
#         object_name = file_name

#     # Upload the file
#     s3_client = boto3.client('s3')
#     try:
#         response = s3_client.upload_file(file_name, bucket, object_name)
#     except ClientError as e:
#         logging.error(e)
#         return False
#     return True


#     # If S3 object_name was not specified, use file_name
#     if object_name is None:
#         object_name = file_name

#     # Upload the file
#     s3_client = boto3.client('s3')
#     try:
#         response = s3_client.upload_file(file_name, bucket, object_name)
#     except ClientError as e:
#         logging.error(e)
#         return False
#     return True


#------------------------------------------TESTED & WORKING MHT CONSTRUCTION-----------------------------------------------------------------------#

# def find_merkle_hash(file_hashes):
#     #find the merkle tree hashes of the files. Recursion is going to be used to solve this probles

#     blocks = []

#     if not file_hashes:
#         raise ValueError(
#             "Missing required file hashes for computing the merkle tree hash")
        
#     for m in file_hashes:
#         blocks.append(m)
    

#     list_len = len(blocks)
#     #adjust the block lenght of the hashes until we have an even number in the blocks,this entails appending to the end of the blocks the last entry

#     while list_len%2 != 0:
#         blocks.extend(blocks[-1:])
#         list_len = len(blocks)

#     secondary = []
#     for k in (blocks[x:x+2] for x in range(0,len(blocks),2)):

#         hasher = hashlib.sha256()
#         hasher.update(k[0].encode() + k[1].encode())

#         secondary.append(hasher.hexdigest())


#     #now because this is a recursice item , we have to determine it ends there is only one element in the list

#     if len(secondary) == 1:
#         return secondary [0][0:64]
#     else:
#         return find_merkle_hash(secondary)




# if __name__ == '__main__':
#     from zipfile import ZipFile

#     import uuid 
#     import hashlib
#     from base64 import b64encode
#     hashTags= []
#     dataInput= []

#     zipFile = "heart.zip"  

#     # read zipfile and contruct MHT root
#     archive = ZipFile(zipFile, 'r')

#     #stores the contents of each file in an array
#     for name in archive.namelist():
#         dataInput.append(name)

#     #stores the hashes of each element of the array dataInput in the file_hashes array
#     for value in dataInput:
#         hashTags.append(hashlib.sha256(value.encode()).hexdigest())
  
#     print ( "Finding the merkle tree hash of the" +str(len(hashTags))+ " random hashes") 
#     mk = find_merkle_hash(hashTags) 
#     print ("The merkel tree has of the hashes below is:  "+ format(mk))
    

#------------------------------------------ END OF TESTED & WORKING MHT CONSTRUCTION-----------------------------------------------------------------------#

#------------------------------------------  TESTED & WORKING DOWNLOAD DOCUMENT FROM CLOUD-----------------------------------------------------------------------#

# #connect to aws to read from file
# import boto3
# import botocore
# import logging



# BUCKET_NAME = "fyptest1"
# FILE_NAME =  "encryptedheart1symmetric.key"
# OBJECT_NAME = FILE_NAME


# s3 = boto3.client('s3')
# s3.download_file(BUCKET_NAME, OBJECT_NAME,FILE_NAME)

# )

# print("done")
#------------------------------------------ END OF TESTED & WORKING DOWNLOAD DOCUMENT FROM CLOUD-----------------------------------------------------------------------#
# from web3 import Web3


# ganache_url = "HTTP://127.0.0.1:7545"
# web3 = Web3(Web3.HTTPProvider(ganache_url))
# print(web3.isConnected())

# account = '0xA791C2c06fca7C1d8A6F0F72BB067f2b37bb308D'
# account_private_key ='4955573bf245ed596f69374bbbf59fe12ebc91ac3efdd2b9519552265db2fafb'
# nonce =web3.eth.getTransactionCount(account)
# tx ={
#     'nonce':nonce,
#     'to':
#     'value'
# }
#-------------------------------------------------------------------------------------------
    #OBTAIN ID AS STRING
# import sqlite3 

# conn = sqlite3.connect('audit.db') #to create a Database or connect to the database
# c = conn.cursor()
# id = "B"
# c.execute("""SELECT cloud_file_name FROM information WHERE id=? """,(id))
# data = c.fetchall()

# print(data)
# data2 = "".join(data[0])
# print(data2)
# print(data.format(",".join(["'{}'".format(string))))

#-----------------------------------------------------------------------
# from zipfile import ZipFile
# import hashlib
# from base64 import b64encode






# def find_merkle_hash(file_hashes):
#     #find the merkle tree hashes of the files. Recursion is going to be used to solve this probles

#     blocks = []

#     if not file_hashes:
#         raise ValueError(
#             "Missing required file hashes for computing the merkle tree hash")
        
#     for m in file_hashes:
#         blocks.append(m)
    

#     list_len = len(blocks)
#     #adjust the block lenght of the hashes until we have an even number in the blocks,this entails appending to the end of the blocks the last entry

#     while list_len%2 != 0:
#         blocks.extend(blocks[-1:])
#         list_len = len(blocks)

#     secondary = []
#     for k in (blocks[x:x+2] for x in range(0,len(blocks),2)):

#         hasher = hashlib.sha256()
#         hasher.update(k[0].encode() + k[1].encode())

#         secondary.append(hasher.hexdigest())


#     #now because this is a recursive item , we have to determine it ends if there is only one element in the list

#     if len(secondary) == 1:
#         return secondary [0][0:64]
#     else:
#         return find_merkle_hash(secondary)    

  

# zipFile = "heart.zip"  
# dataInput = []
# hashTags = []
# # read zipfile and contruct MHT root
# archive = ZipFile(zipFile, 'r')

# #stores the contents of each file in an array
# for name in archive.namelist():
#     # dataInput.append(name)
#     dataInput.append(archive.read(name))
# print("0")
# print(dataInput[0])
# print("1")

# for value in dataInput:
#     hashTags.append(hashlib.sha256(value).hexdigest())

# print(hashTags)

# root = find_merkle_hash(hashTags)

# print("Root")
# print(root)
###########################################################################################################################333
from base64 import b64encode
from zipfile import ZipFile
# from flas_sqlalchemy import SQLAlchemy
from datetime import datetime,timezone
import boto3
import uuid
import sqlite3 
# from web3 import Web3
import botocore
import hashlib
import logging
from io import BytesIO
import rsa
from cryptography.fernet import Fernet
import csv
import pandas as pd
from flask import Flask,render_template,request,redirect,jsonify,make_response,url_for
import os
import json
from web3 import Web3, HTTPProvider, exceptions
from werkzeug.utils import  secure_filename

#--------------------------------------------SOMEWHAT WORKING SMART CONTRACT CONNECTION CODE--------------------------------------------------------------------------------------------
# truffle development blockchain address
blockchain_address = 'http://127.0.0.1:7545'
# Client instance to interact with the blockchain
web3 = Web3(HTTPProvider(blockchain_address))

print(web3.isConnected())

# Set the default account (so we don't need to set the "from" for every transaction call)
web3.eth.default_account = web3.eth.accounts[0]
print("account:")
print(web3.eth.default_account)

# web3.eth.defaultAccount = web3.eth.accounts[0] #Deprecated

# Path to the compiled contract JSON file
compiled_contract_path = 'build/contracts/AuditingFinal.json'
# Deployed contract address (see `migrate` command output: `contract address`)
deployed_contract_address = '0x593b6413F3b81784343cF741b52E8531C8bEB727'
# '0xc2149913D8B40008a658F08a029e609024F941f4'

with open(compiled_contract_path) as file:
    contract_json = json.load(file)  # load contract info as JSON
    contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    # contract_bytecode = contract_json['bytecode']  # fetch contract's abi - necessary to call its functions

# print(deployed_contract_address)
# print(contract_abi)

# Fetch deployed contract reference

contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)

# try:
contract.functions.setAuditDatabase("idjjjj","hashTa","Tobi Oluwa").transact()
    # sayMessage
    # print(contract.functions.sayMessage("hello").transact())
    # print(contract_bytecode)
    # print(contract.functions.sayHello().call())
print("hii")
# except exceptions.SolidityError as error:
#     print(error)
