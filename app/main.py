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

#--------------------------------------------WORKING SMART CONTRACT CONNECTION CODE--------------------------------------------------------------------------------------------
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
deployed_contract_address = '0xA6D39dEe4B4c7B251B4a3AB08B5Ac149C0c7a2A1'
# '0xc2149913D8B40008a658F08a029e609024F941f4'

with open(compiled_contract_path) as file:
    contract_json = json.load(file)  # load contract info as JSON
    contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions

print(deployed_contract_address)
print(contract_abi)
# print(contract_bytecode)

# Fetch deployed contract reference

contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)






app = Flask(__name__)













# ganache_url = "HTTP://127.0.0.1:7545"
# web3 = web3(web3.HTTPProvider(ganache_url))
# print(web3.isConnected())







    # https://www.blopig.com/blog/2016/08/processing-large-files-using-python/
    # with open("input.txt") as f:
    #     for line in f:
    #         ciphertext= cipher.encrypt_and_digest(line)
    #         with open ("encrypted.txt", "w+"):
    #             f.write(b64encode(x).decode('utf-8') for x in ciphertext)

#to connect to SQLite database using FLASK-SQLAlchemy
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///audit.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db =SQLAlchemy(app)


app.config["UPLOAD_FOLDER"] = "/home/tobss/Desktop/FYPBlocAudit/app/src/fileUploads" 
app.config["ALLOWED_FILE_EXTENSIONS"] = ["CSV"] #only csv files are allowed



#------------------------------------------END OF CONNECTION TO SMART CONTRACT-----------------------------------------------------------
def allowed_file(filename):
    if not"." in filename:
        return False

    ext = filename.rsplit(".",1)[1]

    if ext.upper() in app.config["ALLOWED_FILE_EXTENSIONS"]:
        print("ALLOWED")
        return True
    else:
        print("NOT ALLOWED")
        return False


def hybridEncryption(chunkFileName,fileToEncrypt): #Utilises RSA and Fernet encryption

    
    #generate a public and private key and symmetric key
    symmetrickey = Fernet.generate_key()
    print(symmetrickey)
    print("public")
    (publicKey,privateKey) = rsa.newkeys(2048)
    print(publicKey)

    #generate symmetric key file name,public key file name, private key file name
    symmetrickeyFileName = chunkFileName + "symmetric.key"
    privatekeyFileName =  chunkFileName + "private.key"
    publickeyFileName = chunkFileName +"public.key"
    encrytedSymmetrickeyFileName = "encrypted" + symmetrickeyFileName

    #write & store symmetric key to file
    writeSymmetricKey= open(symmetrickeyFileName,"wb")
    writeSymmetricKey.write(symmetrickey)
    writeSymmetricKey.close()

    #write & store public key for RSA
    writePublicKey = open(publickeyFileName,"wb")
    writePublicKey.write(publicKey.save_pkcs1('PEM'))
    writePublicKey.close()

    #write & store private key for RSA
    writePrivateKey = open(privatekeyFileName,"wb")
    writePrivateKey.write(privateKey.save_pkcs1('PEM'))

    # writePrivateKey.write(publicKey)
    writePrivateKey.close()

    #load key from symmetric file
    readsymmetrickey = open(symmetrickeyFileName,"rb")
    skey = readsymmetrickey.read()

    #create the cipher with the loaded symmetric key
    cipher = Fernet(skey)

    #open file for encrytion
    
    file = open(fileToEncrypt,"rb")
    fileData = file.read()

    # encrypt and write the encrypted data / also encrypt the file name 
    encryptedData = cipher.encrypt(fileData)
    print(chunkFileName)
    chunkFileName = chunkFileName.encode('utf-8')
    encryptedChunkFileName = cipher.encrypt(chunkFileName)
    encryptedFile = open(encryptedChunkFileName,"wb")
    encryptedFile.write(encryptedData)

    #open & read the Public Key FileencryptedChunkFileName
    pKey = open(publickeyFileName,'rb')
    pKeYData = pKey.read()

    #load the publick fey from its file
    pubKey = rsa.PublicKey.load_pkcs1(pKeYData)

    #encrypt the symmetric key file with public key
    # encrypt_key = rsa.encrypt(key,pubKey)
    encrypt_key = rsa.encrypt(symmetrickey,pubKey)

    #write the encrypted symmetric to a file
    # ekey= open('encrypt_key.key','wb')
    ekey = open(encrytedSymmetrickeyFileName,'wb')
    ekey.write(encrypt_key)
    ekey.close()

    return encryptedChunkFileName.decode()



    


    # #write the encrypted symmetric key to a file
    # ekey = open(encrypted_key,"wb")
    # ekey.write(encrypted_key)


#-----------------To Decrypt Data----------------------------------------------------------------------------#
    #load private key
    # privKey = open('privatekey','rb')
    # privKey = open()
    # pKey = privKey,read()
    # private_key = rsa.PrivateKey.load_pkcs1(privData)


    # e = open('encrypted_key','rb')
    # ekey = e.read()
    # decryptedPublicKey = rsa.decrypt(ekey,private_key)

    # cipher=Fernet(decryptedPublicKey)

    # #decrypt data with symmetric
    # decrypt_data = cipher.decrypt(FILENAME)
    # print(decrypt_data.decode())


    # share the encrypted symmetric

    #to decrypt the file you will need the encrypted symmetric key and the RSA private key


def dataCompression(files , zipName):
    # Create a ZipFile Object
    zipFile = zipName +".zip"
    with ZipFile(zipFile, 'w') as zipObj: 
        for x in files:
            print
            zipObj.write(x) #store files in the the zip object



  

def upload_fileToAmazonAWS(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # # Upload the file
    # s3_client = boto3.client('s3')
    # try:
    #     response = s3_client.upload_file(file_name, bucket, object_name)
    # # except ClientError as e:
    # except botocore.exceptions.ClientError as error:
    #     logging.error(e)
    #     return False
    # return True


    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name
   # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def find_merkle_hash(file_hashes):
    #find the merkle tree hashes of the files. Recursion is going to be used to solve this probles

    blocks = []

    if not file_hashes:
        raise ValueError(
            "Missing required file hashes for computing the merkle tree hash")
        
    for m in file_hashes:
        blocks.append(m)
    

    list_len = len(blocks)
    #adjust the block lenght of the hashes until we have an even number in the blocks,this entails appending to the end of the blocks the last entry

    while list_len%2 != 0:
        blocks.extend(blocks[-1:])
        list_len = len(blocks)

    secondary = []
    for k in (blocks[x:x+2] for x in range(0,len(blocks),2)):

        hasher = hashlib.sha256()
        hasher.update(k[0].encode() + k[1].encode())

        secondary.append(hasher.hexdigest())


    #now because this is a recursive item , we have to determine it ends if there is only one element in the list

    if len(secondary) == 1:
        return secondary [0][0:64]
    else:
        return find_merkle_hash(secondary)    

  



@app.route("/", methods=['GET','POST'])
def landingPage():
    print(contract)
    # if request.method == 'GET':
        # if request.form['signIn_button']:
            # message = contract_instance.functions.signIn().call()
            # print(message)
            # if message == "true" :
            #     return redirect(url_for('upload_File'))

    if "signIn_button" in request.form:
        print("sign in button clicked")
        # message = contract.functions.signIn().call()
        try:
            # print( contract.functions.getUsername.estimateGas())
            # message = contract.functions.sayHello().call({'from': web3.eth.default_account,'gas': 200000})
            message = contract.functions.signIn().call()
            contract.functions.register("Tobi Oluwa",True).transact()
            # print(message) 
            # print(contract.functions.getUsername.call())
            
        except exceptions.SolidityError as error:
            print(error)
        if message == True:
            return redirect(url_for('homepage'))
        else:
            print(message)

            return redirect(url_for('landingPage.html'))

    elif "register_button" in request.form:
        try:
            print(contract)
            print("register button clicked")
            #register the Username as Tobi Oluwa
            contract.functions.register("Tobi Oluwa",True).transact()

        except exceptions.SolidityError as error:
            print(error)

        # while contract.functions.register.call({'from': web3.eth.default_account,'gas': 200000}) == None:
        # message
        # if message == "true":
        #     return redirect(url_for('home'))
        # else:
            print("Already Registered")
            # return redirect(url_for('homepage'))
    return render_template("landingPage.html")#the html file
            


@app.route("/home", methods=['GET','POST'])
def homepage():
    if "upload_button" in request.form:
        return redirect(url_for('uploadFile'))

    if "audit_button" in request.form:
        return redirect(url_for('auditData'))

    return render_template("homepage.html")#the html file





@app.route("/uploadFile", methods=['GET','POST'])
def uploadFile():
    if request.method == 'POST':

        if request.files:
            file = request.files["file"]
            print(file)
            if file.filename =="":
                print("File must have a name")
                return redirect(request.url)

            if allowed_file(file.name):
                print("The file extension is not allowed")
                return  redirect(request.url)
            else:
                filename = secure_filename(file.filename) #gives a secure filename

            # file.save(os.walk(path),file.filename)
            # +-file.save(os.path.join(app.config["UPLOAD_FOLDER"]),file.filename)
            file.save(os.path.join(os.getcwd(),file.filename))
            # print(request.files["chunkSize"])
            print("file saved")

#-------------------------------------------------------------------------------------------------------------------------------

#To split the uploaded file into the input amount of chunks
            filename2 = file.filename
            chunk_size = 30  # how many records I want per file
            batchNumber = 1  # added to each chunked file for identification
            name = filename2.split(".",1)[0] #The original file name without file extension
            print("hekki")
            print(name)

            # error_bad_lines=False
            storage =[]
            encryptedFileNamesList = []
            for chunk in pd.read_csv(filename2, chunksize=chunk_size):
                chunk.to_csv(name + str(batchNumber) + '.csv', index=False)
                newChunkName =name + str(batchNumber)  #new name is the chunk name
                newChunkFile = name +str(batchNumber)+'.csv'
                
                # encryptedFileNamesList = hybridEncryption(newChunkName, newChunkFile)
                encryptedFileNamesList.append(hybridEncryption(newChunkName, newChunkFile))

                storage.append(newChunkFile)
                
                batchNumber += 1


            for x in range(len(encryptedFileNamesList)):
                print(encryptedFileNamesList[x])

            for x in range(len(storage)):
                print (storage[x])
    
#-------------------------------------------------------------------------------------------------------------------------------
    
            # To compress files into zip using the encryptedFileNamesList as a reference
            #Data Compression using python in built data compression
            dataCompression(encryptedFileNamesList,name)
            zipFile = name + ".zip"
            bucket = "fyptest1"
            object_name = None
            #To store the zipfile on amazon cloud services
            upload_fileToAmazonAWS(zipFile, bucket,object_name)

#-------------------------------------------------------------------------------------------------------------------------------
            #read zipfile and contruct MHT root
            hashTags = []
            
            dataInput= []
            

            # zipFile = "heart.zip"  

            # read zipfile and contruct MHT root
            archive = ZipFile(zipFile, 'r')

            #stores the contents of each file in an array
            for name in archive.namelist():
                # dataInput.append(name)
                dataInput.append(archive.read(name))

            #stores the hashes of each element of the array dataInput in the file_hashes array
            for value in dataInput:
                print(hashlib.sha256(value))
                hashTags.append(hashlib.sha256(value).hexdigest())

        
            print ( "Finding the merkle tree hash of the " +str(len(hashTags))+ " random hashes") 
            mk = find_merkle_hash(hashTags) 
            print ("The merkle tree root has of the hashes below is:  "+ format(mk))

         


#-------------------------------------------------------------------------------------------------------------------------------            
          
            #construct Database in databasetest.py and connect  to it using SQLAlchemy
            currentTime = datetime.now(timezone.utc)
        
            # id = zipFile + str(currentTime)
            id = str(uuid.uuid4().hex)
            cloud_file_name = zipFile
            data_created =str(currentTime)
            user_uploaded = None
            date_last_audited = None
            MHT_Root_local = mk
            MHT_Root_cloud = None
            MHT_Root_blockchain = None

            #To connect to SQLite3 Database
            conn = sqlite3.connect('audit.db') #to create a Database or connect to the database
            c = conn.cursor()

            #insert data into the database
            c.execute("INSERT INTO information VALUES(?,?,?,?,?,?,?,?)",(id,cloud_file_name,data_created,user_uploaded,date_last_audited,MHT_Root_local,MHT_Root_cloud,MHT_Root_blockchain))
            conn.commit()
            conn.close()

            print("All values stored into database")
            print(hashTags)
            #to store merkle hash tags in Ethereum Blockchain
            print(contract.functions.signIn().call())
            # print(contract.functions.getUsername().call())
            try:
                contract.functions.setAuditDatabase(id,hashTags,cloud_file_name,"Tobi Oluwa").transact()
                print("TRY")
                # print(contract.functions.getMerkleRoot(id).call())
                # contract.functions.setAuditDatabase("idnnn","hashTa","Tobi Oluwa").transact()
            except exceptions.SolidityError as error:
                print(error)
            print("successfully added to Blockchain")
            #DataBase Implementation: get filename of symmetric,encryptedSymmetric ,private key, unique ID(using currentData and Time),zip File Name, and Amazon ID,
            #and maybe orignal ,MHT root, MHT ROOT constructed by the smart contract, MHT root constructed by the cloud
            #use My Sql to compare and contrast the 3 different roots

            #store file names in an array
           
     

            return redirect(request.url)


    return render_template("upload_File.html")#the html file




@app.route("/dataAuditing", methods=['GET','POST'])
def auditData():
    conn = sqlite3.connect('audit.db') #to create a Database or connect to the database
    c = conn.cursor()
 
    c.execute('SELECT * FROM information')
    data = c.fetchall()
    print(data)
    conn.close()

    return render_template("auditTable.html",data = data)#the html file

@app.route('/Audit/<id>', methods = ['POST', 'GET'])
def audit(id):
    #get the name of the zip file
    conn = sqlite3.connect('audit.db') #to connect to the database
    c = conn.cursor()
    print(id)
    c.execute("SELECT cloud_file_name FROM information WHERE id = ?",(id,))
    data = c.fetchall()
    data = "".join(data[0])

    #Retrieve Merkle Hash Tags from Blockchain



    

    #download file from cloud
    BUCKET_NAME = "fyptest1"
    FILE_NAME =  data
    OBJECT_NAME = FILE_NAME


    s3 = boto3.client('s3')
    s3.download_file(BUCKET_NAME, OBJECT_NAME,FILE_NAME)
    
    hashTags = []
    dataInput = []
    #read downloaded zipfile and contruct MHT root
    archive = ZipFile(data, 'r')

    #stores the downloaded contents of each file in an array
    for name in archive.namelist():
        # dataInput.append(name)
        dataInput.append(archive.read(name))



    #stores the hashes of each element of the  array dataInput in the file_hashes array
    for value in dataInput:
        hashTags.append(hashlib.sha256(value).hexdigest())
    #find merkle root f cloud data
    print ( "Finding the merkle tree hash of the" +str(len(hashTags))+ " random hashes") 
    mk = find_merkle_hash(hashTags) 
    print ("The merkle tree has of the hashes below is:  "+ format(mk))

    #obtain MHT Root from hashtags stored in blockchai
    blockchainMHT_hashtags = contract.functions.getMerkleRoot(id).call()
    blockchainMHT_root = find_merkle_hash(blockchainMHT_hashtags)

    # conn.execute("UPDATE STUDENT set ROLL = 005 where ID = 1")
    c.execute("UPDATE information SET MHT_Root_blockchain = ?, MHT_Root_cloud = ? WHERE id = ? ",(blockchainMHT_root,mk,id))
    

    c.execute('SELECT * FROM information')
    data = c.fetchall()
    conn.close()
    redirect(url_for('auditData'))

    return render_template("auditTable.html",data = data)#the html file





if __name__ == '__main__':
    app.run()




