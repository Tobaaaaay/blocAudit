#DataBase Implementation: get filename of symmetric,encryptedSymmetric ,private key, unique ID(using currentData and Time),zip File Name, and Amazon ID,
#and maybe orignal ,MHT root, MHT ROOT constructed by the smart contract, MHT root constructed by the cloud
#use My Sql to compare and contrast the 3 different roots

from datetime import datetime,timezone
import sqlite3 

conn = sqlite3.connect('audit.db') #to create a Database or connect to the database
c = conn.cursor() #create a cursor

# c.execute("""CREATE TABLE information(
#     id TEXT  NOT NULL PRIMARY KEY,
#     cloud_file_name TEXT,
#     date_created TEXT,
#     user_uploaded TEXT ,
#     date_last_audited TEXT ,
#     MHT_Root_local TEXT ,
#     MHT_Root_cloud TEXT ,
#     MHT_Root_blockchain TEXT 
# 
#      )""")

hello = "gello"
c.execute("""INSERT INTO information VALUES(hello,"b","c","e",NULL,"y","e","t")            """)
c.execute("""SELECT * FROM information           """)
rows = c.fetchall()
for rows in rows:
    print(rows)

conn.commit()
conn.close()






