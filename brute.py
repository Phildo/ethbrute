from multikdf.scrypt import scrypt_kdf
import hashlib
import sha3
import json

with open('../wallet.json') as wallet_file:
  wallet = json.load(wallet_file)

dklen = 32
salt = bytearray.fromhex(wallet["crypto"]["kdfparams"]["salt"])
r = 8
p = 1
n = 18 #262144 #NOTE- put Log BASE2 n here. so, if n = 262144 in the .json wallet file, put 18 here
ciphertext = bytearray.fromhex(wallet["crypto"]["ciphertext"])
mac = bytearray.fromhex(wallet["crypto"]["mac"])

file = open("../password.txt", "r")
for line in file:
    password = line.strip('\n')
    print ("trying "+password)

    derived_key = scrypt_kdf(password, salt, r, p, n, dklen)[16:32]
    concat = derived_key + ciphertext

    k = sha3.keccak_256()
    k.update(concat)
    hashconcat = bytearray.fromhex(k.hexdigest())

    if hashconcat == mac:
        print (password + " WORKED!")
        exit()

