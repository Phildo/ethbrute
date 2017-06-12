from multikdf.scrypt import scrypt_kdf
import sha3

dklen = 32
salt = bytearray.fromhex("d77fe79c1162d34e85994a338e815d3904c171c67cc3f72d4b433aa19dbc7bb1")
r = 8
p = 1
n = 18 #262144
ciphertext = bytearray.fromhex("c6d18f78af6e5e7cea4ab804d8b9a5f974ccf92ea2537416b90abebd77c6b580")
mac = bytearray.fromhex("89655fd4bb9ccf9de0d8f1a78025a8616c9416ec700cfaafef17e76c7c47338e")

real_password = "thisisatestwallet"

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

