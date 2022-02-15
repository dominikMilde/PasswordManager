import sys
from os import path

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

try:
    ################
    ###   INIT  ####
    ################
    if sys.argv[1] == "init":
        if len(sys.argv) == 3:
            initSalt = get_random_bytes(16)
            initString = b'testingString:testnaLozinka\n'
            key = PBKDF2(sys.argv[2], initSalt, 16, count=100000, hmac_hash_module=SHA256)

            cipher = AES.new(key, AES.MODE_GCM)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(initString);

            f = open("tajnik.bin", "wb")
            f.write(initSalt)
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
            f.close()

            print("Tajnik je inicijaliziran.")
        else:
            print("Krivi format unosa! Primjer ispravnog unosa argumenta: init masterLozinka")

    ################
    ###   PUT   ####
    ################
    if sys.argv[1] == "put":
        if len(sys.argv) == 5:
            if path.exists("tajnik.bin"):
                f = open("tajnik.bin", "rb")
                rSalt = f.read(16)
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()
                f.close()
                key = PBKDF2(sys.argv[2], rSalt, 16, count=100000, hmac_hash_module=SHA256)

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    print("Master lozinka kriva ili je dokument kompromitiran od treće strane!")
                    exit(0)
                list = plaintext.split(b'\n')
                dictionary = {}
                for i in range(0, len(list)-1):
                    splitted = list[i].split(b':')
                    dictionary[splitted[0]] = splitted[1]
                dictionary[str.encode(sys.argv[3])] = str.encode(sys.argv[4]) #stavi vrijednost iz ispisa

                #složi sve u bytove i generiraj salt i nonce, enkriptiraj pomoću masterPass
                combined = b''
                for key in dictionary:
                    combined += key + b':' + dictionary[key] + b'\n'

                #print(combined)
                salt = get_random_bytes(16)
                key = PBKDF2(sys.argv[2], salt, 16, count=100000, hmac_hash_module=SHA256)

                cipher = AES.new(key, AES.MODE_GCM)
                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(combined);

                f = open("tajnik.bin", "wb")
                f.write(salt)
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
                f.close()
                print("Unijeta lozinka za:", sys.argv[3])
            else:
                print("Potrebno je prvo inicijalizirati tajnika naredbom: put masterLozinka www.fer.hr ferLozinka")
        else:
            print("Krivi format unosa! Primjer dobrog unosa: put masterLozinka.")

    ################
    ###   GET   ####
    ################
    if sys.argv[1] == "get":
        if len(sys.argv) == 4:
            if path.exists("tajnik.bin"):
                f = open("tajnik.bin", "rb")
                rSalt = f.read(16)
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()
                f.close()
                key = PBKDF2(sys.argv[2], rSalt, 16, count=100000, hmac_hash_module=SHA256)

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    print("Master lozinka kriva ili je dokument kompromitiran od treće strane!")
                    exit(0)
                list = plaintext.split(b'\n')
                dictionary = {}
                for i in range(0, len(list)-1):
                    splitted = list[i].split(b':')
                    dictionary[splitted[0]] = splitted[1]

                if str.encode(sys.argv[3]) in dictionary:
                    password = dictionary[str.encode(sys.argv[3])].decode("UTF-8")
                    print("Lozinka za", sys.argv[3], "je", password)
                else:
                    print("Nema te adrese u tajniku.")
                # složi sve u bytove i generiraj salt i nonce, enkriptiraj pomoću masterPass
                combined = b''
                for key in dictionary:
                    combined += key + b':' + dictionary[key] + b'\n'

                salt = get_random_bytes(16)
                key = PBKDF2(sys.argv[2], salt, 16, count=100000, hmac_hash_module=SHA256)

                cipher = AES.new(key, AES.MODE_GCM)
                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(combined);

                f = open("tajnik.bin", "wb")
                f.write(salt)
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
                f.close()

            else:
                print("Potrebno je prvo inicijalizirati tajnika naredbom: init mojaLozinka")
        else:
            print("Krivi format unosa! Primjer dobrog unosa: get masterLozinka www.fer.hr")

except IndexError:
    print("Greška u unosu.")