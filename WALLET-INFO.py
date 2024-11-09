#!/usr/bin/env python2
import textwrap
import pyfiglet
import sys, os.path, bsddb.db, struct, binascii
from Crypto.Cipher import AES
import pbkdf2


banner_text = "BTC CRACK"
wrapped_text = "\n".join(textwrap.wrap(banner_text, width=30))
banner = pyfiglet.figlet_format(wrapped_text)
print(banner)

#Print Welcome message
print('https://t.me/+TtAIawVFhwEyMzdk')
print ("                                     \n")
print ("                                     \n")

def hex_padding(s, length):
    if len(s) % length != 0:
        r = (length) - (len(s) % length)
        s = "0" * r + s
    return s


def read_encrypted_key(wallet_filename):
    with open(wallet_filename, "rb") as wallet_file:
        wallet_file.seek(12)
        if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            print(prog+": ERROR: file is not a Bitcoin Core wallet")
            sys.exit(1)

        db_env = bsddb.db.DBEnv()
        db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
        db = bsddb.db.DB(db_env)

        db.open(wallet_filename, b"main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
        db.close()
        db_env.close()

        if not mkey:
            raise ValueError("Encrypted master key not found in the Bitcoin Core wallet file")

        encrypted_master_key, salt, method, iter_count = struct.unpack_from("< 49p 9p I I", mkey)

        if method != 0:
            print(prog+": warning: unexpected Bitcoin Core key derivation method ", str(method))

        print("mkey: " + binascii.hexlify(mkey))
        print("mk  : " + binascii.hexlify(encrypted_master_key))

        iv = binascii.hexlify(encrypted_master_key[16:32])
        ct = binascii.hexlify(encrypted_master_key[-16:])
        iterations = hex_padding('{:x}'.format(iter_count), 8)

        print("ct  : " + ct)
        print("salt: " + binascii.hexlify(salt))
        print("iv  : " + iv)
        print("rawi: " + iterations)
        print("iter: " + str(int(iterations, 16)))

        return encrypted_master_key, salt, iv, ct, iterations


def decrypt_master_key(encrypted_master_key, salt, iv, ct, iterations):
    passphrase = "YOUR_PREDEFINED_KEY"  # Replace this with your own key
    key = pbkdf2.PBKDF2(passphrase, salt, int(iterations, 16))
    cipher = AES.new(key.read(32), AES.MODE_CBC, binascii.unhexlify(iv))
    master_key = cipher.decrypt(binascii.unhexlify(ct))
    return master_key.rstrip()



######### main

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage: walletinfo.py WALLET_FILE")
    sys.exit(2)

wallet_filename = os.path.abspath(sys.argv[1])
encrypted_key, salt, iv, ct, iterations = read_encrypted_key(wallet_filename)


# Prompt for the passphrase to decrypt the master key
passphrase = raw_input("Enter the passphrase: ")


try:
    master_key = decrypt_master_key(encrypted_key, salt, iv, ct, iterations)
    print("Decrypted Master Key: " + binascii.hexlify(master_key))
    # Additional steps for validating the wallet file can be performed here
except Exception as e:
    print("Decryption failed: " + str(e))
