import hashlib
import base58
import os
import struct
import binascii
import bsddb3 as bsddb
from Crypto.Hash import RIPEMD160

# Mesaj de avertizare
def print_warning():
    print("********************************************************")
    print("*                   LOGO BEKLI23                       *")
    print("* Acest script este privat. Strict interzis pentru public *")
    print("********************************************************\n")

def tohex(data):
    return data.hex()

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def pubkeytopubaddress(pubkey):
    digest = sha256(pubkey)
    ripemd = ripemd160(digest)
    prefixed_ripemd = b'\x00' + ripemd
    checksum = sha256(sha256(prefixed_ripemd))[:4]
    address = prefixed_ripemd + checksum
    return base58.b58encode(address)

def hex_padding(s, length):
    return s.zfill(length)

def read_encrypted_key(wallet_filename):
    with open(wallet_filename, "rb") as wallet_file:
        wallet_file.seek(12)
        if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            print("ERROR: file is not a Bitcoin Core wallet")
            return None

    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
    db = bsddb.db.DB(db_env)

    try:
        db.open(wallet_filename, "main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    finally:
        db.close()
        db_env.close()

    if not mkey:
        raise ValueError("Encrypted master key not found in the Bitcoin Core wallet file")

    encrypted_master_key, salt, method, iter_count = struct.unpack_from("<49p9pII", mkey)

    if method != 0:
        print("warning: unexpected Bitcoin Core key derivation method ", str(method))

    iv = binascii.hexlify(encrypted_master_key[16:32]).decode()
    ct = binascii.hexlify(encrypted_master_key[-16:]).decode()
    iterations = hex_padding('{:x}'.format(iter_count), 8)

    target_mkey = binascii.hexlify(encrypted_master_key).decode() + binascii.hexlify(salt).decode() + iterations
    mkey_encrypted = binascii.hexlify(encrypted_master_key).decode()

    print(f"Mkey_encrypted: {mkey_encrypted}")
    print(f"target mkey  : {target_mkey}")
    print(f"ct           : {ct}")
    print(f"salt         : {binascii.hexlify(salt).decode()}")
    print(f"iv           : {iv}")
    print(f"rawi         : {iterations}")
    print(f"iter         : {str(int(iterations, 16))}")

def read_wallet(file_path):
    print_warning()  # Afișează mesajul de avertizare

    read_encrypted_key(file_path)  # Afișează valorile iter, rawi, iv, salt, ct și Mkey_encrypted

    with open(file_path, 'rb') as wallet:
        data = wallet.read()

    mkey_offset = data.find(b'mkey')
    if mkey_offset == -1:
        print("There is no Master Key in the file")
        return

    mkey_data = data[mkey_offset - 72:mkey_offset - 72 + 48]
    print(f"Mkey_encrypted: {tohex(mkey_data)}")

    offset = 0

    ckey_offset = data.find(b'ckey', offset)
    if ckey_offset != -1:
        ckey_data = data[ckey_offset - 52:ckey_offset - 52 + 123]
        ckey_encrypted = ckey_data[:48]
        public_key_length = ckey_data[56]
        public_key = ckey_data[57:57 + public_key_length]

        print(f"encrypted ckey: {tohex(ckey_encrypted)}")
        print(f"public key    : {tohex(public_key)}")
        print(f"public address: {pubkeytopubaddress(public_key)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} 8.5btc.dat")
        sys.exit(0)

    read_wallet(sys.argv[1])
