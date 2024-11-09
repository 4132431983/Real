import hashlib
import base58
import binascii

decrypted_master_key = "88128a4daa4ff191d5015b883cac3064"

# Step 1: Concatenate raw private key with salt and iv
rawi = "0002bd10"
salt = "e7407357d2f9e7ff"
iv = "4aab999ff2b818f440361da8496509fe"
concatenated_string = rawi + salt + iv

# Step 2: Convert concatenated string to byte array
seed = binascii.unhexlify(concatenated_string)

# Step 3: Apply KDF (PBKDF2)
iterations = 100000  # Update the number of iterations as needed
derived_key = hashlib.pbkdf2_hmac('sha256', seed, binascii.unhexlify(salt), iterations, dklen=32)

# Step 4: Convert derived key to hex-encoded string
hex_derived_key = binascii.hexlify(derived_key).decode()

# Step 5: Convert derived key to WIF key
decoded_key = binascii.unhexlify(hex_derived_key)

# Add WIF version byte
decoded_key_with_prefix = b"\x80" + decoded_key

# Perform double SHA-256 hash
hash1 = hashlib.sha256(decoded_key_with_prefix).digest()
hash2 = hashlib.sha256(hash1).digest()

# Extract first 4 bytes of the hash as checksum
checksum = hash2[:4]

# Append checksum to the decoded key
decoded_key_with_checksum = decoded_key_with_prefix + checksum

# Convert to base58 encoding
wif_key = base58.b58encode(decoded_key_with_checksum)

with open('WIF-KEY.txt', 'w') as file:
    file.write(wif_key.decode())


print(wif_key)
