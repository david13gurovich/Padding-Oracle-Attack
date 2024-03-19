from pwn import *
# Set the architecture to x86
context.arch = 'i386'
# Generate the shellcode using shellcraft
shellcode = asm(shellcraft.execve('/bin/sh', ['/bin/sh', '-c', 'echo "hi" > id.txt'], 0))
# Convert the shellcode to a string of hex bytes
hex_bytes = ''.join('\\x{:02x}'.format(b) for b in shellcode)
print(hex_bytes)